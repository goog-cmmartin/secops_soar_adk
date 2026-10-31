# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import annotations

"""Unified Detection Rule Repository Audit Workflow.

Orchestrates customer and curated rule inventory reconciliation, Vertex AI
768-d vector embedding synchronization, 90-day alert telemetry decay analysis (DPS),
execution error tracking, and cross-rule conflict/curated shadowing evaluation (COS)
into a single, comprehensive detection health audit.
"""

from datetime import datetime, timezone
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    Provenance,
    RuleAuditFinding,
    RuleAuditReport,
    RuleHealthStatus,
    RuleSourceType,
)
from engine.workflows.detection_rules import (
    ListRuleDeploymentsWorkflow,
    ListRuleErrorsWorkflow,
    ListRulesWorkflow,
)
from engine.workflows.rule_conflict import (
    SyncRuleEmbeddingsWorkflow,
)
from engine.workflows.rule_decay import (
    QueryRuleDetectionCountsWorkflow,
)

logger = logging.getLogger(__name__)


class AuditRulesWorkflow:
    """Unified workflow orchestrating full detection repository health auditing."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            try:
                from agents.core.evidence_store import get_evidence_store
                self.store = get_evidence_store()
            except Exception as e:
                logger.warning("Could not initialize EvidenceFabricStore for AuditRulesWorkflow: %s", e)
                self.store = None

    def execute(
        self,
        include_curated: bool = True,
        sync_embeddings: bool = True,
        lookback_days: int = 90,
        run_conflict_scan: bool = True,
        batch_size: int = 50,
        page_size: int = 1000,
    ) -> RuleAuditReport:
        """Executes full detection rule repository audit across custom and curated rules."""
        logger.info(
            "Starting Unified Rule Repository Audit (include_curated=%s, sync_embeddings=%s, lookback_days=%d, run_conflict_scan=%s)...",
            include_curated,
            sync_embeddings,
            lookback_days,
            run_conflict_scan,
        )

        embeddings_synced_count = 0

        # Phase 1: Vector Embeddings Synchronization
        if sync_embeddings and self.store:
            try:
                sync_wf = SyncRuleEmbeddingsWorkflow(self.adapter, self.store)
                sync_res = sync_wf.execute(
                    batch_size=batch_size,
                    include_curated=include_curated,
                )
                embeddings_synced_count = sync_res.get("embedded_count", 0)
                logger.info("Rule Embedding Synchronization finished: %d new embeddings written.", embeddings_synced_count)
            except Exception as ex:
                logger.warning("Rule embedding synchronization failed during repository audit: %s", ex)

        # Phase 2: Inventory & Deployments
        deployment_map: Dict[str, Any] = {}
        archived_rule_ids: Set[str] = set()
        try:
            dep_wf = ListRuleDeploymentsWorkflow(self.adapter)
            dep_res = dep_wf.execute(page_size=page_size)
            for dep in getattr(dep_res, "deployments", []):
                rid = getattr(dep, "rule_id", "")
                if rid:
                    deployment_map[rid] = dep
                raw_name = getattr(dep, "name", "")
                if raw_name:
                    parts = raw_name.split("/")
                    if len(parts) >= 2 and parts[-1] == "deployment":
                        deployment_map[parts[-2]] = dep
                    else:
                        deployment_map[parts[-1]] = dep
                if getattr(dep, "archived", False):
                    if rid:
                        archived_rule_ids.add(rid)
                    if raw_name:
                        archived_rule_ids.add(raw_name.split("/")[-1])
        except Exception as ex:
            logger.warning("Could not fetch rule deployments for audit: %s", ex)

        # Customer Rules
        list_rules_wf = ListRulesWorkflow(self.adapter)
        custom_rules_res = list_rules_wf.execute(page_size=page_size)
        customer_rules = getattr(custom_rules_res, "rules", []) or []

        # Curated Rules
        curated_rules: List[Dict[str, Any]] = []
        if include_curated and hasattr(self.adapter, "list_curated_rules"):
            try:
                c_res = self.adapter.list_curated_rules(page_size=1000)
                curated_rules = c_res.get("curatedRules", []) if isinstance(c_res, dict) else []
            except Exception as ex:
                logger.warning("Could not fetch curated rules for audit: %s", ex)

        # Phase 3: Runtime Execution Errors
        errors_by_rule: Dict[str, List[Any]] = {}
        try:
            list_errors_wf = ListRuleErrorsWorkflow(self.adapter)
            errors_res = list_errors_wf.execute(page_size=100)
            for err in getattr(errors_res, "errors", []):
                r_key = (getattr(err, "rule_resource_name", "") or "").split("/")[-1].lower()
                curated_ref = getattr(err, "curated_rule", "") or ""
                if not r_key and curated_ref:
                    r_key = curated_ref.split("/")[-1].lower()
                if r_key:
                    errors_by_rule.setdefault(r_key, []).append(err)
                    base_key = r_key.split("@")[0]
                    if base_key != r_key:
                        errors_by_rule.setdefault(base_key, []).append(err)
        except Exception as ex:
            logger.warning("Could not fetch rule execution errors for audit: %s", ex)

        # Phase 4: 90-Day Telemetry & Decay Evaluation
        telemetry_map: Dict[str, int] = {}
        try:
            telemetry_wf = QueryRuleDetectionCountsWorkflow(self.adapter)
            telemetry_map = telemetry_wf.execute(lookback_days=lookback_days)
        except Exception as ex:
            logger.warning("Could not fetch 90-day telemetry counts for audit: %s", ex)

        # Phase 5: Evaluate Findings for Customer Rules
        findings: List[RuleAuditFinding] = []
        healthy_count = 0
        silent_decay_count = 0
        failing_count = 0
        misconfigured_count = 0
        disabled_count = 0
        conflict_count = 0
        shadowed_by_curated_count = 0
        total_detections_90d = 0

        for rule in customer_rules:
            rid = getattr(rule, "rule_id", "")
            rname = getattr(rule, "rule_name", "") or getattr(rule, "display_name", "") or rid
            sev = getattr(rule, "severity", "MEDIUM")

            dep = deployment_map.get(rid)
            is_archived = rid in archived_rule_ids or (getattr(dep, "archived", False) if dep else False)
            if is_archived:
                continue

            enabled = getattr(dep, "enabled", False) if dep else getattr(rule, "enabled", True)
            alerting = getattr(dep, "alerting", False) if dep else getattr(rule, "alerting", True)
            run_freq = getattr(dep, "run_frequency", "LIVE") if dep else "LIVE"

            # Telemetry
            telemetry_entry = (
                telemetry_map.get(rid)
                or telemetry_map.get(rname)
                or telemetry_map.get(rid.lower())
                or 0
            )
            if isinstance(telemetry_entry, dict):
                detections_90d = int(telemetry_entry.get("count", 0))
            elif isinstance(telemetry_entry, (int, float)):
                detections_90d = int(telemetry_entry)
            else:
                detections_90d = 0

            total_detections_90d += detections_90d

            # Execution errors
            rule_errors = errors_by_rule.get(rid.lower(), []) or errors_by_rule.get(rname.lower(), [])
            error_count = len(rule_errors)
            last_err_msg = getattr(rule_errors[0], "error_message", None) if rule_errors else None

            # Vector embedding status
            has_embedding = False
            highest_conflict_cos = 0.0
            highest_conflict_type = None
            shadowed_by_curated_id = None
            shadowed_by_curated_name = None

            if self.store:
                state = self.store.get_rule_state(rid)
                if state and state.get("embedding"):
                    has_embedding = True

                # Check conflict / curated shadowing
                if run_conflict_scan and has_embedding:
                    similar = self.store.find_similar_rules(target_rule_id=rid, limit=5)
                    for cand in similar:
                        cand_id = cand.get("rule_id", "")
                        cand_name = cand.get("rule_name") or cand.get("display_name", "")
                        sim_score = cand.get("similarity_score", 0.0)
                        cand_cos = round(sim_score * 100.0, 1)

                        if cand_cos > highest_conflict_cos:
                            highest_conflict_cos = cand_cos
                            highest_conflict_type = "OVERLAP" if cand_cos < 85 else "REDUNDANCY"

                        is_curated = (
                            cand_id.startswith("ur_")
                            or cand.get("rule_source") == "GOOGLE_CURATED"
                            or "curated" in cand_id.lower()
                        )
                        if is_curated and cand_cos >= 70.0 and not shadowed_by_curated_id:
                            shadowed_by_curated_id = cand_id
                            shadowed_by_curated_name = cand_name

            # Health classification
            remediation: List[str] = []
            if error_count > 0:
                status = RuleHealthStatus.EXECUTION_ERROR
                failing_count += 1
                remediation.append(f"Resolve runtime compilation/execution errors: {last_err_msg or 'Execution failure'}")
            elif not enabled:
                status = RuleHealthStatus.DISABLED
                disabled_count += 1
                remediation.append("Rule is disabled. Enable rule deployment if threat detection is required.")
            elif enabled and not alerting:
                status = RuleHealthStatus.MISCONFIGURED_ALERTING
                misconfigured_count += 1
                remediation.append("Rule is actively executing but alerting is disabled. Enable alerting in Rule Deployments.")
            elif enabled and detections_90d == 0:
                status = RuleHealthStatus.SILENT_DECAY
                silent_decay_count += 1
                remediation.append("Rule produced 0 detections in 90 days. Verify underlying UDM log sources are actively streaming.")
            else:
                status = RuleHealthStatus.HEALTHY
                healthy_count += 1

            if highest_conflict_cos >= 75.0:
                conflict_count += 1

            if shadowed_by_curated_id:
                shadowed_by_curated_count += 1
                remediation.append(
                    f"Consolidate rule logic: Customer rule shadows Google Curated detection '{shadowed_by_curated_name}' ({shadowed_by_curated_id}) with {highest_conflict_cos}% overlap."
                )

            # DPS score (Detection Performance Score: 0-100)
            dps_score = 100.0
            if error_count > 0:
                dps_score -= 40.0
            if detections_90d == 0:
                dps_score -= 35.0
            if not alerting and enabled:
                dps_score -= 20.0
            if highest_conflict_cos >= 75.0:
                dps_score -= 15.0
            dps_score = max(0.0, round(dps_score, 1))

            decay_status = "HEALTHY" if detections_90d > 0 else "SILENT"

            finding = RuleAuditFinding(
                rule_id=rid,
                display_name=rname,
                rule_source=RuleSourceType.CUSTOMER.value,
                severity=sev,
                status=status,
                enabled=enabled,
                alerting=alerting,
                run_frequency=run_freq,
                dps_score=dps_score,
                decay_status=decay_status,
                detection_count_90d=detections_90d,
                execution_error_count=error_count,
                last_error_message=last_err_msg,
                has_embedding=has_embedding,
                highest_conflict_cos=highest_conflict_cos,
                highest_conflict_type=highest_conflict_type,
                shadowed_by_curated_id=shadowed_by_curated_id,
                shadowed_by_curated_name=shadowed_by_curated_name,
                details=f"Status: {status.value}, 90d Detections: {detections_90d}, DPS: {dps_score}.",
                remediation_steps=remediation,
                raw=getattr(rule, "raw", {}) or {},
            )
            findings.append(finding)

            # Update Evidence Fabric state
            if self.store:
                self.store.save_rule_state(
                    rid,
                    {
                        "rule_id": rid,
                        "rule_name": rname,
                        "display_name": rname,
                        "rule_source": "CUSTOMER",
                        "status": status.value,
                        "enabled": enabled,
                        "alerting": alerting,
                        "dps_score": dps_score,
                        "decay_status": decay_status,
                        "detection_count_90d": detections_90d,
                        "execution_error_count": error_count,
                        "last_error_message": last_err_msg,
                        "has_embedding": has_embedding,
                        "highest_conflict_cos": highest_conflict_cos,
                        "shadowed_by_curated_id": shadowed_by_curated_id,
                        "shadowed_by_curated_name": shadowed_by_curated_name,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

        # Phase 6: Evaluate Curated Rules
        for c_rule in curated_rules:
            c_name = c_rule.get("displayName") or ""
            c_path = c_rule.get("name", "")
            c_id = c_path.split("/")[-1] if c_path else ""
            if not c_id:
                continue

            sev_dict = c_rule.get("severity", {})
            c_sev = sev_dict.get("displayName", "MEDIUM") if isinstance(sev_dict, dict) else str(sev_dict or "MEDIUM")

            has_embedding = False
            if self.store:
                state = self.store.get_rule_state(c_id)
                if state and state.get("embedding"):
                    has_embedding = True

            c_telemetry_entry = (
                telemetry_map.get(c_id)
                or telemetry_map.get(c_name)
                or telemetry_map.get(c_id.lower())
                or 0
            )
            if isinstance(c_telemetry_entry, dict):
                c_detections_90d = int(c_telemetry_entry.get("count", 0))
            elif isinstance(c_telemetry_entry, (int, float)):
                c_detections_90d = int(c_telemetry_entry)
            else:
                c_detections_90d = 0

            total_detections_90d += c_detections_90d

            c_finding = RuleAuditFinding(
                rule_id=c_id,
                display_name=c_name or c_id,
                rule_source=RuleSourceType.GOOGLE_CURATED.value,
                severity=c_sev,
                status=RuleHealthStatus.HEALTHY,
                enabled=True,
                alerting=True,
                run_frequency="LIVE",
                dps_score=100.0,
                decay_status="ACTIVE",
                detection_count_90d=c_detections_90d,
                execution_error_count=0,
                last_error_message=None,
                has_embedding=has_embedding,
                highest_conflict_cos=0.0,
                highest_conflict_type=None,
                shadowed_by_curated_id=None,
                shadowed_by_curated_name=None,
                details=f"Google Curated Rule: {c_rule.get('description', '')[:120]}",
                remediation_steps=[],
                raw=c_rule,
            )
            findings.append(c_finding)

        report = RuleAuditReport(
            findings=findings,
            total_rules_scanned=len(findings),
            customer_rules_count=len(customer_rules),
            curated_rules_count=len(curated_rules),
            embeddings_synced_count=embeddings_synced_count,
            healthy_count=healthy_count,
            silent_decay_count=silent_decay_count,
            failing_count=failing_count,
            misconfigured_count=misconfigured_count,
            disabled_count=disabled_count,
            conflict_count=conflict_count,
            shadowed_by_curated_count=shadowed_by_curated_count,
            total_detections_90d=total_detections_90d,
            generated_at=datetime.now(timezone.utc),
            provenance=Provenance(
                source="GoogleSecOpsAdapter",
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={"method": "AuditRulesWorkflow.execute"},
            ),
        )

        # Save snapshot to Evidence Fabric
        if self.store:
            try:
                self.store.save_rule_audit(report.to_dict())
                logger.info("Saved unified Rule Audit Report to Evidence Fabric.")
            except Exception as ex:
                logger.warning("Could not persist Rule Audit Report to Evidence Fabric: %s", ex)

        logger.info(
            "Unified Rule Audit Complete: %d rules scanned (%d customer, %d curated), %d healthy, %d silent, %d failing, %d conflicts.",
            report.total_rules_scanned,
            report.customer_rules_count,
            report.curated_rules_count,
            report.healthy_count,
            report.silent_decay_count,
            report.failing_count,
            report.conflict_count,
        )

        return report
