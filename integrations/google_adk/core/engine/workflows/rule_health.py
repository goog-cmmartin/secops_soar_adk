"""Rule & Detection Health Audit Workflow.

Orchestrates comprehensive health auditing for Chronicle YARA-L detection rules,
curated rulesets, compilation errors, execution errors, latency observability,
and detection decay across Google SecOps.

Error visibility: inventory reads (rules, deployments, execution errors) raise.
Telemetry reads (per-rule detection counts, curated deployments/counts, the two
curated dashboards) are recorded in ``RuleHealthReport.telemetry_errors`` with
per-source availability flags, so a failed read is never reported as healthy.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    RuleHealthFinding,
    RuleHealthReport,
    RuleHealthStatus,
    RuleSummary,
    RuleExecutionError,
)
from engine.workflows.curated_detections import ListCuratedRuleSetDeploymentsWorkflow
from engine.workflows.dashboards import (
    ExecuteDashboardQueryWorkflow,
    GetDashboardDetailWorkflow,
)
from engine.workflows.detection_rules import (
    ListRulesWorkflow,
    ListRuleDeploymentsWorkflow,
    ListRuleErrorsWorkflow,
)
from engine.workflows.rule_decay import QueryRuleDetectionCountsWorkflow

logger = logging.getLogger(__name__)

RULE_DETECTIONS_OVERVIEW_DASHBOARD_ID = "8c706509-d2c9-4f1c-9572-5f96f10e0df6"
RULE_OBSERVABILITY_DASHBOARD_ID = "ede65743-5a8f-4c80-bc31-ebdf9797b2ce"


class AuditRuleHealthWorkflow:
    """Orchestrates comprehensive posture auditing for Chronicle YARA-L rules and curated rulesets."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        include_curated: bool = True,
        latency_threshold_min: float = 30.0,
        page_size: int = 100,
        error_lookback_days: Optional[int] = None,
    ) -> RuleHealthReport:
        """Executes full rule health audit correlating live rules, errors, and telemetry.

        Args:
            include_curated: Also classify curated rule sets from their real
                precision deployments.
            latency_threshold_min: HIGH_LATENCY threshold (ingestion -> detection).
            page_size: Page size for the rule list; all pages are always read.
            error_lookback_days: Only count execution errors whose
                ``timeRange.endTime`` is within this many days. None (default,
                backward compatible) counts the full error history the API returns.
        """
        started = datetime.now(timezone.utc)
        telemetry_errors: List[str] = []

        # 1. Custom rules (all pages). Raises on failure.
        rules = ListRulesWorkflow(self.adapter).execute(page_size=page_size, all_pages=True).rules

        # 2. Execution errors (all pages, optional window). Raises on failure.
        since = started - timedelta(days=error_lookback_days) if error_lookback_days else None
        errors = ListRuleErrorsWorkflow(self.adapter).execute(page_size=1000, all_pages=True, since=since).errors

        errors_by_rule: Dict[str, List[RuleExecutionError]] = {}
        for err in errors:
            r_key = (err.rule_resource_name or "").split("/")[-1].split("@")[0].lower()
            if not r_key and err.curated_rule:
                r_key = err.curated_rule.split("/")[-1].split("@")[0].lower()
            if r_key:
                errors_by_rule.setdefault(r_key, []).append(err)

        # 3. Deployments (all pages). Raises on failure: enabled/alerting cannot be guessed.
        deployments_by_rule = self._collect_deployments()

        # 4. Telemetry (recorded, never swallowed).
        detection_counts, detection_counts_available = self._collect_detection_counts(telemetry_errors)
        telemetry = self._collect_rule_dashboard_telemetry(telemetry_errors)

        findings: List[RuleHealthFinding] = []
        for rule in rules:
            findings.append(
                self._evaluate_rule(
                    rule=rule,
                    errors_by_rule=errors_by_rule,
                    telemetry=telemetry,
                    latency_threshold_min=latency_threshold_min,
                    deployment=deployments_by_rule.get(rule.rule_id),
                    detection_counts=detection_counts,
                )
            )
        custom_count = len(findings)

        curated_available = False
        if include_curated:
            curated_findings, curated_available = self._evaluate_curated_rulesets(telemetry_errors)
            findings.extend(curated_findings)

        counts = {status: 0 for status in RuleHealthStatus}
        for f in findings:
            counts[f.status] += 1

        return RuleHealthReport(
            findings=findings,
            healthy_count=counts[RuleHealthStatus.HEALTHY],
            failing_count=counts[RuleHealthStatus.EXECUTION_ERROR] + counts[RuleHealthStatus.COMPILATION_ERROR],
            decay_count=counts[RuleHealthStatus.SILENT_DECAY],
            latency_alert_count=counts[RuleHealthStatus.HIGH_LATENCY],
            misconfigured_count=counts[RuleHealthStatus.MISCONFIGURED_ALERTING],
            disabled_count=counts[RuleHealthStatus.DISABLED],
            unknown_count=counts[RuleHealthStatus.UNKNOWN],
            total_rules_audited=len(findings),
            custom_rules_audited=custom_count,
            curated_rulesets_audited=len(findings) - custom_count,
            total_detections_24h=sum(detection_counts.values()),
            rules_firing_24h=sum(1 for v in detection_counts.values() if v > 0),
            execution_errors_considered=len(errors),
            error_lookback_days=error_lookback_days,
            average_risk_score=telemetry.get("average_risk_score", 0.0),
            top_mitre_tactics=telemetry.get("top_mitre_tactics", []),
            top_threat_categories=telemetry.get("top_threat_categories", []),
            detection_counts_available=detection_counts_available,
            overview_dashboard_available=telemetry.get("overview_available", False),
            observability_dashboard_available=telemetry.get("observability_available", False),
            curated_available=curated_available,
            telemetry_errors=telemetry_errors,
            duration_s=round((datetime.now(timezone.utc) - started).total_seconds(), 2),
            generated_at=datetime.now(timezone.utc),
        )

    def _evaluate_rule(
        self,
        rule: RuleSummary,
        errors_by_rule: Dict[str, List[RuleExecutionError]],
        telemetry: Dict[str, Any],
        latency_threshold_min: float,
        deployment: Optional[Any] = None,
        detection_counts: Optional[Dict[str, int]] = None,
    ) -> RuleHealthFinding:
        """Evaluates health status, latency, detection volume, and error diagnostics for a rule."""
        rule_id = rule.name.split("/")[-1].split("@")[0] if rule.name else ""
        rule_id_lower = rule_id.lower()
        rule_display_lower = (rule.display_name or "").lower()

        rule_errors = errors_by_rule.get(rule_id_lower, [])
        last_error_msg = rule_errors[0].error_message if rule_errors else None
        exec_error_count = len(rule_errors)

        # Per-rule 24h detection count, keyed by rule_id (not display name).
        detection_count = int((detection_counts or {}).get(rule_id, 0))

        latencies_by_name = telemetry.get("latencies_by_name", {})
        lat_info = latencies_by_name.get(rule_display_lower) or latencies_by_name.get(rule_id_lower)
        ingestion_latency = lat_info.get("ingestion_to_detection") if lat_info else None
        event_latency = lat_info.get("event_to_detection") if lat_info else None

        least_active_set = telemetry.get("least_active_rules", set())
        is_in_decay_set = (rule_display_lower in least_active_set) or (rule_id_lower in least_active_set)

        remediations: List[str] = []
        status = RuleHealthStatus.HEALTHY
        details = "Rule is operating normally."

        if deployment is not None:
            is_enabled = bool(deployment.enabled)
            is_alerting = bool(deployment.alerting)
            run_frequency = deployment.run_frequency
        elif "enabled" in rule.raw:
            is_enabled = bool(rule.raw["enabled"])
            is_alerting = bool(rule.raw.get("alerting", True))
            run_frequency = rule.run_frequency or rule.raw.get("runFrequency") or "UNKNOWN"
        elif rule.raw.get("executionState") in ("PAUSED", "DISABLED"):
            is_enabled = False
            is_alerting = bool(rule.raw.get("alerting", False))
            run_frequency = rule.run_frequency or "UNKNOWN"
        elif rule.run_frequency or rule.raw.get("executionState"):
            # Legacy fallback (no deployment record): infer from the rule's own fields.
            is_enabled = bool(
                rule.run_frequency in ("LIVE", "HOURLY", "DAILY")
                or rule.raw.get("executionState") == "ACTIVE"
            )
            is_alerting = bool(rule.raw.get("alerting", True))
            run_frequency = rule.run_frequency or "UNKNOWN"
        else:
            # No deployment record and no state on the rule (the live Rule
            # resource never carries runFrequency): unknown, not "disabled".
            is_enabled = False
            is_alerting = False
            run_frequency = "UNKNOWN"
            status = RuleHealthStatus.UNKNOWN
            details = f"No deployment record found for rule '{rule.display_name}'; enabled/alerting state is unknown."

        if status == RuleHealthStatus.UNKNOWN:
            pass
        elif not is_enabled:
            status = RuleHealthStatus.DISABLED
            details = f"Rule '{rule.display_name}' is currently disabled or has no active run frequency."
            remediations.append("Review rule logic and enable rule execution if detection coverage is required.")
        elif exec_error_count > 0:
            status = RuleHealthStatus.EXECUTION_ERROR
            details = f"Rule encountered {exec_error_count} runtime execution error(s). Last error: {last_error_msg}"
            remediations.append(f"Inspect YARA-L logic for runtime evaluation errors: {last_error_msg}")
            remediations.append("Validate rule against test events using VerifyRule workflow.")
        elif ingestion_latency is not None and ingestion_latency > latency_threshold_min:
            status = RuleHealthStatus.HIGH_LATENCY
            details = f"Rule detection latency is {ingestion_latency:.1f} min (threshold: {latency_threshold_min} min)."
            remediations.append("Optimize YARA-L condition window duration (e.g. reduce match window or narrow events).")
            remediations.append("Ensure joins utilize indexed UDM fields (e.g. principal.hostname, target.user.userid).")
        elif is_in_decay_set and detection_count == 0:
            status = RuleHealthStatus.SILENT_DECAY
            details = f"Rule '{rule.display_name}' is flagged in Least Active Rules with 0 detections."
            remediations.append("Verify if upstream log sources mapped to this rule are still ingesting active telemetry.")
            remediations.append("Review rule conditions against recent UDM events to check for schema drift or stale values.")
        elif not is_alerting and is_enabled:
            status = RuleHealthStatus.MISCONFIGURED_ALERTING
            details = f"Rule '{rule.display_name}' is executing but alerting is disabled."
            remediations.append("Enable alerting on rule deployment if detection notifications should generate alerts/cases.")

        return RuleHealthFinding(
            rule_id=rule_id,
            display_name=rule.display_name or rule_id,
            rule_owner="CUSTOMER",
            severity=rule.severity,
            status=status,
            enabled=is_enabled,
            alerting=is_alerting,
            run_frequency=run_frequency,
            detection_count_recent=detection_count,
            execution_error_count=exec_error_count,
            last_error_message=last_error_msg,
            ingestion_to_detection_latency_min=ingestion_latency,
            event_to_detection_latency_min=event_latency,
            details=details,
            remediation_steps=remediations,
            raw=rule.raw,
        )

    def _collect_deployments(self) -> Dict[str, Any]:
        """Maps rule_id -> RuleDeployment across all pages. Raises on failure."""
        res = ListRuleDeploymentsWorkflow(self.adapter).execute(page_size=1000, all_pages=True)
        return {dep.rule_id: dep for dep in res.deployments if dep.rule_id}

    def _collect_detection_counts(self, telemetry_errors: List[str]) -> "tuple[Dict[str, int], bool]":
        """Per-rule detection counts over the last day (custom and curated rule IDs)."""
        try:
            raw = QueryRuleDetectionCountsWorkflow(self.adapter).execute(lookback_days=1)
        except Exception as exc:
            msg = f"Per-rule detection count query (1d) failed: {type(exc).__name__}: {exc}"
            logger.warning(msg)
            telemetry_errors.append(msg)
            return {}, False
        return {rid: int(v.get("count", 0)) for rid, v in raw.items()}, True

    def _evaluate_curated_rulesets(self, telemetry_errors: List[str]) -> "tuple[List[RuleHealthFinding], bool]":
        """Classifies curated rule sets from their real BROAD/PRECISE deployments.

        A rule set is enabled when any precision is enabled, alerting when any
        enabled precision alerts. If the deployment list cannot be read, every
        rule set is reported as UNKNOWN (not DISABLED).
        """
        try:
            dep_res = ListCuratedRuleSetDeploymentsWorkflow(self.adapter).execute(include_display_names=True)
        except Exception as exc:
            msg = f"Curated rule set deployment listing failed: {type(exc).__name__}: {exc}"
            logger.warning(msg)
            telemetry_errors.append(msg)
            return [], False

        by_set: Dict[str, List[Any]] = {}
        names: Dict[str, str] = {}
        for d in dep_res.deployments:
            by_set.setdefault(d.rule_set_id, []).append(d)
            if d.display_name:
                names[d.rule_set_id] = d.display_name
        missing_names = dep_res.provenance.get("display_name_error")
        if missing_names:
            telemetry_errors.append(f"Curated rule set catalog (display names) unavailable: {missing_names}")

        set_counts: Dict[str, int] = {}
        counts_ok = True
        try:
            now = datetime.now(timezone.utc)
            res = self.adapter.count_curated_ruleset_detections(
                (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            )
            for c in (res.get("curatedRuleSetCounts", []) if isinstance(res, dict) else []):
                set_counts[str(c.get("curatedRuleSet", "")).split("/")[-1]] = int(c.get("count", 0))
        except Exception as exc:
            counts_ok = False
            msg = f"Curated rule set detection counts (1d) failed: {type(exc).__name__}: {exc}"
            logger.warning(msg)
            telemetry_errors.append(msg)

        findings: List[RuleHealthFinding] = []
        for rs_id, deps in sorted(by_set.items()):
            title = names.get(rs_id) or rs_id
            enabled_precisions = sorted(d.precision for d in deps if d.enabled)
            alerting_precisions = sorted(d.precision for d in deps if d.enabled and d.alerting)
            enabled = bool(enabled_precisions)
            alerting = bool(alerting_precisions)
            remediations: List[str] = []
            if enabled:
                status = RuleHealthStatus.HEALTHY
                details = (
                    f"Curated rule set enabled ({', '.join(enabled_precisions)}); "
                    f"alerting: {', '.join(alerting_precisions) or 'none'}."
                )
            else:
                status = RuleHealthStatus.DISABLED
                details = "Curated rule set is disabled for every precision."
                remediations.append(f"Enable curated ruleset '{title}' to activate Google out-of-the-box detection coverage.")
            findings.append(
                RuleHealthFinding(
                    rule_id=rs_id,
                    display_name=title,
                    rule_owner="GOOGLE",
                    severity="UNKNOWN",
                    status=status,
                    enabled=enabled,
                    alerting=alerting,
                    run_frequency="LIVE" if enabled else "UNKNOWN",
                    detection_count_recent=set_counts.get(rs_id, 0) if counts_ok else 0,
                    details=details,
                    remediation_steps=remediations,
                    raw={"deployments": [d.raw for d in deps]},
                )
            )
        return findings, True

    def _collect_rule_dashboard_telemetry(self, telemetry_errors: List[str]) -> Dict[str, Any]:
        """Latencies, least-active rules, risk score, MITRE tactics and threat categories from curated dashboards.

        Every dashboard/chart failure is appended to ``telemetry_errors``;
        ``overview_available`` / ``observability_available`` are True only when
        the dashboard was read and at least one target chart executed.
        """
        telemetry: Dict[str, Any] = {
            "latencies_by_name": {},
            "least_active_rules": set(),
            "top_mitre_tactics": [],
            "top_threat_categories": [],
            "average_risk_score": 0.0,
            "overview_available": False,
            "observability_available": False,
        }

        def run(label: str, q_name: str):
            try:
                return ExecuteDashboardQueryWorkflow(self.adapter).execute(query_name_or_id=q_name)
            except Exception as exc:
                msg = f"Dashboard chart '{label}' failed: {type(exc).__name__}: {exc}"
                logger.warning(msg)
                telemetry_errors.append(msg)
                return None

        # Rule Detections Overview
        try:
            overview_dash = GetDashboardDetailWorkflow(self.adapter).execute(
                RULE_DETECTIONS_OVERVIEW_DASHBOARD_ID, include_queries=False
            )
        except Exception as exc:
            msg = f"Rule Detections Overview dashboard unavailable: {type(exc).__name__}: {exc}"
            logger.warning(msg)
            telemetry_errors.append(msg)
            overview_dash = None
        if overview_dash is not None:
            for chart in overview_dash.charts:
                q_name = chart.query_name or chart.raw.get("chartDatasource", {}).get("dashboardQuery")
                if not q_name:
                    continue
                c_name = (chart.display_name or "").lower()
                if "least 10 active rules" in c_name:
                    res = run(chart.display_name, q_name)
                    if res is not None:
                        telemetry["overview_available"] = True
                        for row in res.rows:
                            r_name = (row.get("Rulename") or row.get("rule_name") or "").lower()
                            if r_name:
                                telemetry["least_active_rules"].add(r_name)
                elif "average risk score" in c_name:
                    res = run(chart.display_name, q_name)
                    if res is not None:
                        telemetry["overview_available"] = True
                        if res.rows:
                            telemetry["average_risk_score"] = float(
                                res.rows[0].get("Average_Risk_Score") or res.rows[0].get("risk_score") or 0.0
                            )
                elif "mitre" in c_name:
                    res = run(chart.display_name, q_name)
                    if res is not None:
                        telemetry["overview_available"] = True
                        telemetry["top_mitre_tactics"] = res.rows[:10]
                elif "threat categories" in c_name:
                    res = run(chart.display_name, q_name)
                    if res is not None:
                        telemetry["overview_available"] = True
                        telemetry["top_threat_categories"] = res.rows[:10]

        # Rule Observability
        try:
            obs_dash = GetDashboardDetailWorkflow(self.adapter).execute(
                RULE_OBSERVABILITY_DASHBOARD_ID, include_queries=False
            )
        except Exception as exc:
            msg = f"Rule Observability dashboard unavailable: {type(exc).__name__}: {exc}"
            logger.warning(msg)
            telemetry_errors.append(msg)
            obs_dash = None
        if obs_dash is not None:
            for chart in obs_dash.charts:
                q_name = chart.query_name or chart.raw.get("chartDatasource", {}).get("dashboardQuery")
                if not q_name:
                    continue
                c_name = (chart.display_name or "").lower()
                if "per-detection latency" in c_name or "latency numbers" in c_name:
                    res = run(chart.display_name, q_name)
                    if res is None:
                        continue
                    telemetry["observability_available"] = True
                    for row in res.rows:
                        r_name = (row.get("rule_name") or row.get("Rulename") or "").lower()
                        if not r_name:
                            continue
                        try:
                            ingest_to_det = float(row.get("ingestion_to_detection") or 0.0)
                            event_to_det = float(row.get("event_to_deteciton") or row.get("event_to_detection") or 0.0)
                        except (TypeError, ValueError) as exc:
                            telemetry_errors.append(f"Unparseable latency row for '{r_name}': {exc}")
                            continue
                        telemetry["latencies_by_name"][r_name] = {
                            "ingestion_to_detection": ingest_to_det,
                            "event_to_detection": event_to_det,
                            "detect_id": row.get("detect_id", ""),
                        }

        return telemetry
