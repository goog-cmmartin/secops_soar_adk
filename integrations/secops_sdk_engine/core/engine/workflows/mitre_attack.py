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

"""MITRE ATT&CK Strategic Mapping & Gap Analysis Engine Workflows.

Provides high-speed Firestore-backed rule synchronization, telemetry-to-tactic
cross-referencing, contextual coverage scoring, and strategic gap identification
against Google SecOps SIEM detection logic and ingestion pipelines.
"""

from datetime import datetime, timezone
import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import MitreCoverageAssessment, Provenance
from engine.mitre_catalog import MitreCatalog

logger = logging.getLogger(__name__)

# Fallback query ID for tenant ingestion log types
DEFAULT_INGESTION_QUERY_ID = "825b61da-751f-45c6-b08e-ba7eea249c16"


class SyncMitreRulesWorkflow:
    """Synchronizes custom and curated Google SecOps rules to Firestore cache with MITRE tags."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            from agents.core.evidence_store import get_evidence_store
            self.store = get_evidence_store()
        self.catalog = MitreCatalog.get_instance()

    def execute(
        self,
        force_refresh: bool = False,
        include_curated: bool = True,
        max_rules: Optional[int] = None,
    ) -> Dict[str, Any]:
        logger.info(
            "Starting MITRE Rules Sync (force_refresh=%s, include_curated=%s, max_rules=%s)...",
            force_refresh,
            include_curated,
            max_rules,
        )

        rule_records: List[Dict[str, Any]] = []
        all_techniques: Set[str] = set()
        all_tactics: Set[str] = set()

        # 1. Fetch Custom Rules with FULL view to get metadata and rule text
        custom_count = 0
        try:
            page_token = None
            while True:
                custom_res = self.adapter.list_rules(view="FULL", page_size=1000, page_token=page_token)
                raw_rules = []
                if isinstance(custom_res, dict):
                    raw_rules = custom_res.get("rules", [])
                elif hasattr(custom_res, "rules"):
                    raw_rules = getattr(custom_res, "rules", []) or []

                for r in raw_rules:
                    if isinstance(r, dict):
                        rule_id = r.get("id") or r.get("ruleId") or r.get("name", "")
                        display_name = r.get("displayName") or r.get("display_name") or rule_id
                        rule_text = r.get("ruleText") or r.get("rule_text") or ""
                        metadata = r.get("metadata", {}) or {}
                        tags = r.get("tags", []) or []
                        enabled = bool(r.get("enabled", True))
                        alerting = bool(r.get("alerting", True))
                        severity = str(r.get("severity", "MEDIUM") or "MEDIUM")
                        revision_id = str(r.get("revisionId") or r.get("revision_id") or "")
                    else:
                        rule_id = getattr(r, "id", "") or ""
                        display_name = getattr(r, "display_name", "") or rule_id
                        rule_text = getattr(r, "rule_text", "") or ""
                        metadata = getattr(r, "metadata", {}) or {}
                        tags = getattr(r, "tags", []) or []
                        enabled = getattr(r, "enabled", True)
                        alerting = getattr(r, "alerting", True)
                        severity = getattr(r, "severity", "MEDIUM") or "MEDIUM"
                        revision_id = getattr(r, "revision_id", "") or ""

                    # Combine text sources for technique extraction
                    search_corpus = [display_name, rule_text]
                    if isinstance(tags, (list, tuple)):
                        search_corpus.extend(str(t) for t in tags)
                    if isinstance(metadata, dict):
                        for k, v in metadata.items():
                            search_corpus.append(f"{k} {v}")

                    extracted_techs = self.catalog.extract_techniques(" ".join(search_corpus))

                    # Also inspect explicit metadata keys: mitre_attack_technique, mitre_attack_tactic
                    if isinstance(metadata, dict):
                        for key in ("mitre_attack_technique", "technique_id", "technique", "mitre_technique"):
                            if key in metadata and metadata[key]:
                                val = str(metadata[key])
                                more_techs = self.catalog.extract_techniques(val)
                                for mt in more_techs:
                                    if mt not in extracted_techs:
                                        extracted_techs.append(mt)

                    # Derive tactics
                    rule_tactics = set()
                    for t in extracted_techs:
                        all_techniques.add(t)
                        tech_meta = self.catalog.get_technique(t)
                        if tech_meta:
                            for tac in tech_meta.get("tactics", []):
                                rule_tactics.add(tac.lower())
                                all_tactics.add(tac.lower())

                    rule_records.append({
                        "rule_id": rule_id,
                        "display_name": display_name,
                        "rule_source": "CUSTOMER",
                        "enabled": enabled,
                        "alerting": alerting,
                        "severity": str(severity),
                        "mitre_techniques": sorted(extracted_techs),
                        "mitre_tactics": sorted(list(rule_tactics)),
                        "revision_id": revision_id,
                        "cached_at": datetime.now(timezone.utc).isoformat(),
                    })
                    custom_count += 1
                    if max_rules and custom_count >= max_rules:
                        break

                if max_rules and custom_count >= max_rules:
                    break
                if isinstance(custom_res, dict):
                    page_token = custom_res.get("nextPageToken")
                else:
                    page_token = getattr(custom_res, "next_page_token", None)
                if not page_token:
                    break
        except Exception as ex:
            logger.error("Failed to list custom rules during MITRE sync: %s", ex)
            raise

        # 2. Fetch Google Curated Rules from Content Hub Marketplace
        curated_count = 0
        if include_curated:
            try:
                page_token = None
                while True:
                    curated_res = {}
                    if hasattr(self.adapter, "list_featured_content_rules"):
                        curated_res = self.adapter.list_featured_content_rules(page_size=1000, page_token=page_token)

                    curated_rules = []
                    if isinstance(curated_res, dict):
                        curated_rules = curated_res.get("featuredContentRules", [])

                    # Fallback to list_curated_rules if featuredContentRules is not present or empty on initial page
                    if not curated_rules and not page_token and hasattr(self.adapter, "list_curated_rules"):
                        fallback_res = self.adapter.list_curated_rules(page_size=1000)
                        if isinstance(fallback_res, dict):
                            curated_rules = fallback_res.get("curatedRules", [])

                    for cr in curated_rules:
                        content_meta = cr.get("contentMetadata", {}) or {}
                        curated_content = cr.get("curatedRuleContent", {}) or {}

                        rule_id = (
                            content_meta.get("id")
                            or cr.get("ruleId")
                            or cr.get("id")
                            or cr.get("name", "").split("/")[-1]
                        )
                        display_name = (
                            content_meta.get("displayName")
                            or cr.get("displayName")
                            or cr.get("name")
                            or rule_id
                        )
                        rule_text = cr.get("ruleText", "") or ""

                        cr_techs = set()
                        # Extract from curatedRuleContent techniques
                        for t_item in curated_content.get("techniques", []):
                            tid = t_item.get("id", "") if isinstance(t_item, dict) else str(t_item)
                            cr_techs.update(self.catalog.extract_techniques(tid))

                        # Also check if techniques were in cr root (fallback API)
                        for t_item in cr.get("techniques", []):
                            tid = t_item.get("id", "") if isinstance(t_item, dict) else str(t_item)
                            cr_techs.update(self.catalog.extract_techniques(tid))

                        # Also extract from rule text if present
                        if rule_text:
                            cr_techs.update(self.catalog.extract_techniques(rule_text))

                        rule_tactics = set()
                        for tac_item in curated_content.get("tactics", []):
                            tac_id = tac_item.get("id", "") if isinstance(tac_item, dict) else str(tac_item)
                            if tac_id:
                                rule_tactics.add(tac_id.lower())

                        for t in cr_techs:
                            all_techniques.add(t)
                            tech_meta = self.catalog.get_technique(t)
                            if tech_meta:
                                for tac in tech_meta.get("tactics", []):
                                    rule_tactics.add(tac.lower())
                                    all_tactics.add(tac.lower())

                        enabled = cr.get("liveStatusEnabled", cr.get("enabled", True))
                        alerting = cr.get("alerting", True)
                        severity = cr.get("severity", "HIGH")
                        if isinstance(severity, dict):
                            severity = severity.get("displayName", "HIGH")

                        rule_records.append({
                            "rule_id": rule_id,
                            "display_name": display_name,
                            "rule_source": "GOOGLE_CURATED",
                            "enabled": bool(enabled),
                            "alerting": bool(alerting),
                            "severity": str(severity),
                            "mitre_techniques": sorted(list(cr_techs)),
                            "mitre_tactics": sorted(list(rule_tactics)),
                            "categories": content_meta.get("categories", []),
                            "author": content_meta.get("author", "Google Cloud Threat Intelligence"),
                            "cached_at": datetime.now(timezone.utc).isoformat(),
                        })
                        curated_count += 1
                        if max_rules and (custom_count + curated_count) >= max_rules:
                            break

                    if max_rules and (custom_count + curated_count) >= max_rules:
                        break

                    page_token = curated_res.get("nextPageToken") if isinstance(curated_res, dict) else None
                    if not page_token:
                        break
            except Exception as ex:
                logger.warning("Could not fetch curated rules during MITRE sync: %s", ex)

        # 3. Batch commit to EvidenceFabricStore
        saved_count = self.store.batch_save_rule_states(rule_records)
        logger.info(
            "MITRE Rule Sync completed: %d total rules saved (%d custom, %d curated), %d techniques mapped.",
            saved_count,
            custom_count,
            curated_count,
            len(all_techniques),
        )

        return {
            "status": "COMPLETED",
            "total_rules_synced": saved_count,
            "custom_rules_count": custom_count,
            "curated_rules_count": curated_count,
            "techniques_mapped_count": len(all_techniques),
            "tactics_mapped_count": len(all_tactics),
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }


class AnalyzeMitreCoverageWorkflow:
    """Analyzes tenant detection rules and live ingestion telemetry against MITRE ATT&CK."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            from agents.core.evidence_store import get_evidence_store
            self.store = get_evidence_store()
        self.catalog = MitreCatalog.get_instance()

    def execute(
        self,
        profile_id: str = "global_baseline",
        sync_cache_if_empty: bool = True,
        time_unit: str = "DAY",
        time_value: str = "7",
        persist: bool = True,
    ) -> MitreCoverageAssessment:
        """Computes MITRE coverage from the cached rule states and live ingestion telemetry.

        ``persist=False`` performs no writes: the empty-cache sync (which saves
        rule states) is skipped and the assessment is not saved. Note that
        constructing this workflow without an explicit ``store`` calls
        ``get_evidence_store()``, whose Firestore connectivity probe writes a
        ``system_configs/connectivity_check`` document when Firestore is
        reachable; pass a store to avoid it.
        """
        logger.info("Executing MITRE ATT&CK Strategic Coverage Analysis (profile=%s)...", profile_id)

        # 1. Fetch rules from Firestore cache
        rules = self.store.list_rule_states(limit=10000)
        if not rules and sync_cache_if_empty:
            if persist:
                logger.info("No cached rules found in EvidenceFabricStore. Initiating sync...")
                sync_wf = SyncMitreRulesWorkflow(self.adapter, self.store)
                sync_wf.execute()
                rules = self.store.list_rule_states(limit=10000)
            else:
                logger.warning(
                    "MITRE rule cache is empty and persist=False: skipping the cache sync (it writes rule "
                    "states); coverage is computed from 0 cached rules."
                )

        # 2. Query live tenant ingestion telemetry
        ingested_log_types: List[str] = []
        try:
            res = self.adapter.execute_dashboard_query(
                query_name=DEFAULT_INGESTION_QUERY_ID,
                time_unit=time_unit,
                time_value=time_value,
            )
            if hasattr(res, "rows") and res.rows:
                for row in res.rows:
                    lt = row.get("logType") or row.get("log_type")
                    if lt:
                        ingested_log_types.append(str(lt))
        except Exception as ex:
            logger.warning("Could not query live dashboard ingestion metrics: %s", ex)

        # 3. Categorize logs and derive telemetry visibility
        categorized_logs = self.catalog.categorize_log_types(ingested_log_types)
        active_categories = [cat for cat, logs in categorized_logs.items() if logs and cat != "OTHER"]
        visibility_tactics = self.catalog.get_tactical_visibility_for_categories(active_categories)

        # 4. Map rules to techniques and tactics
        technique_counts: Dict[str, int] = {}
        technique_to_rules: Dict[str, List[Dict[str, Any]]] = {}
        covered_tactics: Set[str] = set()
        enabled_count = 0

        for r in rules:
            is_enabled = r.get("enabled", True)
            if is_enabled:
                enabled_count += 1

            for t in r.get("mitre_techniques", []):
                norm_t = str(t).upper().replace("_", ".")
                technique_counts[norm_t] = technique_counts.get(norm_t, 0) + 1
                if norm_t not in technique_to_rules:
                    technique_to_rules[norm_t] = []
                technique_to_rules[norm_t].append({
                    "rule_id": r.get("rule_id"),
                    "display_name": r.get("display_name", r.get("rule_id")),
                    "rule_source": r.get("rule_source", "CUSTOMER"),
                    "severity": r.get("severity", "MEDIUM"),
                    "enabled": is_enabled,
                })

                tech_meta = self.catalog.get_technique(norm_t)
                if tech_meta:
                    for tac in tech_meta.get("tactics", []):
                        covered_tactics.add(tac.lower())

        # 5. Evaluate against selected Threat Profile
        profile = self.catalog.get_threat_profile(profile_id)
        high_risk_map = profile.get("high_risk_techniques", {})
        total_relevant = profile.get("relevant_techniques", 100) or 100

        sum_risk_relevance = sum(high_risk_map.get(t, 1) for t in technique_counts)
        resilience_bonus = sum(0.5 for count in technique_counts.values() if count > 1)
        raw_score = (sum_risk_relevance + resilience_bonus) / total_relevant
        coverage_score = round(min(100.0, raw_score * 100.0), 2)

        # 6. Strategic Gap Identification
        all_matrix_tactics = set(self.catalog.tactics.keys())
        visibility_gaps = sorted(list(all_matrix_tactics - visibility_tactics))
        detection_gaps = sorted(list(all_matrix_tactics - covered_tactics))
        blind_tactics = sorted(list(set(visibility_gaps).intersection(set(detection_gaps))))

        # Critical technique gaps: profile high-risk techniques with 0 rules
        critical_techniques: List[Dict[str, Any]] = []
        for tech_id, weight in sorted(high_risk_map.items(), key=lambda x: x[1], reverse=True):
            if tech_id not in technique_counts:
                meta = self.catalog.get_technique(tech_id) or {}
                critical_techniques.append({
                    "technique_id": tech_id,
                    "name": meta.get("name", "Unknown Technique"),
                    "risk_weight": weight,
                    "tactics": meta.get("tactics", []),
                    "url": meta.get("url", f"https://attack.mitre.org/techniques/{tech_id}"),
                })

        # Resilience classification: Resilient (>=2 rules) vs Fragile (1 rule)
        resilient_techniques: List[Dict[str, Any]] = []
        fragile_techniques: List[Dict[str, Any]] = []

        for tech_id, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True):
            meta = self.catalog.get_technique(tech_id) or {}
            tech_entry = {
                "technique_id": tech_id,
                "name": meta.get("name", "Unknown Technique"),
                "rule_count": count,
                "tactics": meta.get("tactics", []),
                "rules": technique_to_rules.get(tech_id, []),
                "url": meta.get("url", f"https://attack.mitre.org/techniques/{tech_id}"),
            }
            if count > 1:
                resilient_techniques.append(tech_entry)
            else:
                fragile_techniques.append(tech_entry)

        now_str = datetime.now(timezone.utc).isoformat()
        assessment_id = f"mitre_assess_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        prov = Provenance(
            source="Chronicle Rules & Dashboards API",
            timestamp=now_str,
            details={
                "target_entity": f"Threat Profile: {profile.get('name', profile_id)}",
                "confidence_score": 1.0,
                "extracted_by": "AnalyzeMitreCoverageWorkflow",
                "raw_query_id": "825b61da-751f-45c6-b08e-ba7eea249c16",
                "profile_id": profile_id,
                "rules_evaluated": len(rules),
                "log_sources_count": len(ingested_log_types),
            },
        )

        assessment = MitreCoverageAssessment(
            assessment_id=assessment_id,
            profile_id=profile_id,
            profile_name=str(profile.get("name", profile_id)),
            coverage_score=coverage_score,
            total_baseline_techniques=total_relevant,
            validated_technique_count=len(technique_counts),
            total_rules_evaluated=len(rules),
            enabled_rules_count=enabled_count,
            visibility_tactics_count=len(visibility_tactics),
            detection_tactics_count=len(covered_tactics),
            visibility_tactics=sorted(list(visibility_tactics)),
            covered_tactics=sorted(list(covered_tactics)),
            visibility_gaps=visibility_gaps,
            detection_gaps=detection_gaps,
            blind_tactics=blind_tactics,
            critical_techniques=critical_techniques,
            resilient_techniques=resilient_techniques,
            fragile_techniques=fragile_techniques,
            categorized_logs=categorized_logs,
            score_breakdown={
                "sum_risk_weighted_techniques": sum_risk_relevance,
                "resilience_bonus": resilience_bonus,
                "total_relevant_baseline": total_relevant,
                "formula": "min(100.0, (Sum_Risk_Weighted_Techniques + Resilience_Bonus) / Total_Relevant * 100)",
            },
            created_at=now_str,
            provenance=prov,
        )

        # 7. Persist to store
        if persist:
            try:
                self.store.save_mitre_assessment(assessment.to_dict())
            except Exception as ex:
                logger.warning("Could not persist MITRE assessment to store: %s", ex)

        return assessment


class GenerateMitreReportWorkflow:
    """Generates comprehensive Markdown and Slack reporting artifacts for MITRE posture."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            from agents.core.evidence_store import get_evidence_store
            self.store = get_evidence_store()

    def execute(
        self,
        assessment: Optional[MitreCoverageAssessment] = None,
        profile_id: str = "global_baseline",
    ) -> Dict[str, Any]:
        if assessment is None:
            analyze_wf = AnalyzeMitreCoverageWorkflow(self.adapter, self.store)
            assessment = analyze_wf.execute(profile_id=profile_id)

        lines: List[str] = [
            f"# MITRE ATT&CK Strategic Coverage Report",
            f"**Threat Profile:** {assessment.profile_name} (`{assessment.profile_id}`)",
            f"**Generated:** {assessment.created_at}",
            "",
            "## 1. Executive Posture Summary",
            "",
            f"| Metric | Value |",
            f"| :--- | :--- |",
            f"| **Contextual Coverage Score** | **{assessment.coverage_score:.1f}%** |",
            f"| **Covered MITRE Techniques** | {assessment.validated_technique_count} |",
            f"| **Total Rules Evaluated** | {assessment.total_rules_evaluated} ({assessment.enabled_rules_count} enabled) |",
            f"| **Resilient Techniques (>= 2 Rules)** | {len(assessment.resilient_techniques)} |",
            f"| **Fragile Techniques (Single Point of Failure)** | {len(assessment.fragile_techniques)} |",
            f"| **Telemetry Visibility Tactics** | {assessment.visibility_tactics_count} / 14 |",
            f"| **Detection Covered Tactics** | {assessment.detection_tactics_count} / 14 |",
            f"| **Blind Tactics (Zero Telemetry & Rules)** | {len(assessment.blind_tactics)} |",
            "",
        ]

        if assessment.blind_tactics:
            lines.extend([
                "### ⚠️ Blind Tactics",
                "> The following ATT&CK tactics have **zero ingestion telemetry** and **zero detection rules**:",
                "",
            ])
            for bt in assessment.blind_tactics:
                lines.append(f"- `{bt}`")
            lines.append("")

        if assessment.critical_techniques:
            lines.extend([
                "## 2. High-Risk Technique Gaps",
                "The following techniques are designated high-risk in the target threat profile but currently have **zero detection rules**:",
                "",
                "| Technique ID | Name | Risk Weight | Tactics | Action |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ])
            for ct in assessment.critical_techniques[:15]:
                tacts = ", ".join(ct.get("tactics", []))
                lines.append(f"| [{ct['technique_id']}]({ct.get('url', '')}) | {ct['name']} | {ct['risk_weight']} / 5 | {tacts} | Author YARA-L rule |")
            lines.append("")

        lines.extend([
            "## 3. Resilience & Detection Health",
            f"- **Resilient Techniques:** {len(assessment.resilient_techniques)} techniques have redundant detection coverage across multiple rules.",
            f"- **Fragile Techniques:** {len(assessment.fragile_techniques)} techniques rely on a single rule (potential Single Point of Failure).",
            "",
            "### Top Resilient Detections",
            "| Technique ID | Name | Rule Count | Tactics |",
            "| :--- | :--- | :--- | :--- |",
        ])
        for rt in assessment.resilient_techniques[:10]:
            tacts = ", ".join(rt.get("tactics", []))
            lines.append(f"| [{rt['technique_id']}]({rt.get('url', '')}) | {rt['name']} | {rt['rule_count']} rules | {tacts} |")
        lines.append("")

        lines.extend([
            "## 4. Telemetry Domain Distribution",
            "Ingested telemetry categories and their active source log types:",
            "",
        ])
        for cat, logs in assessment.categorized_logs.items():
            if logs:
                lines.append(f"- **{cat}** ({len(logs)} log types): {', '.join(logs[:8])}{' ...' if len(logs) > 8 else ''}")

        lines.extend([
            "",
            "---",
            "*Report compiled automatically by SecOps MITRE ATT&CK Engine.*",
        ])

        return {
            "assessment": assessment.to_dict(),
            "markdown": "\n".join(lines),
        }
