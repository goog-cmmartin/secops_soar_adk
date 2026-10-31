"""Detection Rule Conflict & Overlap Scoring Engine Workflows.

Implements semantic conflict discovery, dual YARA-L logic comparison,
and Conflict Overlap Scoring (COS: 0-100) across Google SecOps detection rules.
Supports vector search with text-embedding-004, Gemini-powered semantic reasoning,
and batch tenant synchronization for thousands of deployed rules.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    BatchRuleConflictAuditResult,
    ConflictSeverityTier,
    Provenance,
    RuleConflictAuditResult,
    RuleConflictPair,
    RuleConflictType,
    RuleDetail,
    RuleSummary,
)

logger = logging.getLogger(__name__)

# Section extraction regexes for YARA-L 2.0
META_BLOCK_REGEX = re.compile(r"meta:\s*(.*?)(?:events:|match:|outcome:|condition:|options:|\Z)", re.DOTALL | re.IGNORECASE)
EVENTS_BLOCK_REGEX = re.compile(r"events:\s*(.*?)(?:match:|outcome:|condition:|options:|\Z)", re.DOTALL | re.IGNORECASE)
MATCH_BLOCK_REGEX = re.compile(r"match:\s*(.*?)(?:outcome:|condition:|options:|\Z)", re.DOTALL | re.IGNORECASE)
OUTCOME_BLOCK_REGEX = re.compile(r"outcome:\s*(.*?)(?:condition:|options:|\Z)", re.DOTALL | re.IGNORECASE)
CONDITION_BLOCK_REGEX = re.compile(r"condition:\s*(.*?)(?:options:|\Z)", re.DOTALL | re.IGNORECASE)

UDM_FIELD_REGEX = re.compile(
    r"\$[a-zA-Z0-9_]+\.((?:metadata|principal|target|src|about|security_result|observer|network|intermediary)(?:\.[a-zA-Z0-9_]+)+)"
)

# Conflict Scoring Weights
CONFLICT_TYPE_WEIGHTS: Dict[str, float] = {
    RuleConflictType.REDUNDANCY: 30.0,
    RuleConflictType.CONTRADICTION: 25.0,
    RuleConflictType.OVERLAP: 15.0,
    RuleConflictType.SCOPE_GAPS: 5.0,
}

SEVERITY_WEIGHTS: Dict[str, float] = {
    "HIGH": 30.0,
    "MEDIUM": 15.0,
    "LOW": 5.0,
}


def calculate_conflict_overlap_score(
    similarity_score: float,
    conflict_type: str,
    impact_severity: str,
) -> Tuple[float, float, float, float, str]:
    """Calculates Conflict Overlap Score (COS: 0-100).

    Formula:
        COS = (Similarity Score * 40.0) + Conflict Type Weight + Severity Weight

    Weights:
        Conflict Type: REDUNDANCY (+30), CONTRADICTION (+25), OVERLAP (+15), SCOPE GAPS (+5)
        Severity: HIGH (+30), MEDIUM (+15), LOW (+5)

    Tiers:
        CRITICAL OVERLAP: COS >= 75
        MODERATE OVERLAP: 45 <= COS < 75
        LOW / NO OVERLAP: COS < 45

    Returns:
        Tuple of (cos_score, similarity_pts, conflict_type_pts, severity_pts, severity_tier)
    """
    bounded_sim = max(0.0, min(1.0, float(similarity_score)))
    sim_pts = round(bounded_sim * 40.0, 1)

    normalized_type = conflict_type.strip().upper()
    if normalized_type not in CONFLICT_TYPE_WEIGHTS:
        if "REDUNDAN" in normalized_type:
            normalized_type = RuleConflictType.REDUNDANCY
        elif "CONTRADICT" in normalized_type:
            normalized_type = RuleConflictType.CONTRADICTION
        elif "GAP" in normalized_type:
            normalized_type = RuleConflictType.SCOPE_GAPS
        else:
            normalized_type = RuleConflictType.OVERLAP
    type_pts = CONFLICT_TYPE_WEIGHTS.get(normalized_type, 15.0)

    normalized_sev = impact_severity.strip().upper()
    if normalized_sev not in SEVERITY_WEIGHTS:
        if "CRIT" in normalized_sev or "HIGH" in normalized_sev:
            normalized_sev = "HIGH"
        elif "LOW" in normalized_sev or "INFO" in normalized_sev:
            normalized_sev = "LOW"
        else:
            normalized_sev = "MEDIUM"
    sev_pts = SEVERITY_WEIGHTS.get(normalized_sev, 15.0)

    cos = round(sim_pts + type_pts + sev_pts, 1)
    cos = max(0.0, min(100.0, cos))

    if cos >= 75.0:
        tier = ConflictSeverityTier.CRITICAL
    elif cos >= 45.0:
        tier = ConflictSeverityTier.MODERATE
    else:
        tier = ConflictSeverityTier.LOW

    return cos, sim_pts, type_pts, sev_pts, tier


def synthesize_rule_summary(rule_data: Any) -> str:
    """Synthesizes text for vector embedding generation.

    Summary = Rule Name + Description + MITRE ATT&CK Tactics/Techniques + Severity
    """
    if hasattr(rule_data, "rule_name"):
        name = getattr(rule_data, "rule_name", "") or getattr(rule_data, "display_name", "")
        desc = getattr(rule_data, "description", "")
        sev = getattr(rule_data, "severity", "MEDIUM")
        raw = getattr(rule_data, "raw", {}) or {}
    elif isinstance(rule_data, dict):
        name = rule_data.get("rule_name") or rule_data.get("display_name") or rule_data.get("displayName") or rule_data.get("name") or ""
        desc = rule_data.get("description", "")
        sev = rule_data.get("severity", "MEDIUM")
        if isinstance(sev, dict):
            sev = sev.get("displayName") or sev.get("severity") or "MEDIUM"
        raw = rule_data.get("raw", {}) or rule_data
    else:
        name = str(rule_data)
        desc = ""
        sev = "MEDIUM"
        raw = {}

    mitre_items = []
    meta = raw.get("meta", {}) or raw.get("metadata", {})
    if isinstance(meta, dict):
        for k, v in meta.items():
            if "mitre" in k.lower() or "attack" in k.lower() or "tactic" in k.lower() or "technique" in k.lower():
                if isinstance(v, list):
                    mitre_items.extend([str(item) for item in v])
                elif isinstance(v, str):
                    mitre_items.append(v)

    techniques = raw.get("techniques", [])
    if isinstance(techniques, list):
        for t in techniques:
            if isinstance(t, dict):
                tid = t.get("id", "")
                tdn = t.get("displayName", "")
                if tid and tdn:
                    mitre_items.append(f"{tid} - {tdn}")
                elif tid or tdn:
                    mitre_items.append(tid or tdn)
            elif isinstance(t, str):
                mitre_items.append(t)

    mitre_str = ", ".join(sorted(set(mitre_items))) if mitre_items else "None"
    return f"Rule: {name}. Description: {desc}. MITRE ATT&CK: {mitre_str}. Severity: {sev}."


def extract_yaral_sections(rule_text: str) -> Dict[str, str]:
    """Parses a YARA-L rule into its core logic blocks."""
    if not rule_text:
        return {"meta": "", "events": "", "match": "", "outcome": "", "condition": ""}

    meta_match = META_BLOCK_REGEX.search(rule_text)
    events_match = EVENTS_BLOCK_REGEX.search(rule_text)
    match_match = MATCH_BLOCK_REGEX.search(rule_text)
    outcome_match = OUTCOME_BLOCK_REGEX.search(rule_text)
    condition_match = CONDITION_BLOCK_REGEX.search(rule_text)

    return {
        "meta": meta_match.group(1).strip() if meta_match else "",
        "events": events_match.group(1).strip() if events_match else "",
        "match": match_match.group(1).strip() if match_match else "",
        "outcome": outcome_match.group(1).strip() if outcome_match else "",
        "condition": condition_match.group(1).strip() if condition_match else "",
    }


def extract_udm_fields(rule_text: str) -> List[str]:
    """Extracts referenced UDM field paths from YARA-L rule text."""
    if not rule_text:
        return []
    matches = UDM_FIELD_REGEX.findall(rule_text)
    return sorted(list(set(matches)))


class SyncRuleEmbeddingsWorkflow:
    """Synchronizes vector embeddings for all active tenant detection rules.

    Operates in batches to support repositories with thousands of rules without hitting quotas.
    """

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            from agents.core.evidence_store import get_evidence_store
            self.store = get_evidence_store()

    def execute(
        self,
        batch_size: int = 50,
        force_refresh: bool = False,
        include_curated: bool = True,
    ) -> Dict[str, Any]:
        """Fetches active customer rules and curated rules, computes embeddings in batches of 50, and batch writes to store."""
        logger.info(
            "Starting Rule Embedding Sync (batch_size=%d, force_refresh=%s, include_curated=%s)...",
            batch_size,
            force_refresh,
            include_curated,
        )

        # 1. Fetch deployment status to filter out archived rules
        archived_rule_ids: Set[str] = set()
        try:
            dep_res = self.adapter.list_rule_deployments()
            for dep in dep_res.deployments:
                if dep.archived:
                    archived_rule_ids.add(dep.rule_id)
                    archived_rule_ids.add(dep.name.split("/")[-2] if "deployment" in dep.name else dep.name)
        except Exception as ex:
            logger.warning("Could not fetch deployments for archive filtering: %s", ex)

        # 2. List all customer rules
        rules_res = self.adapter.list_rules()
        active_rules = []
        for r in rules_res.rules:
            rid = getattr(r, "rule_id", "")
            if rid in archived_rule_ids:
                continue
            active_rules.append(r)

        # 3. Discover curated rules if requested
        curated_rules: List[Dict[str, Any]] = []
        if include_curated and hasattr(self.adapter, "list_curated_rules"):
            try:
                curated_res = self.adapter.list_curated_rules(page_size=1000)
                for cr in curated_res.get("curatedRules", []):
                    c_id = cr.get("name", "").split("/")[-1]
                    if not c_id:
                        continue
                    curated_rules.append({
                        "rule_id": c_id,
                        "rule_name": cr.get("displayName") or c_id,
                        "display_name": cr.get("displayName") or c_id,
                        "description": cr.get("description", ""),
                        "severity": cr.get("severity", {}).get("displayName", "MEDIUM") if isinstance(cr.get("severity"), dict) else cr.get("severity", "MEDIUM"),
                        "raw": cr,
                        "rule_source": "GOOGLE_CURATED",
                    })
                logger.info("Discovered %d Google Curated Rules for embedding synchronization.", len(curated_rules))
            except Exception as ex:
                logger.warning("Could not fetch curated rules for embedding synchronization: %s", ex)

        all_rules: List[Any] = list(active_rules) + curated_rules
        logger.info(
            "Discovered %d total rules for embedding synchronization (%d customer rules [%d archived excluded], %d curated rules).",
            len(all_rules),
            len(active_rules),
            len(archived_rule_ids),
            len(curated_rules),
        )

        embedded_count = 0
        skipped_count = 0
        batches_written = 0

        # 4. Process in chunks
        chunk_size = max(1, min(100, batch_size))
        for i in range(0, len(all_rules), chunk_size):
            chunk = all_rules[i : i + chunk_size]
            summaries_to_embed: List[str] = []
            rules_to_embed: List[Any] = []

            for rule in chunk:
                rid = getattr(rule, "rule_id", "") if not isinstance(rule, dict) else rule.get("rule_id", "")
                if not force_refresh:
                    existing = self.store.get_rule_state(rid)
                    if existing and existing.get("embedding"):
                        skipped_count += 1
                        continue

                summary = synthesize_rule_summary(rule)
                summaries_to_embed.append(summary)
                rules_to_embed.append(rule)

            if not summaries_to_embed:
                continue

            vectors = self.store.generate_rule_embeddings(summaries_to_embed)

            records: List[Dict[str, Any]] = []
            for rule, summary, vec in zip(rules_to_embed, summaries_to_embed, vectors):
                rid = getattr(rule, "rule_id", "") if not isinstance(rule, dict) else rule.get("rule_id", "")
                rname = getattr(rule, "rule_name", "") or getattr(rule, "display_name", "") if not isinstance(rule, dict) else (rule.get("rule_name") or rule.get("display_name", ""))
                sev = getattr(rule, "severity", "MEDIUM") if not isinstance(rule, dict) else rule.get("severity", "MEDIUM")
                source = getattr(rule, "rule_source", "CUSTOMER") if not isinstance(rule, dict) else rule.get("rule_source", "GOOGLE_CURATED" if rid.startswith("ur_") else "CUSTOMER")

                records.append({
                    "rule_id": rid,
                    "rule_name": rname,
                    "display_name": rname,
                    "summary": summary,
                    "embedding": vec,
                    "severity": sev,
                    "rule_source": source,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                })

            self.store.batch_save_rule_embeddings(records)
            embedded_count += len(records)
            batches_written += 1

        logger.info(
            "Rule Embedding Sync Complete: %d rules embedded, %d skipped, %d batch commits.",
            embedded_count,
            skipped_count,
            batches_written,
        )

        return {
            "total_active_rules": len(active_rules),
            "total_curated_rules": len(curated_rules),
            "total_scanned": len(all_rules),
            "embedded_count": embedded_count,
            "skipped_count": skipped_count,
            "batches_written": batches_written,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class FindSimilarRulesWorkflow:
    """Finds candidate overlapping or conflicting rules via vector similarity search."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            from agents.core.evidence_store import get_evidence_store
            self.store = get_evidence_store()

    def execute(
        self,
        rule_id: str,
        limit: int = 6,
        auto_embed: bool = True,
        persist: bool = True,
    ) -> List[Dict[str, Any]]:
        """Queries Evidence Fabric vector store for top semantically similar rules.

        Args:
            auto_embed: On a cache miss, embed the target rule and search with
                that vector. False = read the existing vector store only.
            persist: Save the fresh embedding (default, previous behaviour).
                False = search with it without writing anything.
        """
        similar = self.store.find_similar_rules(target_rule_id=rule_id, limit=limit)
        if not similar and auto_embed:
            try:
                target_rule = self.adapter.get_rule(rule_id)
                summary = synthesize_rule_summary(target_rule)
                vecs = self.store.generate_rule_embeddings([summary])
                if vecs:
                    if persist:
                        self.store.save_rule_embeddings(rule_id, vecs[0], {
                            "rule_id": rule_id,
                            "rule_name": getattr(target_rule, "rule_name", rule_id),
                            "summary": summary,
                        })
                    similar = self.store.find_similar_rules(target_rule_id=rule_id, embedding=vecs[0], limit=limit)
            except Exception as ex:
                logger.warning("Could not auto-embed target rule %s: %s", rule_id, ex)

        return similar


class AuditRuleConflictWorkflow:
    """Performs deep dual-rule YARA-L logic comparison and Conflict Overlap Scoring (COS)."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            from agents.core.evidence_store import get_evidence_store
            self.store = get_evidence_store()

    def execute(self, rule_id: str, limit: int = 6) -> RuleConflictAuditResult:
        """Audits target rule for conflicts and overlaps against similar tenant rules."""
        logger.info("Auditing rule conflicts for target rule: %s (limit=%d)...", rule_id, limit)

        # 1. Fetch target rule detail
        target_rule = self.adapter.get_rule(rule_id)
        target_name = getattr(target_rule, "rule_name", "") or getattr(target_rule, "display_name", "") or rule_id
        target_text = getattr(target_rule, "rule_text", "") or getattr(target_rule, "text", "")
        target_sections = extract_yaral_sections(target_text)
        target_fields = set(extract_udm_fields(target_text))

        # Check target deployment status
        is_live = False
        try:
            dep_res = self.adapter.list_rule_deployments()
            for dep in dep_res.deployments:
                if dep.rule_id == rule_id or dep.name.endswith(f"/rules/{rule_id}/deployment"):
                    # Only `enabled` means the rule runs; alerting without enabled produces nothing.
                    is_live = bool(dep.enabled)
                    break
        except Exception:
            pass

        # Check silent status from decay records
        is_silent = False
        target_state = self.store.get_rule_state(rule_id)
        if target_state:
            decay_meta = target_state.get("decay_meta", {})
            if decay_meta.get("is_silent") or decay_meta.get("detection_count_90d", 1) == 0:
                is_silent = True

        # 2. Find top similar rules via vector search
        similar_candidates = self.store.find_similar_rules(target_rule_id=rule_id, limit=limit)
        if not similar_candidates:
            summary = synthesize_rule_summary(target_rule)
            vecs = self.store.generate_rule_embeddings([summary])
            if vecs:
                self.store.save_rule_embeddings(rule_id, vecs[0], {
                    "rule_id": rule_id,
                    "rule_name": target_name,
                    "summary": summary,
                })
                similar_candidates = self.store.find_similar_rules(target_rule_id=rule_id, embedding=vecs[0], limit=limit)

        conflict_pairs: List[RuleConflictPair] = []

        # 3. Perform dual YARA-L comparison for each candidate
        for cand in similar_candidates:
            cand_id = cand.get("rule_id", "")
            cand_name = cand.get("rule_name") or cand.get("display_name") or cand_id
            sim_score = float(cand.get("similarity_score", 0.5))

            try:
                cand_rule = self.adapter.get_rule(cand_id)
                cand_text = getattr(cand_rule, "rule_text", "") or getattr(cand_rule, "text", "")
            except Exception as ex:
                logger.debug("Could not fetch candidate rule %s for full text diff: %s", cand_id, ex)
                cand_text = ""

            cand_sections = extract_yaral_sections(cand_text)
            cand_fields = set(extract_udm_fields(cand_text))

            c_type, c_sev, expl, strat, rec = self._compare_rules(
                target_name=target_name,
                target_text=target_text,
                target_sections=target_sections,
                target_fields=target_fields,
                cand_name=cand_name,
                cand_text=cand_text,
                cand_sections=cand_sections,
                cand_fields=cand_fields,
                sim_score=sim_score,
            )

            cos, s_pts, t_pts, sev_pts, tier = calculate_conflict_overlap_score(
                similarity_score=sim_score,
                conflict_type=c_type,
                impact_severity=c_sev,
            )

            shared_fields = sorted(list(target_fields.intersection(cand_fields)))
            events_comp = {
                "shared_udm_fields": shared_fields,
                "target_exclusive_fields": sorted(list(target_fields - cand_fields)),
                "candidate_exclusive_fields": sorted(list(cand_fields - target_fields)),
            }
            match_comp = {
                "target_match": target_sections.get("match", "None"),
                "candidate_match": cand_sections.get("match", "None"),
                "is_match_identical": (target_sections.get("match") == cand_sections.get("match")),
            }
            condition_comp = {
                "target_condition": target_sections.get("condition", "None"),
                "candidate_condition": cand_sections.get("condition", "None"),
                "is_condition_identical": (target_sections.get("condition") == cand_sections.get("condition")),
            }

            pair = RuleConflictPair(
                target_rule_id=rule_id,
                target_rule_name=target_name,
                similar_rule_id=cand_id,
                similar_rule_name=cand_name,
                similarity_score=sim_score,
                conflict_type=c_type,
                impact_severity=c_sev,
                cos_score=cos,
                similarity_pts=s_pts,
                conflict_type_pts=t_pts,
                impact_severity_pts=sev_pts,
                explanation=expl,
                consolidation_strategy=strat,
                recommendation=rec,
                events_overlap=events_comp,
                match_overlap=match_comp,
                condition_overlap=condition_comp,
            )
            conflict_pairs.append(pair)

        conflict_pairs.sort(key=lambda p: p.cos_score, reverse=True)

        highest_cos = conflict_pairs[0].cos_score if conflict_pairs else 0.0
        if highest_cos >= 75.0:
            top_tier = ConflictSeverityTier.CRITICAL
        elif highest_cos >= 45.0:
            top_tier = ConflictSeverityTier.MODERATE
        else:
            top_tier = ConflictSeverityTier.LOW

        strategic_rec = ""
        if conflict_pairs:
            top_pair = conflict_pairs[0]
            if is_silent and top_pair.conflict_type == RuleConflictType.REDUNDANCY:
                strategic_rec = (
                    f"RETIRE / ARCHIVE: '{target_name}' produced 0 detections in 90-day telemetry and is functionally redundant "
                    f"with active sibling '{top_pair.similar_rule_name}' (COS: {top_pair.cos_score:.1f}). Archive target rule to eliminate detection sprawl."
                )
            elif top_pair.conflict_type == RuleConflictType.CONTRADICTION:
                strategic_rec = (
                    f"RESOLVE CONTRADICTION: Conflicting logic detected between '{target_name}' and '{top_pair.similar_rule_name}' "
                    f"(COS: {top_pair.cos_score:.1f}). Reconcile opposing conditions to ensure deterministic alert firing."
                )
            elif top_pair.conflict_type == RuleConflictType.REDUNDANCY:
                strategic_rec = (
                    f"CONSOLIDATE RULES: High semantic and event overlap with '{top_pair.similar_rule_name}' (COS: {top_pair.cos_score:.1f}). "
                    f"Propose merging into single parameterized rule."
                )
            elif top_pair.conflict_type == RuleConflictType.OVERLAP:
                strategic_rec = (
                    f"REFINE MATCH / THRESHOLD: Overlapping detection surface with '{top_pair.similar_rule_name}' (COS: {top_pair.cos_score:.1f}). "
                    f"Clarify scope boundaries or adjust time windows."
                )
            else:
                strategic_rec = f"MONITOR: Minor scope divergence with '{top_pair.similar_rule_name}'. No immediate remediation required."
        else:
            strategic_rec = "CLEAN: No semantically overlapping or conflicting rules found in tenant repository."

        result = RuleConflictAuditResult(
            rule_id=rule_id,
            rule_name=target_name,
            highest_cos=highest_cos,
            severity_tier=top_tier,
            conflicts=conflict_pairs,
            is_live=is_live,
            is_silent=is_silent,
            strategic_recommendation=strategic_rec,
            timestamp=datetime.now(timezone.utc).isoformat(),
            provenance=Provenance(
                source="Chronicle SIEM Rule Engine & Evidence Fabric",
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={"target_rule_id": rule_id, "similar_count": len(conflict_pairs)},
            ),
        )

        self.store.save_rule_conflict(rule_id, result.to_dict())

        if highest_cos >= 45.0:
            todo_id = f"todo_conflict_{rule_id}"
            priority = "HIGH" if highest_cos >= 75.0 else "MEDIUM"
            self.store.upsert_todo(
                todo_id=todo_id,
                task_dict={
                    "title": f"Resolve Rule Conflict: {target_name} ({top_tier})",
                    "target_agent": "@rule-conflict-agent",
                    "target_resource_id": rule_id,
                    "action_type": "resolve_rule_conflict",
                    "priority": priority,
                    "rationale": strategic_rec,
                    "metadata": {
                        "highest_cos": highest_cos,
                        "conflict_type": conflict_pairs[0].conflict_type if conflict_pairs else "OVERLAP",
                        "top_sibling_id": conflict_pairs[0].similar_rule_id if conflict_pairs else "",
                    },
                },
            )

        return result

    def _compare_rules(
        self,
        target_name: str,
        target_text: str,
        target_sections: Dict[str, str],
        target_fields: Set[str],
        cand_name: str,
        cand_text: str,
        cand_sections: Dict[str, str],
        cand_fields: Set[str],
        sim_score: float,
    ) -> Tuple[str, str, str, str, str]:
        """Compares two rules using Gemini if available, falling back to deterministic AST heuristics."""
        try:
            from google import genai
            pid = (
                os.getenv("GCP_PROJECT_ID")
                or os.getenv("SECOPS_PROJECT_ID")
                or os.getenv("GOOGLE_CLOUD_PROJECT")
            )
            client = genai.Client(vertexai=True, project=pid, location="global")

            prompt = (
                f"You are the Chronicle SIEM Rule Conflict and Overlap Agent.\n"
                f"Analyze these two YARA-L rules for detection overlap and semantic conflict.\n\n"
                f"RULE A: {target_name}\n"
                f"EVENTS:\n{target_sections.get('events', 'N/A')}\n"
                f"MATCH:\n{target_sections.get('match', 'N/A')}\n"
                f"CONDITION:\n{target_sections.get('condition', 'N/A')}\n\n"
                f"RULE B: {cand_name}\n"
                f"EVENTS:\n{cand_sections.get('events', 'N/A')}\n"
                f"MATCH:\n{cand_sections.get('match', 'N/A')}\n"
                f"CONDITION:\n{cand_sections.get('condition', 'N/A')}\n\n"
                f"Vector Similarity: {sim_score:.3f}\n\n"
                f"Classify the conflict into exactly ONE of:\n"
                f"1. REDUNDANCY (duplicate alerts for identical activity)\n"
                f"2. OVERLAP (shared criteria with slight scope/threshold difference)\n"
                f"3. CONTRADICTION (mutually exclusive or opposing conditions)\n"
                f"4. SCOPE GAPS (complementary rules leaving unmonitored blind spots)\n\n"
                f"Assess Impact Severity as HIGH, MEDIUM, or LOW.\n"
                f"Return JSON matching:\n"
                f'{{"conflict_type": "...", "impact_severity": "...", "explanation": "...", "consolidation_strategy": "...", "recommendation": "..."}}'
            )

            res = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            raw_text = res.text or ""
            clean_json = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text.strip(), flags=re.DOTALL)
            parsed = json.loads(clean_json)
            c_type = parsed.get("conflict_type", RuleConflictType.OVERLAP)
            c_sev = parsed.get("impact_severity", "MEDIUM")
            expl = parsed.get("explanation", "")
            strat = parsed.get("consolidation_strategy", "")
            rec = parsed.get("recommendation", "")
            return c_type, c_sev, expl, strat, rec
        except Exception as ex:
            logger.debug("Vertex AI rule comparison fallback used: %s", ex)
            return self._deterministic_comparison_fallback(
                target_name=target_name,
                target_sections=target_sections,
                target_fields=target_fields,
                cand_name=cand_name,
                cand_sections=cand_sections,
                cand_fields=cand_fields,
                sim_score=sim_score,
            )

    def _deterministic_comparison_fallback(
        self,
        target_name: str,
        target_sections: Dict[str, str],
        target_fields: Set[str],
        cand_name: str,
        cand_sections: Dict[str, str],
        cand_fields: Set[str],
        sim_score: float,
    ) -> Tuple[str, str, str, str, str]:
        """Deterministic heuristic comparison based on UDM fields, match windows, and conditions."""
        union_fields = target_fields.union(cand_fields)
        intersect_fields = target_fields.intersection(cand_fields)
        jaccard = len(intersect_fields) / len(union_fields) if union_fields else 0.0

        target_cond = target_sections.get("condition", "").replace(" ", "")
        cand_cond = cand_sections.get("condition", "").replace(" ", "")
        same_condition = bool(target_cond and cand_cond and target_cond == cand_cond)

        target_match = target_sections.get("match", "").replace(" ", "")
        cand_match = cand_sections.get("match", "").replace(" ", "")
        same_match = bool(target_match and cand_match and target_match == cand_match)

        if ("<" in target_cond and ">" in cand_cond) or (">" in target_cond and "<" in cand_cond):
            c_type = RuleConflictType.CONTRADICTION
            c_sev = "HIGH"
            expl = f"Rules share event scopes but enforce contradictory threshold conditions ('{target_cond}' vs '{cand_cond}')."
            strat = "Standardize threshold boundaries into a unified tiered rule."
            rec = "Reconcile opposing operator conditions to avoid divergent alerting."
        elif jaccard >= 0.85 and sim_score >= 0.80 and (same_condition or same_match):
            c_type = RuleConflictType.REDUNDANCY
            c_sev = "HIGH"
            expl = f"High Jaccard UDM overlap ({jaccard * 100:.1f}%) and identical conditions produce duplicate alert records."
            strat = "Retire or disable the older/redundant rule; merge unique filters into surviving rule."
            rec = f"Consolidate '{target_name}' into '{cand_name}'."
        elif jaccard >= 0.50 or sim_score >= 0.65:
            c_type = RuleConflictType.OVERLAP
            c_sev = "MEDIUM"
            expl = f"Rules monitor overlapping telemetry with {len(intersect_fields)} shared UDM fields ({', '.join(sorted(list(intersect_fields))[:3])})."
            strat = "Parameterize variable thresholds or constrain principal process filters."
            rec = "Clarify scope boundaries between parent and child threat definitions."
        else:
            c_type = RuleConflictType.SCOPE_GAPS
            c_sev = "LOW"
            expl = f"Complementary rules cover related tactics with distinct event paths ({len(intersect_fields)} shared fields)."
            strat = "Maintain separate rules but verify coverage across boundary telemetry."
            rec = "Document detection scope boundaries in rule metadata."

        return c_type, c_sev, expl, strat, rec


class BatchAuditRuleConflictsWorkflow:
    """Discovers and scores rule conflicts and overlaps across all tenant rules."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        if store is not None:
            self.store = store
        else:
            from agents.core.evidence_store import get_evidence_store
            self.store = get_evidence_store()
        self.audit_wf = AuditRuleConflictWorkflow(adapter=self.adapter, store=self.store)

    def execute(
        self,
        limit: int = 50,
        batch_size: int = 10,
        min_cos: float = 45.0,
    ) -> BatchRuleConflictAuditResult:
        """Audits multiple active rules and compiles an aggregated conflict report."""
        logger.info("Executing Batch Rule Conflict Audit (limit=%d, batch_size=%d)...", limit, batch_size)

        archived_ids: Set[str] = set()
        try:
            dep_res = self.adapter.list_rule_deployments()
            for dep in dep_res.deployments:
                if dep.archived:
                    archived_ids.add(dep.rule_id)
        except Exception:
            pass

        rules_res = self.adapter.list_rules()
        active_rules = [r for r in rules_res.rules if getattr(r, "rule_id", "") not in archived_ids]

        rules_to_scan = active_rules[:limit]
        total_scanned = len(rules_to_scan)
        total_pairs = 0

        conflict_counts = {
            RuleConflictType.REDUNDANCY: 0,
            RuleConflictType.OVERLAP: 0,
            RuleConflictType.CONTRADICTION: 0,
            RuleConflictType.SCOPE_GAPS: 0,
        }
        severity_counts = {
            "CRITICAL": 0,
            "MODERATE": 0,
            "LOW": 0,
        }

        audited_results: List[RuleConflictAuditResult] = []

        for rule in rules_to_scan:
            rid = getattr(rule, "rule_id", "")
            try:
                res = self.audit_wf.execute(rule_id=rid, limit=6)
                audited_results.append(res)
                total_pairs += len(res.conflicts)

                if res.highest_cos >= 75.0:
                    severity_counts["CRITICAL"] += 1
                elif res.highest_cos >= 45.0:
                    severity_counts["MODERATE"] += 1
                else:
                    severity_counts["LOW"] += 1

                for pair in res.conflicts:
                    ctype = pair.conflict_type
                    if ctype in conflict_counts:
                        conflict_counts[ctype] += 1
            except Exception as ex:
                logger.warning("Error auditing rule %s: %s", rid, ex)

        audited_results.sort(key=lambda r: r.highest_cos, reverse=True)
        flagged_rules = [r for r in audited_results if r.highest_cos >= min_cos]

        return BatchRuleConflictAuditResult(
            total_rules_scanned=total_scanned,
            total_pairs_evaluated=total_pairs,
            conflict_counts=conflict_counts,
            severity_counts=severity_counts,
            highest_cos_rules=flagged_rules[:20],
            timestamp=datetime.now(timezone.utc).isoformat(),
            provenance=Provenance(
                source="Chronicle SIEM Rule Engine & Evidence Fabric",
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={"scanned": total_scanned, "flagged": len(flagged_rules)},
            ),
        )
