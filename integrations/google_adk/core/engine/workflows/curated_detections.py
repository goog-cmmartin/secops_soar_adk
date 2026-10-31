"""Curated Detections Workflows (Milestone 5.7).

Implements discovery, multi-facet search, MITRE ATT&CK mapping, precision/deployment inspection,
YARA-L rule logic retrieval, detection metrics aggregation, and quota telemetry for Google SecOps Curated Detections.
Invariants: Strict live API provenance, zero synthetic data, explicit error visibility.
"""

from datetime import datetime, timedelta, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from engine.domain import (
    CuratedDetectionMetrics,
    CuratedPrecision,
    CuratedRuleDetail,
    CuratedRuleListResult,
    CuratedRuleSearchQuery,
    CuratedRuleSetBatch,
    CuratedRuleSetDeployment,
    CuratedRuleSetDeploymentListResult,
    CuratedRuleSetDeploymentRecord,
    CuratedRuleSetDetail,
    CuratedRuleSetListResult,
    CuratedRuleSetSummary,
    CuratedRuleSummary,
    MitreAttackMapping,
    TenantRuleMetrics,
)
from engine.pagination import collect_pages

logger = logging.getLogger(__name__)


def _map_mitre_mapping(raw: Dict[str, Any], kind: str = "tactic") -> MitreAttackMapping:
    return MitreAttackMapping(
        id=raw.get("id", ""),
        display_name=raw.get("displayName", ""),
        kind=kind,
    )


def _map_curated_deployment(raw: Dict[str, Any]) -> CuratedRuleSetDeployment:
    precision_raw = raw.get("precision", "UNKNOWN")
    return CuratedRuleSetDeployment(
        precision=precision_raw,
        enabled=raw.get("enabled", False),
        alerting=raw.get("alerting", False),
        resource_name=raw.get("name", ""),
    )


def _map_curated_rule_summary(raw: Dict[str, Any]) -> CuratedRuleSummary:
    raw_name = raw.get("name", "")
    rule_id = raw_name.split("/")[-1] if raw_name else ""
    techniques = [_map_mitre_mapping(t, "technique") for t in raw.get("techniques", []) if isinstance(t, dict)]
    severity_obj = raw.get("severity", {})
    severity_str = severity_obj.get("displayName", "UNKNOWN") if isinstance(severity_obj, dict) else str(severity_obj)
    metadata = raw.get("metadata", {})
    false_positives = metadata.get("false_positives", "") if isinstance(metadata, dict) else ""
    
    curated_set_raw = raw.get("curatedRuleSet") or raw.get("ruleSet") or ""
    if isinstance(curated_set_raw, dict):
        curated_set_id = curated_set_raw.get("id", "")
    elif isinstance(curated_set_raw, str):
        curated_set_id = curated_set_raw.split("/")[-1] if curated_set_raw else ""
    else:
        curated_set_id = ""

    return CuratedRuleSummary(
        id=rule_id,
        title=raw.get("displayName", ""),
        severity=severity_str,
        precision=raw.get("precision", "UNKNOWN"),
        rule_type=raw.get("type", "SINGLE_EVENT"),
        curated_rule_set_id=curated_set_id,
        techniques=techniques,
        description=raw.get("description", ""),
        false_positives=false_positives,
        resource_name=raw_name,
    )


def _map_curated_ruleset_summary(
    raw: Dict[str, Any],
    categories_map: Optional[Dict[str, str]] = None,
    deployments: Optional[List[CuratedRuleSetDeployment]] = None,
    detection_count: int = 0,
) -> CuratedRuleSetSummary:
    raw_name = raw.get("name", "")
    ruleset_id = raw_name.split("/")[-1] if raw_name else ""
    
    # Extract category ID from resource path
    cat_id = ""
    if "/curatedRuleSetCategories/" in raw_name:
        cat_id = raw_name.split("/curatedRuleSetCategories/")[1].split("/")[0]

    cat_name = ""
    if categories_map and cat_id in categories_map:
        cat_name = categories_map[cat_id]

    tactics = [_map_mitre_mapping(t, "tactic") for t in raw.get("tactics", []) if isinstance(t, dict)]
    techniques = [_map_mitre_mapping(t, "technique") for t in raw.get("techniques", []) if isinstance(t, dict)]
    quota = raw.get("quota", {})
    quota_size = quota.get("quotaSize", 1) if isinstance(quota, dict) else 1

    return CuratedRuleSetSummary(
        id=ruleset_id,
        title=raw.get("displayName", ""),
        description=raw.get("description", ""),
        category_id=cat_id,
        category_name=cat_name,
        log_sources=raw.get("logSources", []),
        tactics=tactics,
        techniques=techniques,
        authors=raw.get("authors", []),
        quota_size=quota_size,
        deployments=deployments or [],
        detection_count=detection_count,
        resource_name=raw_name,
    )


_ID_LIKE = re.compile(r"^[A-Za-z0-9_\-]+$")


def resolve_by_identifier(items: List[Dict[str, Any]], identifier: str, kind: str) -> Dict[str, Any]:
    """Resolves an ID, resource name or title against raw catalog items.

    Order: exact (case-insensitive) ID / resource name / title; then a unique
    case-insensitive title substring. Several exact or several substring
    matches raise ``ValueError`` listing the candidates instead of silently
    picking the first one.
    """
    ident = identifier.strip().lower()

    def keys(r: Dict[str, Any]) -> Tuple[str, str, str]:
        name = str(r.get("name", ""))
        return name.split("/")[-1].lower(), name.lower(), str(r.get("displayName", "")).lower()

    exact = [r for r in items if ident in keys(r)]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        titles = [r.get("displayName", "") for r in exact[:5]]
        raise ValueError(f"{kind} identifier '{identifier}' is ambiguous: {len(exact)} exact matches {titles}")
    partial = [r for r in items if ident and ident in keys(r)[2]]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        titles = [r.get("displayName", "") for r in partial[:5]]
        raise ValueError(
            f"{kind} title '{identifier}' is ambiguous: {len(partial)} titles contain it, e.g. {titles}; "
            "pass the exact title or ID"
        )
    raise ValueError(f"{kind} not found: '{identifier}'")


def list_all_curated_rulesets_raw(adapter: Any, page_size: int = 1000) -> List[Dict[str, Any]]:
    """Every raw Curated Rule Set across all pages (raises on API error)."""

    def fetch(tok: Optional[str]):
        res = adapter.list_curated_rulesets(page_size=page_size, page_token=tok)
        if not isinstance(res, dict):
            return [], None
        return list(res.get("curatedRuleSets", []) or []), res.get("nextPageToken")

    items, _, _ = collect_pages(fetch)
    return items


def list_all_curated_rules_raw(adapter: Any, page_size: int = 1000) -> List[Dict[str, Any]]:
    """Every raw curated rule across all pages (slow: ~20 s per page; raises on API error)."""

    def fetch(tok: Optional[str]):
        res = adapter.list_curated_rules(page_size=page_size, page_token=tok)
        if not isinstance(res, dict):
            return [], None
        return list(res.get("curatedRules", []) or []), res.get("nextPageToken")

    items, _, _ = collect_pages(fetch)
    return items


def _parse_curated_deployment_name(name: str) -> Tuple[str, str]:
    """``(category_id, rule_set_id)`` from a ``.../curatedRuleSetCategories/{c}/curatedRuleSets/{r}/curatedRuleSetDeployments/{p}`` name."""
    cat_id = ""
    rs_id = ""
    if "/curatedRuleSetCategories/" in name:
        cat_id = name.split("/curatedRuleSetCategories/")[1].split("/")[0]
    if "/curatedRuleSets/" in name:
        rs_id = name.split("/curatedRuleSets/")[1].split("/")[0]
    return cat_id, rs_id


def map_curated_deployment_record(raw: Dict[str, Any], display_name: str = "") -> CuratedRuleSetDeploymentRecord:
    name = str(raw.get("name", ""))
    cat_id, rs_id = _parse_curated_deployment_name(name)
    precision = str(raw.get("precision") or "").upper()
    if not precision and "/curatedRuleSetDeployments/" in name:
        precision = name.rsplit("/", 1)[-1].upper()
    return CuratedRuleSetDeploymentRecord(
        rule_set_id=rs_id,
        category_id=cat_id,
        precision=precision or CuratedPrecision.UNKNOWN.value,
        # proto3 omits false booleans
        enabled=bool(raw.get("enabled", False)),
        alerting=bool(raw.get("alerting", False)),
        display_name=display_name,
        resource_name=name,
        raw=raw,
    )


class ListCuratedRuleSetDeploymentsWorkflow:
    """Bulk read of every curated rule set precision deployment (``-`` wildcards, one call per page)."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        include_display_names: bool = True,
        page_size: int = 1000,
        max_results: Optional[int] = None,
    ) -> CuratedRuleSetDeploymentListResult:
        """Lists all curated deployments across all pages.

        Args:
            include_display_names: Join rule set display names from the rule set
                catalog (one extra ~1.3 s list call). If that join fails the
                deployments are still returned with ``display_name=""`` and the
                error in ``provenance["display_name_error"]``.
            page_size: API page size.
            max_results: Optional cap on returned deployments.

        Raises:
            Any adapter error from the deployment list.
        """

        def fetch(tok: Optional[str]):
            res = self.adapter.list_curated_ruleset_deployments(page_size=page_size, page_token=tok)
            if not isinstance(res, dict):
                raise ValueError(f"Unexpected curatedRuleSetDeployments response type: {type(res).__name__}")
            return list(res.get("curatedRuleSetDeployments", []) or []), res.get("nextPageToken")

        raw_deps, next_token, pages = collect_pages(fetch, max_results=max_results)
        names: Dict[str, str] = {}
        name_error: Optional[str] = None
        if include_display_names and raw_deps:
            try:
                for rs in list_all_curated_rulesets_raw(self.adapter):
                    rs_id = str(rs.get("name", "")).split("/")[-1]
                    if rs_id:
                        names[rs_id] = rs.get("displayName", "")
            except Exception as exc:
                name_error = f"{type(exc).__name__}: {exc}"
                logger.warning("Curated rule set display-name join failed: %s", name_error)
        records = []
        for d in raw_deps:
            if not isinstance(d, dict):
                continue
            rec = map_curated_deployment_record(d)
            rec.display_name = names.get(rec.rule_set_id, "")
            records.append(rec)
        return CuratedRuleSetDeploymentListResult(
            deployments=records,
            next_page_token=next_token,
            pages_fetched=pages,
            provenance={
                "api": "curatedRuleSetCategories/-/curatedRuleSets/-/curatedRuleSetDeployments",
                "count": len(records),
                "display_names_joined": include_display_names and name_error is None,
                "display_name_error": name_error,
            },
        )


class ListCuratedRuleSetsWorkflow:
    """Lists Curated Rule Sets with page-token support (single page by default)."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
        category_id: Optional[str] = None,
    ) -> CuratedRuleSetListResult:
        raw_cats = self.adapter.list_curated_ruleset_categories()
        cats_list = raw_cats.get("curatedRuleSetCategories", []) if isinstance(raw_cats, dict) else []
        cat_map = {c.get("name", "").split("/")[-1]: c.get("displayName", "") for c in cats_list if c.get("name")}

        def fetch(tok: Optional[str]):
            res = self.adapter.list_curated_rulesets(category_id=category_id, page_size=page_size, page_token=tok)
            if not isinstance(res, dict):
                return [], None
            return list(res.get("curatedRuleSets", []) or []), res.get("nextPageToken")

        if all_pages or max_results is not None:
            raw_items, next_token, pages = collect_pages(fetch, page_token=page_token, max_results=max_results)
        else:
            raw_items, next_token = fetch(page_token)
            pages = 1
        return CuratedRuleSetListResult(
            rule_sets=[_map_curated_ruleset_summary(r, categories_map=cat_map) for r in raw_items if isinstance(r, dict)],
            next_page_token=next_token if isinstance(next_token, str) and next_token else None,
            pages_fetched=pages,
            provenance={"count": len(raw_items), "category_id": category_id},
        )


class ListCuratedRulesWorkflow:
    """Lists individual curated rules with page-token support (single page by default).

    The endpoint has no server-side filter and is slow (~20 s per page);
    cache results.
    """

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> CuratedRuleListResult:
        def fetch(tok: Optional[str]):
            res = self.adapter.list_curated_rules(page_size=page_size, page_token=tok)
            if not isinstance(res, dict):
                return [], None
            return list(res.get("curatedRules", []) or []), res.get("nextPageToken")

        if all_pages or max_results is not None:
            raw_items, next_token, pages = collect_pages(fetch, page_token=page_token, max_results=max_results)
        else:
            raw_items, next_token = fetch(page_token)
            pages = 1
        return CuratedRuleListResult(
            rules=[_map_curated_rule_summary(r) for r in raw_items if isinstance(r, dict)],
            next_page_token=next_token if isinstance(next_token, str) and next_token else None,
            pages_fetched=pages,
            provenance={"count": len(raw_items)},
        )


class SearchCuratedRuleSetsWorkflow:
    """Executes multi-facet search across Curated Rule Sets, MITRE mappings, and log sources."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, query: CuratedRuleSearchQuery) -> CuratedRuleSetBatch:
        # 1. Fetch categories to build lookup table
        raw_cats = self.adapter.list_curated_ruleset_categories()
        cats_list = raw_cats.get("curatedRuleSetCategories", []) if isinstance(raw_cats, dict) else []
        cat_map: Dict[str, str] = {}
        for c in cats_list:
            c_name = c.get("name", "")
            c_id = c_name.split("/")[-1] if c_name else ""
            if c_id:
                cat_map[c_id] = c.get("displayName", "")

        # 2. Fetch all curated rule sets (all pages)
        raw_rulesets = list_all_curated_rulesets_raw(self.adapter)

        summaries = [_map_curated_ruleset_summary(r, categories_map=cat_map) for r in raw_rulesets]

        # 3. Multi-facet filtering
        filtered: List[CuratedRuleSetSummary] = []
        for s in summaries:
            # Query text matching
            if query.query:
                q = query.query.lower()
                title_match = q in s.title.lower()
                desc_match = q in s.description.lower()
                author_match = any(q in a.lower() for a in s.authors)
                cat_match = q in s.category_name.lower() or q in s.category_id.lower()
                if not (title_match or desc_match or author_match or cat_match):
                    continue

            # Category filter
            if query.category:
                c_req = query.category.lower()
                if not (c_req == s.category_name.lower() or c_req == s.category_id.lower() or c_req in s.category_name.lower()):
                    continue

            # Log source filter
            if query.log_source:
                ls_req = query.log_source.lower()
                if not any(ls_req in ls.lower() for ls in s.log_sources):
                    continue

            # MITRE Tactic filter
            if query.mitre_tactic:
                t_req = query.mitre_tactic.lower()
                t_match = any(t_req == t.id.lower() or t_req in t.display_name.lower() for t in s.tactics)
                if not t_match:
                    continue

            # MITRE Technique filter
            if query.mitre_technique:
                tech_req = query.mitre_technique.lower()
                tech_match = any(tech_req == t.id.lower() or tech_req in t.display_name.lower() for t in s.techniques)
                if not tech_match:
                    continue

            filtered.append(s)

        total_matching = len(filtered)
        limit = query.limit if query.limit > 0 else 50
        results = filtered[:limit]

        return CuratedRuleSetBatch(
            results=results,
            total_count=total_matching,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetCuratedRuleSetDetailWorkflow:
    """Deep-inspects a specific Curated Rule Set, its deployments, member rules, and detection telemetry."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def _resolve(self, identifier: str) -> Dict[str, Any]:
        """Direct GET for an ID / resource name; title resolution over the catalog otherwise."""
        if identifier.startswith("projects/") or _ID_LIKE.match(identifier):
            if hasattr(self.adapter, "get_curated_ruleset"):
                try:
                    res = self.adapter.get_curated_ruleset(identifier)
                    if isinstance(res, dict) and res.get("name"):
                        return res
                except Exception as exc:
                    # 400/404: not a rule set ID (e.g. a one-word title); fall back to title resolution.
                    if getattr(exc, "status", None) not in (400, 404):
                        raise
        return resolve_by_identifier(list_all_curated_rulesets_raw(self.adapter), identifier, "Curated Rule Set")

    def execute(
        self,
        ruleset_id_or_title: str,
        include_rules: bool = True,
        include_detection_count: bool = True,
    ) -> CuratedRuleSetDetail:
        """Resolves and inspects one Curated Rule Set.

        Args:
            include_rules: Scan the curated rule catalog for member rules (slow,
                ~20-30 s; the ``curatedRules`` endpoint has no filter).
            include_detection_count: 7-day ``countAllCuratedRuleSetDetections``.

        Failures of the deployment, count or member reads are recorded in
        ``CuratedRuleSetDetail.errors`` (and logged); the corresponding field
        is then empty/0 *because it is unknown*.
        """
        if not ruleset_id_or_title or not ruleset_id_or_title.strip():
            raise ValueError("Curated Rule Set identifier or title is required")

        identifier = ruleset_id_or_title.strip()
        errors: List[str] = []

        # 1. Fetch categories
        raw_cats = self.adapter.list_curated_ruleset_categories()
        cats_list = raw_cats.get("curatedRuleSetCategories", []) if isinstance(raw_cats, dict) else []
        cat_map: Dict[str, str] = {c.get("name", "").split("/")[-1]: c.get("displayName", "") for c in cats_list if c.get("name")}

        # 2. Resolve target (raises ValueError when not found or ambiguous)
        target_raw = self._resolve(identifier)
        full_name = target_raw.get("name", "")
        ruleset_id = full_name.split("/")[-1] if full_name else ""

        # 3. Fetch deployments for this rule set
        deployments: List[CuratedRuleSetDeployment] = []
        try:
            dep_res = self.adapter.get_curated_ruleset_deployments(full_name)
            raw_deps = dep_res.get("curatedRuleSetDeployments", []) if isinstance(dep_res, dict) else []
            deployments = [_map_curated_deployment(d) for d in raw_deps if isinstance(d, dict)]
        except Exception as exc:
            errors.append(f"deployments: {type(exc).__name__}: {exc}")

        # 4. Fetch detection counts for the last 7 days
        detection_count = 0
        if include_detection_count:
            try:
                now = datetime.now(timezone.utc)
                start_iso = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                end_iso = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                count_res = self.adapter.count_curated_ruleset_detections(start_iso, end_iso)
                raw_counts = count_res.get("curatedRuleSetCounts", []) if isinstance(count_res, dict) else []
                for c in raw_counts:
                    if str(c.get("curatedRuleSet", "")).split("/")[-1] == ruleset_id:
                        detection_count = int(c.get("count", 0))
                        break
            except Exception as exc:
                errors.append(f"detection_count: {type(exc).__name__}: {exc}")

        # 5. Fetch member rules belonging to this curated rule set
        member_rules: List[CuratedRuleSummary] = []
        if include_rules:
            try:
                for rule in list_all_curated_rules_raw(self.adapter):
                    rs_ref = rule.get("curatedRuleSet", "")
                    if isinstance(rs_ref, str) and (rs_ref == full_name or rs_ref.endswith(f"/{ruleset_id}")):
                        member_rules.append(_map_curated_rule_summary(rule))
            except Exception as exc:
                errors.append(f"member_rules: {type(exc).__name__}: {exc}")

        for e in errors:
            logger.warning("get_curated_ruleset(%s) partial failure: %s", identifier, e)

        summary = _map_curated_ruleset_summary(
            target_raw,
            categories_map=cat_map,
            deployments=deployments,
            detection_count=detection_count,
        )

        return CuratedRuleSetDetail(
            rule_set=summary,
            rules=member_rules,
            deployments=deployments,
            detection_count=detection_count,
            raw=target_raw,
            errors=errors,
            rules_checked=include_rules and not any(e.startswith("member_rules") for e in errors),
        )


class GetCuratedRuleDetailWorkflow:
    """Retrieves an individual Curated Rule, its metadata, and its executable YARA-L logic."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, rule_id_or_title: str) -> CuratedRuleDetail:
        if not rule_id_or_title or not rule_id_or_title.strip():
            raise ValueError("Curated Rule identifier or title is required")

        identifier = rule_id_or_title.strip()

        # Fast path: if identifier looks like a rule ID (e.g. starts with 'ur_'), fetch directly from Content Hub
        if identifier.startswith("ur_") or identifier.startswith("projects/"):
            clean_id = identifier.split("/")[-1]
            featured_direct = self.adapter.get_featured_content_rule(clean_id)
            if featured_direct and isinstance(featured_direct, dict) and featured_direct.get("name"):
                c_meta = featured_direct.get("contentMetadata", {})
                rule_set_data = featured_direct.get("ruleSet", {})
                rule_set_id = rule_set_data.get("id", "") if isinstance(rule_set_data, dict) else str(rule_set_data).split("/")[-1]
                crc = featured_direct.get("curatedRuleContent", {})
                tactics = [_map_mitre_mapping(t, "tactic") for t in crc.get("tactics", [])] if isinstance(crc, dict) else []
                techniques = [_map_mitre_mapping(t, "technique") for t in crc.get("techniques", [])] if isinstance(crc, dict) else []

                rule_summary = CuratedRuleSummary(
                    id=c_meta.get("id", clean_id),
                    title=c_meta.get("displayName", ""),
                    severity="UNKNOWN",
                    precision=crc.get("precision", "UNKNOWN") if isinstance(crc, dict) else "UNKNOWN",
                    rule_type="SINGLE_EVENT",
                    curated_rule_set_id=rule_set_id,
                    techniques=techniques,
                    description=c_meta.get("description", ""),
                    resource_name=featured_direct.get("name", ""),
                )
                return CuratedRuleDetail(
                    rule=rule_summary,
                    rule_text=featured_direct.get("ruleText", ""),
                    live_status_enabled=featured_direct.get("liveStatusEnabled", False),
                    tactics=tactics,
                    techniques=techniques,
                    raw=featured_direct,
                )

        # Fallback path: search all curated rules catalog (all pages; exact match first)
        target_rule = resolve_by_identifier(list_all_curated_rules_raw(self.adapter), identifier, "Curated Rule")

        summary = _map_curated_rule_summary(target_rule)

        # Query Content Hub featured rule to extract YARA-L logic
        rule_text = ""
        live_enabled = False
        tactics: List[MitreAttackMapping] = []
        techniques: List[MitreAttackMapping] = summary.techniques
        errors: List[str] = []

        try:
            featured = self.adapter.get_featured_content_rule(summary.id)
            if featured and isinstance(featured, dict):
                rule_text = featured.get("ruleText", "")
                live_enabled = featured.get("liveStatusEnabled", False)
                crc = featured.get("curatedRuleContent", {})
                if isinstance(crc, dict):
                    tactics = [_map_mitre_mapping(t, "tactic") for t in crc.get("tactics", [])]
                    if crc.get("techniques"):
                        techniques = [_map_mitre_mapping(t, "technique") for t in crc.get("techniques", [])]
            else:
                errors.append(f"featured_content_rule: no Content Hub entry for {summary.id}")
        except Exception as exc:
            errors.append(f"featured_content_rule: {type(exc).__name__}: {exc}")
            logger.warning("get_curated_rule(%s): Content Hub lookup failed: %s", summary.id, exc)

        return CuratedRuleDetail(
            rule=summary,
            rule_text=rule_text,
            live_status_enabled=live_enabled,
            tactics=tactics,
            techniques=techniques,
            raw=target_rule,
            errors=errors,
        )


class GetCuratedDetectionMetricsWorkflow:
    """Aggregates detection firing counts and retrieves tenant rule engine quotas."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> CuratedDetectionMetrics:
        now = datetime.now(timezone.utc)
        start_iso = start_time or (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_iso = end_time or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # 1. Fetch tenant rule metrics
        legacy = self.adapter.get_tenant_rule_metrics()
        tenant_metrics = TenantRuleMetrics(
            total_active_count=legacy.get("totalActiveCount", 0),
            total_archived_count=legacy.get("totalArchivedCount", 0),
            total_live_rule_count=legacy.get("totalLiveRuleCount", 0),
            max_live_rule_count=legacy.get("maxLiveRuleCount", 0),
            quota_limit=legacy.get("chronicleRulesQuotaLimit", 0),
            quota_usage=legacy.get("chronicleRulesQuotaUsage", 0),
            counts_per_type=legacy.get("totalLiveRuleCountsPerRuleType", []),
            raw=legacy,
        )

        # 2. Fetch detection counts per curated rule set
        raw_counts_res = self.adapter.count_curated_ruleset_detections(start_iso, end_iso)
        raw_counts = raw_counts_res.get("curatedRuleSetCounts", []) if isinstance(raw_counts_res, dict) else []

        # 3. Fetch rule sets to enrich rule set names (all pages)
        raw_rulesets = list_all_curated_rulesets_raw(self.adapter)
        name_map: Dict[str, str] = {r.get("name", ""): r.get("displayName", "") for r in raw_rulesets if r.get("name")}

        top_firing: List[Dict[str, Any]] = []
        for c in sorted(raw_counts, key=lambda x: int(x.get("count", 0)), reverse=True):
            r_name = c.get("curatedRuleSet", "")
            r_id = r_name.split("/")[-1] if r_name else ""
            display_title = name_map.get(r_name, r_id)
            top_firing.append({
                "ruleset_id": r_id,
                "ruleset_name": display_title,
                "resource_name": r_name,
                "count": int(c.get("count", 0)),
            })

        return CuratedDetectionMetrics(
            tenant_metrics=tenant_metrics,
            top_firing_rulesets=top_firing,
            time_interval={"startTime": start_iso, "endTime": end_iso},
            retrieved_at=now,
        )


class SetCuratedRuleSetDeploymentWorkflow:
    """Updates deployment state (enabled/alerting) for a Curated Rule Set precision profile."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        ruleset_id_or_title: str,
        precision: str = "PRECISE",
        enabled: Optional[bool] = None,
        alerting: Optional[bool] = None,
        sync_rules: bool = True,
    ) -> CuratedRuleSetDeployment:
        if not ruleset_id_or_title or not ruleset_id_or_title.strip():
            raise ValueError("Curated Rule Set identifier or title is required")

        prec_normalized = precision.strip().upper()
        if prec_normalized not in ["PRECISE", "BROAD"]:
            raise ValueError(f"Invalid precision mode '{precision}'. Must be 'PRECISE' or 'BROAD'")

        if enabled is None and alerting is None:
            raise ValueError("At least one of 'enabled' or 'alerting' must be specified to update deployment")

        identifier = ruleset_id_or_title.strip()

        # If identifier is already a full deployment resource name:
        if "/curatedRuleSetDeployments/" in identifier:
            deployment_name = identifier
        else:
            # 1. Resolve ruleset resource name
            if identifier.startswith("projects/") and "/curatedRuleSets/" in identifier:
                ruleset_resource_name = identifier
            else:
                # Resolve ID or title across all pages; ambiguous titles raise
                # instead of patching whichever rule set matched first.
                target_raw = resolve_by_identifier(
                    list_all_curated_rulesets_raw(self.adapter), identifier, "Curated Rule Set"
                )
                ruleset_resource_name = target_raw.get("name", "")

            # Construct deployment resource name
            deployment_name = f"{ruleset_resource_name}/curatedRuleSetDeployments/{prec_normalized.lower()}"

        # 2. Execute patch
        updated_raw = self.adapter.update_curated_ruleset_deployment(
            deployment_name=deployment_name,
            enabled=enabled,
            alerting=alerting,
            sync_rules=sync_rules,
        )

        return _map_curated_deployment(updated_raw)

