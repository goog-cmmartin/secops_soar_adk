from __future__ import annotations

"""Detection Tuning and Findings Refinements Workflows for Google SecOps."""

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import difflib
import logging
import os
import re
import threading
import time
import uuid

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    CorrelatedDetectionSample,
    CorrelatedSamplingBatch,
    DetectionTuningProposal,
    DetectionTuningReport,
    DimensionCardinality,
    EntityCardinalityRecord,
    EntityCardinalityReport,
    FindingsRefinementBatch,
    FindingsRefinementSummary,
    FindingsRefinementTestResult,
    MultiFactorExclusion,
    NoisyRuleRecord,
    NoisyRulesBatch,
    RuleCaseEnvironment,
    RuleCaseEnvironmentResult,
    RuleCaseHistoryBatch,
    RuleCaseHistoryRecord,
)
from engine.pagination import collect_pages


from engine.schema import canonicalize_udm_field

logger = logging.getLogger(__name__)

NOISY_RULES_ROW_LIMIT = 10000
RULE_CASE_ENVIRONMENTS_ROW_LIMIT = 5000
_SAFE_LITERAL = re.compile(r'^[^"\\\n]*$')


def translate_to_udm_refinement(field_name: str, value: str, is_regex: bool = True) -> str:
    """Helper that formats a UDM field and value into findings refinement syntax.
    
    Example:
        >>> translate_to_udm_refinement("target.hostname", "byeserver.com", is_regex=True)
        '(target.hostname = /byeserver.com/)'
    """
    stripped = re.sub(r"^\$[a-zA-Z0-9_]*\.", "", field_name.strip()).lstrip("$")
    clean_field = canonicalize_udm_field(stripped)
    clean_val = value.strip()
    if is_regex:
        # Escape slashes
        escaped = clean_val.replace("/", "\\/")
        return f"({clean_field} = /{escaped}/)"
    escaped_exact = clean_val.replace("\\", "\\\\").replace('"', '\\"')
    return f'({clean_field} = "{escaped_exact}")'


class FindTopNoisyRulesWorkflow:
    """Executes the YARA-L detection noise aggregation query and ranks top alert generators."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        lookback_days: int = 7,
        alert_state: str = "ALL",
        limit: int = 20,
    ) -> NoisyRulesBatch:
        # Explicit row limit: alert_state filtering and `limit` are applied
        # client-side, so the query must return every (rule, alert_state) row.
        # A rule whose alert state changed in the window yields two rows.
        query_text = f"""
$rule_name = detection.detection.rule_name
$rule_id = detection.detection.rule_id
$alerting = detection.detection.alert_state 
match: $rule_name, $rule_id, $alerting
outcome:
  $count = count(detection.id)
  $first_seen = min(detection.detection_time.seconds)
  $last_seen = max(detection.detection_time.seconds)
order: $count desc
limit: {NOISY_RULES_ROW_LIMIT}
"""
        res = self.adapter.execute_dashboard_query(
            query_text=query_text,
            time_unit="DAY",
            time_value=str(max(1, lookback_days)),
        )
        if len(res.rows) >= NOISY_RULES_ROW_LIMIT:
            logger.warning("Noisy-rules query hit the %d-row limit; the tail is truncated.", NOISY_RULES_ROW_LIMIT)

        desired_alert = alert_state.strip().upper()
        records: List[NoisyRuleRecord] = []
        total_detections = 0

        for row in res.rows:
            r_name = row.get("rule_name") or ""
            r_id = row.get("rule_id") or ""
            r_alert = row.get("alerting") or "NOT_ALERTING"
            count_str = row.get("count") or "0"
            first_seen_str = row.get("first_seen") or "0"
            last_seen_str = row.get("last_seen") or "0"

            try:
                c_val = int(count_str)
            except (ValueError, TypeError):
                c_val = 0

            # Filter by alert_state if requested
            if desired_alert != "ALL" and r_alert.upper() != desired_alert:
                continue

            # Classify rule author origin
            if "ur_" in r_id:
                r_type = "GOOGLE_MANAGED"
            elif r_id.startswith("ru_"):
                r_type = "CUSTOMER"
            else:
                r_type = "OTHER"

            first_seen_dt = None
            last_seen_dt = None
            try:
                fs_sec = int(first_seen_str)
                if fs_sec > 0:
                    first_seen_dt = datetime.fromtimestamp(fs_sec, tz=timezone.utc)
            except (ValueError, TypeError):
                pass

            try:
                ls_sec = int(last_seen_str)
                if ls_sec > 0:
                    last_seen_dt = datetime.fromtimestamp(ls_sec, tz=timezone.utc)
            except (ValueError, TypeError):
                pass

            total_detections += c_val
            records.append(
                NoisyRuleRecord(
                    rule_id=r_id,
                    rule_name=r_name,
                    rule_type=r_type,
                    alert_state=r_alert,
                    detection_count=c_val,
                    first_seen=first_seen_dt,
                    last_seen=last_seen_dt,
                    raw=row,
                )
            )
            if len(records) >= limit:
                break

        return NoisyRulesBatch(
            rules=records,
            total_detections=total_detections,
            time_window=f"{lookback_days}d",
            raw=res.raw,
        )


class AnalyzeEntityCardinalityWorkflow:
    """Calculates field-level cardinality distributions across key UDM subfields for a rule."""

    STANDARD_DIMENSIONS: Dict[str, str] = {
        "principal_ip": "detection.collection_elements.references.event.principal.ip",
        "target_ip": "detection.collection_elements.references.event.target.ip",
        "src_ip": "detection.collection_elements.references.event.src.ip",
        "principal_hostname": "detection.collection_elements.references.event.principal.hostname",
        "target_hostname": "detection.collection_elements.references.event.target.hostname",
        "src_hostname": "detection.collection_elements.references.event.src.hostname",
        "principal_user": "detection.collection_elements.references.event.principal.user.userid",
        "target_user": "detection.collection_elements.references.event.target.user.userid",
        "process_cmdline": "detection.collection_elements.references.event.target.process.command_line",
        "process_path": "detection.collection_elements.references.event.target.process.file.full_path",
        "dns_query": "detection.collection_elements.references.event.network.dns.questions.name",
    }

    DIMENSION_GROUPS: Dict[str, List[str]] = {
        "ips": ["principal_ip", "target_ip", "src_ip"],
        "hostnames": ["principal_hostname", "target_hostname", "src_hostname"],
        "users": ["principal_user", "target_user"],
        "processes": ["process_cmdline", "process_path"],
        "all": [
            "principal_ip",
            "principal_hostname",
            "target_hostname",
            "principal_user",
            "process_cmdline",
            "dns_query",
        ],
    }

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        rule_id: str,
        dimensions: Optional[List[str]] = None,
        lookback_days: int = 14,
        limit_per_dimension: int = 10,
    ) -> EntityCardinalityReport:
        clean_rule_id = rule_id.split("/")[-1].strip()

        # Resolve selected dimensions
        target_dims: List[tuple[str, str]] = []
        if not dimensions or "all" in dimensions:
            dim_names = self.DIMENSION_GROUPS["all"]
        else:
            dim_names = []
            for d in dimensions:
                d_lower = d.lower()
                if d_lower in self.DIMENSION_GROUPS:
                    dim_names.extend(self.DIMENSION_GROUPS[d_lower])
                elif d_lower in self.STANDARD_DIMENSIONS:
                    dim_names.append(d_lower)
                else:
                    # Allow custom path
                    dim_names.append(d)

        # De-duplicate preserving order
        seen = set()
        unique_dim_names = []
        for d in dim_names:
            if d not in seen:
                seen.add(d)
                unique_dim_names.append(d)

        for d_name in unique_dim_names:
            path = self.STANDARD_DIMENSIONS.get(d_name, d_name)
            target_dims.append((d_name, path))

        dimension_results: List[DimensionCardinality] = []
        query_errors: List[str] = []

        for dim_name, subfield_path in target_dims:
            query = f"""$ruleId = detection.detection.rule_id
$ruleId = "{clean_rule_id}"
$val = {subfield_path}
$val != ""
match: $val
outcome: $count = count(detection.id)
order: $count desc
limit: {limit_per_dimension}
"""
            try:
                res = self.adapter.execute_dashboard_query(
                    query_text=query,
                    time_unit="DAY",
                    time_value=str(max(1, lookback_days)),
                )
                records: List[EntityCardinalityRecord] = []
                for row in res.rows:
                    val = row.get("val") or ""
                    cnt_str = row.get("count") or "0"
                    try:
                        cnt = int(cnt_str)
                    except (ValueError, TypeError):
                        cnt = 0
                    if val:
                        records.append(EntityCardinalityRecord(value=val, count=cnt, raw=row))

                dimension_results.append(
                    DimensionCardinality(
                        dimension=dim_name,
                        subfield_path=subfield_path,
                        records=records,
                        total_distinct_values=len(records),
                    )
                )
            except Exception as exc:
                # A field may be unsupported for this rule's event type; record
                # the failure instead of reporting an empty distribution.
                err = f"{type(exc).__name__}: {exc}"
                query_errors.append(f"{dim_name}: {err}")
                dimension_results.append(
                    DimensionCardinality(
                        dimension=dim_name,
                        subfield_path=subfield_path,
                        records=[],
                        total_distinct_values=0,
                        error=err,
                    )
                )

        if target_dims and len(query_errors) == len(target_dims):
            raise RuntimeError(
                f"All {len(target_dims)} cardinality queries failed for rule {clean_rule_id}: {query_errors[0]}"
            )

        return EntityCardinalityReport(
            rule_id=clean_rule_id,
            dimensions=dimension_results,
            time_window=f"{lookback_days}d",
            query_errors=query_errors,
        )


class CrossReferenceRuleCasesWorkflow:
    """Queries historical SOAR cases triggered by a rule to extract analyst resolutions."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        rule_id: str,
        lookback_days: int = 90,
        limit: int = 20,
        environment: Optional[str] = None,
    ) -> RuleCaseHistoryBatch:
        """Cases whose alerts came from ``rule_id``.

        Each record carries ``environment`` (``case.environment``) and
        ``soar_case_id`` (``case.response_platform_info.response_platform_id``,
        the numeric SOAR case ID). ``environment`` filters by exact SOAR
        environment name.
        """
        clean_rule_id = rule_id.split("/")[-1].strip()
        if not _SAFE_LITERAL.match(clean_rule_id):
            raise ValueError(f"invalid rule_id {rule_id!r}")
        env_filter = ""
        if environment is not None:
            if not _SAFE_LITERAL.match(environment):
                raise ValueError(f"invalid environment {environment!r}")
            env_filter = f'\n$case_environment = "{environment}"'

        case_query = f"""
$case_name = case.name
$case_display_name = case.display_name
$case_status = case.status
$case_closure_details_reason = case.closure_details.reason
$case_closure_details_root_cause = case.closure_details.root_cause
$case_environment = case.environment{env_filter}
$soar_case_id = case.response_platform_info.response_platform_id
$response_platform_type = case.response_platform_info.response_platform_type
$rule_id = case.alerts.metadata.detection.rule_id 
$rule_id = "{clean_rule_id}"
match:
    $case_name, $case_display_name, $case_status, $case_closure_details_reason, $case_closure_details_root_cause, $case_environment, $soar_case_id, $response_platform_type, $rule_id
limit: {limit}
"""
        res = self.adapter.execute_dashboard_query(
            query_text=case_query,
            time_unit="DAY",
            time_value=str(max(1, lookback_days)),
        )

        cases: List[RuleCaseHistoryRecord] = []
        for row in res.rows:
            c_name = row.get("case_name") or ""
            c_disp = row.get("case_display_name") or ""
            c_status = row.get("case_status") or "UNKNOWN"
            c_reason = row.get("case_closure_details_reason") or ""
            c_root = row.get("case_closure_details_root_cause") or ""
            r_id = row.get("rule_id") or clean_rule_id

            cases.append(
                RuleCaseHistoryRecord(
                    case_name=c_name,
                    display_name=c_disp,
                    status=c_status,
                    close_reason=c_reason,
                    root_cause=c_root,
                    rule_id=r_id,
                    raw=row,
                    environment=str(row.get("case_environment") or ""),
                    soar_case_id=str(row.get("soar_case_id") or ""),
                    response_platform_type=str(row.get("response_platform_type") or ""),
                )
            )

        return RuleCaseHistoryBatch(
            cases=cases,
            rule_id=clean_rule_id,
            total_cases=len(cases),
            raw=res.raw,
        )


RULE_CASE_ENVIRONMENTS_QUERY = f"""$rule_id = case.alerts.metadata.detection.rule_id
$rule_name = case.alerts.metadata.detection.rule_name
$env = case.environment
match: $rule_id, $rule_name, $env
outcome: $cases = count_distinct(case.name)
order: $cases desc
limit: {RULE_CASE_ENVIRONMENTS_ROW_LIMIT}"""


def parse_rule_case_environment_rows(rows: List[Dict[str, Any]]) -> "tuple[List[RuleCaseEnvironment], int]":
    """Merges rows into one record per (rule_id, environment).

    A rule renamed inside the window yields one row per display name; those
    counts are summed (an upper bound if one case carried alerts under both
    names) and the number of merged rows is returned.
    """
    merged: Dict[tuple, RuleCaseEnvironment] = {}
    merged_rows = 0
    for row in rows:
        rid = str(row.get("rule_id") or "")
        if not rid:
            continue
        env = str(row.get("env") or "")
        try:
            count = int(row.get("cases") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Unexpected case count {row.get('cases')!r} for rule {rid}") from exc
        key = (rid, env)
        if key in merged:
            merged[key].case_count += count
            merged_rows += 1
            continue
        merged[key] = RuleCaseEnvironment(
            rule_id=rid,
            environment=env,
            case_count=count,
            rule_name=str(row.get("rule_name") or ""),
            raw=row,
        )
    pairs = sorted(merged.values(), key=lambda p: (-p.case_count, p.rule_id, p.environment))
    return pairs, merged_rows


class QueryRuleCaseEnvironmentsWorkflow:
    """Rule -> SOAR environment join: distinct cases per (rule_id, case.environment)."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, lookback_days: int = 30) -> RuleCaseEnvironmentResult:
        """One dashboard query over the case schema (~15-20 s for 30 days live).

        No regex filter on ``rule_id`` is used (``/^ru_/`` took 112 s live);
        filter by prefix client-side. Raises on query error.
        """
        if lookback_days <= 0:
            raise ValueError("lookback_days must be positive")
        res = self.adapter.execute_dashboard_query(
            query_text=RULE_CASE_ENVIRONMENTS_QUERY,
            time_unit="DAY",
            time_value=str(lookback_days),
            dialect="YL2",
        )
        rows = list(getattr(res, "rows", []) or [])
        truncated = len(rows) >= RULE_CASE_ENVIRONMENTS_ROW_LIMIT
        if truncated:
            logger.warning("Rule/environment join hit the %d-row limit; result truncated.", RULE_CASE_ENVIRONMENTS_ROW_LIMIT)
        pairs, merged_rows = parse_rule_case_environment_rows(rows)
        return RuleCaseEnvironmentResult(
            pairs=pairs,
            lookback_days=lookback_days,
            query=RULE_CASE_ENVIRONMENTS_QUERY,
            provenance={
                "api": "dashboardQueries:execute",
                "raw_rows": len(rows),
                "rename_rows_merged": merged_rows,
                "truncated": truncated,
                "time_window": getattr(res, "time_window", {}),
            },
        )


class TestFindingsRefinementWorkflow:
    """Executes a dry-run test of a findings refinement exclusion against historical detections.

    :testFindingsRefinement has a very low per-minute quota, so successful results are
    cached per (rules, query, window) for CACHE_TTL_S. Errors are never cached.
    """

    CACHE_TTL_S = 3600.0
    _CACHE_MAX = 256

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter
        self._cache: Dict[tuple, tuple] = {}
        self._cache_lock = threading.Lock()

    def _cache_get(self, key: tuple) -> Optional[FindingsRefinementTestResult]:
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit and (time.monotonic() - hit[0]) < self.CACHE_TTL_S:
                return hit[1]
            self._cache.pop(key, None)
            return None

    def _cache_put(self, key: tuple, result: FindingsRefinementTestResult) -> None:
        with self._cache_lock:
            if len(self._cache) >= self._CACHE_MAX:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = (time.monotonic(), result)

    def execute(
        self,
        curated_rule_ids: List[str],
        query: str,
        lookback_days: int = 14,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> FindingsRefinementTestResult:
        if not start_time or not end_time:
            now = datetime.now(timezone.utc)
            start_dt = now - timedelta(days=max(1, lookback_days))
            start_time = start_dt.strftime("%Y-%m-%dT00:00:00.000Z")
            end_time = now.strftime("%Y-%m-%dT23:59:59.999Z")

        cache_key = (
            tuple(sorted(r.split("/")[-1] for r in curated_rule_ids)),
            query.strip(),
            start_time,
            end_time,
        )
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        raw_list = self.adapter.test_findings_refinement(
            curated_rule_ids=curated_rule_ids,
            query=query,
            start_time=start_time,
            end_time=end_time,
        )

        total_count = 0
        excluded_count = 0
        rule_id_ref = curated_rule_ids[0] if curated_rule_ids else ""

        # Inspect activities array in response
        for item in raw_list:
            activity = item.get("activity", {})
            d_activity = activity.get("detectionExclusionActivity", {})
            detector_activities = d_activity.get("detectionExclusionDetectorActivities", [])
            for da in detector_activities:
                t_str = da.get("totalDetectionCount") or "0"
                e_str = da.get("excludedDetectionCount") or "0"
                c_rule = da.get("curatedRule") or rule_id_ref
                try:
                    t_val = int(t_str)
                    e_val = int(e_str)
                    if t_val > total_count:
                        total_count = t_val
                    if e_val > excluded_count:
                        excluded_count = e_val
                    if c_rule:
                        rule_id_ref = c_rule
                except (ValueError, TypeError):
                    pass

        ratio = (float(excluded_count) / float(total_count)) if total_count > 0 else 0.0

        result = FindingsRefinementTestResult(
            curated_rule_id=rule_id_ref,
            query=query,
            total_detections=total_count,
            excluded_detections=excluded_count,
            suppression_ratio=ratio,
            raw=raw_list,
        )
        self._cache_put(cache_key, result)
        return result


class ManageFindingsRefinementsWorkflow:
    """Manages CRUD lifecycle for tenant UDM findings refinements and exclusions."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def list_refinements(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> FindingsRefinementBatch:
        """Lists findings refinements; ``all_pages`` follows ``nextPageToken``."""

        def fetch(tok: Optional[str]):
            resp = self.adapter.list_findings_refinements(page_size=page_size, page_token=tok)
            if not isinstance(resp, dict):
                return [], None, resp
            return list(resp.get("findingsRefinements", []) or []), resp.get("nextPageToken"), resp

        if all_pages or max_results is not None:

            def fetch_page(tok: Optional[str]):
                items, nxt, _ = fetch(tok)
                return items, nxt

            raw_items, next_token, pages = collect_pages(fetch_page, page_token=page_token, max_results=max_results)
            res: Dict[str, Any] = {"findingsRefinements": raw_items, "pages": pages}
            if next_token:
                res["nextPageToken"] = next_token
        else:
            raw_items, _, res = fetch(page_token)
            if not isinstance(res, dict):
                res = {}
        items: List[FindingsRefinementSummary] = []
        for ref in raw_items:
            name = ref.get("name", "")
            ref_id = name.split("/")[-1]
            disp = ref.get("displayName", "")
            q = ref.get("query", "")
            r_type = ref.get("type", "DETECTION_EXCLUSION")
            c_rules: List[str] = []
            dex = ref.get("detectionExclusionApplication", {})
            if isinstance(dex, dict) and "curatedRules" in dex:
                c_rules = dex.get("curatedRules") or []

            items.append(
                FindingsRefinementSummary(
                    id=ref_id,
                    name=name,
                    display_name=disp,
                    type=r_type,
                    query=q,
                    curated_rule_ids=c_rules,
                    raw=ref,
                )
            )

        return FindingsRefinementBatch(refinements=items, raw=res)

    def create_refinement(
        self,
        display_name: str,
        query: str,
        curated_rule_ids: Optional[List[str]] = None,
    ) -> FindingsRefinementSummary:
        res = self.adapter.create_findings_refinement(
            display_name=display_name,
            query=query,
            curated_rule_ids=curated_rule_ids,
        )
        name = res.get("name", "")
        ref_id = name.split("/")[-1]
        return FindingsRefinementSummary(
            id=ref_id,
            name=name,
            display_name=res.get("displayName", display_name),
            type=res.get("type", "DETECTION_EXCLUSION"),
            query=res.get("query", query),
            curated_rule_ids=curated_rule_ids or [],
            raw=res,
        )

    def delete_refinement(self, refinement_id: str) -> Dict[str, Any]:
        return self.adapter.delete_findings_refinement(refinement_id)


class DiagnoseAndTuneDetectionWorkflow:
    """Autonomous end-to-end detection tuning workflow."""

    def __init__(
        self,
        adapter: GoogleSecOpsAdapter,
        cardinality_wf: AnalyzeEntityCardinalityWorkflow,
        case_wf: CrossReferenceRuleCasesWorkflow,
        test_wf: TestFindingsRefinementWorkflow,
    ):
        self.adapter = adapter
        self.cardinality_wf = cardinality_wf
        self.case_wf = case_wf
        self.test_wf = test_wf

    def execute(
        self,
        rule_id: str,
        lookback_days: int = 7,
    ) -> DetectionTuningReport:
        clean_rule_id = rule_id.split("/")[-1].strip()
        is_curated = "ur_" in clean_rule_id

        rule_name = ""
        rule_text = ""
        rule_type = "GOOGLE_MANAGED" if is_curated else "CUSTOMER"

        # 1. Fetch rule logic
        if is_curated:
            rule_data = self.adapter.get_featured_content_rule(clean_rule_id)
            if rule_data:
                meta = rule_data.get("contentMetadata") or {}
                rule_name = (
                    rule_data.get("displayName")
                    or meta.get("displayName")
                    or rule_data.get("ruleId")
                    or clean_rule_id
                )
                rule_text = rule_data.get("ruleText") or ""
        else:
            rule_res = self.adapter.get_rule(clean_rule_id)
            if rule_res:
                rule_name = rule_res.get("displayName") or clean_rule_id
                rule_text = rule_res.get("text") or ""

        # 2. Extract entity distributions
        cardinality_report = self.cardinality_wf.execute(
            rule_id=clean_rule_id,
            lookback_days=lookback_days,
            limit_per_dimension=5,
        )

        # 3. Cross-reference cases
        case_history = self.case_wf.execute(
            rule_id=clean_rule_id,
            lookback_days=90,
            limit=5,
        )

        # 4. Identify the single most impactful entity to exclude
        top_field = ""
        top_val = ""
        top_count = 0
        for dim in cardinality_report.dimensions:
            for rec in dim.records:
                if rec.count > top_count:
                    top_count = rec.count
                    top_val = rec.value
                    # Map dimension to UDM field for refinement
                    if "event." in dim.subfield_path:
                        top_field = dim.subfield_path.split("event.")[-1]
                    elif "_ip" in dim.dimension or dim.dimension.endswith("ip"):
                        if "principal" in dim.dimension:
                            top_field = "principal.ip"
                        elif "src" in dim.dimension:
                            top_field = "src.ip"
                        else:
                            top_field = "target.ip"
                    elif "hostname" in dim.dimension:
                        if "principal" in dim.dimension:
                            top_field = "principal.hostname"
                        elif "src" in dim.dimension:
                            top_field = "src.hostname"
                        else:
                            top_field = "target.hostname"
                    elif "user" in dim.dimension:
                        if "target" in dim.dimension:
                            top_field = "target.user.userid"
                        elif "src" in dim.dimension:
                            top_field = "src.user.userid"
                        else:
                            top_field = "principal.user.userid"
                    elif "dns" in dim.dimension:
                        top_field = "network.dns.questions.name"
                    elif "process" in dim.dimension:
                        top_field = "target.process.command_line"
                    else:
                        top_field = dim.dimension

        # 5. Formulate candidate exclusion
        proposed_refinement = ""
        test_result: Optional[FindingsRefinementTestResult] = None
        validation_errors: List[str] = []

        if top_field and top_val:
            proposed_refinement = translate_to_udm_refinement(top_field, top_val, is_regex=True)
            if is_curated:
                try:
                    test_result = self.test_wf.execute(
                        curated_rule_ids=[clean_rule_id],
                        query=proposed_refinement,
                        lookback_days=lookback_days,
                    )
                except Exception as e:
                    validation_errors.append(f"Dry-run test error: {str(e)}")

        val_status = "VALIDATED" if not validation_errors and (test_result or not is_curated) else "ERROR"

        return DetectionTuningReport(
            rule_id=clean_rule_id,
            rule_name=rule_name,
            rule_type=rule_type,
            rule_text=rule_text,
            total_detections_baseline=top_count,
            entity_cardinality=cardinality_report,
            linked_cases=case_history,
            proposed_refinement_query=proposed_refinement,
            dry_run_impact=test_result,
            validation_status=val_status,
            validation_errors=validation_errors,
        )


class SampleDetectionEventsWorkflow:
    """Samples correlated multi-attribute detection tuples (user + command + host + IP)."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        rule_id: str,
        lookback_days: int = 14,
        limit: int = 20,
    ) -> CorrelatedSamplingBatch:
        clean_rule_id = rule_id.split("/")[-1].strip()

        # Primary query: Process-focused correlated attributes
        query_text = f"""$rule_id = detection.detection.rule_id
$rule_id = "{clean_rule_id}"
$user = detection.collection_elements.references.event.principal.user.userid
$cmd = detection.collection_elements.references.event.target.process.command_line
$host = detection.collection_elements.references.event.principal.hostname
match:
    $user, $cmd, $host
outcome:
    $count = count_distinct(detection.id)
    $last_seen = timestamp.get_timestamp(max(detection.detection_time.seconds))
order:
    $count desc
limit: {limit}
"""
        rule_name = clean_rule_id
        res = None
        query_errors: List[str] = []
        try:
            res = self.adapter.execute_dashboard_query(
                query_text=query_text,
                time_unit="DAY",
                time_value=str(max(1, lookback_days)),
            )
        except Exception as exc:
            query_errors.append(f"primary (user/cmd/host) query: {type(exc).__name__}: {exc}")
            logger.warning("sample_detection_events(%s): %s", clean_rule_id, query_errors[-1])

        rows = res.rows if res and res.rows else []

        # Fallback query for network or cloud audit detections lacking process attributes
        if not rows:
            fallback_query = f"""$rule_id = detection.detection.rule_id
$rule_id = "{clean_rule_id}"
$user = detection.collection_elements.references.event.principal.user.userid
$ip = detection.collection_elements.references.event.principal.ip
match:
    $user, $ip
outcome:
    $count = count_distinct(detection.id)
    $last_seen = timestamp.get_timestamp(max(detection.detection_time.seconds))
order:
    $count desc
limit: {limit}
"""
            try:
                f_res = self.adapter.execute_dashboard_query(
                    query_text=fallback_query,
                    time_unit="DAY",
                    time_value=str(max(1, lookback_days)),
                )
                if f_res and f_res.rows:
                    rows = f_res.rows
            except Exception as exc:
                query_errors.append(f"fallback (user/ip) query: {type(exc).__name__}: {exc}")
                logger.warning("sample_detection_events(%s): %s", clean_rule_id, query_errors[-1])
                if res is None:
                    # Both queries failed: zero samples would be indistinguishable from a quiet rule.
                    raise RuntimeError(
                        f"All detection sample queries failed for rule {clean_rule_id}: {'; '.join(query_errors)}"
                    ) from exc

        samples: List[CorrelatedDetectionSample] = []
        for row in rows:
            u_val = str(row.get("user") or "").strip()
            c_val = str(row.get("cmd") or "").strip()
            h_val = str(row.get("host") or "").strip()
            ip_val = str(row.get("ip") or "").strip()
            ls_val = str(row.get("last_seen") or "").strip()
            cnt_str = row.get("count") or "0"
            try:
                c_num = int(cnt_str)
            except (ValueError, TypeError):
                c_num = 0

            if u_val or c_val or h_val or ip_val:
                samples.append(
                    CorrelatedDetectionSample(
                        user=u_val,
                        command_line=c_val,
                        hostname=h_val,
                        ip=ip_val,
                        count=c_num,
                        last_seen=ls_val or None,
                        raw=row,
                    )
                )

        return CorrelatedSamplingBatch(
            rule_id=clean_rule_id,
            rule_name=rule_name,
            samples=samples,
            total_samples=len(samples),
            time_window=f"{lookback_days}d",
            raw=res.raw if res else {},
            query_errors=query_errors,
        )


BANNED_GLOBAL_BINARIES = {
    "powershell.exe", "powershell", "cmd.exe", "cmd",
    "wmic.exe", "wmic", "bash", "sh", "python.exe",
    "python", "python3", "whoami.exe", "whoami",
    "certutil.exe", "bitsadmin.exe", "rundll32.exe",
    "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
}


class SynthesizeMultiFactorExclusionWorkflow:
    """Synthesizes safe, multi-factor exclusion logic adhering to strict HITL guardrails."""

    def execute(
        self,
        rule_id: str,
        rule_name: str,
        samples: List[CorrelatedDetectionSample],
        total_detections: int,
        event_var: str = "$e",
        dominance_threshold: float = 0.20,
    ) -> MultiFactorExclusion:
        clean_rule_id = rule_id.split("/")[-1].strip()
        guardrail_notes: List[str] = []

        if not samples or total_detections <= 0:
            return MultiFactorExclusion(
                rule_id=clean_rule_id,
                rule_name=rule_name,
                factors={},
                yara_l_condition="",
                udm_refinement_query="",
                is_multi_factor=False,
                safety_guardrail_passed=False,
                guardrail_notes=["No historical detection samples found for exclusion synthesis."],
            )

        # Identify top correlated benign pattern
        top_sample = samples[0]
        dominance_ratio = float(top_sample.count) / float(total_detections) if total_detections > 0 else 0.0

        if dominance_ratio < dominance_threshold:
            guardrail_notes.append(
                f"Diversity check failed: Top pattern represents {dominance_ratio*100:.1f}% of detections "
                f"(below {dominance_threshold*100:.0f}% dominance threshold). Alerts are widely distributed "
                "without a single dominant benign pattern. Forcing an exclusion would risk blinding detection coverage."
            )
            return MultiFactorExclusion(
                rule_id=clean_rule_id,
                rule_name=rule_name,
                factors={},
                yara_l_condition="",
                udm_refinement_query="",
                is_multi_factor=False,
                safety_guardrail_passed=False,
                guardrail_notes=guardrail_notes,
            )

        # Extract potential factors
        factors: Dict[str, str] = {}
        if top_sample.user:
            factors["user"] = top_sample.user
        if top_sample.command_line:
            factors["command_line"] = top_sample.command_line
        if top_sample.hostname:
            factors["hostname"] = top_sample.hostname
        if top_sample.ip:
            factors["ip"] = top_sample.ip

        # Enforce multi-factor constraint
        if len(factors) < 2:
            # Reject single-variable cuts
            if "command_line" in factors:
                val_lower = factors["command_line"].lower()
                for b in BANNED_GLOBAL_BINARIES:
                    if b in val_lower and len(val_lower.strip().split()) <= 2:
                        guardrail_notes.append(f"Rejected broad binary exclusion on '{b}'. Exclusions must not cut system binaries alone.")
            if "user" in factors:
                guardrail_notes.append("Rejected broad user-only exclusion. Exclusions must not cut user accounts globally across all activities.")
            if "ip" in factors:
                guardrail_notes.append("Rejected broad IP-only exclusion without supporting identity or host context.")

            guardrail_notes.append("Multi-factor invariant violation: Exclusions must combine at least two correlating attributes.")
            return MultiFactorExclusion(
                rule_id=clean_rule_id,
                rule_name=rule_name,
                factors=factors,
                yara_l_condition="",
                udm_refinement_query="",
                is_multi_factor=False,
                safety_guardrail_passed=False,
                guardrail_notes=guardrail_notes,
            )

        # Check for banned global binary in command_line (even if multi-factor)
        if "command_line" in factors:
            val_lower = factors["command_line"].lower().strip()
            tokens = val_lower.split()
            first_cmd = os.path.basename(tokens[0]) if tokens else ""
            if val_lower in BANNED_GLOBAL_BINARIES or (len(tokens) <= 1 and first_cmd in BANNED_GLOBAL_BINARIES) or (len(tokens) <= 2 and first_cmd in BANNED_GLOBAL_BINARIES and tokens[1] in ("-c", "/c", "-e", "-enc")):
                guardrail_notes.append(
                    f"Banned global binary violation: '{first_cmd or val_lower}' cannot be excluded as a bare binary. "
                    "Exclusions must include specific benign administrative arguments."
                )
                return MultiFactorExclusion(
                    rule_id=clean_rule_id,
                    rule_name=rule_name,
                    factors=factors,
                    yara_l_condition="",
                    udm_refinement_query="",
                    is_multi_factor=False,
                    safety_guardrail_passed=False,
                    guardrail_notes=guardrail_notes,
                )

        # Check for broad IP subnet
        if "ip" in factors:
            ip_val = factors["ip"].strip()
            if "/" in ip_val:
                try:
                    prefix = int(ip_val.split("/")[-1])
                    if prefix <= 24:
                        guardrail_notes.append(
                            f"Broad subnet violation: Subnet '{ip_val}' cannot be excluded. "
                            "Exclusions must not cut broad CIDR ranges."
                        )
                        return MultiFactorExclusion(
                            rule_id=clean_rule_id,
                            rule_name=rule_name,
                            factors=factors,
                            yara_l_condition="",
                            udm_refinement_query="",
                            is_multi_factor=False,
                            safety_guardrail_passed=False,
                            guardrail_notes=guardrail_notes,
                        )
                except ValueError:
                    pass

        # Build YARA-L condition
        clean_var = event_var.strip()
        if not clean_var.startswith("$"):
            clean_var = f"${clean_var}"

        yara_clauses: List[str] = []
        udm_clauses: List[str] = []

        if "user" in factors:
            u_val = factors["user"].replace('"', '\\"')
            yara_clauses.append(f'{clean_var}.principal.user.userid = "{u_val}" nocase')
            udm_clauses.append(f'(principal.user.userid = "{u_val}")')

        if "command_line" in factors:
            cmd_raw = factors["command_line"]
            cmd_regex = re.escape(cmd_raw).replace("/", "\\/")
            yara_clauses.append(f'{clean_var}.target.process.command_line = /{cmd_regex}/ nocase')
            udm_clauses.append(f'(target.process.command_line = /{cmd_regex}/)')

        if "hostname" in factors:
            h_val = factors["hostname"].replace('"', '\\"')
            yara_clauses.append(f'{clean_var}.principal.hostname = "{h_val}" nocase')
            udm_clauses.append(f'(principal.hostname = "{h_val}")')

        if "ip" in factors and "hostname" not in factors:
            ip_val = factors["ip"].replace('"', '\\"')
            yara_clauses.append(f'{clean_var}.principal.ip = "{ip_val}"')
            udm_clauses.append(f'(principal.ip = "{ip_val}")')

        joined_yara = "\n      and ".join(yara_clauses)
        yara_l_cond = f"""    // Benign administrative noise suppression exclusion
    and not (
      {joined_yara}
    )"""

        udm_refinement = " and ".join(udm_clauses)
        guardrail_notes.append(f"Successfully synthesized multi-factor exclusion combining {len(factors)} attributes.")

        return MultiFactorExclusion(
            rule_id=clean_rule_id,
            rule_name=rule_name,
            factors=factors,
            yara_l_condition=yara_l_cond,
            udm_refinement_query=udm_refinement,
            is_multi_factor=True,
            safety_guardrail_passed=True,
            guardrail_notes=guardrail_notes,
        )


class SynthesizeTuningProposalWorkflow:
    """Orchestrates end-to-end tuning synthesis, compiler validation, diff generation, and impact calculation."""

    def __init__(
        self,
        adapter: GoogleSecOpsAdapter,
        noisy_wf: FindTopNoisyRulesWorkflow,
        cardinality_wf: AnalyzeEntityCardinalityWorkflow,
        sample_wf: SampleDetectionEventsWorkflow,
        synthesis_wf: SynthesizeMultiFactorExclusionWorkflow,
        test_wf: TestFindingsRefinementWorkflow,
    ):
        self.adapter = adapter
        self.noisy_wf = noisy_wf
        self.cardinality_wf = cardinality_wf
        self.sample_wf = sample_wf
        self.synthesis_wf = synthesis_wf
        self.test_wf = test_wf

    def execute(
        self,
        rule_id: str,
        lookback_days: int = 14,
        dominance_threshold: float = 0.20,
    ) -> DetectionTuningProposal:
        clean_rule_id = rule_id.split("/")[-1].strip()
        proposal_id = f"prop-tune-{clean_rule_id[:16]}-{uuid.uuid4().hex[:6]}"
        is_curated = "ur_" in clean_rule_id or clean_rule_id.startswith("ur_")
        rule_type = "GOOGLE_MANAGED" if is_curated else "CUSTOMER"

        # 1. Fetch rule details
        rule_name = clean_rule_id
        orig_text = ""
        if is_curated:
            r_data = self.adapter.get_featured_content_rule(clean_rule_id)
            if r_data:
                meta = r_data.get("contentMetadata") or {}
                rule_name = r_data.get("displayName") or meta.get("displayName") or clean_rule_id
                orig_text = r_data.get("ruleText") or ""
        else:
            r_data = self.adapter.get_rule(clean_rule_id)
            if r_data:
                rule_name = r_data.get("displayName") or clean_rule_id
                orig_text = r_data.get("text") or ""

        # 2. Extract event variable from rule text
        event_var = "$e"
        if orig_text:
            m = re.search(r"events:\s*\n\s*(\$[a-zA-Z0-9_]+)\.", orig_text)
            if m:
                event_var = m.group(1)

        # 3. Aggregate baseline detections
        cardinality_report = self.cardinality_wf.execute(
            rule_id=clean_rule_id,
            lookback_days=lookback_days,
            limit_per_dimension=10,
        )

        total_detections = 0
        entity_bars: List[Dict[str, Any]] = []
        for dim in cardinality_report.dimensions:
            for rec in dim.records:
                if rec.count > total_detections:
                    total_detections = rec.count
                entity_bars.append({
                    "dimension": dim.dimension,
                    "value": rec.value,
                    "count": rec.count,
                })

        # 4. Pull correlated detection event samples
        sampling_batch = self.sample_wf.execute(
            rule_id=clean_rule_id,
            lookback_days=lookback_days,
            limit=10,
        )

        if total_detections == 0 and sampling_batch.samples:
            total_detections = sum(s.count for s in sampling_batch.samples)

        # 5. Synthesize multi-factor exclusion with safety guardrails
        exclusion = self.synthesis_wf.execute(
            rule_id=clean_rule_id,
            rule_name=rule_name,
            samples=sampling_batch.samples,
            total_detections=total_detections,
            event_var=event_var,
            dominance_threshold=dominance_threshold,
        )

        # Handle Diversity Check / NO_TUNING_NEEDED
        if not exclusion.safety_guardrail_passed:
            return DetectionTuningProposal(
                proposal_id=proposal_id,
                rule_id=clean_rule_id,
                rule_name=rule_name,
                rule_type=rule_type,
                status="NO_TUNING_NEEDED",
                unsuppressed_trigger_count=total_detections,
                projected_suppressed_count=0,
                noise_reduction_pct=0.0,
                preserved_real_alerts=total_detections,
                multi_factor_exclusion=exclusion,
                entity_distribution=entity_bars[:10],
                correlated_samples=sampling_batch.samples[:5],
                unified_diff="",
                original_rule_text=orig_text,
                tuned_rule_text=orig_text,
                compiler_verified=True,
                compiler_errors=[],
            )

        # 6. Apply patching & Compiler Pre-Verification
        tuned_text = orig_text
        unified_diff = ""
        compiler_verified = False
        compiler_errors: List[str] = []
        suppressed_count = sampling_batch.samples[0].count if sampling_batch.samples else 0

        if not is_curated and orig_text:
            # Customer rule: patch rule text directly
            cond_pos = orig_text.find("  condition:")
            if cond_pos != -1:
                tuned_text = orig_text[:cond_pos] + exclusion.yara_l_condition + "\n\n" + orig_text[cond_pos:]
            else:
                tuned_text = orig_text + "\n" + exclusion.yara_l_condition

            # Verify against Chronicle YARA-L compiler
            try:
                comp_res = self.adapter.verify_rule_text(tuned_text)
                if comp_res.get("success"):
                    compiler_verified = True
                else:
                    diags = comp_res.get("compilationDiagnostics") or []
                    for d in diags:
                        compiler_errors.append(d.get("message", "Compilation error"))
            except Exception as e:
                compiler_errors.append(str(e))

            # Generate git-style unified diff
            diff_lines = list(difflib.unified_diff(
                orig_text.splitlines(keepends=True),
                tuned_text.splitlines(keepends=True),
                fromfile=f"a/{clean_rule_id}.yaral",
                tofile=f"b/{clean_rule_id}.yaral",
            ))
            unified_diff = "".join(diff_lines)
        else:
            # Curated rule: test findings refinement exclusion
            try:
                dry_res = self.test_wf.execute(
                    curated_rule_ids=[clean_rule_id],
                    query=exclusion.udm_refinement_query,
                    lookback_days=lookback_days,
                )
                compiler_verified = True
                if dry_res.excluded_detections > 0:
                    suppressed_count = dry_res.excluded_detections
            except Exception as e:
                compiler_errors.append(f"Findings refinement dry-run error: {str(e)}")

            # Unified diff representation of refinement
            diff_lines = [
                f"--- a/findings_refinements/{clean_rule_id}.udm\n",
                f"+++ b/findings_refinements/{clean_rule_id}.udm\n",
                "@@ -0,0 +1,5 @@\n",
                f"+// Refinement: Noise Suppression for {rule_name}\n",
                f"+rule_id: {clean_rule_id}\n",
                f"+exclusion_query: {exclusion.udm_refinement_query}\n",
            ]
            unified_diff = "".join(diff_lines)
            tuned_text = f"// UDM Findings Refinement Exclusion\n{exclusion.udm_refinement_query}"

        # 7. Quantitative Impact Projections
        noise_pct = round((float(suppressed_count) / float(total_detections) * 100), 1) if total_detections > 0 else 0.0
        preserved = max(0, total_detections - suppressed_count)

        return DetectionTuningProposal(
            proposal_id=proposal_id,
            rule_id=clean_rule_id,
            rule_name=rule_name,
            rule_type=rule_type,
            status="TUNING_PROPOSED",
            unsuppressed_trigger_count=total_detections,
            projected_suppressed_count=suppressed_count,
            noise_reduction_pct=noise_pct,
            preserved_real_alerts=preserved,
            multi_factor_exclusion=exclusion,
            entity_distribution=entity_bars[:10],
            correlated_samples=sampling_batch.samples[:5],
            unified_diff=unified_diff,
            original_rule_text=orig_text,
            tuned_rule_text=tuned_text,
            compiler_verified=compiler_verified,
            compiler_errors=compiler_errors,
        )

