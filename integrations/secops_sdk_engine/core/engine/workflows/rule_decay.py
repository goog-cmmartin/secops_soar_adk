"""Detection Rule Decay Audit & Telemetry Ingestion Workflow.

Orchestrates continuous evaluation of YARA-L detection rule decay,
Decay Prioritization Scoring (DPS), 90-day telemetry aggregations via dashboardQueries:execute,
and live UDM field population auditing against Google SecOps.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    RuleDecayAssessment,
    RuleDecayReport,
    RuleDetail,
    RuleDetectionBucket,
    RuleDetectionSeries,
    RuleDetectionSeriesResult,
    RuleSummary,
)
from engine.pagination import collect_pages

logger = logging.getLogger(__name__)

# Validated Chronicle detection schema query for aggregating detection volume by rule ID
AUTHORITATIVE_DETECTION_COUNTS_QUERY = """$rule_id = detection.detection.rule_id
$rule_name = detection.detection.rule_name
match:
    $rule_id, $rule_name
outcome:
    $count = count_distinct(detection.id)
    $first_seen = timestamp.get_timestamp(min(detection.detection_time.seconds))
    $last_seen = timestamp.get_timestamp(max(detection.detection_time.seconds))
order:
    $count desc
limit:
    10000"""

# Regex to isolate events: and outcome: sections in YARA-L 2.0
EVENTS_BLOCK_REGEX = re.compile(r"events:\s*(.*?)(?:match:|outcome:|condition:|options:|\Z)", re.DOTALL | re.IGNORECASE)
OUTCOME_BLOCK_REGEX = re.compile(r"outcome:\s*(.*?)(?:condition:|options:|\Z)", re.DOTALL | re.IGNORECASE)

# Regex matching UDM event field paths prefixed by variable bindings (e.g., $e.principal.process.file.full_path)
UDM_FIELD_REGEX = re.compile(
    r"\$[a-zA-Z0-9_]+\.((?:metadata|principal|target|src|about|security_result|observer|network|intermediary)(?:\.[a-zA-Z0-9_]+)+)"
)


def extract_udm_fields_from_yaral(rule_text: str) -> List[str]:
    """Extracts all referenced UDM field paths from YARA-L 2.0 rule text.

    Scans the events: and outcome: sections for canonical UDM namespaces.

    Args:
        rule_text: The complete YARA-L rule text string.

    Returns:
        Sorted list of unique UDM field paths (e.g. ['principal.process.file.full_path', 'target.user.userid']).
    """
    if not rule_text:
        return []

    fields: Set[str] = set()

    # Search in events: block
    ev_match = EVENTS_BLOCK_REGEX.search(rule_text)
    if ev_match:
        for match in UDM_FIELD_REGEX.finditer(ev_match.group(1)):
            fields.add(match.group(1))

    # Search in outcome: block
    out_match = OUTCOME_BLOCK_REGEX.search(rule_text)
    if out_match:
        for match in UDM_FIELD_REGEX.finditer(out_match.group(1)):
            fields.add(match.group(1))

    # Fallback to full rule text if blocks could not be delineated
    if not fields:
        for match in UDM_FIELD_REGEX.finditer(rule_text):
            fields.add(match.group(1))

    return sorted(list(fields))


def calculate_decay_score(
    rule_detail: Any,
    detection_telemetry_90d: Optional[Dict[str, Any]] = None,
    unpopulated_fields: Optional[List[str]] = None,
    syntax_verified: bool = True,
    compiler_diagnostics: Optional[List[str]] = None,
    is_live: Optional[bool] = None,
    telemetry_available: bool = True,
) -> Tuple[int, List[str], str, int]:
    """Computes the Decay Prioritization Score (DPS: 0-100) and operational classification.

    Scoring Model:
      - Base Weight:
          Broken Compilation (+40), Silent (+30), Unpopulated (+20), Healthy (+5).
      - Operational Weight:
          Live/Enabled rule (+30).
      - Staleness Bonus:
          >365 days unrevised (+30), >180 days (+15), >90 days (+5).

    Args:
        rule_detail: Rule domain object or dictionary with metadata and timestamps.
        detection_telemetry_90d: Telemetry dictionary with detection_count, first_seen, last_seen.
        unpopulated_fields: List of UDM fields in the rule with 0 observed events in telemetry.
        syntax_verified: Whether the rule text passed live Chronicle compilation.
        compiler_diagnostics: Optional list of compiler diagnostic messages.
        is_live: Optional explicit boolean flag indicating if rule is live/enabled in production.
        telemetry_available: False when the detection-count query failed. SILENT
            is then not evaluated (a failed query is not evidence of silence) and
            the flag ``TELEMETRY_UNAVAILABLE`` is added instead.

    Returns:
        Tuple of (dps_score, decay_flags, recommendation, days_stale).
    """
    flags: List[str] = []
    base_weight = 0

    # 1. Broken compilation check
    has_compilation_error = not syntax_verified
    if not has_compilation_error and compiler_diagnostics:
        for diag in compiler_diagnostics:
            diag_str = str(diag).lower()
            if "error" in diag_str or "fail" in diag_str:
                has_compilation_error = True
                break

    if has_compilation_error:
        base_weight += 40
        flags.append("BROKEN_COMPILATION")

    # 2. Operational / Live status check
    if is_live is None:
        if hasattr(rule_detail, "live_mode_enabled"):
            is_live = bool(rule_detail.live_mode_enabled)
        elif hasattr(rule_detail, "deployment_state"):
            is_live = str(rule_detail.deployment_state).upper() in ("LIVE", "ENABLED")
        elif isinstance(rule_detail, dict):
            is_live = bool(rule_detail.get("live_mode_enabled") or rule_detail.get("liveModeEnabled") or rule_detail.get("deployment_state") == "LIVE")
        else:
            is_live = False

    operational_weight = 30 if is_live else 0

    # 3. 90-day detection count / Silence check
    count_90d = 0
    if detection_telemetry_90d:
        count_90d = int(detection_telemetry_90d.get("count", 0))

    if not telemetry_available:
        flags.append("TELEMETRY_UNAVAILABLE")
    elif is_live and count_90d == 0:
        base_weight += 30
        flags.append("SILENT")

    # 4. Unpopulated UDM fields check
    unpop = unpopulated_fields or []
    if unpop:
        base_weight += 20
        flags.append("UNPOPULATED")

    if not flags:
        base_weight += 5
        flags.append("HEALTHY")

    # 5. Staleness calculation
    days_stale = 0
    now = datetime.now(timezone.utc)
    rev_time_str = None

    if hasattr(rule_detail, "revision_create_time") and rule_detail.revision_create_time:
        rev_time_str = str(rule_detail.revision_create_time)
    elif hasattr(rule_detail, "create_time") and rule_detail.create_time:
        rev_time_str = str(rule_detail.create_time)
    elif isinstance(rule_detail, dict):
        rev_time_str = rule_detail.get("revision_create_time") or rule_detail.get("revisionCreateTime") or rule_detail.get("create_time") or rule_detail.get("createTime")

    if rev_time_str:
        try:
            clean_ts = rev_time_str.replace("Z", "+00:00")
            parsed_dt = datetime.fromisoformat(clean_ts)
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
            delta = now - parsed_dt
            days_stale = max(0, delta.days)
        except Exception:
            days_stale = 0

    staleness_bonus = 0
    if days_stale >= 365:
        staleness_bonus = 30
        flags.append("STALE")
    elif days_stale >= 180:
        staleness_bonus = 15
        flags.append("STALE")
    elif days_stale >= 90:
        staleness_bonus = 5
        flags.append("STALE")

    # Compute total DPS clamped to [0, 100]
    total_dps = min(100, max(0, base_weight + operational_weight + staleness_bonus))

    # Determine recommended action
    if "BROKEN_COMPILATION" in flags or "UNPOPULATED" in flags:
        recommendation = "REFACTOR"
    elif "STALE" in flags and "SILENT" in flags:
        recommendation = "ARCHIVE"
    elif total_dps >= 60:
        recommendation = "REFACTOR"
    else:
        recommendation = "KEEP_ACTIVE"

    return total_dps, flags, recommendation, days_stale


class QueryRuleDetectionCountsWorkflow:
    """Executes the authoritative SecOps detection count aggregation query over 90 days."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, lookback_days: int = 90) -> Dict[str, Dict[str, Any]]:
        """Queries 90-day detection counts for all rules in the tenant.

        Raises the underlying API/query error. An empty dict therefore means
        "the query ran and no rule fired", never "the query failed".

        Returns:
            Dictionary mapping rule_id to telemetry dict:
            {
               "ru_123": {
                   "rule_id": "ru_123",
                   "rule_name": "Suspicious PowerShell Execution",
                   "count": 42,
                   "first_seen": "2026-06-20T10:00:00Z",
                   "last_seen": "2026-09-19T14:30:00Z"
               }
            }
        """
        results_by_rule: Dict[str, Dict[str, Any]] = {}
        query_res = self.adapter.execute_dashboard_query(
            query_text=AUTHORITATIVE_DETECTION_COUNTS_QUERY,
            time_unit="DAY",
            time_value=str(lookback_days),
            dialect="YL2",
        )
        for row in getattr(query_res, "rows", []):
            rule_id = str(row.get("rule_id") or row.get("$rule_id") or "")
            if not rule_id:
                continue
            rule_name = str(row.get("rule_name") or row.get("$rule_name") or "")
            raw_count = row.get("count") or row.get("$count") or 0
            first_seen = str(row.get("first_seen") or row.get("$first_seen") or "")
            last_seen = str(row.get("last_seen") or row.get("$last_seen") or "")

            try:
                count_val = int(raw_count)
            except (ValueError, TypeError):
                count_val = 0

            prev = results_by_rule.get(rule_id)
            if prev:
                # Same rule id under a second display name (renamed in window).
                prev["count"] += count_val
                continue
            results_by_rule[rule_id] = {
                "rule_id": rule_id,
                "rule_name": rule_name,
                "count": count_val,
                "first_seen": first_seen if first_seen else None,
                "last_seen": last_seen if last_seen else None,
            }

        return results_by_rule


# Bucket formats for timestamp.get_timestamp (UTC). Verified live 2026-10-10:
# hour -> "2026-10-09T13", day -> "2026-10-03".
DETECTION_SERIES_BUCKETS: Dict[str, str] = {
    "hour": "%Y-%m-%dT%H",
    "day": "%Y-%m-%d",
}
DETECTION_SERIES_ROW_LIMIT = 10000


def build_detection_series_query(bucket: str = "hour", rule_id: Optional[str] = None) -> str:
    """YARA-L dashboard query: detections per (rule_id, rule_name, time bucket).

    A single ``rule_id`` is applied as an equality filter (cheap). Regex filters
    on ``rule_id`` are deliberately not used: ``rule_id = /^ru_/`` took 112 s live.
    Rows are ordered newest bucket first so that hitting the row limit drops the
    oldest buckets.
    """
    if bucket not in DETECTION_SERIES_BUCKETS:
        raise ValueError(f"bucket must be one of {sorted(DETECTION_SERIES_BUCKETS)}, got {bucket!r}")
    fmt = DETECTION_SERIES_BUCKETS[bucket]
    if rule_id is not None and not re.fullmatch(r"[A-Za-z0-9_\-]+", rule_id):
        raise ValueError(f"invalid rule_id {rule_id!r}")
    rule_filter = f'\n$rule_id = "{rule_id}"' if rule_id else ""
    return (
        "$rule_id = detection.detection.rule_id"
        f"{rule_filter}\n"
        "$rule_name = detection.detection.rule_name\n"
        f'$bucket = timestamp.get_timestamp(detection.detection_time.seconds, "{fmt}")\n'
        "match: $rule_id, $rule_name, $bucket\n"
        "outcome: $count = count_distinct(detection.id)\n"
        "order: $bucket desc\n"
        f"limit: {DETECTION_SERIES_ROW_LIMIT}"
    )


def parse_detection_series_rows(
    rows: List[Dict[str, Any]],
    bucket: str,
    rule_ids: Optional[List[str]] = None,
) -> Tuple[List[RuleDetectionSeries], int]:
    """Groups query rows into per-rule series (oldest bucket first).

    Raises ValueError on a row whose bucket does not match the requested
    format (unexpected schema must stay visible).
    """
    fmt = DETECTION_SERIES_BUCKETS[bucket]
    wanted = set(rule_ids) if rule_ids else None
    by_rule: Dict[str, Dict[datetime, int]] = {}
    names: Dict[str, str] = {}
    total = 0
    for row in rows:
        rid = str(row.get("rule_id") or "")
        if not rid or (wanted is not None and rid not in wanted):
            continue
        raw_bucket = str(row.get("bucket") or "")
        try:
            start = datetime.strptime(raw_bucket, fmt).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError(f"Unexpected detection series bucket {raw_bucket!r} for rule {rid} (format {fmt})") from exc
        try:
            count = int(row.get("count") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Unexpected detection count {row.get('count')!r} for rule {rid}") from exc
        buckets = by_rule.setdefault(rid, {})
        buckets[start] = buckets.get(start, 0) + count
        total += count
        name = str(row.get("rule_name") or "")
        if name:
            names[rid] = name
    series = [
        RuleDetectionSeries(
            rule_id=rid,
            rule_name=names.get(rid, ""),
            buckets=[RuleDetectionBucket(bucket_start=k, count=v) for k, v in sorted(b.items())],
        )
        for rid, b in by_rule.items()
    ]
    series.sort(key=lambda s: (-s.total, s.rule_id))
    return series, total


class QueryRuleDetectionSeriesWorkflow:
    """Bucketed (hour/day) per-rule detection counts in one dashboard query."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        lookback_hours: int = 24,
        bucket: str = "hour",
        rule_ids: Optional[List[str]] = None,
    ) -> RuleDetectionSeriesResult:
        """Returns per-rule ``(bucket_start, count)`` series, oldest first.

        Args:
            lookback_hours: Relative window ending now (dashboard ``HOUR`` unit).
            bucket: ``"hour"`` or ``"day"`` (UTC buckets).
            rule_ids: Optional rule IDs to keep. One ID is filtered server-side
                by equality; several are filtered client-side from one query.

        Raises:
            ValueError: invalid arguments or unexpected row schema.
            Any adapter error from the dashboard query (never swallowed).
        """
        if lookback_hours <= 0:
            raise ValueError("lookback_hours must be positive")
        ids = [r.split("/")[-1].strip() for r in (rule_ids or []) if r and r.strip()]
        single = ids[0] if len(ids) == 1 else None
        query = build_detection_series_query(bucket=bucket, rule_id=single)
        res = self.adapter.execute_dashboard_query(
            query_text=query,
            time_unit="HOUR",
            time_value=str(lookback_hours),
            dialect="YL2",
        )
        rows = list(getattr(res, "rows", []) or [])
        truncated = len(rows) >= DETECTION_SERIES_ROW_LIMIT
        if truncated:
            logger.warning(
                "Detection series query hit the %d-row limit; oldest buckets may be missing. "
                "Use a shorter lookback or bucket='day'.",
                DETECTION_SERIES_ROW_LIMIT,
            )
        series, total = parse_detection_series_rows(rows, bucket, ids or None)
        return RuleDetectionSeriesResult(
            series=series,
            bucket=bucket,
            lookback_hours=lookback_hours,
            total_detections=total,
            query=query,
            raw_row_count=len(rows),
            provenance={
                "api": "dashboardQueries:execute",
                "time_window": getattr(res, "time_window", {}),
                "truncated": truncated,
                "rule_filter": ids or None,
            },
        )


class AuditUdmFieldPopulationWorkflow:
    """Audits live UDM field population for detection rule telemetry."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        self.adapter = adapter

    def _build_field_population_query(
        self,
        path: str,
        vendor_product: Optional[str] = None,
        is_array: bool = False,
    ) -> str:
        # Dashboard (YL2 statement) syntax: predicates are top-level statements.
        # An ``events:`` section after ``match:`` is rejected by the compiler
        # ("mismatched input 'events' expecting <EOF>", verified live 2026-10-10).
        filter_clause = f"$e.{path} = /.+/" if is_array else f'$e.{path} != ""'
        vendor_filter = f'\n$e.metadata.product_name = "{vendor_product}"' if vendor_product else ""
        return f"""$field_val = $e.{path}
{filter_clause}{vendor_filter}
match:
    $field_val
outcome:
    $count = count_distinct($e.metadata.id)
limit:
    10"""

    def execute(
        self,
        field_paths: List[str],
        vendor_product: Optional[str] = None,
        lookback_days: int = 30,
        schema_cache: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Checks whether given UDM fields contain values in live events over lookback_days.

        Args:
            field_paths: List of UDM field paths (e.g. ['principal.process.file.full_path']).
            vendor_product: Optional vendor/product scope to avoid cross-product false negatives.
            lookback_days: Number of days to audit.
            schema_cache: Optional dictionary or Firestore client for self-healing schema types.

        Returns:
            Dictionary mapping field_path to audit result:
            {
               "principal.process.file.full_path": {
                   "populated": True,
                   "count": 1420,
                   "is_array": False,
                   "error": None
               }
            }
        """
        audit_results: Dict[str, Dict[str, Any]] = {}
        for path in field_paths:
            is_array = False
            if schema_cache and hasattr(schema_cache, "get_udm_field_schema"):
                cached = schema_cache.get_udm_field_schema(path)
                if cached:
                    is_array = cached.get("is_array", False)

            query_text = self._build_field_population_query(
                path=path,
                vendor_product=vendor_product,
                is_array=is_array,
            )

            try:
                res = self.adapter.execute_dashboard_query(
                    query_text=query_text,
                    time_unit="DAY",
                    time_value=str(lookback_days),
                    dialect="YL2",
                )
                rows = getattr(res, "rows", [])
                total_events = 0
                for r in rows:
                    cnt = r.get("count") or r.get("$count") or 0
                    try:
                        total_events += int(cnt)
                    except (ValueError, TypeError):
                        pass

                audit_results[path] = {
                    "populated": total_events > 0,
                    "count": total_events,
                    "is_array": is_array,
                    "error": None,
                }
            except Exception as query_err:
                err_msg = str(query_err)
                logger.info("Field check error for %s: %s", path, err_msg)
                
                # Self-healing: if error indicates array or repeated field, update cache and retry with array syntax
                if "array" in err_msg.lower() or "repeated" in err_msg.lower():
                    if schema_cache and hasattr(schema_cache, "save_udm_field_schema"):
                        schema_cache.save_udm_field_schema(path, {
                            "field_path": path,
                            "is_array": True,
                            "discovered_at": datetime.now(timezone.utc).isoformat(),
                        })
                    retry_query = self._build_field_population_query(
                        path=path, vendor_product=vendor_product, is_array=True
                    )
                    try:
                        retry_res = self.adapter.execute_dashboard_query(
                            query_text=retry_query,
                            time_unit="DAY",
                            time_value=str(lookback_days),
                            dialect="YL2",
                        )
                        retry_rows = getattr(retry_res, "rows", [])
                        total_events = len(retry_rows)
                        audit_results[path] = {
                            "populated": total_events > 0,
                            "count": total_events,
                            "is_array": True,
                            "error": None,
                        }
                        continue
                    except Exception as retry_err:
                        audit_results[path] = {
                            "populated": False,
                            "count": 0,
                            "is_array": True,
                            "error": str(retry_err),
                        }
                        continue

                audit_results[path] = {
                    "populated": False,
                    "count": 0,
                    "is_array": is_array,
                    "error": err_msg,
                }

        return audit_results

def _get(obj: Any, *keys: str) -> Any:
    """First non-empty value of ``keys`` on a dict or attribute-bearing object."""
    for key in keys:
        val = obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)
        if val:
            return val
    return None


def _rule_id_of(obj: Any) -> str:
    rid = _get(obj, "rule_id", "id")
    if rid:
        return str(rid)
    name = _get(obj, "name") or ""
    return str(name).split("/")[-1].split("@")[0] if name else ""


def _deployment_rule_id(name: str) -> str:
    parts = (name or "").split("/")
    if len(parts) >= 2 and parts[-1] == "deployment":
        return parts[-2]
    return parts[-1] if parts else ""


def parse_verify_response(resp: Any) -> Tuple[bool, List[str]]:
    """Interprets a raw ``verifyRuleText`` response dict.

    Returns ``(success, error_messages)``; diagnostics are only reported as
    errors when compilation did not succeed (warnings on a successful compile
    are not breakage).

    Raises:
        ValueError: when the response is not a dict (unexpected schema).
    """
    if not isinstance(resp, dict):
        raise ValueError(f"Unexpected verifyRuleText response type: {type(resp).__name__}")
    success = bool(resp.get("success", False))
    diags = resp.get("compilationDiagnostics") or []
    messages = [str(d.get("message") or d) if isinstance(d, dict) else str(d) for d in diags]
    if success:
        return True, []
    return False, messages or ["verifyRuleText returned success=false without diagnostics"]


class AuditRuleDecayWorkflow:
    """Orchestrates comprehensive tenant-wide or single-rule decay auditing.

    Read-only against the tenant when ``schema_cache`` is None (a supplied
    ``schema_cache`` may persist discovered array-field types via
    ``save_udm_field_schema``).
    """

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        rule_id: Optional[str] = None,
        lookback_days: int = 90,
        check_population: bool = True,
        schema_cache: Optional[Any] = None,
        max_workers: int = 4,
    ) -> RuleDecayReport:
        """Executes the decay audit correlating inventory, detection telemetry and live checks.

        * Rules and deployments are read across all pages; a failure to read
          them raises (an empty inventory must not look like "nothing decayed").
        * A failed detection-count query is recorded in ``telemetry_errors``
          with ``telemetry_available=False``; rules are then flagged
          ``TELEMETRY_UNAVAILABLE`` and never ``SILENT``.
        * Each non-archived rule's ``text`` is compiled with ``verifyRuleText``.
          An API failure of that call is recorded per rule in
          ``compile_check_error`` and in ``check_errors``; it is not treated as
          broken compilation.
        * With ``check_population`` the first 10 UDM fields of each rule are
          checked (deduplicated across rules). Fields whose check query failed
          go to ``population_check_errors``, not ``unpopulated_fields``.

        Args:
            max_workers: Concurrent per-rule compile/population checks. Default 4:
                with 8 workers ``verifyRuleText`` returned 429 (quota) for 8 of 200
                rules live. Population checks cost ~6-16 s per distinct UDM field.
        """
        started = datetime.now(timezone.utc)
        telemetry_errors: List[str] = []
        check_errors: List[str] = []
        telemetry_available = True
        try:
            telemetry_map = QueryRuleDetectionCountsWorkflow(self.adapter).execute(lookback_days=lookback_days)
        except Exception as exc:
            telemetry_available = False
            telemetry_map = {}
            msg = f"Detection count query ({lookback_days}d) failed: {type(exc).__name__}: {exc}"
            logger.warning(msg)
            telemetry_errors.append(msg)

        deployment_map: Dict[str, Any] = {}
        target_rules: List[Any] = []
        if rule_id:
            clean_id = rule_id.split("/")[-1].split("@")[0]
            deployment_map[clean_id] = self.adapter.get_rule_deployment(rule_id)
            target_rules.append(self.adapter.get_rule(rule_id, view="FULL"))
        else:
            def fetch_deps(tok: Optional[str]):
                resp = self.adapter.list_rule_deployments(page_size=1000, page_token=tok)
                return list(resp.get("ruleDeployments", []) or []), resp.get("nextPageToken")

            raw_deps, _, _ = collect_pages(fetch_deps)
            for d in raw_deps:
                d_id = _deployment_rule_id(_get(d, "name") or "")
                if d_id:
                    deployment_map[d_id] = d

            def fetch_rules(tok: Optional[str]):
                resp = self.adapter.list_rules(page_size=1000, page_token=tok, view="FULL")
                return list(resp.get("rules", []) or []), resp.get("nextPageToken")

            target_rules, _, _ = collect_pages(fetch_rules)

        # Archived rules are out of scope.
        active: List[Tuple[Any, str, Any]] = []
        for r in target_rules:
            curr_id = _rule_id_of(r)
            dep = deployment_map.get(curr_id)
            if bool(_get(dep, "archived")) if dep is not None else False:
                continue
            if bool(_get(r, "archived")):
                continue
            active.append((r, curr_id, dep))

        pop_cache: Dict[str, Dict[str, Any]] = {}

        def check(entry: Tuple[Any, str, Any]) -> Dict[str, Any]:
            r, curr_id, _ = entry
            out: Dict[str, Any] = {
                "compile_checked": False,
                "syntax_verified": True,
                "compiler_errors": [],
                "compile_check_error": None,
                "unpopulated": [],
                "population_check_errors": {},
                "population_checked": False,
            }
            text = _get(r, "text", "rule_text") or ""
            if not text:
                out["compile_check_error"] = "Rule text not returned by the API (view=FULL expected)"
                return out
            try:
                success, errs = parse_verify_response(self.adapter.verify_rule_text(rule_text=text))
                out["compile_checked"] = True
                out["syntax_verified"] = success
                out["compiler_errors"] = errs
            except Exception as exc:
                out["compile_check_error"] = f"verifyRuleText failed: {type(exc).__name__}: {exc}"
            if check_population:
                fields = extract_udm_fields_from_yaral(text)[:10]
                todo = [f for f in fields if f not in pop_cache]
                if todo:
                    results = AuditUdmFieldPopulationWorkflow(self.adapter).execute(
                        field_paths=todo, lookback_days=30, schema_cache=schema_cache
                    )
                    pop_cache.update(results)
                for f in fields:
                    info = pop_cache.get(f) or {}
                    if info.get("error"):
                        out["population_check_errors"][f] = str(info["error"])
                    elif not info.get("populated", False):
                        out["unpopulated"].append(f)
                out["population_checked"] = bool(fields)
            return out

        if max_workers and max_workers > 1 and len(active) > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                checks = list(pool.map(check, active))
        else:
            checks = [check(e) for e in active]

        assessments: List[RuleDecayAssessment] = []
        broken_count = silent_count = stale_count = unpopulated_count = 0
        compile_checked = population_checked = 0

        for (r, curr_id, dep), chk in zip(active, checks):
            # Only `enabled` means deployed. runFrequency is always present and
            # "ACTIVE" is not an ExecutionState value (DEFAULT/LIMITED/PAUSED).
            if dep is not None:
                is_live = bool(_get(dep, "enabled"))
            else:
                is_live = bool(_get(r, "live_mode_enabled"))
            curr_name = _get(r, "displayName", "display_name", "rule_name") or _get(r, "name") or curr_id

            if chk["compile_checked"]:
                compile_checked += 1
            if chk["compile_check_error"]:
                check_errors.append(f"{curr_id}: {chk['compile_check_error']}")
            if chk["population_checked"]:
                population_checked += 1
            for f_path, err in chk["population_check_errors"].items():
                check_errors.append(f"{curr_id}: population check {f_path}: {err}")

            rule_telemetry = telemetry_map.get(curr_id)
            dps_score, flags, rec, days_stale = calculate_decay_score(
                rule_detail=r,
                detection_telemetry_90d=rule_telemetry,
                unpopulated_fields=chk["unpopulated"],
                syntax_verified=chk["syntax_verified"],
                compiler_diagnostics=chk["compiler_errors"],
                is_live=is_live,
                telemetry_available=telemetry_available,
            )

            if "BROKEN_COMPILATION" in flags:
                broken_count += 1
            if "SILENT" in flags:
                silent_count += 1
            if "STALE" in flags:
                stale_count += 1
            if "UNPOPULATED" in flags:
                unpopulated_count += 1

            assessments.append(
                RuleDecayAssessment(
                    rule_id=curr_id,
                    rule_name=str(curr_name),
                    dps_score=dps_score,
                    decay_flags=flags,
                    is_live=is_live,
                    days_stale=days_stale,
                    detection_count_90d=rule_telemetry.get("count", 0) if rule_telemetry else 0,
                    first_seen=rule_telemetry.get("first_seen") if rule_telemetry else None,
                    last_seen=rule_telemetry.get("last_seen") if rule_telemetry else None,
                    unpopulated_fields=chk["unpopulated"],
                    compiler_errors=chk["compiler_errors"] if not chk["syntax_verified"] else [],
                    recommendation=rec,
                    compile_checked=chk["compile_checked"],
                    compile_check_error=chk["compile_check_error"],
                    population_check_errors=chk["population_check_errors"],
                    raw={
                        "rule_id": curr_id,
                        "name": curr_name,
                        "dps_score": dps_score,
                        "flags": flags,
                    },
                )
            )

        assessments.sort(key=lambda x: x.dps_score, reverse=True)
        avg_dps = sum(a.dps_score for a in assessments) / len(assessments) if assessments else 0.0

        return RuleDecayReport(
            assessments=assessments,
            total_audited=len(assessments),
            broken_compilation_count=broken_count,
            silent_count=silent_count,
            stale_count=stale_count,
            unpopulated_count=unpopulated_count,
            average_dps=round(avg_dps, 2),
            lookback_days=lookback_days,
            telemetry_available=telemetry_available,
            telemetry_errors=telemetry_errors,
            compile_checked_count=compile_checked,
            population_checked_count=population_checked,
            check_errors=check_errors,
            duration_s=round((datetime.now(timezone.utc) - started).total_seconds(), 2),
        )
