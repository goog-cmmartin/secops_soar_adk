"""Chronicle SIEM Custom YARA-L Detection Rules workflows.

Orchestrates listing, retrieving, validating, creating, updating, deleting,
versioning, deployment management, and error tracking for detection rules.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    RuleCompilationDiagnostic,
    RuleDeployment,
    RuleDeploymentListResult,
    RuleDetail,
    RuleExecutionError,
    RuleExecutionErrorListResult,
    RuleListResult,
    RuleRevisionListResult,
    RuleSummary,
    RuleValidationResult,
)
from engine.pagination import DEFAULT_MAX_PAGES, collect_pages

# Value used when the API omits a field we would otherwise have to guess.
# Absent compilationState / runFrequency / severity used to default to
# SUCCEEDED / LIVE / INFO, which made a missing value look healthy.
UNKNOWN = "UNKNOWN"

# Revision suffix on rule resource names: ``.../rules/ru_x@v_<seconds>_<nanos>``.
_REVISION_RE = re.compile(r"@(v_(\d+)_(\d+))$")


def parse_rule_revision(name: str) -> Tuple[str, str]:
    """Returns ``(revision_id, revision_create_time)`` derived from a rule resource name.

    ``rules.listRevisions`` returns the revision only in ``name``
    (``...@v_1700000000_123456000``). The ``v_<seconds>_<nanos>`` pair is the
    revision creation timestamp; it is rendered as RFC3339 UTC with
    microsecond precision. Returns ``("", "")`` when the name has no suffix.
    """
    m = _REVISION_RE.search(name or "")
    if not m:
        return "", ""
    rev_id, secs, nanos = m.group(1), int(m.group(2)), int(m.group(3))
    ts = datetime.fromtimestamp(secs, tz=timezone.utc).replace(microsecond=min(999999, nanos // 1000))
    return rev_id, ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def normalize_severity(raw_severity: Any) -> str:
    """Upper-cases the rule ``severity.displayName`` (``Low``/``low``/``LOW`` -> ``LOW``).

    Returns ``UNKNOWN`` when the rule declares no severity: the API does not
    supply a default, so none is invented here.
    """
    if isinstance(raw_severity, dict):
        value = raw_severity.get("displayName") or ""
    elif raw_severity is None:
        value = ""
    else:
        value = str(raw_severity)
    value = value.strip().upper()
    return value or UNKNOWN


def _map_rule_summary(raw: Dict[str, Any]) -> RuleSummary:
    """Maps raw rule summary JSON into RuleSummary dataclass."""
    rev_id, _ = parse_rule_revision(raw.get("name", ""))
    return RuleSummary(
        name=raw.get("name", ""),
        display_name=raw.get("displayName", ""),
        author=raw.get("author", ""),
        severity=normalize_severity(raw.get("severity")),
        rule_type=raw.get("type", "SINGLE_EVENT"),
        allowed_run_frequencies=raw.get("allowedRunFrequencies", []),
        near_real_time_live_rule_eligible=bool(raw.get("nearRealTimeLiveRuleEligible", False)),
        etag=raw.get("etag", ""),
        rule_text_tags=raw.get("ruleTextTags", []),
        time_window_duration=raw.get("timeWindowDuration", ""),
        create_time=raw.get("createTime", ""),
        revision_id=raw.get("revisionId", "") or rev_id,
        # The rule resource does not carry runFrequency (it lives on the
        # deployment); "" means "not on this resource", see list_rule_deployments.
        run_frequency=raw.get("runFrequency", ""),
        raw=raw,
    )


def _map_rule_detail(raw: Dict[str, Any]) -> RuleDetail:
    """Maps raw rule detail JSON into RuleDetail dataclass.

    ``compilation_state`` and ``run_frequency`` are ``UNKNOWN`` when the API
    omits them (e.g. BASIC view, or revisions), never an assumed healthy value.
    """
    rev_id, rev_time = parse_rule_revision(raw.get("name", ""))
    return RuleDetail(
        name=raw.get("name", ""),
        display_name=raw.get("displayName", ""),
        text=raw.get("text", ""),
        revision_id=raw.get("revisionId", "") or rev_id,
        author=raw.get("author", ""),
        severity=normalize_severity(raw.get("severity")),
        metadata=raw.get("metadata", {}),
        create_time=raw.get("createTime", ""),
        revision_create_time=raw.get("revisionCreateTime", "") or rev_time,
        compilation_state=raw.get("compilationState") or UNKNOWN,
        rule_type=raw.get("type", "SINGLE_EVENT"),
        allowed_run_frequencies=raw.get("allowedRunFrequencies", []),
        etag=raw.get("etag", ""),
        near_real_time_live_rule_eligible=bool(raw.get("nearRealTimeLiveRuleEligible", False)),
        inputs_used=raw.get("inputsUsed", {}),
        rule_owner=raw.get("ruleOwner", "CUSTOMER"),
        run_frequency=raw.get("runFrequency") or UNKNOWN,
        rule_language=raw.get("ruleLanguage", "YARA_L_2_0"),
        raw=raw,
    )


def _map_diagnostic(raw: Dict[str, Any]) -> RuleCompilationDiagnostic:
    """Maps raw compilation diagnostic into RuleCompilationDiagnostic."""
    pos = raw.get("position", {})
    return RuleCompilationDiagnostic(
        message=raw.get("message", ""),
        severity=raw.get("severity", "ERROR"),
        start_line=pos.get("startLine"),
        start_column=pos.get("startColumn"),
        end_line=pos.get("endLine"),
        end_column=pos.get("endColumn"),
        raw=raw,
    )


def _map_rule_deployment(raw: Dict[str, Any]) -> RuleDeployment:
    """Maps raw rule deployment JSON into RuleDeployment dataclass.

    Proto3 omits false booleans, so a missing ``enabled``/``alerting`` is
    False. A missing ``runFrequency`` is ``UNKNOWN`` (not LIVE).
    """
    enabled = (
        bool(raw["enabled"])
        if "enabled" in raw
        else bool(raw.get("executionState") == "ACTIVE")
    )
    return RuleDeployment(
        name=raw.get("name", ""),
        run_frequency=raw.get("runFrequency") or UNKNOWN,
        execution_state=raw.get("executionState", "DEFAULT"),
        enabled=enabled,
        alerting=bool(raw.get("alerting", False)),
        archived=bool(raw.get("archived", False)),
        archive_time=raw.get("archiveTime", ""),
        last_alert_status_change_time=raw.get("lastAlertStatusChangeTime", ""),
        display_name=raw.get("displayName", ""),
        raw=raw,
    )


def _map_execution_error(raw: Dict[str, Any]) -> RuleExecutionError:
    """Maps raw rule execution error JSON into RuleExecutionError dataclass."""
    err_obj = raw.get("error", {})
    err_code = err_obj.get("code", 0) if isinstance(err_obj, dict) else 0
    err_msg = err_obj.get("message", "") if isinstance(err_obj, dict) else str(err_obj)

    time_range = raw.get("timeRange", {})
    return RuleExecutionError(
        name=raw.get("name", ""),
        error_code=err_code,
        error_message=err_msg,
        start_time=time_range.get("startTime", ""),
        end_time=time_range.get("endTime", ""),
        rule_resource_name=raw.get("rule", ""),
        curated_rule=raw.get("curatedRule", ""),
        raw=raw,
    )


def _page_items(resp: Any, key: str) -> List[Dict[str, Any]]:
    items = resp.get(key, []) if hasattr(resp, "get") else []
    return [i for i in (items or []) if isinstance(i, dict)]


def _next_token(resp: Any) -> Any:
    return resp.get("nextPageToken") if hasattr(resp, "get") else None


def _walk(
    fetch: Any,
    key: str,
    page_token: Optional[str],
    all_pages: bool,
    max_results: Optional[int],
    max_pages: int = DEFAULT_MAX_PAGES,
) -> Tuple[List[Dict[str, Any]], Optional[str], int]:
    """Single page (legacy behaviour) unless ``all_pages`` or ``max_results`` is set."""
    if not all_pages and max_results is None:
        resp = fetch(page_token)
        return _page_items(resp, key), _next_token(resp), 1

    def fetch_page(tok: Optional[str]):
        resp = fetch(tok)
        return _page_items(resp, key), _next_token(resp)

    return collect_pages(fetch_page, page_token=page_token, max_results=max_results, max_pages=max_pages)


class ListRulesWorkflow:
    """Workflow to list detection rules in Chronicle SIEM."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
        view: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> RuleListResult:
        """Lists rules. One page by default; ``all_pages=True`` follows ``nextPageToken``
        to the end (``next_page_token`` is then None unless the safety page cap or
        ``max_results`` stopped the walk early)."""
        raw_rules, next_token, pages = _walk(
            lambda tok: self._adapter.list_rules(
                page_size=page_size,
                page_token=tok,
                filter_expr=filter_expr,
                view=view,
            ),
            "rules",
            page_token,
            all_pages,
            max_results,
        )
        rules = [_map_rule_summary(r) for r in raw_rules]
        return RuleListResult(
            rules=rules,
            next_page_token=next_token,
            provenance={"count": len(rules), "filter": filter_expr, "view": view, "pages": pages},
        )


class GetRuleWorkflow:
    """Workflow to fetch full details and YARA-L logic of a detection rule."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(self, rule_id_or_name: str, view: str = "FULL") -> RuleDetail:
        resp = self._adapter.get_rule(rule_id_or_name=rule_id_or_name, view=view)
        return _map_rule_detail(resp)


class VerifyRuleWorkflow:
    """Workflow to compile/verify YARA-L rule text against Chronicle compiler."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(self, rule_text: str) -> RuleValidationResult:
        resp = self._adapter.verify_rule_text(rule_text=rule_text)
        success = bool(resp.get("success", False))
        diag_raw = resp.get("compilationDiagnostics", [])
        diagnostics = [_map_diagnostic(d) for d in diag_raw]
        return RuleValidationResult(
            success=success,
            diagnostics=diagnostics,
            raw=resp,
        )


class CreateRuleWorkflow:
    """Workflow to create a new YARA-L detection rule in Chronicle SIEM."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(self, rule_text: str) -> RuleDetail:
        resp = self._adapter.create_rule(rule_text=rule_text)
        return _map_rule_detail(resp)


class PatchRuleWorkflow:
    """Workflow to update an existing detection rule's YARA-L text."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(
        self,
        rule_id_or_name: str,
        rule_text: str,
        update_mask: Optional[str] = None,
    ) -> RuleDetail:
        resp = self._adapter.patch_rule(
            rule_id_or_name=rule_id_or_name,
            rule_text=rule_text,
            update_mask=update_mask,
        )
        return _map_rule_detail(resp)


class DeleteRuleWorkflow:
    """Workflow to delete a detection rule from Chronicle SIEM."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(self, rule_id_or_name: str) -> Dict[str, Any]:
        return self._adapter.delete_rule(rule_id_or_name=rule_id_or_name)


class ListRuleRevisionsWorkflow:
    """Workflow to list past revisions and version history of a rule."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(
        self,
        rule_id_or_name: str,
        page_size: int = 100,
        page_token: Optional[str] = None,
    ) -> RuleRevisionListResult:
        resp = self._adapter.list_rule_revisions(
            rule_id_or_name=rule_id_or_name,
            page_size=page_size,
            page_token=page_token,
        )
        raw_rules = resp.get("rules", [])
        revisions = [_map_rule_detail(r) for r in raw_rules]
        return RuleRevisionListResult(
            rule_id=rule_id_or_name.split("/")[-1].split("@")[0],
            revisions=revisions,
            next_page_token=resp.get("nextPageToken"),
            provenance={"count": len(revisions)},
        )


class ListRuleDeploymentsWorkflow:
    """Workflow to list deployments across all detection rules in Chronicle SIEM."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> RuleDeploymentListResult:
        """Lists rule deployments. Note the list response omits ``displayName``;
        join to ``list_rules`` on ``rule_id`` for names."""
        raw_deps, next_token, pages = _walk(
            lambda tok: self._adapter.list_rule_deployments(page_size=page_size, page_token=tok),
            "ruleDeployments",
            page_token,
            all_pages,
            max_results,
        )
        deployments = [_map_rule_deployment(d) for d in raw_deps]
        return RuleDeploymentListResult(
            deployments=deployments,
            next_page_token=next_token,
            provenance={"count": len(deployments), "pages": pages},
        )


class GetRuleDeploymentWorkflow:
    """Workflow to fetch deployment and frequency status of a rule."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(self, rule_id_or_name: str) -> RuleDeployment:
        resp = self._adapter.get_rule_deployment(rule_id_or_name=rule_id_or_name)
        return _map_rule_deployment(resp)


class UpdateRuleDeploymentWorkflow:
    """Workflow to update deployment properties (enabled, alerting, frequency)."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(
        self,
        rule_id_or_name: str,
        enabled: Optional[bool] = None,
        alerting: Optional[bool] = None,
        run_frequency: Optional[str] = None,
        update_mask: Optional[str] = None,
    ) -> RuleDeployment:
        resp = self._adapter.update_rule_deployment(
            rule_id_or_name=rule_id_or_name,
            enabled=enabled,
            alerting=alerting,
            run_frequency=run_frequency,
            update_mask=update_mask,
        )
        return _map_rule_deployment(resp)


def parse_rfc3339(value: Any) -> Optional[datetime]:
    """Parses an RFC3339 timestamp (nanosecond fractions allowed) to an aware UTC datetime.

    Accepts a ``datetime`` (naive values are taken as UTC). Returns None for
    empty or unparseable input.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", s)
    if m:
        frac = (m.group(2) or "")[:7]  # '.' + at most 6 digits
        s = f"{m.group(1)}{frac}{m.group(3)}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ListRuleErrorsWorkflow:
    """Workflow to list execution and runtime errors across rules."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self._adapter = adapter

    def execute(
        self,
        rule_id_or_name: Optional[str] = None,
        page_size: int = 100,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
        since: Optional[Any] = None,
    ) -> RuleExecutionErrorListResult:
        """Lists rule execution errors.

        ``ruleExecutionErrors`` has no time filter and returns the full history
        (observed: 2,713 errors back to Nov 2025). ``since`` (datetime or RFC3339
        string) keeps only errors whose ``timeRange.endTime`` is at or after it;
        because order is not guaranteed it implies ``all_pages=True``. Errors
        without a parseable ``endTime`` are kept and counted in
        ``provenance["undated"]``. ``max_results`` is applied after the window.
        """
        since_dt = parse_rfc3339(since) if since is not None else None
        if since is not None and since_dt is None:
            raise ValueError(f"since must be a datetime or RFC3339 timestamp, got {since!r}")
        walk_all = all_pages or since_dt is not None
        raw_errors, next_token, pages = _walk(
            lambda tok: self._adapter.list_rule_execution_errors(
                rule_id_or_name=rule_id_or_name,
                page_size=page_size,
                page_token=tok,
            ),
            "ruleExecutionErrors",
            page_token,
            walk_all,
            None if since_dt is not None else max_results,
        )
        errors = [_map_execution_error(e) for e in raw_errors]
        fetched = len(errors)
        undated = 0
        if since_dt is not None:
            kept = []
            for err in errors:
                end_dt = parse_rfc3339(err.end_time)
                if end_dt is None:
                    undated += 1
                    kept.append(err)
                elif end_dt >= since_dt:
                    kept.append(err)
            errors = kept
            if max_results is not None:
                errors = errors[:max_results]
        return RuleExecutionErrorListResult(
            errors=errors,
            next_page_token=next_token,
            provenance={
                "count": len(errors),
                "fetched": fetched,
                "pages": pages,
                "rule_filter": rule_id_or_name,
                "since": since_dt.isoformat() if since_dt else None,
                "undated": undated,
            },
        )
