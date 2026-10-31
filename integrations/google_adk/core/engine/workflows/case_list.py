"""Native Case Listing Workflow (`case.list`).

Lists cases from the native ``.../instances/{customer}/cases`` collection with an
exact server-side filter (open/closed status, environment, priority, stage,
assignee, importance, incident) and no time window. Complements ``case.search``
(legacy ``legacyCaseSearchEverything``), which has no status filter and is
bounded by a time range, so long-lived open cases fall outside it.

Filter grammar and pagination behaviour were verified live; see
``discovery/observations/04_case_list_native_collection.md``.
"""

import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from engine.domain import (
    CaseListBatch,
    CaseListItem,
    CasePriority,
    CaseStatus,
)
from engine.parsing import (
    parse_priority as _parse_priority,
    parse_status as _parse_status,
    parse_timestamp as _parse_timestamp,
)

CASES_ENDPOINT = "instances/{customer}/cases"

# Server rejects pageSize > 1000 with HTTP 400 ("The limit of '1000' for Top
# query has been exceeded"). Omitting pageSize yields 50 per page.
MAX_PAGE_SIZE = 1000

# Status enum constants accepted by the server filter. Anything else returns
# HTTP 400 "not a valid enumeration type constant" (verified: OPEN, CLOSE,
# UNKNOWN, STATUS_UNSPECIFIED are all rejected).
_STATUS_VALUES = {
    "OPEN": "OPENED",
    "OPENED": "OPENED",
    "CLOSE": "CLOSED",
    "CLOSED": "CLOSED",
}

# Priority enum constants accepted by the server filter (each verified to
# return matching cases). Bare names (``CRITICAL``) are rejected by the server,
# so they are normalized to the ``PRIORITY_`` form here.
_PRIORITY_VALUES = frozenset({
    "PRIORITY_CRITICAL",
    "PRIORITY_HIGH",
    "PRIORITY_MEDIUM",
    "PRIORITY_LOW",
    "PRIORITY_INFO",
})


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (str, CaseStatus, CasePriority)):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    raise ValueError(f"Expected a string or list of strings, got {type(value).__name__}")


def quote_filter_value(value: Any, field_name: str) -> str:
    """Returns ``value`` as a double-quoted filter literal.

    The server answered an escaped double quote (``\\"``) inside a literal with
    HTTP 500, so there is no verified escape sequence. Values containing ``"``
    or ``\\`` are rejected rather than sent in a form the server cannot parse.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} values must be strings, got {value!r}")
    clean = value.strip()
    if not clean:
        raise ValueError(f"{field_name} values must be non-empty strings")
    if '"' in clean or "\\" in clean:
        raise ValueError(
            f"{field_name} value {clean!r} contains a double quote or backslash; "
            "the cases filter has no verified escape sequence for these characters"
        )
    return f'"{clean}"'


def normalize_status(value: Union[str, CaseStatus]) -> str:
    """Maps ``OPEN``/``OPENED``/``CaseStatus.OPEN`` (and CLOSED forms) to the server enum."""
    raw = value.value if isinstance(value, CaseStatus) else str(value)
    key = raw.strip().upper()
    if key not in _STATUS_VALUES:
        raise ValueError(f"status must be one of OPENED or CLOSED, got {value!r}")
    return _STATUS_VALUES[key]


def normalize_priority(value: Union[str, CasePriority]) -> str:
    """Maps ``HIGH``/``PRIORITY_HIGH``/``CasePriority.HIGH`` to the server ``PRIORITY_*`` enum."""
    raw = value.value if isinstance(value, CasePriority) else str(value)
    key = raw.strip().upper()
    if not key.startswith("PRIORITY_"):
        key = f"PRIORITY_{key}"
    if key not in _PRIORITY_VALUES:
        raise ValueError(
            f"priority must be one of {sorted(_PRIORITY_VALUES)} (or the bare names), got {value!r}"
        )
    return key


def _any_of(field_name: str, literals: Sequence[str]) -> str:
    """Builds ``field=a`` or ``(field=a OR field=b)``; OR in parentheses verified live."""
    clauses = [f"{field_name}={lit}" for lit in literals]
    if len(clauses) == 1:
        return clauses[0]
    return "(" + " OR ".join(clauses) + ")"


def _dedupe(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    for v in values:
        if v not in out:
            out.append(v)
    return out


def build_case_filter(
    status: Optional[Union[str, CaseStatus]] = None,
    environments: Optional[Union[str, Sequence[str]]] = None,
    priorities: Optional[Union[str, CasePriority, Sequence[Union[str, CasePriority]]]] = None,
    stages: Optional[Union[str, Sequence[str]]] = None,
    assignees: Optional[Union[str, Sequence[str]]] = None,
    is_important: Optional[bool] = None,
    is_incident: Optional[bool] = None,
    raw_filter: Optional[str] = None,
) -> str:
    """Builds a server filter string for the native cases collection.

    Values within one facet are OR-ed inside parentheses; facets are AND-ed.
    ``raw_filter`` is passed through verbatim (wrapped in parentheses) and
    AND-ed with the typed facets. Raises ``ValueError`` on invalid input.
    """
    clauses: List[str] = []
    if raw_filter is not None and raw_filter.strip():
        clauses.append(f"({raw_filter.strip()})")
    if status is not None:
        clauses.append(f'status="{normalize_status(status)}"')
    envs = _dedupe(quote_filter_value(v, "environment") for v in _as_list(environments))
    if envs:
        clauses.append(_any_of("environment", envs))
    prios = _dedupe(f'"{normalize_priority(p)}"' for p in _as_list(priorities))
    if prios:
        clauses.append(_any_of("priority", prios))
    stage_lits = _dedupe(quote_filter_value(v, "stage") for v in _as_list(stages))
    if stage_lits:
        clauses.append(_any_of("stage", stage_lits))
    assignee_lits = _dedupe(quote_filter_value(v, "assignee") for v in _as_list(assignees))
    if assignee_lits:
        clauses.append(_any_of("assignee", assignee_lits))
    if is_important is not None:
        if not isinstance(is_important, bool):
            raise ValueError(f"is_important must be a bool, got {is_important!r}")
        clauses.append(f"important={'true' if is_important else 'false'}")
    if is_incident is not None:
        if not isinstance(is_incident, bool):
            raise ValueError(f"is_incident must be a bool, got {is_incident!r}")
        clauses.append(f"incident={'true' if is_incident else 'false'}")
    return " AND ".join(clauses)


def _to_int(value: Any, field_name: str) -> int:
    if value is None or value == "":
        return 0
    try:
        return int(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Unexpected non-integer {field_name} in cases payload: {value!r}") from e


def parse_case_list_item(raw: Dict[str, Any]) -> CaseListItem:
    """Maps one native ``cases`` item to :class:`CaseListItem`.

    Raises ``ValueError`` when the item lacks a resource ``name`` (unexpected
    schema stays visible instead of producing a blank case).
    """
    if not isinstance(raw, dict):
        raise ValueError(f"Unexpected case item type in cases payload: {type(raw).__name__}")
    name = str(raw.get("name") or "")
    if not name:
        raise ValueError(f"Case item is missing 'name': keys={sorted(raw.keys())}")
    raw_status = str(raw.get("status") or "")
    return CaseListItem(
        case_id=name.rsplit("/", 1)[-1],
        name=name,
        display_name=str(raw.get("displayName") or ""),
        create_time=_parse_timestamp(raw.get("createTime")),
        update_time=_parse_timestamp(raw.get("updateTime")),
        priority=_parse_priority(raw.get("priority")),
        raw_priority=str(raw.get("priority") or ""),
        status=_parse_status(raw_status),
        raw_status=raw_status,
        stage=str(raw.get("stage") or ""),
        environment=str(raw.get("environment") or ""),
        assignee=raw.get("assignee") or None,
        alert_count=_to_int(raw.get("alertCount"), "alertCount"),
        is_important=bool(raw.get("important", False)),
        is_incident=bool(raw.get("incident", False)),
        description=str(raw.get("description") or ""),
        case_type=str(raw.get("type") or ""),
        workflow_status=str(raw.get("workflowStatus") or ""),
        source=str(raw.get("source") or ""),
        last_modifying_user_id=raw.get("lastModifyingUserId") or None,
        involved_suspicious_entity=bool(raw.get("involvedSuspiciousEntity", False)),
        raw=raw,
    )


class ListCasesWorkflow:
    """Lists cases from the native cases collection with exact filtering and bounded pagination."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        status: Optional[Union[str, CaseStatus]] = None,
        environments: Optional[Union[str, Sequence[str]]] = None,
        priorities: Optional[Union[str, CasePriority, Sequence[Union[str, CasePriority]]]] = None,
        stages: Optional[Union[str, Sequence[str]]] = None,
        assignees: Optional[Union[str, Sequence[str]]] = None,
        is_important: Optional[bool] = None,
        is_incident: Optional[bool] = None,
        raw_filter: Optional[str] = None,
        order_by: Optional[str] = "createTime desc",
        max_results: int = 1000,
        page_size: int = MAX_PAGE_SIZE,
    ) -> CaseListBatch:
        """Builds the filter, follows ``nextPageToken`` up to ``max_results``, returns a typed batch.

        API errors (invalid filter, bad orderBy field, auth) propagate as raised
        by the adapter.
        """
        if not isinstance(max_results, int) or isinstance(max_results, bool) or max_results < 1:
            raise ValueError(f"max_results must be a positive integer, got {max_results!r}")
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= MAX_PAGE_SIZE:
            raise ValueError(f"page_size must be an integer in [1, {MAX_PAGE_SIZE}], got {page_size!r}")

        filter_str = build_case_filter(
            status=status,
            environments=environments,
            priorities=priorities,
            stages=stages,
            assignees=assignees,
            is_important=is_important,
            is_incident=is_incident,
            raw_filter=raw_filter,
        )

        started = time.monotonic()
        cases: List[CaseListItem] = []
        token: Optional[str] = None
        seen_tokens = set()
        pages = 0
        total_size = 0
        page_sizes: List[int] = []

        while len(cases) < max_results:
            # The server honours a different pageSize on follow-up pages (verified),
            # so request only what is still needed and never discard a partial page:
            # the returned nextPageToken then resumes exactly after the last case kept.
            request_size = min(page_size, max_results - len(cases))
            res = self.adapter.list_cases(
                filter=filter_str,
                page_size=request_size,
                page_token=token,
                order_by=order_by,
            )
            pages += 1
            raw_items = res.get("cases", [])
            if not isinstance(raw_items, list):
                raise ValueError(f"Unexpected 'cases' type in cases payload: {type(raw_items).__name__}")
            # Zero matches return an empty body (no 'cases'/'totalSize' keys).
            if "totalSize" in res:
                total_size = _to_int(res.get("totalSize"), "totalSize")
            page_sizes.append(len(raw_items))
            cases.extend(parse_case_list_item(r) for r in raw_items)

            token = res.get("nextPageToken") or None
            if not token:
                break
            if token in seen_tokens:
                raise RuntimeError("Cases pagination returned a repeated nextPageToken; aborting to avoid an infinite loop.")
            seen_tokens.add(token)
            if not raw_items:
                raise RuntimeError("Cases pagination returned an empty page with a nextPageToken.")

        provenance: Dict[str, Any] = {
            "endpoint": CASES_ENDPOINT,
            "method": "GET",
            "filter": filter_str,
            "order_by": order_by,
            "page_size": page_size,
            "max_results": max_results,
            "pages_fetched": pages,
            "page_item_counts": page_sizes,
            "total_size": total_size,
            "returned_count": len(cases),
            "truncated": bool(token),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
        return CaseListBatch(
            cases=cases,
            total_count=total_size,
            next_page_token=token,
            provenance=provenance,
        )
