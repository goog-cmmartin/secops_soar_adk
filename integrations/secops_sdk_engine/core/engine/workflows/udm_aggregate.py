"""Bounded UDM aggregation (``aggregate_udm``) over the synchronous dashboard SQL endpoint.

Builds a GoogleSQL pipe query (``dashboardQueries:execute``, dialect ``SQL``)
from validated, allow-listed inputs only:

    FROM events
    |> WHERE <translated filter>                      (optional)
    |> LEFT JOIN UNNEST(<repeated field>) AS _u0      (repeated group_by only)
    |> AGGREGATE COUNT(1) AS agg_count GROUP BY <dims>, <bucket>
    |> ORDER BY ...
    |> LIMIT <limit + 1>

Why the dashboard SQL path (verified live 2026-10-10): it is one synchronous
call (no LRO polling or cancellation), it was the fastest option measured
(4.1 s for log_type x hour over 24 h vs 3.5-6 s for the search view and
8.2 s for YL2), it returns exact-case values, and it has no streamed-chunk
duplication. Fallback (not implemented): the search view
(``legacyFetchUdmSearchView`` with ``userSql``) returns the same grid as
``stats.results`` but needs LRO polling and index paging.

Filter grammar (UDM-search style, translated to SQL; nothing else is accepted):

    expr       := or_expr
    or_expr    := and_expr ( "OR" and_expr )*
    and_expr   := unary ( "AND" unary )*
    unary      := "NOT" unary | "(" expr ")" | comparison
    comparison := FIELD OP STRING
    FIELD      := an allow-listed UDM field path (see UDM_AGGREGATE_FIELDS)
    OP         := "=" | "!=" | "<" | "<=" | ">" | ">="
    STRING     := double-quoted, escapes \\" and \\\\ only, printable characters,
                  at most 512 characters

Keywords are case-insensitive. Enum and repeated fields accept only ``=`` and
``!=``; enum values must look like enum names (``[A-Z0-9_]+``). Implicit AND,
regex (``/.../``), ``nocase``, functions, placeholders, numbers and any other
character raise ``UdmFilterError``. The output SQL is assembled from SDK
constants plus string literals escaped for GoogleSQL, so a caller cannot add
pipe stages, comments or statements.

Semantics notes:
- ``!=`` on scalar fields also matches events where the field is NULL
  (``(f IS NULL OR f != v)``), mirroring UDM search where absent == "".
- Repeated fields (``principal.ip``, ``target.ip``) match if ANY element
  matches (``v IN UNNEST(f)``); ``!=`` means no element equals the value.
- Grouping by a repeated field counts per value: an event with N values adds
  1 to each of N rows, and events with an empty array land in the NULL row.
- ``security_result.action`` is repeated inside repeated ``security_result``;
  it is unnested twice and follows the same per-value semantics.
- Time buckets are UTC (``TIMESTAMP_TRUNC(..., HOUR|DAY, 'UTC')``). Without the
  'UTC' argument DAY buckets started at 07:00Z (tenant time zone), observed live.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from engine.domain import UdmAggregateResult, UdmAggregateRow

MAX_LOOKBACK_HOURS = 168
MAX_LIMIT = 2000
MAX_GROUP_BY = 2
MAX_FILTER_COMPARISONS = 20
MAX_FILTER_DEPTH = 6
MAX_VALUE_LENGTH = 512
MAX_FILTER_LENGTH = 4000

TIME_BUCKETS = {"hour": "HOUR", "day": "DAY"}
METRICS = ("count", "count_distinct")

COUNT_COLUMN = "agg_count"
BUCKET_COLUMN = "bucket"


class UdmFilterError(ValueError):
    """The filter string uses syntax or fields outside the supported grammar."""


@dataclass(frozen=True)
class UdmAggregateField:
    """An allow-listed UDM field and how it maps to dashboard SQL.

    kind: ``scalar`` | ``repeated`` (ARRAY<STRING>) | ``nested_repeated``
    (``parent`` is a repeated message, ``leaf`` a repeated scalar inside it).
    """

    path: str
    kind: str = "scalar"
    enum: bool = False
    parent: Optional[str] = None
    leaf: Optional[str] = None


# Every entry verified live 2026-10-10 as a GROUP BY dimension and as a filter
# (see discovery/observations/07_search_read_observations.md).
UDM_AGGREGATE_FIELDS: Dict[str, UdmAggregateField] = {
    f.path: f
    for f in (
        UdmAggregateField("metadata.log_type"),
        UdmAggregateField("metadata.event_type", enum=True),
        UdmAggregateField("metadata.product_name"),
        UdmAggregateField("metadata.vendor_name"),
        UdmAggregateField("metadata.product_event_type"),
        UdmAggregateField("principal.hostname"),
        UdmAggregateField("principal.ip", kind="repeated"),
        UdmAggregateField("principal.user.userid"),
        UdmAggregateField("target.hostname"),
        UdmAggregateField("target.ip", kind="repeated"),
        UdmAggregateField("target.user.userid"),
        UdmAggregateField(
            "security_result.action", kind="nested_repeated", enum=True, parent="security_result", leaf="action"
        ),
        UdmAggregateField("network.application_protocol", enum=True),
        UdmAggregateField("network.ip_protocol", enum=True),
    )
}

_ENUM_VALUE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_FIELD_RE = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+")
_WORD_RE = re.compile(r"[A-Za-z0-9_]+")
_OPS = ("!=", "<=", ">=", "=", "<", ">")
_KEYWORDS = {"AND", "OR", "NOT"}


# ---------------------------------------------------------------------------
# Filter tokenizer / parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Tok:
    kind: str  # FIELD, OP, STRING, AND, OR, NOT, LPAREN, RPAREN
    value: str
    pos: int


def _tokenize(text: str) -> List[_Tok]:
    toks: List[_Tok] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in " \t":
            i += 1
            continue
        if ch in "\r\n":
            raise UdmFilterError(f"Line breaks are not supported in filters (position {i}).")
        if ch == "(":
            toks.append(_Tok("LPAREN", ch, i))
            i += 1
            continue
        if ch == ")":
            toks.append(_Tok("RPAREN", ch, i))
            i += 1
            continue
        if ch == '"':
            j = i + 1
            buf: List[str] = []
            closed = False
            while j < n:
                c = text[j]
                if c == "\\":
                    if j + 1 >= n:
                        break
                    nxt = text[j + 1]
                    if nxt not in ('"', "\\"):
                        raise UdmFilterError(
                            f"Unsupported escape '\\{nxt}' at position {j}; only \\\" and \\\\ are allowed."
                        )
                    buf.append(nxt)
                    j += 2
                    continue
                if c == '"':
                    closed = True
                    break
                if ord(c) < 32 or ord(c) == 127:
                    raise UdmFilterError(f"Control characters are not allowed in values (position {j}).")
                buf.append(c)
                j += 1
            if not closed:
                raise UdmFilterError(f"Unterminated string starting at position {i}.")
            value = "".join(buf)
            if len(value) > MAX_VALUE_LENGTH:
                raise UdmFilterError(f"Value at position {i} is longer than {MAX_VALUE_LENGTH} characters.")
            toks.append(_Tok("STRING", value, i))
            i = j + 1
            continue
        op = next((o for o in _OPS if text.startswith(o, i)), None)
        if op:
            toks.append(_Tok("OP", op, i))
            i += len(op)
            continue
        m = _FIELD_RE.match(text, i)
        if m:
            toks.append(_Tok("FIELD", m.group(0), i))
            i = m.end()
            continue
        m = _WORD_RE.match(text, i)
        if m and m.group(0).upper() in _KEYWORDS:
            toks.append(_Tok(m.group(0).upper(), m.group(0).upper(), i))
            i = m.end()
            continue
        if ch == "/":
            raise UdmFilterError(f"Regular expressions are not supported in filters (position {i}).")
        if m:
            raise UdmFilterError(
                f"Unsupported token '{m.group(0)}' at position {i}; expected a field path, AND, OR, NOT or parentheses."
            )
        raise UdmFilterError(f"Unsupported character {ch!r} at position {i}.")
    return toks


@dataclass
class _Cmp:
    field: UdmAggregateField
    op: str
    value: str


@dataclass
class _Bool:
    op: str  # AND / OR
    items: List[Any]


@dataclass
class _Not:
    item: Any


class _Parser:
    def __init__(self, toks: List[_Tok]):
        self.toks = toks
        self.i = 0
        self.comparisons = 0

    def _peek(self) -> Optional[_Tok]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _take(self, kind: str) -> _Tok:
        tok = self._peek()
        if tok is None or tok.kind != kind:
            where = f"'{tok.value}' at position {tok.pos}" if tok else "end of filter"
            raise UdmFilterError(f"Expected {kind} but found {where}.")
        self.i += 1
        return tok

    def parse(self) -> Any:
        node = self._or(0)
        tok = self._peek()
        if tok is not None:
            hint = " (use AND/OR between comparisons)" if tok.kind in ("FIELD", "LPAREN", "NOT") else ""
            raise UdmFilterError(f"Unexpected '{tok.value}' at position {tok.pos}{hint}.")
        return node

    def _or(self, depth: int) -> Any:
        items = [self._and(depth)]
        while (tok := self._peek()) is not None and tok.kind == "OR":
            self.i += 1
            items.append(self._and(depth))
        return items[0] if len(items) == 1 else _Bool("OR", items)

    def _and(self, depth: int) -> Any:
        items = [self._unary(depth)]
        while (tok := self._peek()) is not None and tok.kind == "AND":
            self.i += 1
            items.append(self._unary(depth))
        return items[0] if len(items) == 1 else _Bool("AND", items)

    def _unary(self, depth: int) -> Any:
        if depth > MAX_FILTER_DEPTH:
            raise UdmFilterError(f"Filter nesting deeper than {MAX_FILTER_DEPTH} levels.")
        tok = self._peek()
        if tok is None:
            raise UdmFilterError("Filter ends unexpectedly; expected a comparison.")
        if tok.kind == "NOT":
            self.i += 1
            return _Not(self._unary(depth + 1))
        if tok.kind == "LPAREN":
            self.i += 1
            node = self._or(depth + 1)
            self._take("RPAREN")
            return node
        return self._comparison()

    def _comparison(self) -> _Cmp:
        ftok = self._take("FIELD")
        spec = UDM_AGGREGATE_FIELDS.get(ftok.value)
        if spec is None:
            raise UdmFilterError(
                f"Field '{ftok.value}' is not allowed in filters. Allowed: {', '.join(sorted(UDM_AGGREGATE_FIELDS))}."
            )
        op = self._take("OP").value
        vtok = self._peek()
        if vtok is None or vtok.kind != "STRING":
            where = f"'{vtok.value}' at position {vtok.pos}" if vtok else "end of filter"
            raise UdmFilterError(f"Expected a double-quoted value after '{ftok.value} {op}', found {where}.")
        self.i += 1
        if (spec.enum or spec.kind != "scalar") and op not in ("=", "!="):
            raise UdmFilterError(f"Field '{spec.path}' supports only = and != (got {op}).")
        if spec.enum and not _ENUM_VALUE_RE.match(vtok.value):
            raise UdmFilterError(f"'{vtok.value}' is not a valid enum value for {spec.path} (expected e.g. NETWORK_CONNECTION).")
        self.comparisons += 1
        if self.comparisons > MAX_FILTER_COMPARISONS:
            raise UdmFilterError(f"Filter has more than {MAX_FILTER_COMPARISONS} comparisons.")
        return _Cmp(spec, op, vtok.value)


def sql_string_literal(value: str) -> str:
    """GoogleSQL single-quoted literal. Only printable characters reach here."""
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise UdmFilterError("Control characters are not allowed in values.")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _cmp_sql(node: _Cmp) -> str:
    f = node.field
    lit = sql_string_literal(node.value)
    if f.kind == "repeated":
        return f"{lit} IN UNNEST({f.path})" if node.op == "=" else f"{lit} NOT IN UNNEST({f.path})"
    if f.kind == "nested_repeated":
        exists = f"EXISTS(SELECT 1 FROM UNNEST({f.parent}) AS _fp, UNNEST(_fp.{f.leaf}) AS _fl WHERE _fl = {lit})"
        return exists if node.op == "=" else f"NOT {exists}"
    if node.op == "!=":
        return f"({f.path} IS NULL OR {f.path} != {lit})"
    return f"{f.path} {node.op} {lit}"


def _node_sql(node: Any) -> str:
    if isinstance(node, _Cmp):
        return _cmp_sql(node)
    if isinstance(node, _Not):
        return f"NOT ({_node_sql(node.item)})"
    if isinstance(node, _Bool):
        return "(" + f" {node.op} ".join(_node_sql(x) for x in node.items) + ")"
    raise UdmFilterError("Internal: unknown filter node.")


def translate_udm_filter(filter_text: str) -> str:
    """Translates a restricted UDM-search predicate into a GoogleSQL WHERE expression.

    Returns "" for an empty filter. Raises UdmFilterError for anything outside
    the grammar documented in this module.
    """
    text = (filter_text or "").strip()
    if not text:
        return ""
    if len(text) > MAX_FILTER_LENGTH:
        raise UdmFilterError(f"Filter is longer than {MAX_FILTER_LENGTH} characters.")
    toks = _tokenize(text)
    if not toks:
        return ""
    return _node_sql(_Parser(toks).parse())


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------


def _resolve_group_by(group_by: Optional[Sequence[str]]) -> List[UdmAggregateField]:
    if group_by is None:
        return []
    if isinstance(group_by, str):
        group_by = [group_by]
    fields = list(group_by)
    if len(fields) > MAX_GROUP_BY:
        raise ValueError(f"group_by accepts at most {MAX_GROUP_BY} fields (got {len(fields)}).")
    if len(set(fields)) != len(fields):
        raise ValueError("group_by fields must be distinct.")
    out = []
    for name in fields:
        spec = UDM_AGGREGATE_FIELDS.get(str(name))
        if spec is None:
            raise ValueError(
                f"group_by field '{name}' is not allowed. Allowed: {', '.join(sorted(UDM_AGGREGATE_FIELDS))}."
            )
        out.append(spec)
    return out


def build_aggregate_sql(
    filter: str = "",
    group_by: Optional[Sequence[str]] = ("metadata.log_type",),
    time_bucket: Optional[str] = None,
    limit: int = 500,
    metric: str = "count",
    distinct_field: Optional[str] = None,
) -> str:
    """Builds the dashboard SQL pipe query. Requests ``limit + 1`` rows."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > MAX_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {MAX_LIMIT} (got {limit!r}).")
    if time_bucket is not None and time_bucket not in TIME_BUCKETS:
        raise ValueError(f"time_bucket must be one of {sorted(TIME_BUCKETS)} or None (got {time_bucket!r}).")
    if metric not in METRICS:
        raise ValueError(f"metric must be one of {METRICS} (got {metric!r}).")
    dims = _resolve_group_by(group_by)

    if metric == "count_distinct":
        if not distinct_field:
            raise ValueError("metric='count_distinct' requires distinct_field.")
        dspec = UDM_AGGREGATE_FIELDS.get(distinct_field)
        if dspec is None:
            raise ValueError(
                f"distinct_field '{distinct_field}' is not allowed. Allowed: {', '.join(sorted(UDM_AGGREGATE_FIELDS))}."
            )
        if dspec.kind != "scalar":
            raise ValueError(f"distinct_field '{distinct_field}' is repeated; only scalar fields are supported.")
        agg_expr = f"COUNT(DISTINCT {dspec.path})"
    else:
        if distinct_field:
            raise ValueError("distinct_field is only valid with metric='count_distinct'.")
        agg_expr = "COUNT(1)"

    where = translate_udm_filter(filter)
    stages = ["FROM events"]
    if where:
        stages.append(f"|> WHERE {where}")

    group_exprs: List[str] = []
    for i, spec in enumerate(dims):
        if spec.kind == "scalar":
            group_exprs.append(f"{spec.path} AS d{i}")
        elif spec.kind == "repeated":
            stages.append(f"|> LEFT JOIN UNNEST({spec.path}) AS _u{i}")
            group_exprs.append(f"_u{i} AS d{i}")
        else:  # nested_repeated
            stages.append(f"|> LEFT JOIN UNNEST({spec.parent}) AS _p{i}")
            stages.append(f"|> LEFT JOIN UNNEST(_p{i}.{spec.leaf}) AS _u{i}")
            group_exprs.append(f"_u{i} AS d{i}")
    if time_bucket:
        group_exprs.append(
            f"TIMESTAMP_TRUNC(TIMESTAMP_SECONDS(metadata.event_timestamp.seconds), {TIME_BUCKETS[time_bucket]}, 'UTC') AS {BUCKET_COLUMN}"
        )

    agg = f"|> AGGREGATE {agg_expr} AS {COUNT_COLUMN}"
    if group_exprs:
        agg += " GROUP BY " + ", ".join(group_exprs)
    stages.append(agg)
    if time_bucket:
        stages.append(f"|> ORDER BY {BUCKET_COLUMN} DESC, {COUNT_COLUMN} DESC")
    elif group_exprs:
        stages.append(f"|> ORDER BY {COUNT_COLUMN} DESC")
    stages.append(f"|> LIMIT {limit + 1}")
    return "\n".join(stages)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_dt(value: Union[str, datetime], name: str) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"{name} is not an ISO-8601 timestamp: {value!r}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def resolve_aggregate_window(
    lookback_hours: int = 24,
    start_time: Optional[Union[str, datetime]] = None,
    end_time: Optional[Union[str, datetime]] = None,
    now: Optional[datetime] = None,
) -> Tuple[datetime, datetime]:
    """Resolves and bounds the time window (<= MAX_LOOKBACK_HOURS)."""
    now = now or datetime.now(timezone.utc)
    if start_time is None:
        if isinstance(lookback_hours, bool) or not isinstance(lookback_hours, (int, float)):
            raise ValueError(f"lookback_hours must be a number (got {lookback_hours!r}).")
        if lookback_hours <= 0 or lookback_hours > MAX_LOOKBACK_HOURS:
            raise ValueError(f"lookback_hours must be in (0, {MAX_LOOKBACK_HOURS}] (got {lookback_hours}).")
    end = _to_dt(end_time, "end_time") if end_time is not None else now
    start = _to_dt(start_time, "start_time") if start_time is not None else end - timedelta(hours=lookback_hours)
    if end <= start:
        raise ValueError("end_time must be after start_time.")
    if end - start > timedelta(hours=MAX_LOOKBACK_HOURS):
        raise ValueError(f"Time window exceeds {MAX_LOOKBACK_HOURS} hours.")
    return start, end


def _parse_bucket(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise RuntimeError(f"Unexpected bucket value from dashboard query: {value!r}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_aggregate_rows(
    rows: List[Dict[str, Any]],
    dimensions: Sequence[str],
    time_bucket: Optional[str],
    limit: int,
) -> Tuple[List[UdmAggregateRow], bool]:
    """Maps dashboard rows to UdmAggregateRow; returns (rows[:limit], truncated)."""
    out: List[UdmAggregateRow] = []
    for r in rows:
        if COUNT_COLUMN not in r:
            raise RuntimeError(f"Dashboard query result is missing column '{COUNT_COLUMN}': {sorted(r)}")
        raw_count = r.get(COUNT_COLUMN)
        try:
            count = int(raw_count) if raw_count is not None else 0
        except (TypeError, ValueError) as e:
            raise RuntimeError(f"Non-integer {COUNT_COLUMN} value {raw_count!r}") from e
        dims: Dict[str, Optional[str]] = {}
        for i, name in enumerate(dimensions):
            v = r.get(f"d{i}")
            dims[name] = None if v is None else str(v)
        out.append(
            UdmAggregateRow(
                dims=dims,
                bucket=_parse_bucket(r.get(BUCKET_COLUMN)) if time_bucket else None,
                count=count,
            )
        )
    truncated = len(out) > limit
    return out[:limit], truncated


class AggregateUdmWorkflow:
    """Bounded UDM event aggregation (0-2 allow-listed dimensions x optional time bucket)."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        filter: str = "",
        group_by: Optional[Sequence[str]] = ("metadata.log_type",),
        time_bucket: Optional[str] = None,
        lookback_hours: int = 24,
        limit: int = 500,
        metric: str = "count",
        distinct_field: Optional[str] = None,
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        clear_cache: Optional[bool] = None,
    ) -> UdmAggregateResult:
        dims = [f.path for f in _resolve_group_by(group_by)]
        query = build_aggregate_sql(
            filter=filter,
            group_by=dims,
            time_bucket=time_bucket,
            limit=limit,
            metric=metric,
            distinct_field=distinct_field,
        )
        start, end = resolve_aggregate_window(lookback_hours, start_time, end_time)
        marker = self.adapter.retry_marker() if hasattr(self.adapter, "retry_marker") else None
        t0 = time.monotonic()
        res = self.adapter.execute_dashboard_query(
            query_text=query,
            dialect="SQL",
            start_time=_fmt(start),
            end_time=_fmt(end),
            clear_cache=clear_cache,
        )
        elapsed = time.monotonic() - t0
        rows, truncated = parse_aggregate_rows(res.rows, dims, time_bucket, limit)
        retries = self.adapter.retries_since(marker) if marker is not None and hasattr(self.adapter, "retries_since") else []
        return UdmAggregateResult(
            dimensions=dims,
            rows=rows,
            truncated=truncated,
            limit=limit,
            metric=metric,
            distinct_field=distinct_field,
            time_bucket=time_bucket,
            filter=filter or "",
            query_text=query,
            dialect="SQL",
            time_window=dict(res.time_window or {"startTime": _fmt(start), "endTime": _fmt(end)}),
            elapsed_s=round(elapsed, 3),
            last_cache_refreshed_time=res.last_cache_refreshed_time,
            api_retries=retries,
        )
