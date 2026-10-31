import inspect
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from engine.domain import (
    CompletenessState,
    LifecycleState,
    SearchBatchResult,
    SearchRequest,
    SearchSession,
    UdmFieldAggregation,
    UdmFieldValueCount,
    UdmSearchStats,
    UdmTimelineBucket,
    UDMEvent,
)

logger = logging.getLogger(__name__)


# Minimum server-side result window (eventList.maxReturnedEvents) requested from
# SecOps regardless of how small the caller's client-side receive_limit is.
# Prevents low limits (e.g. receive_limit=1 from entity/investigation workflows)
# from starving the operation's event list, which is shared with prevalence/
# aggregation/AI-overview assembly. The retrieval loop still trims delivered
# events to receive_limit, so this never causes over-delivery to the caller.
MATERIALIZE_BUDGET_FLOOR = 1000

# How long the workflow keeps re-polling :streamSearch while the operation
# reports it is still running and has delivered nothing consumable.
DEFAULT_MAX_POLL_SECONDS = 120.0
DEFAULT_POLL_INTERVAL = 1.0

# Search-view options passed to adapter.start_search when it accepts them.
_SEARCH_OPTION_FIELDS = (
    "dialect",
    "user_sql",
    "case_insensitive",
    "generate_ai_overview",
    "max_values_per_field",
    "include_detections",
    "include_prevalence",
)


def _is_cancelled(token: Any) -> bool:
    if token is None:
        return False
    if callable(token):
        return bool(token())
    if hasattr(token, "is_set"):
        return bool(token.is_set())
    return bool(token)


def _parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Trim sub-microsecond precision (e.g. ...31.488091236+00:00).
    if "." in s:
        head, _, tail = s.partition(".")
        frac = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                rest = tail[i:]
                break
        s = f"{head}.{frac[:6]}{rest}" if frac else f"{head}{rest}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _agg_value(v: Any) -> Any:
    """Unwraps {"value": {"stringValue": "x"}} style aggregation values."""
    if isinstance(v, dict) and "value" in v:
        v = v["value"]
    if isinstance(v, dict):
        for key in ("stringValue", "stringVal", "enumValue", "boolValue", "boolVal", "timestampValue", "bytesValue"):
            if key in v:
                return v[key]
        for key in ("int64Value", "int64Val", "uint64Value", "int32Value"):
            if key in v:
                return _int(v[key])
        for key in ("doubleValue", "doubleVal", "floatValue"):
            if key in v:
                try:
                    return float(v[key])
                except (TypeError, ValueError):
                    return v[key]
        if len(v) == 1:
            return next(iter(v.values()))
        if not v:
            return None
    return v


def _value_counts(raw: Any) -> List[UdmFieldValueCount]:
    out: List[UdmFieldValueCount] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        out.append(
            UdmFieldValueCount(
                value=_agg_value(item.get("value")),
                count=_int(item.get("eventCount")) or 0,
                baseline_count=_int(item.get("baselineEventCount")) or 0,
            )
        )
    return out


def _field_aggregations(raw: Any, keep: Optional[Sequence[str]] = None) -> List[UdmFieldAggregation]:
    fields = raw.get("fields", []) if isinstance(raw, dict) else []
    keep_set = set(keep) if keep is not None else None
    out: List[UdmFieldAggregation] = []
    for f in fields or []:
        if not isinstance(f, dict):
            continue
        name = str(f.get("fieldName", ""))
        if keep_set is not None and name not in keep_set:
            continue
        if f.get("allValues") is not None:
            values = _value_counts(f.get("allValues"))
        else:
            values = _value_counts(f.get("topValues"))
        out.append(
            UdmFieldAggregation(
                field=name,
                event_count=_int(f.get("eventCount")) or 0,
                baseline_event_count=_int(f.get("baselineEventCount")) or 0,
                value_count=_int(f.get("valueCount")) or 0,
                too_many_values=bool(f.get("tooManyValues", False)),
                values=values,
                bottom_values=_value_counts(f.get("bottomValues")),
            )
        )
    return out


def _timeline(raw: Any, window_start: Optional[datetime]) -> Tuple[List[UdmTimelineBucket], Optional[int]]:
    """Places server timeline buckets on the UTC axis.

    The server sends ``{sizeOfBucketMs, buckets: [...]}`` without timestamps;
    empty buckets carry no counts. Buckets are aligned to multiples of the
    bucket size since the epoch, starting at the bucket containing the window
    start. Evidence (live 2026-10-10): 60 one-minute buckets for a 1 h window
    starting on a minute, 2 one-hour buckets for a 1 h window starting at
    :36, 97 fifteen-minute buckets for a 24 h window starting mid-bucket.
    """
    if not isinstance(raw, dict):
        return [], None
    size_ms = _int(raw.get("sizeOfBucketMs"))
    buckets = raw.get("buckets") or []
    if not size_ms or size_ms <= 0 or window_start is None:
        return [], (size_ms // 1000 if size_ms else None)
    start_ms = int(window_start.timestamp() * 1000)
    first_ms = (start_ms // size_ms) * size_ms
    out: List[UdmTimelineBucket] = []
    for i, b in enumerate(buckets):
        b = b if isinstance(b, dict) else {}
        out.append(
            UdmTimelineBucket(
                bucket_start=datetime.fromtimestamp((first_ms + i * size_ms) / 1000, tz=timezone.utc),
                count=_int(b.get("eventCount")) or 0,
                baseline_count=_int(b.get("baselineEventCount")) or 0,
            )
        )
    return out, size_ms // 1000


def parse_udm_search_stats(
    raw: Optional[Dict[str, Any]],
    window_start: Any = None,
    aggregation_fields: Optional[Sequence[str]] = None,
) -> Optional[UdmSearchStats]:
    """Builds UdmSearchStats from the non-event part of a streamSearch response.

    ``total_matched`` is ``filteredEventsCount`` (the count after any snapshot
    filter), falling back to ``baselineEventsCount``. Both are capped at the
    server's event cap; ``too_many_events`` says when the cap was hit.
    """
    if not raw:
        return None
    flags = raw.get("eventListFlags") or {}
    baseline = _int(raw.get("baselineEventsCount"))
    filtered = _int(raw.get("filteredEventsCount"))
    available = _int(raw.get("availableResultCount"))
    too_many = bool(raw.get("tooManyEvents", flags.get("tooManyEvents", False)))
    has_any = any(
        k in raw
        for k in (
            "baselineEventsCount",
            "filteredEventsCount",
            "availableResultCount",
            "tooManyEvents",
            "timeline",
            "activityTimeline",
            "fieldAggregations",
            "groupedFieldAggregations",
        )
    ) or "tooManyEvents" in flags
    if not has_any:
        return None
    ws = _parse_ts(window_start)
    timeline, tl_size = _timeline(raw.get("timeline"), ws)
    activity, act_size = _timeline(raw.get("activityTimeline"), ws)
    return UdmSearchStats(
        total_matched=filtered if filtered is not None else baseline,
        baseline_count=baseline,
        filtered_count=filtered,
        available_count=available,
        too_many_events=too_many,
        timeline=timeline,
        timeline_bucket_seconds=tl_size,
        activity_timeline=activity,
        activity_timeline_bucket_seconds=act_size,
        field_aggregations=_field_aggregations(raw.get("fieldAggregations"), aggregation_fields),
        grouped_field_aggregations=_field_aggregations(raw.get("groupedFieldAggregations")),
    )


def _event_id(ev: Any) -> Optional[str]:
    if not isinstance(ev, dict):
        return None
    inner = ev.get("event") if isinstance(ev.get("event"), dict) else ev
    meta = inner.get("metadata") if isinstance(inner, dict) else None
    if isinstance(meta, dict) and meta.get("id"):
        return str(meta["id"])
    return None


def _validate_query(adapter: Any, request: SearchRequest) -> Any:
    """Validate with the request's dialect when the adapter takes one (older adapters don't)."""
    dialect = getattr(request, "dialect", None)
    if dialect:
        try:
            params = inspect.signature(adapter.validate_query).parameters
        except (TypeError, ValueError):
            params = {}
        if "dialect" in params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return adapter.validate_query(request.query, dialect=dialect)
    return adapter.validate_query(request.query)


def _is_stats_query(request: SearchRequest, val_res: Any) -> bool:
    """SQL / pipe-syntax / stats queries return rows from the stats stream, not events."""
    return (
        getattr(val_res, "raw_query_type", None) == "QUERY_TYPE_STATS_QUERY"
        or getattr(request, "dialect", None) == "DIALECT_SQL"
        or getattr(request, "user_sql", None) is not None
        or (isinstance(request.query, str) and ("|>" in request.query or request.query.strip().startswith("FROM ")))
    )


def _start_search_kwargs(adapter: Any, request: SearchRequest) -> Dict[str, Any]:
    """Search-view options the adapter's start_search accepts.

    Adapters with the legacy 4-argument signature still work; options they
    cannot take are logged at WARNING (never silently assumed applied).
    """
    wanted = {name: getattr(request, name) for name in _SEARCH_OPTION_FIELDS if hasattr(request, name)}
    try:
        params = inspect.signature(adapter.start_search).parameters
    except (TypeError, ValueError):
        return wanted
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return wanted
    accepted = {k: v for k, v in wanted.items() if k in params}
    dropped = sorted(set(wanted) - set(accepted))
    if dropped:
        logger.warning(
            "%s.start_search does not accept search options %s; they were not applied.",
            type(adapter).__name__,
            dropped,
        )
    return accepted


class SearchUDMWorkflow:

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        request: SearchRequest,
        on_batch: Optional[Callable[[SearchBatchResult, SearchSession], None]] = None,
        on_state_change: Optional[
            Callable[[LifecycleState, CompletenessState, SearchSession], None]
        ] = None,
        cancel_token: Optional[Any] = None,
        max_poll_seconds: float = DEFAULT_MAX_POLL_SECONDS,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> SearchSession:
        """Executes the SearchUDM workflow synchronously, streaming batches via callbacks."""
        session = SearchSession(
            request=request,
            lifecycle=LifecycleState.VALIDATING,
            completeness=CompletenessState.EMPTY,
            started_at=datetime.now(timezone.utc),
        )
        retry_marker = self.adapter.retry_marker() if hasattr(self.adapter, "retry_marker") else None

        def _collect_retries() -> None:
            if retry_marker is not None and hasattr(self.adapter, "retries_since"):
                session.api_retries = self.adapter.retries_since(retry_marker)

        def _notify_state():
            if on_state_change:
                on_state_change(session.lifecycle, session.completeness, session)

        def _finish(lifecycle: LifecycleState, completeness: CompletenessState, error: Optional[str] = None) -> SearchSession:
            session.lifecycle = lifecycle
            session.completeness = completeness
            if error is not None:
                session.error = error
            session.completed_at = datetime.now(timezone.utc)
            _collect_retries()
            _notify_state()
            return session

        _notify_state()

        # Step 1: Query Validation. A failed validation *request* (network,
        # auth, 429) is reported as such, never as invalid syntax.
        try:
            val_res = _validate_query(self.adapter, request)
        except Exception as e:
            return _finish(
                LifecycleState.FAILED,
                CompletenessState.EMPTY,
                f"Query validation request failed (not a syntax error): {e}",
            )
        if not val_res.valid:
            msg = val_res.error_message or "Query validation failed: invalid UDM syntax"
            return _finish(LifecycleState.FAILED, CompletenessState.EMPTY, msg)

        # Check early cancellation
        if _is_cancelled(cancel_token):
            return _finish(LifecycleState.CANCELLED, session.completeness)

        # Step 2: Initiate Search Operation
        session.lifecycle = LifecycleState.STARTING
        _notify_state()

        # Decouple the server-side materialization budget from the client-side
        # receive_limit. Honor an explicit request.materialize_budget when set;
        # otherwise floor the derived budget so tiny receive_limits don't starve
        # the shared event list. The loop below still enforces receive_limit.
        materialize_budget = (
            request.materialize_budget
            if request.materialize_budget is not None
            else max(request.receive_limit, MATERIALIZE_BUDGET_FLOOR)
        )
        try:
            operation_id = self.adapter.start_search(
                query=request.query,
                start_time=request.start_time,
                end_time=request.end_time,
                max_events=materialize_budget,
                **_start_search_kwargs(self.adapter, request),
            )
            session.session_id = operation_id
        except Exception as e:
            return _finish(LifecycleState.FAILED, CompletenessState.EMPTY, f"Search initiation failed: {e}")

        # Step 3: Incremental Retrieval Loop
        session.lifecycle = LifecycleState.RUNNING
        _notify_state()

        if _is_stats_query(request, val_res):
            # Stats / SQL results arrive whole from the stats stream; poll until complete.
            while True:
                if _is_cancelled(cancel_token):
                    session.lifecycle = LifecycleState.CANCELLING
                    _notify_state()
                    self.adapter.cancel_operation(session.session_id)
                    return _finish(
                        LifecycleState.CANCELLED,
                        CompletenessState.PARTIAL if session.received_count > 0 else CompletenessState.EMPTY,
                    )
                try:
                    stats_res = self.adapter.get_stats(
                        operation_id=session.session_id,
                        start_index=1,
                        batch_size=request.receive_limit,
                    )
                except Exception as e:
                    return _finish(
                        LifecycleState.FAILED,
                        CompletenessState.PARTIAL if session.received_count > 0 else CompletenessState.EMPTY,
                        f"Stream retrieval failed: {e}",
                    )
                rows = stats_res.rows[: request.receive_limit]
                session.events = [UDMEvent(r) if isinstance(r, dict) and not isinstance(r, UDMEvent) else r for r in rows]
                session.received_count = len(session.events)
                if stats_res.complete:
                    session.more_data_available = False
                    return _finish(
                        LifecycleState.COMPLETED,
                        CompletenessState.COMPLETE if session.received_count > 0 else CompletenessState.EMPTY,
                    )
                time.sleep(0.5)

        seen_ids: set = set()
        stream_has_more = True
        poll_deadline = time.monotonic() + max_poll_seconds

        while session.more_data_available and session.received_count < request.receive_limit:
            # Check cancellation before requesting batch
            if _is_cancelled(cancel_token):
                session.lifecycle = LifecycleState.CANCELLING
                _notify_state()
                self.adapter.cancel_operation(session.session_id)
                return _finish(
                    LifecycleState.CANCELLED,
                    CompletenessState.PARTIAL if session.received_count > 0 else CompletenessState.EMPTY,
                )

            batch_limit = min(request.batch_size, request.receive_limit - session.received_count)
            try:
                batch_res = self.adapter.get_events(
                    operation_id=session.session_id,
                    start_index=session.next_index,
                    batch_size=batch_limit,
                )
            except Exception as e:
                return _finish(
                    LifecycleState.FAILED,
                    CompletenessState.PARTIAL if session.received_count > 0 else CompletenessState.EMPTY,
                    f"Stream retrieval failed at index {session.next_index}: {e}",
                )

            raw_stats = getattr(batch_res, "search_stats_raw", None)
            if raw_stats:
                parsed = parse_udm_search_stats(raw_stats, request.start_time, request.aggregation_fields)
                if parsed is not None:
                    session.search_stats = parsed

            # The operation is still running: its snapshot may be partial, so
            # poll again instead of consuming it (or treating 0 events as an
            # empty result). Adapters that do not report done-ness (None) keep
            # the old consume-immediately behaviour.
            if getattr(batch_res, "operation_done", None) is False:
                if time.monotonic() > poll_deadline:
                    try:
                        self.adapter.cancel_operation(session.session_id)
                    except Exception as cancel_err:
                        logger.warning("Cancelling timed-out search %s failed: %s", session.session_id, cancel_err)
                    return _finish(
                        LifecycleState.FAILED,
                        CompletenessState.PARTIAL if session.received_count > 0 else CompletenessState.EMPTY,
                        f"Search operation still running after {max_poll_seconds:.0f}s at index {session.next_index}",
                    )
                time.sleep(poll_interval)
                continue

            session.duplicates_dropped += int(getattr(batch_res, "duplicates_dropped", 0) or 0)

            # Strict enforcement of receive_limit, with cross-batch dedupe by
            # metadata.id (events without an id are always kept).
            remaining_quota = request.receive_limit - session.received_count
            events_to_add: List[Any] = []
            consumed = 0
            for e in batch_res.events:
                if len(events_to_add) >= remaining_quota:
                    break
                consumed += 1
                eid = _event_id(e)
                if eid is not None:
                    if eid in seen_ids:
                        session.duplicates_dropped += 1
                        continue
                    seen_ids.add(eid)
                events_to_add.append(UDMEvent(e) if isinstance(e, dict) and not isinstance(e, UDMEvent) else e)
            session.events.extend(events_to_add)
            session.received_count += len(events_to_add)
            # Advance by the provider positions consumed (duplicates included).
            session.next_index += consumed

            # Check if there is still more data available or if we capped before stream exhausted
            stream_has_more = batch_res.more_data_available or len(batch_res.events) > consumed
            session.more_data_available = stream_has_more

            # Emit batch with the actual added events
            if on_batch:
                trimmed_batch = SearchBatchResult(
                    events=events_to_add,
                    provider_event_count=batch_res.provider_event_count,
                    emitted_event_count=len(events_to_add),
                    more_data_available=stream_has_more,
                    provider=batch_res.provider,
                    workflow_id=batch_res.workflow_id,
                    operation_id=batch_res.operation_id,
                    requested_start_index=batch_res.requested_start_index,
                    requested_end_index=batch_res.requested_end_index,
                    returned_start_index=batch_res.returned_start_index,
                    returned_end_index=batch_res.returned_start_index + len(events_to_add) - 1
                    if events_to_add
                    else batch_res.returned_start_index,
                    retrieved_at=batch_res.retrieved_at,
                    raw_response=batch_res.raw_response,
                    search_stats_raw=raw_stats,
                    operation_done=getattr(batch_res, "operation_done", None),
                    duplicates_dropped=int(getattr(batch_res, "duplicates_dropped", 0) or 0),
                )
                on_batch(trimmed_batch, session)

            _notify_state()

            # Break if quota met or the stream is exhausted.
            if session.received_count >= request.receive_limit or consumed == 0 or not batch_res.more_data_available:
                break

        # Step 4: Completion. more_data_available means "the caller does not
        # hold every matching event": the stream can still page, or the server
        # reports more matches than were delivered (including its 30k cap).
        stats = session.search_stats
        more_matches = False
        if stats is not None:
            if stats.too_many_events:
                more_matches = True
            elif stats.total_matched is not None and session.received_count < stats.total_matched:
                more_matches = True
        session.more_data_available = bool(stream_has_more) or more_matches

        if session.received_count == 0:
            # Done with zero events is a genuine empty result only when the
            # server does not report matches.
            completeness = CompletenessState.PARTIAL if more_matches else CompletenessState.COMPLETE
        elif session.more_data_available:
            completeness = CompletenessState.PARTIAL
        else:
            completeness = CompletenessState.COMPLETE
        return _finish(LifecycleState.COMPLETED, completeness)
