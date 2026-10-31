"""Workflow for UDM Stats Search (Aggregation, Analytics, and Outcome Metrics)."""

from datetime import datetime, timezone
import time
from typing import Any, Callable, Optional

from engine.domain import (
    CompletenessState,
    LifecycleState,
    StatsSearchResult,
    StatsSearchRequest,
    StatsSearchSession,
)
from engine.workflows.search_udm import _start_search_kwargs, _validate_query


def _is_cancelled(token: Any) -> bool:
    if token is None:
        return False
    if callable(token):
        return bool(token())
    if hasattr(token, "is_set"):
        return bool(token.is_set())
    return bool(token)


class SearchUDMStatsWorkflow:
    """Executes UDM analytical queries with match and outcome aggregation via LRO."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        request: StatsSearchRequest,
        on_batch: Optional[Callable[[StatsSearchResult, StatsSearchSession], None]] = None,
        on_state_change: Optional[
            Callable[[LifecycleState, CompletenessState, StatsSearchSession], None]
        ] = None,
        cancel_token: Optional[Any] = None,
        poll_interval: float = 0.5,
        max_poll_seconds: float = 120.0,
    ) -> StatsSearchSession:
        """Executes the SearchUDMStats workflow synchronously, returning the completed session."""
        session = StatsSearchSession(
            request=request,
            lifecycle=LifecycleState.VALIDATING,
            completeness=CompletenessState.EMPTY,
            started_at=datetime.now(timezone.utc),
        )

        def _notify_state():
            if on_state_change:
                on_state_change(session.lifecycle, session.completeness, session)

        _notify_state()

        # Step 1: Query Validation. A failed validation *request* (network,
        # auth, 429) is reported as such, never as invalid syntax.
        try:
            val_res = _validate_query(self.adapter, request)
        except Exception as e:
            session.lifecycle = LifecycleState.FAILED
            session.completeness = CompletenessState.EMPTY
            session.error = f"Query validation request failed (not a syntax error): {e}"
            session.completed_at = datetime.now(timezone.utc)
            _notify_state()
            return session
        if not val_res.valid:
            session.lifecycle = LifecycleState.FAILED
            session.completeness = CompletenessState.EMPTY
            session.error = val_res.error_message or "Query validation failed: invalid UDM syntax"
            session.completed_at = datetime.now(timezone.utc)
            _notify_state()
            return session

        # Check early cancellation
        if _is_cancelled(cancel_token):
            session.lifecycle = LifecycleState.CANCELLED
            session.completed_at = datetime.now(timezone.utc)
            _notify_state()
            return session

        # Step 2: Initiate Search Operation
        session.lifecycle = LifecycleState.STARTING
        _notify_state()

        try:
            operation_id = self.adapter.start_search(
                query=request.query,
                start_time=request.start_time,
                end_time=request.end_time,
                max_events=request.max_events,
                **_start_search_kwargs(self.adapter, request),
            )
            session.session_id = operation_id
        except Exception as e:
            session.lifecycle = LifecycleState.FAILED
            session.completeness = CompletenessState.EMPTY
            session.error = f"Search initiation failed: {e}"
            session.completed_at = datetime.now(timezone.utc)
            _notify_state()
            return session

        # Step 3: LRO Polling Loop
        session.lifecycle = LifecycleState.RUNNING
        _notify_state()

        start_poll = time.time()
        final_result: Optional[StatsSearchResult] = None

        while True:
            # Check cancellation before requesting batch
            if _is_cancelled(cancel_token):
                session.lifecycle = LifecycleState.CANCELLING
                _notify_state()
                self.adapter.cancel_operation(session.session_id)
                session.lifecycle = LifecycleState.CANCELLED
                session.completeness = (
                    CompletenessState.PARTIAL if final_result and final_result.rows else CompletenessState.EMPTY
                )
                session.result = final_result
                session.completed_at = datetime.now(timezone.utc)
                _notify_state()
                return session

            try:
                stats_res = self.adapter.get_stats(
                    operation_id=session.session_id,
                    start_index=1,
                    batch_size=request.max_events,
                )
                final_result = stats_res
                session.result = stats_res
            except Exception as e:
                session.lifecycle = LifecycleState.FAILED
                session.completeness = (
                    CompletenessState.PARTIAL if final_result and final_result.rows else CompletenessState.EMPTY
                )
                session.error = f"Stats retrieval failed: {e}"
                session.completed_at = datetime.now(timezone.utc)
                _notify_state()
                return session

            if on_batch:
                on_batch(stats_res, session)

            if stats_res.complete:
                break

            if time.time() - start_poll > max_poll_seconds:
                session.lifecycle = LifecycleState.FAILED
                session.completeness = CompletenessState.PARTIAL if final_result and final_result.rows else CompletenessState.EMPTY
                session.error = f"Stats search timed out after {max_poll_seconds}s"
                session.completed_at = datetime.now(timezone.utc)
                _notify_state()
                return session

            time.sleep(poll_interval)

        # Step 4: Completion
        session.lifecycle = LifecycleState.COMPLETED
        session.completeness = CompletenessState.COMPLETE
        session.result = final_result
        session.completed_at = datetime.now(timezone.utc)
        _notify_state()
        return session
