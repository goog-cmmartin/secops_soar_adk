"""Google SecOps Provider Adapter.

Responsible exclusively for translating canonical domain operations to/from live
Google SecOps (Chronicle) REST & Long Running Operation (LRO) APIs.
"""

import base64
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

from engine.auth import CredentialProvider
from engine.config import SecOpsConfig, SecOpsConfigurationError, load_config
from engine.domain import (
    DashboardQueryResult,
    RawLogPayload,
    SearchBatchResult,
    StatsColumn,
    StatsColumnMetadata,
    StatsFieldAggregation,
    StatsSearchResult,
    StatsValueCount,
    UDMEvent,
    ValidationResult,
)
from engine.parsing import parse_id_list

logger = logging.getLogger(__name__)


class SecOpsApiError(RuntimeError):
    """HTTP error from a Google SecOps API. Subclasses RuntimeError for backward compatibility."""

    def __init__(self, status: int, message: str):
        super().__init__(f"Google SecOps API Error [{status}]: {message}")
        self.status = status
        self.api_message = message


class QueryValidationUnavailableError(RuntimeError):
    """``:validateQuery`` answered with BACKEND_ERROR_TYPE: the validator failed, not the query.

    Raised instead of returning ``valid=False`` so callers never show a backend
    outage as a syntax error.
    """

    def __init__(self, message: str, dialect: str):
        super().__init__(f"Query validation backend error ({dialect}): {message}")
        self.dialect = dialect


# Query types each validator accepts as valid.
UDM_SEARCH_QUERY_TYPES = ("QUERY_TYPE_UDM_QUERY", "QUERY_TYPE_ENTITY_GRAPH_QUERY", "QUERY_TYPE_STATS_QUERY")
STATS_QUERY_TYPES = ("QUERY_TYPE_STATS_QUERY", "QUERY_TYPE_UDM_QUERY")


def parse_validate_query_response(
    res: Any,
    dialect: str,
    accepted_types: Optional[Tuple[str, ...]] = None,
) -> ValidationResult:
    """Maps a ``:validateQuery`` 200 response onto ValidationResult.

    Verified live 2026-10-10: compile errors come back as HTTP 200 with
    ``errorType``/``errorText``/``errorPosition`` (line + column). Transport,
    auth and quota failures are HTTP errors and are raised by ``_request``;
    this function never sees them. ``BACKEND_ERROR_TYPE`` ("general backend
    error") is a validator failure and raises QueryValidationUnavailableError.
    """
    if not isinstance(res, dict):
        raise RuntimeError(f"Unexpected :validateQuery response shape: {type(res).__name__}")
    query_type = res.get("queryType")
    err_type = res.get("errorType")
    err_text = res.get("errorText")
    if err_type == "BACKEND_ERROR_TYPE":
        raise QueryValidationUnavailableError(str(err_text or err_type), dialect)
    pos_raw = res.get("errorPosition")
    position = None
    if isinstance(pos_raw, dict) and pos_raw:
        position = {
            "start_line": int(pos_raw.get("startLine", 0) or 0),
            "start_column": int(pos_raw.get("startColumn", 0) or 0),
            "end_line": int(pos_raw.get("endLine", 0) or 0),
            "end_column": int(pos_raw.get("endColumn", 0) or 0),
        }
    if err_type or err_text:
        return ValidationResult(
            valid=False,
            dialect=dialect,
            raw_query_type=query_type,
            error_message=str(err_text or err_type),
            error_type=err_type,
            error_position=position,
        )
    if accepted_types is not None and query_type not in accepted_types:
        return ValidationResult(
            valid=False,
            dialect=dialect,
            raw_query_type=query_type,
            error_message=f"Query type {query_type or 'UNSPECIFIED'} is not accepted here (expected one of {', '.join(accepted_types)}).",
            error_type="UNSUPPORTED_QUERY_TYPE",
        )
    return ValidationResult(
        valid=True,
        dialect=dialect,
        raw_query_type=query_type,
        warning=res.get("warning"),
    )


def _udm_event_id(ev: Any) -> Optional[str]:
    """metadata.id of a streamed UDM search event ({"event": {...}} or bare UDM)."""
    if not isinstance(ev, dict):
        return None
    inner = ev.get("event") if isinstance(ev.get("event"), dict) else ev
    meta = inner.get("metadata") if isinstance(inner, dict) else None
    if isinstance(meta, dict):
        mid = meta.get("id")
        return str(mid) if mid else None
    return None


def _select_final_stream_chunk(items: List[Dict[str, Any]], payload_key: str) -> Optional[Dict[str, Any]]:
    """Picks the authoritative chunk from a ``:streamSearch`` response.

    The stream returns cumulative snapshots: observed live 2026-10-10 as chunks
    of (1, 100, 100 done) events for a 100-event page, and (5, 0, 5 done) in an
    earlier probe. Concatenating them duplicated every event / stats row. The
    last ``done`` chunk wins; otherwise the last chunk that carries
    ``payload_key``; otherwise the last chunk.
    """
    if not items:
        return None
    done = [op for op in items if op.get("done") is True]
    if done:
        return done[-1]
    with_payload = [op for op in items if (op.get("response", op) or {}).get(payload_key)]
    if with_payload:
        return with_payload[-1]
    return items[-1]


def _stream_operations(res: Any) -> List[Dict[str, Any]]:
    """Normalizes a streamSearch response into operation dicts, raising on operation errors."""
    raw_items = res if isinstance(res, list) else [res]
    ops: List[Dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        op_obj = item.get("operation", item)
        if not isinstance(op_obj, dict):
            continue
        if "error" in op_obj:
            err = op_obj["error"]
            err_code = err.get("code", "UNKNOWN") if isinstance(err, dict) else "UNKNOWN"
            err_msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise RuntimeError(f"Google SecOps Operation Error [{err_code}]: {err_msg}")
        ops.append(op_obj)
    return ops


# Response keys of the search view that are not events and not bulky
# per-request extras the SDK does not parse.
_SEARCH_STATS_EXCLUDED_KEYS = frozenset({"events", "operation", "@type", "detections", "aiOverview", "prevalence"})


def _extract_error_message(error_body: str) -> str:
    """Pulls the human-readable message out of a Google API error body.

    Most endpoints return ``{"error": {...}}``; some (e.g. :testFindingsRefinement)
    return a JSON array ``[{"error": {...}}]``. Falls back to the raw body.
    """
    try:
        err_json = json.loads(error_body)
    except (ValueError, TypeError):
        return error_body
    if isinstance(err_json, list) and err_json:
        err_json = err_json[0]
    if isinstance(err_json, dict):
        err = err_json.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
    return error_body


class GoogleSecOpsAdapter:
    def __init__(
        self,
        config: Optional[SecOpsConfig] = None,
        project_id: Optional[str] = None,
        project_number: Optional[str] = None,
        customer_id: Optional[str] = None,
        location: Optional[str] = None,
        api_base: Optional[str] = None,
        credential_provider: Optional[CredentialProvider] = None,
    ):
        if config is not None:
            self.config = config
        else:
            self.config = load_config(
                project_id=project_id,
                customer_id=customer_id,
                project_number=project_number,
                location=location,
                api_base=api_base,
            )

        self.project_id = self.config.project_id
        self.project_number = self.config.project_number
        self.customer_id = self.config.customer_id
        self.location = self.config.location
        self.api_base = self.config.api_base
        self.default_timeout = 35.0
        self._credential_provider = credential_provider or CredentialProvider()
        self._retry_lock = threading.Lock()
        self._retry_seq = 0
        # Bounded log of transient-error retries (see _record_retry).
        self.retry_log: Deque[Dict[str, Any]] = deque(maxlen=500)

    def _get_auth_token(self) -> str:
        """Acquires a valid Google Cloud access token for SecOps REST calls.

        Delegates to the configured :class:`~engine.auth.CredentialProvider`,
        which resolves credentials via (in order) a static token override,
        google-auth ADC, then a gcloud ADC subprocess fallback. See
        ``engine/auth.py`` for the full resolution contract.
        """
        return self._credential_provider.get_token()

    # ------------------------------------------------------------------
    # Retry visibility. _request silently retried 429/5xx/network errors up to
    # five times; the semantics are unchanged, but every retry is now logged at
    # WARNING and recorded so workflows can attach it to their results
    # (SearchSession.api_retries, UdmAggregateResult.api_retries).
    # ------------------------------------------------------------------

    def _record_retry(self, status: Any, attempt: int, sleep_s: float, url: str) -> None:
        lock = getattr(self, "_retry_lock", None)
        if lock is None:
            self._retry_lock = lock = threading.Lock()
            self._retry_seq = 0
            self.retry_log = deque(maxlen=500)
        path = url.split("?", 1)[0]
        api_base = getattr(self, "api_base", None)
        if api_base and path.startswith(api_base):
            path = path[len(api_base):]
        with lock:
            self._retry_seq += 1
            entry = {
                "seq": self._retry_seq,
                "status": status,
                "attempt": attempt,
                "sleep_s": sleep_s,
                "path": path,
                "at": datetime.now(timezone.utc).isoformat(),
                "thread": threading.get_ident(),
            }
            self.retry_log.append(entry)
        logger.warning(
            "Google SecOps transient error %s on %s (attempt %d); retrying in %.1fs",
            status, path, attempt, sleep_s,
        )

    def retry_marker(self) -> int:
        """Sequence number of the most recent recorded retry (pass to retries_since)."""
        return getattr(self, "_retry_seq", 0)

    def retries_since(self, marker: int, current_thread_only: bool = True) -> List[Dict[str, Any]]:
        """Retries recorded after ``marker`` (optionally only for the calling thread)."""
        log = list(getattr(self, "retry_log", []) or [])
        tid = threading.get_ident()
        return [
            {k: v for k, v in e.items() if k not in ("seq", "thread")}
            for e in log
            if e["seq"] > marker and (not current_thread_only or e["thread"] == tid)
        ]

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Any] = None,
        body: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Executes an authenticated REST request against Google SecOps APIs with transient retry."""
        if path.startswith("https://"):
            url = path
        else:
            encoded_path = urllib.parse.quote(path, safe="/:@&=+$,?%#")
            url = f"{self.api_base}{encoded_path}"
        if params:
            query_string = urllib.parse.urlencode(params, doseq=True)
            url = f"{url}?{query_string}"

        data = json.dumps(body).encode("utf-8") if body is not None else None
        effective_timeout = timeout if timeout is not None else getattr(self, "default_timeout", 35.0)
        max_retries = 5
        for attempt in range(1, max_retries + 1):
            token = self._get_auth_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                    resp_data = resp.read().decode("utf-8")
                    if not resp_data.strip():
                        return {}
                    return json.loads(resp_data)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 1 and hasattr(self._credential_provider, "invalidate"):
                    self._credential_provider.invalidate()
                    continue
                if e.code in [429, 502, 503, 504] and attempt < max_retries:
                    self._record_retry(e.code, attempt, 2.5 * attempt, url)
                    time.sleep(2.5 * attempt)
                    continue
                error_body = e.read().decode("utf-8")
                err_msg = _extract_error_message(error_body)
                raise SecOpsApiError(e.code, err_msg) from e
            except (TimeoutError, urllib.error.URLError) as e:
                if attempt < max_retries:
                    self._record_retry(f"network:{type(e).__name__}", attempt, 1.0 * attempt, url)
                    time.sleep(1.0 * attempt)
                    continue
                raise RuntimeError(f"Network error connecting to Google SecOps: {e}") from e

        raise RuntimeError(f"Google SecOps API request to {url} failed after {max_retries} attempts.")

    def validate_query(self, query: str, dialect: Optional[str] = None) -> ValidationResult:
        """Translates query.validate domain operation to :validateQuery API.

        The dialect is picked from the query when not given (pipe syntax or ``FROM`` ->
        SQL, else UDM search). Returns ``valid=False`` only for compile errors reported by
        the server. HTTP failures (network, auth, 429, 5xx) propagate as exceptions.
        """
        resolved_dialect = dialect
        if not resolved_dialect:
            if isinstance(query, str) and ("|>" in query or query.strip().startswith("FROM ")):
                resolved_dialect = "DIALECT_SQL"
            else:
                resolved_dialect = "DIALECT_UDM_SEARCH"
        elif resolved_dialect.lower() in ("udm", "dialect_udm_search"):
            resolved_dialect = "DIALECT_UDM_SEARCH"
        elif resolved_dialect.lower() in ("sql", "dialect_sql"):
            resolved_dialect = "DIALECT_SQL"
        elif resolved_dialect.lower() in ("stats", "dialect_stats"):
            resolved_dialect = "DIALECT_STATS"

        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:validateQuery"
        params = {
            "dialect": resolved_dialect,
            "allowUnreplacedPlaceholders": "false",
            "rawQuery": query,
        }
        res = self._request("GET", path, params=params)
        return parse_validate_query_response(res, dialect=resolved_dialect, accepted_types=UDM_SEARCH_QUERY_TYPES)

    def start_search(
        self,
        query: str,
        start_time: str,
        end_time: str,
        max_events: int = 10000,
        dialect: Optional[str] = None,
        user_sql: Optional[str] = None,
        case_insensitive: bool = True,
        generate_ai_overview: bool = True,
        max_values_per_field: int = 60,
        include_detections: bool = True,
        include_prevalence: bool = True,
    ) -> str:
        """Translates search.start domain operation to legacyFetchUdmSearchView API.

        The option defaults reproduce the body this method always sent before
        they were parameters. ``include_detections=False`` /
        ``include_prevalence=False`` / ``generate_ai_overview=False`` drop the
        detection list (1000), 15-min prevalence and the AI overview from the
        request (verified live 2026-10-10: the lean body still returns events,
        totals, timelines and field aggregations).

        Returns normalized operation_id.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacy:legacyFetchUdmSearchView"
        body: Dict[str, Any] = {
            "baselineQuery": query,
            "baselineTimeRange": {
                "startTime": start_time,
                "endTime": end_time,
            },
            "snapshotQuery": None,
            "eventList": {"maxReturnedEvents": max_events},
            "fieldAggregations": {"maxValuesPerField": max_values_per_field},
            "caseInsensitive": bool(case_insensitive),
            "generateAiOverview": bool(generate_ai_overview),
            "returnOperationIdOnly": True,
        }
        if user_sql:
            body["userSql"] = user_sql
        elif (
            (dialect and dialect.upper() in ("DIALECT_SQL", "SQL"))
            or (isinstance(query, str) and ("|>" in query or query.strip().startswith("FROM ")))
        ):
            body["userSql"] = query
        if include_detections:
            body["detectionOptions"] = {
                "detectionList": {"maxReturnedDetections": 1000},
                "snapshotQuery": 'feedback_summary.status != "CLOSED"',
                "fieldAggregations": {"maxValuesPerField": max_values_per_field},
                "fetchNonAlertingDetections": True,
            }
        if include_prevalence:
            body["prevalence"] = {
                "bucketSize": {"resolutionInSeconds": 900},
                "getPrevalence": True,
            }

        res = self._request("POST", path, body=body)
        # Observed response: [{"operation": "projects/.../operations/s-udm-..."}]
        if isinstance(res, list) and len(res) > 0 and "operation" in res[0]:
            return res[0]["operation"]
        elif isinstance(res, dict) and "operation" in res:
            return res["operation"]
        elif isinstance(res, dict) and "name" in res:
            return res["name"]
        else:
            raise RuntimeError(f"Unexpected start_search response shape: {res}")

    def get_events(
        self,
        operation_id: str,
        start_index: int,
        batch_size: int = 2000,
    ) -> SearchBatchResult:
        """Translates search.events domain operation to :streamSearch API.

        Returns normalized SearchBatchResult.
        """
        # operation_id is full path or relative operation ID
        if operation_id.startswith("projects/"):
            path = f"/v1alpha/{operation_id}:streamSearch"
        else:
            path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/operations/{operation_id}:streamSearch"

        end_index = start_index + batch_size - 1
        params = {
            "eventIndexStart": start_index,
            "eventIndexEnd": end_index,
            "pageRequest": "false",
            "paginationEnabled": "true",
        }

        res = self._request("GET", path, params=params)
        ops = _stream_operations(res)
        final = _select_final_stream_chunk(ops, "events")
        resp_obj: Dict[str, Any] = {}
        events_field: Any = []
        if final is not None:
            resp_obj = final.get("response", final) or {}
            events_field = resp_obj.get("events", [])
        flags: Dict[str, Any] = {}
        if isinstance(events_field, dict):
            raw_events = events_field.get("events", []) or []
            flags = {k: v for k, v in events_field.items() if k != "events"}
        elif isinstance(events_field, list):
            raw_events = events_field
        else:
            raw_events = []

        # Dedupe by metadata.id (defence in depth; the final chunk alone is
        # already a full snapshot). Earlier chunks are snapshots of the same
        # page; ids seen only there are appended so nothing is lost if the
        # server ever streams increments instead.
        seen: set = set()
        all_events: List[Any] = []
        dropped = 0
        for ev in raw_events:
            eid = _udm_event_id(ev)
            if eid is not None and eid in seen:
                dropped += 1
                continue
            if eid is not None:
                seen.add(eid)
            all_events.append(ev)
        total_streamed = len(raw_events)
        for op in ops:
            if op is final:
                continue
            ef = (op.get("response", op) or {}).get("events", [])
            chunk_events = ef.get("events", []) if isinstance(ef, dict) else (ef if isinstance(ef, list) else [])
            total_streamed += len(chunk_events or [])
            for ev in chunk_events or []:
                eid = _udm_event_id(ev)
                if eid is None or eid in seen:
                    continue
                if len(all_events) >= batch_size:
                    break
                seen.add(eid)
                all_events.append(ev)
        dropped = max(dropped, total_streamed - len(all_events))

        # Done-ness: the operation finished, or the event list is complete.
        done_flag = final.get("done") if final is not None else None
        complete_flag = flags.get("complete", resp_obj.get("complete"))
        if done_flag is True or complete_flag is True:
            operation_done: Optional[bool] = True
        elif done_flag is False or complete_flag is False or (final is not None and "done" not in final and "name" in final):
            operation_done = False
        else:
            operation_done = None

        available = resp_obj.get("availableResultCount")
        try:
            available_n = int(available) if available is not None else None
        except (TypeError, ValueError):
            available_n = None
        if flags.get("moreDataAvailable") is True or resp_obj.get("moreDataAvailable") is True:
            more_data = True
        elif operation_done is False:
            more_data = True
        else:
            # A full page means the next index range may hold more events,
            # unless the server says fewer are available.
            more_data = len(all_events) >= batch_size and (available_n is None or end_index < available_n)

        stats_raw = {k: v for k, v in resp_obj.items() if k not in _SEARCH_STATS_EXCLUDED_KEYS}
        if flags:
            stats_raw["eventListFlags"] = flags

        wrapped_events = [UDMEvent(e) if isinstance(e, dict) and not isinstance(e, UDMEvent) else e for e in all_events]

        return SearchBatchResult(
            events=wrapped_events,
            provider_event_count=len(all_events),
            emitted_event_count=len(all_events),
            more_data_available=more_data,
            provider="google_secops",
            workflow_id="search.udm",
            operation_id=operation_id,
            requested_start_index=start_index,
            requested_end_index=end_index,
            returned_start_index=start_index,
            returned_end_index=start_index + len(all_events) - 1 if all_events else start_index,
            retrieved_at=datetime.now(timezone.utc),
            raw_response=res if isinstance(res, (dict, list)) else None,
            search_stats_raw=stats_raw or None,
            operation_done=operation_done,
            duplicates_dropped=dropped,
        )

    def get_stats(
        self,
        operation_id: str,
        start_index: int = 1,
        batch_size: int = 2000,
    ) -> StatsSearchResult:
        """Translates search.udm.stats operation to :streamSearch API and parses stats payload.

        Returns normalized StatsSearchResult.
        """
        if operation_id.startswith("projects/"):
            path = f"/v1alpha/{operation_id}:streamSearch"
        else:
            path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/operations/{operation_id}:streamSearch"

        end_index = start_index + batch_size - 1
        params = {
            "eventIndexStart": start_index,
            "eventIndexEnd": end_index,
            "pageRequest": "false",
            "paginationEnabled": "true",
        }

        res = self._request("GET", path, params=params)

        def _extract_val(v_obj: Any) -> Any:
            if not isinstance(v_obj, dict):
                return v_obj
            if "value" in v_obj:
                v_obj = v_obj["value"]
            if not isinstance(v_obj, dict):
                return v_obj
            if "stringVal" in v_obj:
                return v_obj["stringVal"]
            if "stringValue" in v_obj:
                return v_obj["stringValue"]
            if "int64Val" in v_obj:
                try:
                    return int(v_obj["int64Val"])
                except (ValueError, TypeError):
                    return v_obj["int64Val"]
            if "int64Value" in v_obj:
                try:
                    return int(v_obj["int64Value"])
                except (ValueError, TypeError):
                    return v_obj["int64Value"]
            if "doubleVal" in v_obj:
                try:
                    return float(v_obj["doubleVal"])
                except (ValueError, TypeError):
                    return v_obj["doubleVal"]
            if "doubleValue" in v_obj:
                try:
                    return float(v_obj["doubleValue"])
                except (ValueError, TypeError):
                    return v_obj["doubleValue"]
            if "boolVal" in v_obj:
                return bool(v_obj["boolVal"])
            if "boolValue" in v_obj:
                return bool(v_obj["boolValue"])
            if "timestampVal" in v_obj:
                return v_obj["timestampVal"]
            if "timestampValue" in v_obj:
                return v_obj["timestampValue"]
            if len(v_obj) == 1:
                return next(iter(v_obj.values()))
            return v_obj

        columns: List[StatsColumn] = []
        aggregations: List[StatsFieldAggregation] = []
        total_results = 0
        filtered_result_count = 0
        data_query_expr = ""
        progress = 1.0
        complete = True

        # Only the authoritative chunk: the stream repeats cumulative snapshots,
        # and extending columns across them duplicated every row (observed
        # live: 490 rows for totalResults=245).
        stream_ops = _stream_operations(res)
        final_op = _select_final_stream_chunk(stream_ops, "stats")
        items = [final_op] if final_op is not None else []
        for item in items:
            op_obj = item.get("operation", item) if isinstance(item, dict) else {}
            if "error" in op_obj:
                err = op_obj["error"]
                err_code = err.get("code", "UNKNOWN")
                err_msg = err.get("message", str(err))
                raise RuntimeError(f"Google SecOps Operation Error [{err_code}]: {err_msg}")

            metadata = op_obj.get("metadata", {})
            done = op_obj.get("done", False)
            resp_obj = op_obj.get("response", op_obj)

            progress = metadata.get("progress", resp_obj.get("progress", 1.0 if done else 0.0))
            complete = resp_obj.get("complete", done)

            stats_data = resp_obj.get("stats", {})
            if stats_data:
                data_query_expr = stats_data.get("dataQueryExpression", data_query_expr)
                total_results = stats_data.get("totalResults", total_results)
                filtered_result_count = stats_data.get("filteredResultCount", filtered_result_count)

                # Parse columnar results
                raw_results = stats_data.get("results", [])
                for r in raw_results:
                    col_name = r.get("column", "")
                    filterable = r.get("filterable", False)
                    filter_expr = r.get("filterExpression")
                    meta_raw = r.get("columnMetadata", {})
                    col_meta = StatsColumnMetadata(
                        column=meta_raw.get("column", col_name),
                        field_path=meta_raw.get("fieldPath", ""),
                        function_name_used=meta_raw.get("functionNameUsed"),
                        data_type=meta_raw.get("dataType", "STRING"),
                    ) if meta_raw else None

                    vals_raw = r.get("values", [])
                    extracted_vals = [_extract_val(v) for v in vals_raw]

                    # Find or update column in columns list
                    existing_col = next((c for c in columns if c.column == col_name), None)
                    if existing_col:
                        existing_col.values.extend(extracted_vals)
                    else:
                        columns.append(
                            StatsColumn(
                                column=col_name,
                                values=extracted_vals,
                                filterable=filterable,
                                filter_expression=filter_expr,
                                column_metadata=col_meta,
                            )
                        )

            # Parse statsResultAggregation
            raw_agg = resp_obj.get("statsResultAggregation", {})
            if raw_agg and "fields" in raw_agg:
                for f in raw_agg["fields"]:
                    fname = f.get("fieldName", "")
                    b_count = f.get("baselineEventCount", 0)
                    e_count = f.get("eventCount", 0)
                    v_count = f.get("valueCount", 0)
                    vals = []
                    for v in f.get("allValues", []):
                        raw_v = _extract_val(v.get("value"))
                        vals.append(
                            StatsValueCount(
                                value=raw_v,
                                event_count=v.get("eventCount", 0),
                                baseline_event_count=v.get("baselineEventCount", 0),
                            )
                        )
                    aggregations.append(
                        StatsFieldAggregation(
                            field_name=fname,
                            baseline_event_count=b_count,
                            event_count=e_count,
                            value_count=v_count,
                            all_values=vals,
                        )
                    )

        # Assemble row records from columns
        rows: List[Dict[str, Any]] = []
        if columns:
            max_rows = max(len(c.values) for c in columns)
            if total_results == 0:
                total_results = max_rows
            for i in range(max_rows):
                row_dict: Dict[str, Any] = {}
                for col in columns:
                    row_dict[col.column] = col.values[i] if i < len(col.values) else None
                rows.append(row_dict)

        return StatsSearchResult(
            columns=columns,
            rows=rows,
            total_results=total_results,
            filtered_result_count=filtered_result_count,
            data_query_expression=data_query_expr,
            aggregations=aggregations,
            progress=progress,
            complete=complete,
            operation_id=operation_id,
            raw_response=res if isinstance(res, (dict, list)) else None,
            retrieved_at=datetime.now(timezone.utc),
        )

    def cancel_operation(self, operation_id: str) -> None:
        """Translates search.cancel domain operation to :cancel API."""
        if operation_id.startswith("projects/"):
            path = f"/v1alpha/{operation_id}:cancel"
        else:
            path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/operations/{operation_id}:cancel"

        try:
            self._request("POST", path, body={})
        except RuntimeError as e:
            # If the operation is already done/cancelled/expired (HTTP 404 or not found), cancellation is idempotent
            err_str = str(e).lower()
            if "404" in err_str or "not found" in err_str or "already finished" in err_str:
                return
            logger.warning(f"Error cancelling operation {operation_id}: {e}")
            raise

    def fetch_enriched_event(self, event_id: str) -> Dict[str, Any]:
        """Fetches full enriched UDM event by event ID from Google SecOps."""
        # Convert standard base64 to RFC 4648 section 5 URL-safe unpadded base64
        b64url_id = event_id.rstrip("=").replace("+", "-").replace("/", "_")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/events/{b64url_id}:fetchEnrichedEvent"
        res = self._request("GET", path)
        if isinstance(res, dict) and "udm" in res:
            return res["udm"]
        return res if isinstance(res, dict) else {}

    def get_raw_log(self, event_id: str, log_token: Optional[str] = None) -> RawLogPayload:
        """Fetches and decodes the unparsed raw log associated with an event ID."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacy:legacyFindRawLogs"
        params: Dict[str, Any] = {
            "ids": event_id,
            "caseSensitive": "false",
            "maxResponseByteSize": 300000000,
            "query": "",
            "regexSearch": "false",
        }
        if log_token:
            params["batchToken"] = log_token

        res = self._request("GET", path, params=params)
        raw_logs_group = res.get("rawLogs", [])
        if not raw_logs_group:
            raise RuntimeError(f"No raw log found for event ID: {event_id}")

        first_entry = raw_logs_group[0]
        inner_entries = first_entry.get("rawLogs", [first_entry])
        if not inner_entries:
            raise RuntimeError(f"Empty raw logs payload returned for event ID: {event_id}")

        entry = inner_entries[0]
        log_bytes_b64 = entry.get("logBytes", "")
        if log_bytes_b64:
            decoded_text = base64.b64decode(log_bytes_b64).decode("utf-8", errors="replace")
        else:
            decoded_text = ""

        return RawLogPayload(
            raw_text=decoded_text,
            source_product=entry.get("sourceProduct", ""),
            log_type=entry.get("type", ""),
            timestamp=entry.get("timestamp"),
            raw_bytes_size=len(decoded_text.encode("utf-8")),
            retrieved_at=datetime.now(timezone.utc),
        )

    def query_product_source_stats(
        self,
        start_time: str,
        end_time: str,
    ) -> Dict[str, Any]:
        """Queries product source statistics and ingested data sizes across the evaluation window."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:queryProductSourceStats"
        params = {
            "timeRange.startTime": start_time,
            "timeRange.endTime": end_time,
        }
        res = self._request("GET", path, params=params)
        return res if isinstance(res, dict) else {}

    def validate_raw_log_query(
        self,
        raw_query: str,
        allow_unreplaced_placeholders: bool = False,
    ) -> Dict[str, Any]:
        """Validates raw log query syntax against Chronicle query engine.

        Dialect: ``DIALECT_UDM_SEARCH`` is correct for raw log search. Verified
        live 2026-10-10: ``raw = "sshd"`` validates as
        ``QUERY_TYPE_RAW_LOG_QUERY`` under this dialect, while a bare ``sshd``
        or ``"sshd"`` is rejected both here and by ``:searchRawLogs`` itself
        (HTTP 400). ``DIALECT_LEGACY`` rejects both forms. The validateQuery
        Dialect enum has no raw-log value.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:validateQuery"
        params = {
            "allowUnreplacedPlaceholders": "true" if allow_unreplaced_placeholders else "false",
            "dialect": "DIALECT_UDM_SEARCH",
            "rawQuery": raw_query,
        }
        res = self._request("GET", path, params=params)
        return res if isinstance(res, dict) else {}

    def search_raw_logs(
        self,
        query: str,
        start_time: str,
        end_time: str,
        log_types: Optional[List[str]] = None,
        case_sensitive: bool = False,
        max_aggregations: int = 60,
        page_size: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Executes raw log search across ingested unparsed or unnormalized logs."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:searchRawLogs"
        body = {
            "baselineQuery": query,
            "baselineTimeRange": {"startTime": start_time, "endTime": end_time},
            "snapshotQuery": "",
            "caseSensitive": case_sensitive,
            "logTypes": log_types or [],
            "maxAggregationsPerField": max_aggregations,
            "pageSize": page_size,
        }
        res = self._request("POST", path, body=body)
        if isinstance(res, list):
            return [x for x in res if isinstance(x, dict)]
        elif isinstance(res, dict):
            return [res]
        return []

    def get_case(self, case_id: str) -> Dict[str, Any]:
        """Fetches raw case metadata by case ID."""
        case_id_clean = case_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}"
        res = self._request("GET", path)
        if not isinstance(res, dict) or "name" not in res:
            raise RuntimeError(f"Case '{case_id}' not found or invalid response from SecOps.")
        return res

    def update_case(
        self,
        case_id: str,
        updates: Dict[str, Any],
        update_mask: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates case metadata and returns the confirmed case record."""
        raw_id = case_id.split("/")[-1]
        case_id_clean = urllib.parse.quote(raw_id, safe="")
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}"
        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = update_mask
        body = dict(updates)
        if "name" not in body:
            body["name"] = f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{raw_id}"
        res = self._request("PATCH", path, body=body, params=params if params else None)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to update case {case_id}: invalid provider response.")
        return res

    def list_case_alerts(
        self,
        case_id: str,
        expand: Optional[str] = None,
        filter: Optional[str] = None,
        page_size: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Lists all alerts associated with a specific case."""
        case_id_clean = urllib.parse.quote(case_id.split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}/caseAlerts"
        params: Dict[str, Any] = {}
        if expand:
            params["expand"] = expand
        if filter:
            params["filter"] = filter
        if page_size:
            params["pageSize"] = page_size
        res = self._request("GET", path, params=params if params else None)
        if isinstance(res, dict):
            return res.get("caseAlerts", [])
        return []

    def list_cases(
        self,
        filter: str = "",
        page_size: int = 1000,
        page_token: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists cases from the native ``cases`` collection (one page).

        ``GET /v1alpha/projects/{project}/locations/{loc}/instances/{customer}/cases``.
        Returns the raw response dict: ``cases`` (list), ``nextPageToken`` and
        ``totalSize``. The server rejects ``pageSize`` > 1000 with HTTP 400 and
        defaults to 50 when it is omitted. ``filter`` uses quoted string literals
        (``status="OPENED" AND environment="Demoverse"``); invalid filters raise
        :class:`SecOpsApiError`. See
        ``discovery/observations/04_case_list_native_collection.md``.
        """
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases"
        params: Dict[str, Any] = {}
        if page_size:
            params["pageSize"] = int(page_size)
        if filter:
            params["filter"] = filter
        if page_token:
            params["pageToken"] = page_token
        if order_by:
            params["orderBy"] = order_by
        # The endpoint intermittently answers valid requests with HTTP 500
        # "Internal error encountered" (~3 in 110 live calls; each identical
        # request succeeded on retry). _request does not retry 500, so this
        # idempotent GET retries a bounded number of times, then re-raises.
        max_500_retries = 2
        attempt = 0
        while True:
            try:
                res = self._request("GET", path, params=params if params else None)
                break
            except SecOpsApiError as e:
                if e.status != 500 or attempt >= max_500_retries:
                    raise
                attempt += 1
                logger.warning("list_cases: transient HTTP 500, retry %d/%d", attempt, max_500_retries)
                time.sleep(1.0 * attempt)
        if not isinstance(res, dict):
            raise RuntimeError("Failed to list cases: invalid provider response (expected JSON object).")
        return res

    def get_case_alert(self, alert_name: str) -> Dict[str, Any]:
        """Fetches specific alert details by resource name."""
        clean_name = alert_name.lstrip("/")
        if not clean_name.startswith("projects/"):
            clean_name = f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/{clean_name}"
        path = f"/v1alpha/{clean_name}"
        res = self._request("GET", path)
        if not isinstance(res, dict) or "name" not in res:
            raise RuntimeError(f"Case Alert '{alert_name}' not found.")
        return res

    def update_case_alert(
        self,
        case_id: str,
        alert_id: str,
        updates: Dict[str, Any],
        update_mask: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates case alert details (e.g. priority, status) and returns the confirmed record."""
        raw_case_id = case_id.split("/")[-1]
        raw_alert_id = alert_id.split("/")[-1]
        case_id_clean = urllib.parse.quote(raw_case_id, safe="")
        alert_id_clean = urllib.parse.quote(raw_alert_id, safe="")
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}/caseAlerts/{alert_id_clean}"
        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = update_mask
        body = dict(updates)
        if "name" not in body:
            body["name"] = f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{raw_case_id}/caseAlerts/{raw_alert_id}"
        res = self._request("PATCH", path, body=body, params=params if params else None)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to update alert {alert_id} for case {case_id}: invalid provider response.")
        return res

    def create_case_alert_recommendation(
        self,
        case_id: str,
        alert_id: str,
    ) -> Dict[str, Any]:
        """Initiates an asynchronous request to generate a Gemini AI recommendation for a case alert."""
        raw_case_id = case_id.split("/")[-1]
        raw_alert_id = alert_id.split("/")[-1]
        case_id_clean = urllib.parse.quote(raw_case_id, safe="")
        alert_id_clean = urllib.parse.quote(raw_alert_id, safe="")
        path = f"/v1/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}/caseAlerts/{alert_id_clean}:createRecommendationLongRunning"
        res = self._request("POST", path, body={})
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to create recommendation for alert {alert_id} in case {case_id}: invalid response.")
        return res

    def fetch_case_alert_recommendation(
        self,
        case_id: str,
        recommendation_id: str,
    ) -> Dict[str, Any]:
        """Fetches a previously generated AI recommendation for a case alert using its recommendationId."""
        raw_case_id = case_id.split("/")[-1]
        case_id_clean = urllib.parse.quote(raw_case_id, safe="")
        path = f"/v1/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}/caseAlerts:fetchRecommendation"
        params = {"recommendationId": recommendation_id}
        res = self._request("GET", path, params=params)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to fetch recommendation {recommendation_id} for case {case_id}: invalid response.")
        return res

    def get_or_create_case_summary(self, case_id: str) -> Dict[str, Any]:
        """Gets or initiates creation of an AI-driven summary for a SOAR case using v1alpha endpoint."""
        raw_case_id = case_id.split("/")[-1]
        case_id_clean = urllib.parse.quote(raw_case_id, safe="")
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}:getOrCreateCaseSummary"
        res = self._request("POST", path, body={})
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to get/create summary for case {case_id}: invalid response.")
        return res

    def batch_attach_case_evidence(
        self,
        case_id: Union[str, int],
        evidence_requests: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Batch attaches evidence items (e.g. EVIDENCE_TYPE_DETECTION, EVIDENCE_TYPE_EVENT) to a case.

        Args:
            case_id: The ID or resource name of the case.
            evidence_requests: List of evidence items or requests. Each item should have 'evidenceId'
                and 'evidenceType', e.g.
                {'evidenceId': '...', 'evidenceType': 'EVIDENCE_TYPE_DETECTION'}
                or wrapped as {'attachCaseEvidenceRequest': {'evidenceId': ..., 'evidenceType': ...}}.

        Returns:
            Dict containing 'caseEvidences' list.
        """
        raw_case_id = str(case_id).split("/")[-1]
        case_id_clean = urllib.parse.quote(raw_case_id, safe="")
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}:batchAttachEvidence"

        formatted_requests = []
        for req in evidence_requests:
            if "attachCaseEvidenceRequest" in req:
                formatted_requests.append(req)
            elif "evidenceId" in req and "evidenceType" in req:
                formatted_requests.append({
                    "attachCaseEvidenceRequest": {
                        "evidenceId": req["evidenceId"],
                        "evidenceType": req["evidenceType"],
                    }
                })
            else:
                formatted_requests.append(req)

        body = {"requests": formatted_requests}
        res = self._request("POST", path, body=body)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to attach evidence to case {case_id}: invalid provider response.")
        return res

    def batch_detach_case_evidence(
        self,
        case_id: Union[str, int],
        evidence_requests: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Batch detaches evidence items from a case.

        Args:
            case_id: The ID or resource name of the case.
            evidence_requests: List of items. Each item must have 'evidenceId' and 'evidenceType',
                e.g. {'evidenceId': '...', 'evidenceType': 'EVIDENCE_TYPE_DETECTION'}.

        Returns:
            Dict response (empty on success).
        """
        raw_case_id = str(case_id).split("/")[-1]
        case_id_clean = urllib.parse.quote(raw_case_id, safe="")
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}:batchDetachEvidence"

        formatted_requests = []
        for req in evidence_requests:
            if "evidenceId" in req and "evidenceType" in req:
                formatted_requests.append({
                    "evidenceId": req["evidenceId"],
                    "evidenceType": req["evidenceType"],
                })
            else:
                formatted_requests.append(req)

        body = {"requests": formatted_requests}
        res = self._request("POST", path, body=body)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to detach evidence from case {case_id}: invalid provider response.")
        return res

    def list_remediation_plans(
        self,
        case_id: Optional[Union[str, int]] = None,
        filter: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists AI-generated agentic response / remediation plans for cases or alerts.

        Args:
            case_id: Optional case ID or case resource name to filter by.
            filter: Optional Chronicle filter expression (e.g. 'caseId = 108188').
            page_size: Optional max number of results per page.
            page_token: Optional pagination page token.

        Returns:
            Dict containing 'remediationPlans' list and 'totalSize'.
        """
        proj = self.project_number or self.project_id
        path = f"/v1alpha/projects/{proj}/locations/{self.location}/instances/{self.customer_id}/remediationPlans"
        params: Dict[str, Any] = {}
        if filter:
            params["filter"] = filter
        elif case_id is not None:
            raw_case_id = str(case_id).split("/")[-1]
            params["filter"] = f"caseId = {raw_case_id}"
        if page_size is not None:
            params["pageSize"] = int(page_size)
        if page_token is not None:
            params["pageToken"] = str(page_token)
        res = self._request("GET", path, params=params)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to list remediation plans: invalid response {type(res)}.")
        return res

    def get_remediation_plan(self, plan_id: str) -> Dict[str, Any]:
        """Fetches a specific AI-generated agentic response / remediation plan.

        Args:
            plan_id: The remediation plan ID (e.g. '45') or full resource path.

        Returns:
            Dict containing the remediation plan details and embedded actions.
        """
        raw_plan_id = str(plan_id).split("/")[-1]
        plan_id_clean = urllib.parse.quote(raw_plan_id, safe="")
        proj = self.project_number or self.project_id
        path = f"/v1alpha/projects/{proj}/locations/{self.location}/instances/{self.customer_id}/remediationPlans/{plan_id_clean}"
        res = self._request("GET", path)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to get remediation plan {plan_id}: invalid response {type(res)}.")
        return res

    def list_remediation_actions(
        self,
        plan_id: str,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists actions belonging to an AI-generated remediation plan.

        Args:
            plan_id: The remediation plan ID or resource path.
            page_size: Optional pagination page size.
            page_token: Optional pagination token.

        Returns:
            Dict containing 'remediationActions' list and 'totalSize'.
        """
        raw_plan_id = str(plan_id).split("/")[-1]
        plan_id_clean = urllib.parse.quote(raw_plan_id, safe="")
        proj = self.project_number or self.project_id
        path = f"/v1alpha/projects/{proj}/locations/{self.location}/instances/{self.customer_id}/remediationPlans/{plan_id_clean}/remediationActions"
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = int(page_size)
        if page_token is not None:
            params["pageToken"] = str(page_token)
        res = self._request("GET", path, params=params)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to list remediation actions for plan {plan_id}: invalid response {type(res)}.")
        return res

    def get_remediation_action(self, plan_id: str, action_id: str) -> Dict[str, Any]:
        """Fetches an individual remediation action from a remediation plan.

        Args:
            plan_id: The remediation plan ID or resource path.
            action_id: The remediation action ID or resource path.

        Returns:
            Dict containing the action details.
        """
        raw_plan_id = str(plan_id).split("/")[-1]
        raw_action_id = str(action_id).split("/")[-1]
        plan_id_clean = urllib.parse.quote(raw_plan_id, safe="")
        action_id_clean = urllib.parse.quote(raw_action_id, safe="")
        proj = self.project_number or self.project_id
        path = f"/v1alpha/projects/{proj}/locations/{self.location}/instances/{self.customer_id}/remediationPlans/{plan_id_clean}/remediationActions/{action_id_clean}"
        res = self._request("GET", path)
        if not isinstance(res, dict):
            raise RuntimeError(f"Failed to get remediation action {action_id} for plan {plan_id}: invalid response {type(res)}.")
        return res

    def list_alert_entities(self, alert_name: str) -> List[Dict[str, Any]]:
        """Lists all involved entities for a specific alert."""
        clean_name = alert_name.lstrip("/")
        if not clean_name.startswith("projects/"):
            clean_name = f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/{clean_name}"
        path = f"/v1alpha/{clean_name}/involvedEntities"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res.get("involvedEntities", [])
        return []

    def add_case_alert_entity(
        self,
        case_id: str,
        case_alert_id: str,
        identifier: str,
        entity_type: str = "IP",
    ) -> Dict[str, Any]:
        """Manually attaches an involved entity to a specific case alert."""
        if not identifier or not str(identifier).strip():
            raise ValueError("Entity identifier cannot be empty.")
        clean_case_id = str(case_id).strip().split("/")[-1]
        clean_alert_id = str(case_alert_id).strip().split("/")[-1]
        path = (
            f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/"
            f"cases/{clean_case_id}/caseAlerts/{clean_alert_id}/involvedEntities"
        )
        body = {
            "identifier": str(identifier).strip(),
            "type": str(entity_type).strip(),
        }
        res = self._request("POST", path, body=body)
        return res if isinstance(res, dict) else {}

    def search_unique_entities(
        self,
        filter_expr: Optional[str] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Searches or lists unique entities across the SecOps instance."""
        path = (
            f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/"
            f"uniqueEntities"
        )
        params: Dict[str, Any] = {"pageSize": min(page_size, 500)}
        if filter_expr and str(filter_expr).strip():
            params["filter"] = str(filter_expr).strip()
        if page_token and str(page_token).strip():
            params["pageToken"] = str(page_token).strip()
        res = self._request("GET", path, params=params)
        return res if isinstance(res, dict) else {}


    def list_case_comments(self, case_id: str) -> List[Dict[str, Any]]:
        """Lists all comments associated with a case."""
        case_id_clean = case_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}/caseComments"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res.get("caseComments", [])
        return []

    def create_case_comment(self, case_id: str, comment: str) -> Dict[str, Any]:
        """Posts a new comment to a case and returns the confirmed comment record."""
        if not comment or not comment.strip():
            raise ValueError("Comment text cannot be empty.")
        case_id_clean = case_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}/caseComments"
        body = {"comment": comment.strip()}
        res = self._request("POST", path, body=body)
        if not isinstance(res, dict) or "name" not in res:
            raise RuntimeError(f"Failed to post comment to case {case_id}: invalid provider response.")
        return res

    def list_case_wall_records(
        self,
        case_id: str,
        page_size: int = 50,
        page_token: Optional[str] = None,
        filter_str: Optional[str] = None,
        order_by: str = "createTime desc",
    ) -> Dict[str, Any]:
        """Lists activity records from the case activity wall."""
        case_id_clean = case_id.split("/")[-1]
        query_params = {
            "pageSize": str(page_size),
            "orderBy": order_by,
        }
        if filter_str:
            query_params["filter"] = filter_str
        else:
            query_params["filter"] = f"caseId = {case_id_clean}"

        if page_token:
            query_params["pageToken"] = page_token

        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/cases/{case_id_clean}/caseWallRecords"
        res = self._request("GET", path, params=query_params)
        if isinstance(res, dict):
            return res
        return {"caseWallRecords": []}

    def search_cases(
        self,
        query_text: str = "",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        tags: Optional[List[str]] = None,
        priorities: Optional[List[str]] = None,
        stages: Optional[List[str]] = None,
        environments: Optional[List[str]] = None,
        assigned_users: Optional[List[str]] = None,
        is_important: Optional[bool] = None,
        page_size: int = 50,
        page_number: int = 0,
    ) -> Dict[str, Any]:
        """Executes free-form and multi-facet search across SOAR cases."""
        now = datetime.now(timezone.utc)
        if end_time is None:
            end_time = now
        if start_time is None:
            start_time = end_time - timedelta(days=30)

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.999Z")

        payload: Dict[str, Any] = {
            "startTime": start_str,
            "endTime": end_str,
            "title": query_text or "",
            "tags": tags or [],
            "ruleGenerator": [],
            "caseSource": [],
            "stage": stages or [],
            "environments": environments or [],
            "assignedUsers": assigned_users or [],
            "products": [],
            "ports": [],
            "categoryOutcomes": [],
            "importance": [is_important] if is_important is not None else [],
            "priorities": priorities or [],
            "incident": [],
            "timeRangeFilter": "CUSTOM",
            "paging": {"pageSize": page_size, "requestedPage": page_number},
            "pageSize": page_size,
            "requestedPage": page_number,
        }

        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/legacySearches:legacyCaseSearchEverything"
        res = self._request("POST", path, body=payload)
        if not isinstance(res, dict):
            return {"results": [], "totalCount": 0, "pageSize": page_size}
        return res

    def get_case_filter_values(
        self,
        filter_type: str,
        search_term: str = "",
        limit: int = 20,
    ) -> List[str]:
        """Retrieves facet filter suggestions for cases (ENVIRONMENTS, TAGS, etc.)."""
        payload = {
            "typeOfFilter": filter_type,
            "numberOfValuesToReturn": limit,
            "searchTerm": search_term,
        }
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/legacySearches:legacyGetCasesFilterValues"
        res = self._request("POST", path, body=payload)
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], list):
            return res["payload"]
        return []

    def get_playbook_menu_cards(
        self,
        playbook_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Lists playbook summary cards with environment/type filter."""
        types = playbook_types or ["NESTED", "REGULAR"]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyGetWorkflowMenuCardsWithEnvFilter"
        res = self._request("POST", path, body={"legacyPayload": types})
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], list):
            return res["payload"]
        elif isinstance(res, list):
            return res
        return []

    def get_playbook_categories(self) -> List[Dict[str, Any]]:
        """Lists all SOAR Playbook categories/folders."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyGetWorkflowCategories"
        res = self._request("GET", path)
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], list):
            return res["payload"]
        elif isinstance(res, list):
            return res
        return []

    def get_playbook_full_info(self, workflow_identifier: str) -> Dict[str, Any]:
        """Fetches complete playbook definition by UUID identifier."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyGetWorkflowFullInfoWithEnvFilterByIdentifier"
        res = self._request("GET", path, params={"workflowIdentifier": workflow_identifier})
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], dict):
            return res["payload"]
        elif isinstance(res, dict):
            return res
        return {}

    def get_playbook_stats(self, original_workflow_identifier: str) -> Dict[str, Any]:
        """Fetches execution statistics for a playbook workflow."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyGetPlaybookStatsMap"
        res = self._request("POST", path, body={"originalWorkflowIdentifier": original_workflow_identifier})
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], dict):
            return res["payload"]
        elif isinstance(res, dict):
            return res
        return {}

    def get_workflow_instances_cards(
        self,
        case_id: str,
        alert_identifier: str,
    ) -> List[Dict[str, Any]]:
        """Lists playbook run-instance summary cards for a specific alert.

        Wraps ``legacyPlaybooks:legacyGetWorkflowInstancesCards``. ``alert_identifier``
        is the opaque ``alertGroupIdentifier`` string associated with the alert.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyGetWorkflowInstancesCards"
        body = {"caseId": str(case_id), "alertIdentifier": alert_identifier}
        res = self._request("POST", path, body=body)
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], list):
            return res["payload"]
        elif isinstance(res, list):
            return res
        return []

    def get_workflow_instance(
        self,
        case_id: str,
        alert_identifier: str,
        definition_identifier: str,
        should_fetch_steps: bool = True,
        collapse_blocks: bool = True,
        loops_requested_iterations: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Fetches the full playbook run instance (incl. step DAG) for an alert.

        Wraps ``legacyPlaybooks:legacyGetWorkflowInstance``. ``definition_identifier``
        is the playbook UUID (obtained from a workflow-instance card).
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyGetWorkflowInstance"
        body = {
            "caseId": str(case_id),
            "alertIdentifier": alert_identifier,
            "shouldFetchSteps": bool(should_fetch_steps),
            "definitionIdentifier": definition_identifier,
            "collapseBlocks": bool(collapse_blocks),
            "loopsRequestedIterations": loops_requested_iterations or [],
        }
        res = self._request("POST", path, body=body)
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], dict):
            return res["payload"]
        elif isinstance(res, dict):
            return res
        return {}

    def save_playbook(
        self,
        playbook_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Creates or updates a SOAR playbook or block workflow definition.

        Wraps ``legacyPlaybooks:legacySaveWorkflowDefinitions``. Note that the
        v1alpha REST endpoint expects the workflow definition dictionary directly
        as the top-level JSON request body (not wrapped in ``workflowDefinitions``).
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacySaveWorkflowDefinitions"
        res = self._request("POST", path, body=playbook_payload)
        if isinstance(res, dict) and "payload" in res and isinstance(res["payload"], dict):
            return res["payload"]
        elif isinstance(res, dict):
            return res
        return {}

    def delete_playbooks(
        self,
        identifiers: List[str],
    ) -> Dict[str, Any]:
        """Deletes one or more SOAR playbooks by UUID identifier.

        Wraps ``legacyPlaybooks:legacyDeleteWorkflows``.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyDeleteWorkflows"
        res = self._request("POST", path, body={"identifiers": list(identifiers)})
        if isinstance(res, dict):
            return res
        return {}

    def export_playbooks(
        self,
        identifiers: List[str],
    ) -> Dict[str, Any]:
        """Exports one or more SOAR playbooks into a portable package payload.

        Wraps ``legacyPlaybooks:legacyExportWorkflows``.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyExportWorkflows"
        res = self._request("POST", path, body={"identifiers": list(identifiers)})
        if isinstance(res, dict):
            return res
        return {}

    def import_playbooks(
        self,
        blob_base64: str,
        import_as_duplicates: bool = False,
        environments_map: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Imports a base64-encoded SOAR playbook package payload.

        Wraps ``legacyPlaybooks:legacyImportWorkflows``.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacyPlaybooks:legacyImportWorkflows"
        body: Dict[str, Any] = {
            "blob": blob_base64,
            "importAsDuplicates": bool(import_as_duplicates),
        }
        if environments_map:
            body["environmentsMap"] = environments_map
        res = self._request("POST", path, body=body)
        if isinstance(res, dict):
            return res
        return {}

    # =========================================================================
    # Milestone 5.4: SOAR Integrations, Instances & Remote Agents API Methods
    # =========================================================================

    def list_integrations(
        self,
        filter_expr: Optional[str] = None,
        page_size: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Lists SOAR base integration catalog items."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations"
        params: Dict[str, Any] = {"pageSize": page_size}
        if filter_expr:
            params["filter"] = filter_expr
        res = self._request("GET", path, params=params)
        if isinstance(res, dict) and "integrations" in res and isinstance(res["integrations"], list):
            return res["integrations"]
        elif isinstance(res, list):
            return res
        return []

    def list_integration_instances(
        self,
        integration_id: Optional[str] = None,
        environment: Optional[str] = None,
        page_size: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Lists configured integration instances across environments or for a specific integration."""
        if integration_id:
            clean_id = urllib.parse.quote(integration_id.strip().split("/")[-1], safe="")
            path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_id}/integrationInstances"
        else:
            path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/-/integrationInstances"
        params: Dict[str, Any] = {"pageSize": page_size}
        if environment:
            params["filter"] = f"environment = '{environment}'"
        res = self._request("GET", path, params=params)
        if isinstance(res, dict) and "integrationInstances" in res and isinstance(res["integrationInstances"], list):
            return res["integrationInstances"]
        elif isinstance(res, list):
            return res
        return []

    def get_integration_instance(
        self,
        integration_id: str,
        instance_id: str,
    ) -> Dict[str, Any]:
        """Retrieves a specific configured integration instance."""
        clean_int = urllib.parse.quote(integration_id.strip().split("/")[-1], safe="")
        clean_inst = urllib.parse.quote(instance_id.strip().split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_int}/integrationInstances/{clean_inst}"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def get_integration_instance_affected_items(
        self,
        integration_id: str,
        instance_id: str,
    ) -> Dict[str, Any]:
        """Retrieves downstream playbooks and items affected by an integration instance."""
        clean_int = urllib.parse.quote(integration_id.strip().split("/")[-1], safe="")
        clean_inst = urllib.parse.quote(instance_id.strip().split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_int}/integrationInstances/{clean_inst}:fetchAffectedItems"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def delete_integration_instance(
        self,
        integration_id: str,
        instance_id: str,
    ) -> Dict[str, Any]:
        """Deletes a configured integration instance."""
        clean_int = urllib.parse.quote(integration_id.strip().split("/")[-1], safe="")
        clean_inst = urllib.parse.quote(instance_id.strip().split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_int}/integrationInstances/{clean_inst}"
        res = self._request("DELETE", path)
        if isinstance(res, dict):
            return res
        return {}


    def list_remote_agents(
        self,
        state_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lists remote proxy execution agents."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/remoteAgents"
        params: Dict[str, Any] = {"pageSize": 100}
        if state_filter:
            params["filter"] = f'agentState = "{state_filter}"'
        res = self._request("GET", path, params=params)
        if isinstance(res, dict) and "remoteAgents" in res and isinstance(res["remoteAgents"], list):
            return res["remoteAgents"]
        elif isinstance(res, list):
            return res
        return []

    def get_marketplace_integration(
        self,
        identifier: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves marketplace metadata and documentation for an integration."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/marketplaceIntegrations"
        params = {
            "filter": f"identifier = '{identifier}'",
            "pageSize": 50,
        }
        res = self._request("GET", path, params=params)
        if isinstance(res, dict) and "marketplaceIntegrations" in res:
            mp_list = res.get("marketplaceIntegrations", [])
            if mp_list and isinstance(mp_list, list):
                return mp_list[0]
        return None
    # =========================================================================
    # Milestone 5.5: SOAR Scheduled Jobs, Instances & Execution Logs
    # =========================================================================

    def list_jobs(
        self,
        integration: Optional[str] = None,
        enabled: Optional[bool] = None,
        exclude_staging: bool = True,
        page_size: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Lists SOAR scheduled job definitions."""
        int_segment = integration or "-"
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{int_segment}/jobs"
        params: Dict[str, Any] = {
            "excludeStaging": str(exclude_staging).lower(),
            "pageSize": page_size,
        }
        if enabled is not None:
            params["filter"] = f"enabled = {str(enabled).lower()}"
        res = self._request("GET", path, params=params)
        if isinstance(res, dict) and "jobs" in res and isinstance(res["jobs"], list):
            return res["jobs"]
        elif isinstance(res, list):
            return res
        return []

    def get_job(
        self,
        integration: str,
        job_id: str,
    ) -> Dict[str, Any]:
        """Retrieves a specific SOAR job definition."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{integration}/jobs/{job_id}"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def list_job_instances(
        self,
        integration: Optional[str] = None,
        job_id: Optional[str] = None,
        page_size: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Lists runtime job instances across environments."""
        int_segment = integration or "-"
        job_segment = job_id or "-"
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{int_segment}/jobs/{job_segment}/jobInstances"
        params: Dict[str, Any] = {"pageSize": page_size}
        res = self._request("GET", path, params=params)
        if isinstance(res, dict) and "jobInstances" in res and isinstance(res["jobInstances"], list):
            return res["jobInstances"]
        elif isinstance(res, list):
            return res
        return []

    def get_job_instance(
        self,
        integration: str,
        job_id: str,
        instance_id: str,
    ) -> Dict[str, Any]:
        """Retrieves a specific runtime job instance."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{integration}/jobs/{job_id}/jobInstances/{instance_id}"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def get_job_instance_logs(
        self,
        instance_id: str,
        page_size: int = 20,
        order_by: str = "endTime desc",
    ) -> Dict[str, Any]:
        """Retrieves execution logs for a specific job instance."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/-/jobs/-/jobInstances/{instance_id}/logs"
        params: Dict[str, Any] = {
            "pageSize": page_size,
            "orderBy": order_by,
        }
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"logs": [], "totalSize": 0}

    def update_job(
        self,
        integration: str,
        job_id: str,
        job_payload: Dict[str, Any],
        update_mask: str = "script",
    ) -> Dict[str, Any]:
        """Updates a SOAR scheduled job definition via PATCH with updateMask."""
        clean_int = urllib.parse.quote(str(integration).strip().split("/")[-1], safe="")
        clean_job = urllib.parse.quote(str(job_id).strip().split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_int}/jobs/{clean_job}"
        params: Dict[str, Any] = {"updateMask": update_mask} if update_mask else {}
        res = self._request("PATCH", path, params=params, body=job_payload)
        if isinstance(res, dict):
            return res
        return {}

    def update_job_instance(
        self,
        integration: str,
        job_id: str,
        instance_id: str,
        instance_payload: Dict[str, Any],
        update_mask: str = "script",
    ) -> Dict[str, Any]:
        """Updates a configured runtime SOAR job instance via PATCH with updateMask."""
        clean_int = urllib.parse.quote(str(integration).strip().split("/")[-1], safe="")
        clean_job = urllib.parse.quote(str(job_id).strip().split("/")[-1], safe="")
        clean_inst = urllib.parse.quote(str(instance_id).strip().split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_int}/jobs/{clean_job}/jobInstances/{clean_inst}"
        params: Dict[str, Any] = {"updateMask": update_mask} if update_mask else {}
        res = self._request("PATCH", path, params=params, body=instance_payload)
        if isinstance(res, dict):
            return res
        return {}

    def create_job_instance(
        self,
        integration: str,
        job_id: str,
        instance_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Creates a new runtime SOAR job instance under a job definition."""
        clean_int = urllib.parse.quote(str(integration).strip().split("/")[-1], safe="")
        clean_job = urllib.parse.quote(str(job_id).strip().split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_int}/jobs/{clean_job}/jobInstances"
        res = self._request("POST", path, body=instance_payload)
        if isinstance(res, dict):
            return res
        return {}

    # ==========================================================================
    # Milestone 5.6: Content Hub (Marketplace) - Content Packs Methods
    # ==========================================================================

    def list_content_packs(
        self,
        query_filter: Optional[str] = None,
        page_size: int = 100,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists Content Packs from Content Hub Marketplace with optional expands and filter."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/contentHub/contentPacks"
        params: Dict[str, Any] = {
            "pageSize": page_size,
            "expand": expand or "playbooks,testCases,connectorInstances,connectorDefinitions,integrations,detectionRules,searchQueries,dashboards,ruleSets",
        }
        if query_filter:
            params["filter"] = query_filter
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"contentPacks": [], "totalSize": 0}

    def get_content_pack(
        self,
        pack_id: str,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieves a specific Content Pack from Content Hub by identifier or resource name."""
        # Strip resource name prefix if passed
        clean_id = pack_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/contentHub/contentPacks/{clean_id}"
        params: Dict[str, Any] = {
            "expand": expand or "playbooks,testCases,connectorInstances,connectorDefinitions,integrations,detectionRules,searchQueries,dashboards,ruleSets",
        }
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {}

    # --- Milestone 5.7: Curated Detections Methods ---

    def list_curated_ruleset_categories(self) -> Dict[str, Any]:
        """Lists all Curated Rule Set categories."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/curatedRuleSetCategories"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {"curatedRuleSetCategories": []}

    def list_curated_rulesets(
        self,
        category_id: Optional[str] = None,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists Curated Rule Sets across all categories or within a specific category."""
        cat_token = category_id.split("/")[-1] if category_id else "-"
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/curatedRuleSetCategories/{cat_token}/curatedRuleSets"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"curatedRuleSets": []}

    def get_curated_ruleset(self, ruleset_id_or_name: str) -> Dict[str, Any]:
        """Gets one Curated Rule Set by ID (category wildcard ``-``) or full resource name."""
        clean = ruleset_id_or_name.strip()
        if clean.startswith("projects/"):
            path = f"/v1alpha/{clean}"
        else:
            path = (
                f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}"
                f"/curatedRuleSetCategories/-/curatedRuleSets/{clean.split('/')[-1]}"
            )
        return self._request("GET", path)

    def list_curated_ruleset_deployments(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists precision deployments (enabled/alerting) of every Curated Rule Set in one call.

        Uses the ``-`` wildcard for category and rule set:
        ``curatedRuleSetCategories/-/curatedRuleSets/-/curatedRuleSetDeployments``.
        """
        path = (
            f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}"
            "/curatedRuleSetCategories/-/curatedRuleSets/-/curatedRuleSetDeployments"
        )
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_curated_ruleset_deployments(self, curated_ruleset_name: str) -> Dict[str, Any]:
        """Retrieves deployment states (broad/precise, enabled, alerting) for a Curated Rule Set."""
        clean_name = curated_ruleset_name.strip()
        if not clean_name.startswith("projects/"):
            # If a simple ID was given, we cannot reliably reconstruct full path without category
            raise ValueError(f"Full resource name required for deployment status: '{curated_ruleset_name}'")
        path = f"/v1alpha/{clean_name}/curatedRuleSetDeployments"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {"curatedRuleSetDeployments": []}

    def update_curated_ruleset_deployment(
        self,
        deployment_name: str,
        enabled: Optional[bool] = None,
        alerting: Optional[bool] = None,
        sync_rules: bool = True,
    ) -> Dict[str, Any]:
        """Updates enabled and/or alerting states for a Curated Rule Set precision deployment."""
        clean_name = deployment_name.strip()
        if not clean_name.startswith("projects/"):
            raise ValueError(f"Full resource name required for deployment update: '{deployment_name}'")

        path = f"/v1alpha/{clean_name}"
        body: Dict[str, Any] = {"name": clean_name}
        mask_fields: List[str] = []
        if enabled is not None:
            body["enabled"] = enabled
            mask_fields.append("enabled")
        if alerting is not None:
            body["alerting"] = alerting
            mask_fields.append("alerting")

        if not mask_fields:
            raise ValueError("At least one field ('enabled' or 'alerting') must be specified for update")

        params: Dict[str, Any] = {
            "updateMask": ",".join(mask_fields),
        }
        if not sync_rules:
            params["ruleSetDeploymentSyncDisabled"] = True

        res = self._request("PATCH", path, params=params, body=body)
        if isinstance(res, dict):
            return res
        return {}

    def batch_update_curated_ruleset_deployments(
        self,
        requests: List[Dict[str, Any]],
        parent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates multiple Curated Rule Set deployments in a single batch request."""
        if not parent:
            parent = f"projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/curatedRuleSetCategories/-/curatedRuleSets/-"
        path = f"/v1alpha/{parent}/curatedRuleSetDeployments:batchUpdate"
        body = {"requests": requests}
        res = self._request("POST", path, body=body)
        if isinstance(res, dict):
            return res
        return {"deployments": []}

    def list_curated_rules(self, page_size: int = 1000, page_token: Optional[str] = None) -> Dict[str, Any]:
        """Lists Google-curated individual rules (one page; the endpoint has no filter)."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/curatedRules"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"curatedRules": []}

    def get_featured_content_rule(self, rule_id: str) -> Dict[str, Any]:
        """Retrieves a Curated Rule and its executable YARA-L logic from Content Hub."""
        clean_id = rule_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/contentHub/featuredContentRules"
        params = {"filter": f'rule_id:"{clean_id}"'}
        res = self._request("GET", path, params=params)
        if isinstance(res, dict) and res.get("featuredContentRules"):
            return res["featuredContentRules"][0]
        return {}

    def list_featured_content_rules(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists Curated Rules and their executable YARA-L logic from Content Hub Marketplace."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/contentHub/featuredContentRules"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if filter_expr:
            params["filter"] = filter_expr
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"featuredContentRules": []}

    def count_curated_ruleset_detections(
        self,
        start_time: str,
        end_time: str,
        timeout: Optional[float] = 120.0,
    ) -> Dict[str, Any]:
        """Aggregates detection firing counts for each curated rule set over a time window."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:countAllCuratedRuleSetDetections"
        body = {
            "interval": {
                "startTime": start_time,
                "endTime": end_time,
            }
        }
        res = self._request("POST", path, body=body, timeout=timeout)
        if isinstance(res, dict):
            return res
        return {"curatedRuleSetCounts": []}

    def get_tenant_rule_metrics(self) -> Dict[str, Any]:
        """Retrieves tenant-wide rule counts and chronicle rules quota usage."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacy:legacyGetRuleCounts"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    # --- Findings Refinements & Detection Tuning ---

    def list_findings_refinements(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists tenant UDM findings refinements and detection exclusions."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/findingsRefinements"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"findingsRefinements": []}

    def get_findings_refinement(self, refinement_id: str) -> Dict[str, Any]:
        """Retrieves details of a specific UDM findings refinement exclusion."""
        clean_id = refinement_id.split("/")[-1].strip()
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/findingsRefinements/{clean_id}"
        return self._request("GET", path)

    def create_findings_refinement(
        self,
        display_name: str,
        query: str,
        curated_rule_ids: Optional[List[str]] = None,
        refinement_type: str = "DETECTION_EXCLUSION",
    ) -> Dict[str, Any]:
        """Creates a new UDM findings refinement detection exclusion."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/findingsRefinements"
        body: Dict[str, Any] = {
            "displayName": display_name,
            "query": query,
            "type": refinement_type,
        }
        curated_rule_ids = parse_id_list(curated_rule_ids, "curated_rule_ids")
        if curated_rule_ids:
            formatted_rules = []
            for r in curated_rule_ids:
                clean_r = r.split("/")[-1].strip()
                if r.startswith("projects/"):
                    formatted_rules.append(r)
                else:
                    formatted_rules.append(
                        f"projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/curatedRules/{clean_r}"
                    )
            body["detectionExclusionApplication"] = {"curatedRules": formatted_rules}
        return self._request("POST", path, body=body)

    def delete_findings_refinement(self, refinement_id: str) -> Dict[str, Any]:
        """Deletes an active UDM findings refinement exclusion."""
        clean_id = refinement_id.split("/")[-1].strip()
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/findingsRefinements/{clean_id}"
        return self._request("DELETE", path)

    def test_findings_refinement(
        self,
        curated_rule_ids: List[str],
        query: str,
        start_time: str,
        end_time: str,
        refinement_type: str = "DETECTION_EXCLUSION",
        timeout: Optional[float] = 120.0,
    ) -> List[Dict[str, Any]]:
        """Simulates and dry-runs an exclusion query against historical detections."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:testFindingsRefinement"
        formatted_rules = []
        for r in parse_id_list(curated_rule_ids, "curated_rule_ids"):
            clean_r = r.split("/")[-1].strip()
            if r.startswith("projects/"):
                formatted_rules.append(r)
            else:
                formatted_rules.append(
                    f"projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/curatedRules/{clean_r}"
                )
        body = {
            "detectionExclusionApplication": {
                "curatedRules": formatted_rules
            },
            "type": refinement_type,
            "query": query,
            "interval": {
                "startTime": start_time,
                "endTime": end_time,
            },
        }
        res = self._request("POST", path, body=body, timeout=timeout)
        if isinstance(res, list):
            return res
        if isinstance(res, dict) and res:
            return [res]
        return []



    # --- Milestone 5.8: Content Hub Marketplace Response Integrations Methods ---

    def list_marketplace_integrations(
        self,
        query_filter: Optional[str] = "powerUp = false",
        order_by: Optional[str] = "identifier asc",
        page_size: int = 1000,
    ) -> Dict[str, Any]:
        """Lists Response Integrations from the Content Hub Marketplace."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/marketplaceIntegrations"
        params: Dict[str, Any] = {
            "pageSize": page_size,
        }
        if query_filter:
            params["filter"] = query_filter
        if order_by:
            params["orderBy"] = order_by
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"marketplaceIntegrations": [], "totalSize": 0}

    def get_marketplace_integration(self, identifier: str) -> Dict[str, Any]:
        """Retrieves full details for a Marketplace Response Integration."""
        clean_id = identifier.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/marketplaceIntegrations/{clean_id}"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def get_marketplace_integration_diff(self, identifier: str) -> Dict[str, Any]:
        """Retrieves commercial version diff comparing installed vs latest marketplace version."""
        clean_id = identifier.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/marketplaceIntegrations/{clean_id}:fetchCommercialDiff"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def get_integration_affected_items(self, identifier: str) -> Dict[str, Any]:
        """Retrieves downstream environment instances and playbooks affected by an integration."""
        clean_id = urllib.parse.quote(identifier.split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/integrations/{clean_id}:fetchAffectedItems"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    # ==========================================
    # Milestone 5.9: Native Dashboards Adapters
    # ==========================================

    def list_native_dashboards(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists native dashboards configured in Google SecOps."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"nativeDashboards": []}

    def get_native_dashboard(self, dashboard_id: str) -> Dict[str, Any]:
        """Retrieves complete definition of a native dashboard."""
        clean_id = dashboard_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards/{clean_id}"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def batch_get_dashboard_charts(self, chart_names: List[str]) -> Dict[str, Any]:
        """Retrieves multiple dashboard charts in a single batch request."""
        if not chart_names:
            return {"dashboardCharts": []}
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardCharts:batchGet"
        params = [("names", name) for name in chart_names]
        res = self._request("GET", path, params=params)
        if isinstance(res, dict):
            return res
        return {"dashboardCharts": []}

    def get_dashboard_chart(self, chart_id: str) -> Dict[str, Any]:
        """Retrieves a single DashboardChart resource by ID or resource name."""
        clean_id = str(chart_id).strip().split("/")[-1]
        full_name = f"projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardCharts/{clean_id}"
        try:
            path = f"/v1alpha/{full_name}"
            res = self._request("GET", path)
            if isinstance(res, dict) and res.get("name"):
                return res
        except Exception:
            pass
        batch_res = self.batch_get_dashboard_charts([full_name])
        charts = batch_res.get("dashboardCharts", []) if isinstance(batch_res, dict) else []
        if charts and isinstance(charts[0], dict):
            return charts[0]
        return {}

    def get_dashboard_query(self, query_id: str) -> Dict[str, Any]:
        """Retrieves definition of a dashboard query."""
        clean_id = query_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardQueries/{clean_id}"
        res = self._request("GET", path)
        if isinstance(res, dict):
            return res
        return {}

    def execute_dashboard_query(
        self,
        query_name: Optional[str] = None,
        query_text: Optional[str] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
        use_previous_time_range: bool = False,
        query_source: str = "DASHBOARD",
        time_unit: str = "DAY",
        time_value: str = "1",
        dialect: str = "YL2",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        clear_cache: Optional[bool] = None,
    ) -> DashboardQueryResult:
        """Executes a dashboard query and returns normalized columnar/row-oriented results.
        
        Dashboard queries return pre-computed analytics from the SecOps Health Hub and
        other telemetry dashboards. This method normalizes the column-oriented API response
        into an easy-to-use row-oriented format.
        
        Supports both pre-configured named query resources (by ID or full resource name)
        and ad-hoc inline query expressions.

        Args:
            query_name: Dashboard query resource name, short ID, or inline query expression.
            query_text: Explicit inline query expression (e.g. YL2 / stats query syntax).
            filters: Optional list of filter dictionaries to apply.
            use_previous_time_range: Whether to use the query's previous time range.
            query_source: Query source context (default: "DASHBOARD").
            time_unit: Relative time unit for inline queries (e.g. "DAY", "HOUR", "MONTH").
            time_value: Relative time value for inline queries (e.g. "1", "24", "7").
            dialect: Query dialect for inline queries (default: "YL2", supports "SQL").
            start_time: Optional absolute start timestamp in RFC3339 format.
            end_time: Optional absolute end timestamp in RFC3339 format.
            clear_cache: Optional boolean to force fresh query execution bypassing cache.
            
        Returns:
            DashboardQueryResult with parsed columns and rows for easy data access.
            
        Example:
            >>> result = adapter.execute_dashboard_query(query_name)
            >>> print(f"{result.row_count} rows × {result.column_count} columns")
            >>> for row in result.rows:
            >>>     print(row['timestamp'], row['total_bytes_ingested'])
        """
        # Determine if query_name is actually an inline query expression
        target_text = query_text
        target_name = query_name

        if target_text is None and target_name is not None:
            stripped = target_name.strip()
            if "\n" in target_name or stripped.startswith("$") or "match:" in target_name or "outcome:" in target_name:
                target_text = target_name
                target_name = None

        if target_text:
            if start_time and end_time:
                input_payload = {
                    "timeWindow": {
                        "startTime": start_time,
                        "endTime": end_time,
                    }
                }
            else:
                input_payload = {
                    "relativeTime": {
                        "timeUnit": time_unit,
                        "startTimeVal": str(time_value),
                    }
                }
            query_payload = {
                "query": target_text,
                "dialect": dialect,
                "input": input_payload,
            }
            query_label = "inline_dashboard_query"
        elif target_name:
            full_query_name = target_name
            if not target_name.startswith("projects/"):
                clean_id = target_name.split("/")[-1]
                full_query_name = f"projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardQueries/{clean_id}"
            query_payload = {"name": full_query_name}
            query_label = target_name
        else:
            raise ValueError("Either query_name or query_text must be provided to execute_dashboard_query.")

        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardQueries:execute"
        body = {
            "query": query_payload,
            "filters": filters or [],
            "usePreviousTimeRange": use_previous_time_range,
            "querySource": query_source,
        }
        if clear_cache is not None:
            body["clearCache"] = bool(clear_cache)
        res = self._request("POST", path, body=body)
        
        # Parse column-oriented response into rows
        return self._parse_dashboard_result(res, query_label)

    def _parse_dashboard_result(self, raw_response: Dict[str, Any], query_name: str) -> DashboardQueryResult:
        """Transforms column-oriented dashboard API response into normalized row-oriented format.
        
        The SecOps dashboard query API returns data in a column-oriented structure where
        each column has its own value array with typed values (stringVal, int64Val, etc.).
        This method transposes that structure into row-oriented records for intuitive access.
        
        Args:
            raw_response: Raw API response from dashboardQueries:execute.
            
        Returns:
            DashboardQueryResult with columns list, rows list, and metadata.
            
        Example API Response Structure:
            {
              "results": [
                {"column": "timestamp", "values": [{"value": {"stringVal": "2024-01-01"}}]},
                {"column": "count", "values": [{"value": {"int64Val": 123}}]}
              ],
              "timeWindow": {"startTime": "...", "endTime": "..."},
              "dataSources": ["feed_1"],
              "dialect": "YL2"
            }
        """
        results = raw_response.get('results', [])

        def _extract_dashboard_val(val_obj: Any) -> Any:
            if not isinstance(val_obj, dict):
                return val_obj
            if "stringVal" in val_obj and val_obj["stringVal"] is not None:
                return val_obj["stringVal"]
            if "stringValue" in val_obj and val_obj["stringValue"] is not None:
                return val_obj["stringValue"]
            for int_key in ("int64Val", "int64Value"):
                if int_key in val_obj and val_obj[int_key] is not None:
                    try:
                        return int(val_obj[int_key])
                    except (ValueError, TypeError):
                        return val_obj[int_key]
            for float_key in ("doubleVal", "doubleValue"):
                if float_key in val_obj and val_obj[float_key] is not None:
                    try:
                        return float(val_obj[float_key])
                    except (ValueError, TypeError):
                        return val_obj[float_key]
            for bool_key in ("boolVal", "boolValue"):
                if bool_key in val_obj and val_obj[bool_key] is not None:
                    return bool(val_obj[bool_key])
            for ts_key in ("timestampVal", "timestampValue"):
                if ts_key in val_obj and val_obj[ts_key] is not None:
                    return val_obj[ts_key]
            # GoogleSQL DATE columns are returned as {"dateVal": {"year", "month", "day"}}
            # (observed live 2026-10-09); normalise to ISO "YYYY-MM-DD".
            for date_key in ("dateVal", "dateValue"):
                date_obj = val_obj.get(date_key)
                if isinstance(date_obj, dict) and date_obj.get("year"):
                    return (
                        f"{int(date_obj['year']):04d}-"
                        f"{int(date_obj.get('month') or 0):02d}-"
                        f"{int(date_obj.get('day') or 0):02d}"
                    )
                if isinstance(date_obj, str) and date_obj:
                    return date_obj
            return None

        # Extract column names
        columns = [r.get('column', f'col_{i}') for i, r in enumerate(results)]
        
        # Determine row count (all columns should have same length)
        num_rows = len(results[0].get('values', [])) if results else 0
        
        # Transpose columns to rows
        rows = []
        for row_idx in range(num_rows):
            row = {}
            for col_idx, col_data in enumerate(results):
                col_name = columns[col_idx]
                values = col_data.get('values', [])
                
                if row_idx < len(values):
                    val_container = values[row_idx]
                    val_obj = val_container.get('value', {})
                    if 'list' in val_container and isinstance(val_container['list'], dict):
                        row[col_name] = [
                            _extract_dashboard_val(item.get('value', item) if isinstance(item, dict) and 'value' in item else item)
                            for item in val_container['list'].get('values', [])
                        ]
                    elif 'arrayVal' in val_obj and isinstance(val_obj['arrayVal'], dict):
                        row[col_name] = [
                            _extract_dashboard_val(item.get('value', item) if isinstance(item, dict) and 'value' in item else item)
                            for item in val_obj['arrayVal'].get('values', [])
                        ]
                    else:
                        row[col_name] = _extract_dashboard_val(val_obj)
            
            rows.append(row)
        
        return DashboardQueryResult(
            query_name=query_name,
            dialect=raw_response.get('dialect', 'YL2'),
            data_sources=raw_response.get('dataSources', []),
            time_window=raw_response.get('timeWindow', {}),
            columns=columns,
            rows=rows,
            total_rows=len(rows),
            last_cache_refreshed_time=raw_response.get('lastBackendCacheRefreshedTime'),
            raw=raw_response,
        )

    def create_native_dashboard(
        self,
        display_name: str,
        description: Optional[str] = None,
        dashboard_type: str = "CUSTOM",
        access: str = "DASHBOARD_PUBLIC",
        filters: Optional[List[Dict[str, Any]]] = None,
        charts: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Creates a new Native Dashboard via v1alpha REST API."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards"
        definition: Dict[str, Any] = {
            "filters": filters if filters is not None else [],
            "charts": charts if charts is not None else [],
        }
        body: Dict[str, Any] = {
            "displayName": display_name,
            "type": dashboard_type,
            "access": access,
            "definition": definition,
        }
        if description is not None:
            body["description"] = description
        res = self._request("POST", path, body=body)
        if isinstance(res, dict):
            return res
        return {}

    def patch_native_dashboard(
        self,
        dashboard_id: str,
        dashboard_payload: Dict[str, Any],
        update_mask: str,
    ) -> Dict[str, Any]:
        """Updates a Native Dashboard's metadata, filters, or chart layouts via PATCH."""
        clean_id = str(dashboard_id).strip().split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards/{clean_id}"
        params: Dict[str, Any] = {"updateMask": update_mask} if update_mask else {}
        res = self._request("PATCH", path, params=params, body=dashboard_payload)
        if isinstance(res, dict):
            return res
        return {}

    def delete_native_dashboard(
        self,
        dashboard_id: str,
    ) -> Dict[str, Any]:
        """Deletes a Native Dashboard by ID or resource name."""
        clean_id = str(dashboard_id).strip().split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards/{clean_id}"
        res = self._request("DELETE", path)
        if isinstance(res, dict):
            return res
        return {}

    def duplicate_native_dashboard(
        self,
        dashboard_id: str,
        display_name: str,
        description: Optional[str] = None,
        dashboard_type: str = "CUSTOM",
    ) -> Dict[str, Any]:
        """Duplicates an existing Native Dashboard under a new display name."""
        clean_id = str(dashboard_id).strip().split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards/{clean_id}:duplicate"
        inner: Dict[str, Any] = {
            "displayName": display_name,
            "type": dashboard_type,
        }
        if description is not None:
            inner["description"] = description
        res = self._request("POST", path, body={"nativeDashboard": inner})
        if isinstance(res, dict):
            return res
        return {}

    def add_dashboard_chart(
        self,
        dashboard_id: str,
        dashboard_chart: Dict[str, Any],
        dashboard_query: Optional[Dict[str, Any]] = None,
        chart_layout: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Adds a new chart (and optional query + layout) to a Native Dashboard."""
        clean_id = str(dashboard_id).strip().split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards/{clean_id}:addChart"
        body: Dict[str, Any] = {"dashboardChart": dashboard_chart}
        if dashboard_query is not None:
            body["dashboardQuery"] = dashboard_query
        if chart_layout is not None:
            body["chartLayout"] = chart_layout
        res = self._request("POST", path, body=body)
        if isinstance(res, dict):
            return res
        return {}

    def remove_dashboard_chart(
        self,
        dashboard_id: str,
        chart_id: str,
    ) -> Dict[str, Any]:
        """Removes a chart from a Native Dashboard."""
        clean_dash = str(dashboard_id).strip().split("/")[-1]
        clean_chart = str(chart_id).strip().split("/")[-1]
        full_chart_name = f"projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardCharts/{clean_chart}"
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards/{clean_dash}:removeChart"
        res = self._request("POST", path, body={"dashboardChart": full_chart_name})
        if isinstance(res, dict):
            return res
        return {}

    def patch_dashboard_chart(
        self,
        chart_id: str,
        chart_payload: Dict[str, Any],
        update_mask: str,
        dashboard_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates an existing DashboardChart resource via nativeDashboards:editChart."""
        clean_id = str(chart_id).strip().split("/")[-1]
        full_chart_name = f"projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardCharts/{clean_id}"
        existing_chart = self.get_dashboard_chart(clean_id)
        resolved_dash = dashboard_id
        if not resolved_dash and existing_chart:
            resolved_dash = existing_chart.get("nativeDashboard", "")
        if not resolved_dash:
            raise ValueError(f"Could not resolve nativeDashboard for chart '{clean_id}'.")
        clean_dash = str(resolved_dash).strip().split("/")[-1]

        merged_chart: Dict[str, Any] = dict(existing_chart) if existing_chart else {"name": full_chart_name}
        merged_chart.update(chart_payload)
        if "name" not in merged_chart:
            merged_chart["name"] = full_chart_name

        # Normalize update_mask into editChart's editMask paths (prefixed with dashboard_chart.)
        mask_parts: List[str] = []
        for raw_field in (update_mask or "").split(","):
            field = raw_field.strip()
            if not field:
                continue
            if field == "visualization" and isinstance(chart_payload.get("visualization"), dict):
                vis = chart_payload["visualization"]
                if "markdown" in vis:
                    mask_parts.append("dashboard_chart.visualization.markdown")
                elif "button" in vis:
                    mask_parts.append("dashboard_chart.visualization.button")
                else:
                    mask_parts.append("dashboard_chart.visualization")
            elif field.startswith("dashboard_chart.") or field.startswith("dashboard_query."):
                mask_parts.append(field)
            else:
                mask_parts.append(f"dashboard_chart.{field}")

        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/nativeDashboards/{clean_dash}:editChart"
        body: Dict[str, Any] = {
            "dashboardChart": merged_chart,
            "editMask": ",".join(mask_parts) if mask_parts else "dashboard_chart.display_name",
        }
        res = self._request("POST", path, body=body)
        if isinstance(res, dict):
            return res
        return {}

    def patch_dashboard_query(
        self,
        query_id: str,
        query_payload: Dict[str, Any],
        update_mask: str,
    ) -> Dict[str, Any]:
        """Updates an existing DashboardQuery resource via PATCH."""
        clean_id = str(query_id).strip().split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dashboardQueries/{clean_id}"
        params: Dict[str, Any] = {"updateMask": update_mask} if update_mask else {}
        res = self._request("PATCH", path, params=params, body=query_payload)
        if isinstance(res, dict):
            return res
        return {}

    def validate_stats_query(
        self,
        raw_query: str,
        dialect: str = "DIALECT_STATS",
    ) -> ValidationResult:
        """Validates statistical or widget query syntax.

        ``valid=False`` only for server-reported compile errors; HTTP failures
        (network, auth, 429, 5xx) propagate as exceptions.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:validateQuery"
        params = {
            "dialect": dialect,
            "allowUnreplacedPlaceholders": "false",
            "rawQuery": raw_query,
        }
        res = self._request("GET", path, params=params)
        return parse_validate_query_response(res, dialect=dialect, accepted_types=STATS_QUERY_TYPES)

    # -------------------------------------------------------------------------
    # Milestone 5.10: SIEM Settings, Feeds, Pipelines & Feed Schemas Methods
    # -------------------------------------------------------------------------

    def get_managed_domain_settings(self) -> Dict[str, Any]:
        """Retrieves approved email domains for report deliveries and alerts."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/managedDomainSettings"
        return self._request("GET", path)

    def list_feeds(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists push and pull log ingestion feeds."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/feeds"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_feed(self, feed_id: str) -> Dict[str, Any]:
        """Retrieves full configuration details for a specific ingestion feed."""
        clean_id = feed_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/feeds/{clean_id}"
        return self._request("GET", path)

    def list_log_processing_pipelines(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists Data Processing Pipelines."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logProcessingPipelines"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_log_processing_pipeline(self, pipeline_id: str) -> Dict[str, Any]:
        """Retrieves full configuration and transforms for a Data Processing Pipeline."""
        clean_id = pipeline_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logProcessingPipelines/{clean_id}"
        return self._request("GET", path)

    def list_feed_source_type_schemas(
        self,
        page_size: int = 1000,
    ) -> Dict[str, Any]:
        """Lists all supported feed source types and metadata."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/feedSourceTypeSchemas"
        params = {"pageSize": page_size}
        return self._request("GET", path, params=params)

    def list_feed_log_type_schemas(
        self,
        feed_source_type: str,
        page_size: int = 100,
        page_token: Optional[str] = None,
        omit_details_fields: bool = True,
    ) -> Dict[str, Any]:
        """Lists log type schemas for a feed source type, with lean payload handling."""
        clean_source = feed_source_type.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/feedSourceTypeSchemas/{clean_source}/logTypeSchemas"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        res = self._request("GET", path, params=params)
        if omit_details_fields and "logTypeSchemas" in res:
            for item in res["logTypeSchemas"]:
                if "detailsFieldSchemas" in item:
                    item["detailsFieldSchemasCount"] = len(item["detailsFieldSchemas"])
                    del item["detailsFieldSchemas"]
        return res

    # --------------------------------------------------------------------------
    # Milestone 5.11: SIEM Settings - Parsers, Log Types, Extensions & Settings
    # --------------------------------------------------------------------------

    def list_log_types(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists supported ingestion log types cataloged in Google SecOps."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logTypes"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def list_parsers(
        self,
        log_type: str = "-",
        view: str = "BASIC_VIEW",
        page_size: int = 1000,
        filter_expr: str = "",
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists parsers across all log types or for a specific log type."""
        clean_lt = log_type.split("/")[-1] if log_type != "-" else "-"
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logTypes/{clean_lt}/parsers"
        params: Dict[str, Any] = {
            "pageSize": page_size,
            "view": view,
        }
        if filter_expr:
            params["filter"] = filter_expr
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_parser(
        self,
        log_type: str,
        parser_id: str,
        view: str = "FULL_VIEW",
    ) -> Dict[str, Any]:
        """Retrieves a single parser with full CBN configuration."""
        clean_lt = log_type.split("/")[-1]
        clean_id = parser_id.split("/")[-1]
        # First attempt direct GET if parser resource endpoint is available
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logTypes/{clean_lt}/parsers/{clean_id}"
        try:
            return self._request("GET", path, params={"view": view})
        except SecOpsConfigurationError:
            raise
        except RuntimeError as e:
            err_msg = str(e)
            if not any(code in err_msg for code in ("[400]", "[404]", "[405]", "[501]")):
                raise
            # Fallback to list with FULL_VIEW and matching ID
            res = self.list_parsers(log_type=clean_lt, view=view, page_size=1000)
            for p in res.get("parsers", []):
                p_name = p.get("name", "")
                if p_name.endswith(clean_id) or p_name.split("/")[-1] == clean_id:
                    return p
            raise ValueError(f"Parser '{clean_id}' not found for log type '{clean_lt}'") from e

    def run_parser(
        self,
        log_type: str,
        parser_cbn_b64: str,
        raw_log_text: str,
    ) -> Dict[str, Any]:
        """Runs a Logstash CBN parser configuration against a raw log string via :runParser API."""
        clean_lt = log_type.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logTypes/{clean_lt}:runParser"
        log_b64 = base64.b64encode(raw_log_text.encode("utf-8")).decode("utf-8")
        body = {
            "parser": {
                "cbn": parser_cbn_b64,
            },
            "log": log_b64,
        }
        return self._request("POST", path, body=body)

    def list_parser_extensions(
        self,
        log_type: str = "-",
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists parser extensions across all log types or for a specific log type."""
        clean_lt = log_type.split("/")[-1] if log_type != "-" else "-"
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logTypes/{clean_lt}/parserExtensions"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_parser_extension(
        self,
        log_type: str,
        extension_id: str,
    ) -> Dict[str, Any]:
        """Retrieves detailed configuration for a parser extension."""
        clean_lt = log_type.split("/")[-1]
        clean_id = extension_id.split("/")[-1]
        # Query extensions for the specific log type and locate matching extension
        res = self.list_parser_extensions(log_type=clean_lt, page_size=1000)
        for ext in res.get("parserExtensions", []):
            ext_name = ext.get("name", "")
            if ext_name.endswith(clean_id) or ext_name.split("/")[-1] == clean_id:
                return ext
        raise ValueError(f"Parser extension '{clean_id}' not found for log type '{clean_lt}'")

    def get_log_type_setting(
        self,
        log_type: str,
    ) -> Dict[str, Any]:
        """Retrieves autonomous parsing extraction settings for a specific log type."""
        clean_lt = log_type.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/logTypes/{clean_lt}/logTypeSetting"
        return self._request("GET", path)

    # --------------------------------------------------------------------------
    # Milestone 5.12: SIEM Settings - Preview Features & Data RBAC
    # --------------------------------------------------------------------------

    def list_preview_features(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists tenant preview features and enablement states."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/features"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_preview_feature(self, feature_id: str) -> Dict[str, Any]:
        """Retrieves specific preview feature configuration."""
        clean_id = feature_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/features/{clean_id}"
        return self._request("GET", path)

    def list_data_access_scopes(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists tenant Data Access Scopes (Data RBAC)."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dataAccessScopes"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_data_access_scope(self, scope_id: str) -> Dict[str, Any]:
        """Retrieves specific Data Access Scope deep configuration."""
        clean_id = scope_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dataAccessScopes/{clean_id}"
        return self._request("GET", path)

    def list_data_access_labels(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists tenant Data Access Labels (UDM query expressions)."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dataAccessLabels"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_data_access_label(self, label_id: str) -> Dict[str, Any]:
        """Retrieves specific Data Access Label deep configuration."""
        clean_id = label_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/dataAccessLabels/{clean_id}"
        return self._request("GET", path)

    def list_soar_environments(
        self,
        fields: Optional[str] = None,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists SOAR environments and attached Data Access Scopes."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/environments"
        params: Dict[str, Any] = {"pageSize": page_size}
        if fields:
            params["fields"] = fields
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    # -------------------------------------------------------------------------
    # Milestone 5.13: Remaining SIEM Settings & Enrichment Controls
    # -------------------------------------------------------------------------

    def get_enrichment_combination(self) -> Dict[str, Any]:
        """Retrieves available entity enrichment combinations."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/enrichmentCombination"
        return self._request("GET", path)

    def list_enrichment_controls(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists deployed enrichment controls."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/enrichmentControls"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_enrichment_control(self, control_id: str) -> Dict[str, Any]:
        """Retrieves specific deployed enrichment control configuration."""
        clean_id = control_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/enrichmentControls/{clean_id}"
        return self._request("GET", path)

    def get_agent_settings(self) -> Dict[str, Any]:
        """Retrieves Gemini Triage & Investigation Agent settings."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/agentSettings"
        return self._request("GET", path)

    def list_investigations(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = "start_time desc",
    ) -> Dict[str, Any]:
        """Lists Gemini Triage & Investigation Agent (TINA) investigations."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/investigations"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if filter:
            params["filter"] = filter
        if order_by:
            params["orderBy"] = order_by
        return self._request("GET", path, params=params)

    def get_investigation(self, investigation_id: str) -> Dict[str, Any]:
        """Retrieves a specific Gemini TINA investigation report by ID or resource name."""
        clean_id = urllib.parse.quote(investigation_id.split("/")[-1], safe="")
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/investigations/{clean_id}"
        return self._request("GET", path)

    def get_alert_latest_investigation(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the latest Gemini TINA investigation associated with a specific alert ID."""
        clean_alert_id = alert_id.split("/")[-1]
        filter_expr = f'alert_id = "{clean_alert_id}"'
        res = self.list_investigations(page_size=1, filter=filter_expr, order_by="start_time desc")
        investigations = res.get("investigations", [])
        if investigations:
            return investigations[0]
        return None


    def get_risk_config(self) -> Dict[str, Any]:
        """Retrieves UEBA entity risk scoring configuration."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/riskConfig"
        return self._request("GET", path)

    def get_tenant_instance(self) -> Dict[str, Any]:
        """Retrieves root tenant instance details and configuration."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}"
        return self._request("GET", path)

    # --- Milestone 6.1: SOAR Settings & Case Data Configuration ---

    def list_soar_users(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists SOAR users and external identity representations."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacySoarUsers"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if filter:
            params["filter"] = filter
        if fields:
            params["fields"] = fields
        return self._request("GET", path, params=params)

    def get_soar_user(self, user_id: str) -> Dict[str, Any]:
        """Retrieves specific SOAR user details."""
        clean_id = user_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacySoarUsers/{clean_id}"
        return self._request("GET", path)

    def list_soc_roles(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists SOC roles and workflow assignment hierarchies."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/socRoles"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_company_settings(self) -> Dict[str, Any]:
        """Retrieves company / rebranding settings properties."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/moduleSettings/CompanySetting/properties"
        return self._request("GET", path)

    def list_case_tag_definitions(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists case tag definitions and classification rules."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/caseTagDefinitions"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if filter_expr:
            params["filter"] = filter_expr
        return self._request("GET", path, params=params)

    def list_case_stage_definitions(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        order_by: str = "order",
    ) -> Dict[str, Any]:
        """Lists ordered SOC case lifecycle stage definitions."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/caseStageDefinitions"
        params: Dict[str, Any] = {"pageSize": page_size, "orderBy": order_by}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def list_case_close_definitions(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists predefined case close reasons and root causes."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/caseCloseDefinitions"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def list_case_close_dynamic_parameters(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        expand: str = "relatedCustomField",
        filter_expr: str = "formType = 'CLOSE_CASE'",
    ) -> Dict[str, Any]:
        """Lists dynamic form parameters for case close dialogs."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/formDynamicParameters"
        params: Dict[str, Any] = {"pageSize": page_size, "expand": expand, "filter": filter_expr}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_case_title_settings(self) -> Dict[str, Any]:
        """Retrieves case title naming rule properties."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/moduleSettings/CaseTitleSettings/properties"
        params: Dict[str, Any] = {"orderBy": "displayName"}
        return self._request("GET", path, params=params)

    # --- Milestone 6.2: Views, Custom Fields & Calculated Fields ---

    def list_views(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists case, alert, and detection overview layout views."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/views"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_view(self, view_id: str) -> Dict[str, Any]:
        """Retrieves deep inspection of a specific layout view template and widgets."""
        clean_id = view_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/views/{clean_id}"
        return self._request("GET", path)

    def list_custom_fields(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists custom typed fields across Case and Alert scopes."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/customFields"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_custom_field(self, field_id: str) -> Dict[str, Any]:
        """Retrieves deep inspection of a single custom field definition."""
        clean_id = field_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/customFields/{clean_id}"
        return self._request("GET", path)

    def list_calculated_fields(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists calculated field formula definitions."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/calculatedFieldDefinitions"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_calculated_field(self, definition_id: str) -> Dict[str, Any]:
        """Retrieves deep inspection of a single calculated field definition."""
        clean_id = definition_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/calculatedFieldDefinitions/{clean_id}"
        return self._request("GET", path)

    # --- Milestone 6.3: Alert Grouping & General SOAR Settings ---

    def list_alert_grouping_rules(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists alert grouping rules."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/alertGroupingRules"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_alert_grouping_rule(self, rule_id: str) -> Dict[str, Any]:
        """Retrieves deep inspection of a single alert grouping rule."""
        clean_id = rule_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/alertGroupingRules/{clean_id}"
        return self._request("GET", path)

    def get_alert_grouping_settings(self) -> Dict[str, Any]:
        """Retrieves global alert grouping module settings properties."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/moduleSettings/AlertGroupingSettings/properties"
        return self._request("GET", path)

    def get_data_retention_settings(self) -> Dict[str, Any]:
        """Retrieves SOAR data retention module settings properties."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/moduleSettings/DataRetention/properties"
        return self._request("GET", path)

    def list_environments(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        fields: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers multi-tenancy environments in the SOAR tenant."""
        return self.list_soar_environments(
            fields=fields,
            page_size=page_size,
            page_token=page_token,
        )

    def get_environment(self, env_id: str) -> Dict[str, Any]:
        """Retrieves deep configuration of a single multi-tenancy environment."""
        clean_id = env_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/environments/{clean_id}"
        return self._request("GET", path)

    def list_environment_groups(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers environment group collections."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/environmentGroups"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def list_remote_agents(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
        state_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers remote SOAR execution agents and bindings."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/remoteAgents"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if filter_expr:
            params["filter"] = filter_expr
        elif state_filter:
            params["filter"] = f'agentState = "{state_filter}"'
        return self._request("GET", path, params=params)

    def get_remote_agent(self, agent_id: str) -> Dict[str, Any]:
        """Retrieves deep configuration of a single remote agent."""
        clean_id = agent_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/remoteAgents/{clean_id}"
        return self._request("GET", path)

    def get_email_settings_type(self) -> Dict[str, Any]:
        """Retrieves email transport type (custom vs Google default SMTP)."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/moduleSettings/EmailSettingsType/properties"
        return self._request("GET", path)

    def get_email_settings(self) -> Dict[str, Any]:
        """Retrieves email SMTP server and credential configuration properties."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/moduleSettings/EmailSettings/properties"
        return self._request("GET", path)

    def get_support_settings(self) -> Dict[str, Any]:
        """Retrieves Google Support access delegation properties."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/moduleSettings/Support/properties"
        return self._request("GET", path)

    def list_soar_networks(
        self,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers customer-defined CIDR network address ranges."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/soarNetworks"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_soar_network(self, network_id: str) -> Dict[str, Any]:
        """Retrieves configuration of a single customer-defined CIDR network."""
        clean_id = network_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/soarNetworks/{clean_id}"
        return self._request("GET", path)

    def list_soar_domains(
        self,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers approved customer domain names."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/soarDomains"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_soar_domain(self, domain_id: str) -> Dict[str, Any]:
        """Retrieves configuration of a single approved customer domain."""
        clean_id = domain_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/soarDomains/{clean_id}"
        return self._request("GET", path)

    def list_soar_custom_lists(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers SOAR custom list key-value retention entries."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/customLists"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_soar_custom_list(self, list_id: str) -> Dict[str, Any]:
        """Retrieves configuration of a single SOAR custom list entry."""
        clean_id = list_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/customLists/{clean_id}"
        return self._request("GET", path)

    def list_email_templates(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers email templates (plain text and HTML)."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/emailTemplates"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_email_template(self, template_id: str) -> Dict[str, Any]:
        """Retrieves complete email template content and parameters."""
        clean_id = template_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/emailTemplates/{clean_id}"
        return self._request("GET", path)

    def list_entities_blocklists(
        self,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers entity noise-reduction blocklist rules."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/entitiesBlocklists"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_entities_blocklist(self, blocklist_id: str) -> Dict[str, Any]:
        """Retrieves configuration of a single entity blocklist rule."""
        clean_id = blocklist_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/entitiesBlocklists/{clean_id}"
        return self._request("GET", path)

    def list_sla_definitions(
        self,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers Service Level Agreement definitions."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/slaDefinitions"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_sla_definition(self, sla_id: str) -> Dict[str, Any]:
        """Retrieves configuration of a single SLA definition."""
        clean_id = sla_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/slaDefinitions/{clean_id}"
        return self._request("GET", path)

    def list_request_templates(
        self,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers manual case request form templates."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/requestTemplates"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_request_template(self, template_id: str) -> Dict[str, Any]:
        """Retrieves configuration of a single manual case request form template."""
        clean_id = template_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/requestTemplates/{clean_id}"
        return self._request("GET", path)

    # -------------------------------------------------------------------------
    # Milestone 6.6: SOAR Ingestion Connectors & Webhooks
    # -------------------------------------------------------------------------

    def list_soar_ingestion_connectors(
        self,
        integration: str = "-",
        connector_id: str = "-",
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers configured SOAR ingestion connector instances across integrations."""
        path = (
            f"/v1alpha/projects/{self.project_number}/locations/{self.location}/"
            f"instances/{self.customer_id}/integrations/{integration}/connectors/{connector_id}/connectorInstances"
        )
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_soar_ingestion_connector(
        self,
        instance_id: str,
        integration: str = "-",
        connector_id: str = "-",
    ) -> Dict[str, Any]:
        """Retrieves configuration of a single SOAR ingestion connector instance."""
        clean_id = instance_id.split("/")[-1]
        path = (
            f"/v1alpha/projects/{self.project_number}/locations/{self.location}/"
            f"instances/{self.customer_id}/integrations/{integration}/connectors/{connector_id}/connectorInstances/{clean_id}"
        )
        return self._request("GET", path)

    def list_soar_webhooks(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers configured SOAR event ingestion webhooks."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/webhooks"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_soar_webhook(self, webhook_id: str) -> Dict[str, Any]:
        """Retrieves configuration and JSON schema mapping for a single SOAR webhook."""
        clean_id = webhook_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/webhooks/{clean_id}"
        return self._request("GET", path)

    def search_enterprise_iocs(
        self,
        value: str,
        value_type: str,
        start_time: str,
        end_time: str,
        max_matches: int = 10000,
        add_mandiant_attributes: bool = True,
    ) -> Dict[str, Any]:
        """Searches enterprise-wide IoC matches and Mandiant threat intel for an indicator."""
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}/legacy:legacySearchEnterpriseWideIoCs"
        params: Dict[str, Any] = {
            "fieldAndValue.value": value,
            "fieldAndValue.valueType": value_type,
            "timestampRange.startTime": start_time,
            "timestampRange.endTime": end_time,
            "maxMatchesToReturn": max_matches,
            "addMandiantAttributes": "true" if add_mandiant_attributes else "false",
        }
        return self._request("GET", path, params=params)

    def summarize_entity(
        self,
        entity_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        return_alerts: bool = False,
        return_prevalence: bool = True,
        include_all_udm_event_types: bool = True,
        field_value: Optional[str] = None,
        value_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Summarizes entity metadata, timeline intervals, and prevalence.

        Look up by ``entity_id`` or by ``field_value`` + ``value_type`` (a
        FieldAndValue.ValueType such as ``HOSTNAME`` or ``ASSET_IP_ADDRESS``;
        both verified live 2026-10-10. ``IP``/``IP_ADDRESS`` are rejected).
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:summarizeEntity"
        params: Dict[str, Any] = {
            "returnAlerts": "true" if return_alerts else "false",
            "returnPrevalence": "true" if return_prevalence else "false",
            "includeAllUdmEventTypesForFirstLastSeen": "true" if include_all_udm_event_types else "false",
        }
        if entity_id:
            params["entityId"] = entity_id.split("/")[-1]
        elif field_value and value_type:
            params["fieldAndValue.value"] = field_value
            params["fieldAndValue.valueType"] = value_type
        else:
            raise ValueError("summarize_entity needs entity_id, or field_value and value_type.")
        if start_time:
            params["timeRange.startTime"] = start_time
        if end_time:
            params["timeRange.endTime"] = end_time
        return self._request("GET", path, params=params)

    def find_udm_field_values(
        self,
        query: str,
        page_size: int = 20,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """``GET :findUdmFieldValues``: UDM field paths whose recent values match ``query``.

        Read-only (verified live 2026-10-10, 1.3 s). Response:
        ``{valueMatches: [{fieldPath, value, ingestionTime, matchStart?, matchEnd}],
        fieldMatchRegex, nextPageToken, hasMoreMatches}``.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:findUdmFieldValues"
        params: Dict[str, Any] = {"query": query, "pageSize": int(page_size)}
        if page_token:
            params["pageToken"] = page_token
        res = self._request("GET", path, params=params)
        if not isinstance(res, dict):
            raise RuntimeError(f"Unexpected :findUdmFieldValues response shape: {type(res).__name__}")
        return res

    def translate_udm_query(self, text: str) -> Dict[str, Any]:
        """``POST :translateUdmQuery {text}``: natural language -> UDM search query.

        Read-only (no tenant state is written; verified live 2026-10-10, 3.5-4.2 s).
        Response: ``{query, timeRange?: {startTime, endTime}}``; ``timeRange`` is
        omitted when the text names no time window.
        """
        path = f"/v1alpha/projects/{self.project_number}/locations/{self.location}/instances/{self.customer_id}:translateUdmQuery"
        res = self._request("POST", path, body={"text": text})
        if not isinstance(res, dict):
            raise RuntimeError(f"Unexpected :translateUdmQuery response shape: {type(res).__name__}")
        return res

    # -------------------------------------------------------------------------
    # Chronicle SIEM Data Tables (projects.locations.instances.dataTables)
    # -------------------------------------------------------------------------

    def list_data_tables(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists structured data tables in Chronicle SIEM."""
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if order_by:
            params["orderBy"] = order_by
        return self._request("GET", path, params=params)

    def get_data_table(self, table_name_or_id: str) -> Dict[str, Any]:
        """Gets metadata and schema for a specific Chronicle SIEM Data Table."""
        clean_id = table_name_or_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables/{clean_id}"
        return self._request("GET", path)

    def create_data_table(
        self,
        table_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        column_info: Optional[List[Dict[str, Any]]] = None,
        row_time_to_live: Optional[str] = None,
        scope_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Creates a new structured Data Table in Chronicle SIEM."""
        clean_id = table_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables"
        params = {"dataTableId": clean_id}
        body: Dict[str, Any] = {
            "displayName": display_name or clean_id,
            "columnInfo": column_info or [],
        }
        if description:
            body["description"] = description
        if row_time_to_live:
            body["rowTimeToLive"] = row_time_to_live
        if scope_info:
            body["scopeInfo"] = scope_info
        return self._request("POST", path, params=params, body=body)

    def patch_data_table(
        self,
        table_name_or_id: str,
        description: Optional[str] = None,
        row_time_to_live: Optional[str] = None,
        scope_info: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates metadata, TTL, or scope info for an existing Data Table."""
        clean_id = table_name_or_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables/{clean_id}"
        body: Dict[str, Any] = {
            "name": f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables/{clean_id}"
        }
        mask_parts = []
        if description is not None:
            body["description"] = description
            mask_parts.append("description")
        if row_time_to_live is not None:
            body["rowTimeToLive"] = row_time_to_live
            mask_parts.append("rowTimeToLive")
        if scope_info is not None:
            body["scopeInfo"] = scope_info
            mask_parts.append("scopeInfo")

        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = update_mask
        elif mask_parts:
            params["updateMask"] = ",".join(mask_parts)

        return self._request("PATCH", path, params=params if params else None, body=body)

    def delete_data_table(self, table_name_or_id: str) -> Dict[str, Any]:
        """Deletes a Chronicle SIEM Data Table."""
        clean_id = table_name_or_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables/{clean_id}"
        return self._request("DELETE", path)

    def list_data_table_rows(
        self,
        table_name_or_id: str,
        page_size: int = 50,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists rows contained within a Chronicle SIEM Data Table."""
        clean_id = table_name_or_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables/{clean_id}/dataTableRows"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if filter_expr:
            params["filter"] = filter_expr
        return self._request("GET", path, params=params)

    def bulk_create_data_table_rows(
        self,
        table_name_or_id: str,
        rows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Creates data table rows in bulk in Chronicle SIEM."""
        clean_id = table_name_or_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables/{clean_id}/dataTableRows:bulkCreate"
        # Each row can be {"values": [...]} or raw list of values
        requests = []
        for r in rows:
            if isinstance(r, dict) and "values" in r:
                requests.append({"row": r})
            elif isinstance(r, (list, tuple)):
                requests.append({"row": {"values": [str(v) for v in r]}})
            elif isinstance(r, dict):
                requests.append({"row": r})
        body = {"requests": requests}
        return self._request("POST", path, body=body)

    def delete_data_table_row(
        self,
        table_name_or_id: str,
        row_id: str,
    ) -> Dict[str, Any]:
        """Deletes a specific row from a Chronicle SIEM Data Table."""
        clean_table_id = table_name_or_id.split("/")[-1]
        clean_row_id = row_id.split("/")[-1]
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/dataTables/{clean_table_id}/dataTableRows/{clean_row_id}"
        return self._request("DELETE", path)

    # -------------------------------------------------------------------------
    # Chronicle SIEM Detection Rules (projects.locations.instances.rules)
    # -------------------------------------------------------------------------

    def list_rules(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
        view: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists custom YARA-L detection rules in Chronicle SIEM."""
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if filter_expr:
            params["filter"] = filter_expr
        if view:
            params["view"] = view
        return self._request("GET", path, params=params)

    def get_rule(
        self,
        rule_id_or_name: str,
        view: str = "FULL",
    ) -> Dict[str, Any]:
        """Retrieves full details of a custom Chronicle SIEM detection rule."""
        clean_id = rule_id_or_name.strip()
        if clean_id.startswith("projects/"):
            path = f"/v1alpha/{clean_id}"
        else:
            path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/{clean_id}"
        params = {"view": view} if view else None
        return self._request("GET", path, params=params)

    def verify_rule_text(self, rule_text: str) -> Dict[str, Any]:
        """Validates/compiles YARA-L 2.0 rule text against the Chronicle compiler."""
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}:verifyRuleText"
        body = {"ruleText": rule_text}
        return self._request("POST", path, body=body)

    def create_rule(self, rule_text: str) -> Dict[str, Any]:
        """Creates a new YARA-L detection rule in Chronicle SIEM."""
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules"
        body = {"text": rule_text}
        return self._request("POST", path, body=body)

    def patch_rule(
        self,
        rule_id_or_name: str,
        rule_text: str,
        update_mask: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates a custom detection rule with new YARA-L text."""
        clean_id = rule_id_or_name.strip()
        if clean_id.startswith("projects/"):
            path = f"/v1alpha/{clean_id}"
            res_name = clean_id
        else:
            res_name = f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/{clean_id}"
            path = f"/v1alpha/{res_name}"
        body = {
            "name": res_name,
            "text": rule_text,
        }
        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = update_mask
        else:
            params["updateMask"] = "text"
        return self._request("PATCH", path, params=params, body=body)

    def delete_rule(self, rule_id_or_name: str) -> Dict[str, Any]:
        """Deletes a custom detection rule from Chronicle SIEM."""
        clean_id = rule_id_or_name.strip()
        if clean_id.startswith("projects/"):
            path = f"/v1alpha/{clean_id}"
        else:
            path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/{clean_id}"
        return self._request("DELETE", path)

    def list_rule_revisions(
        self,
        rule_id_or_name: str,
        page_size: int = 100,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists all revisions/version history of a custom detection rule."""
        clean_id = rule_id_or_name.strip()
        if clean_id.startswith("projects/"):
            path = f"/v1alpha/{clean_id}:listRevisions"
        else:
            path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/{clean_id}:listRevisions"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def list_rule_deployments(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists rule deployments across all detection rules in Chronicle SIEM."""
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/-/deployments"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", path, params=params)

    def get_rule_deployment(self, rule_id_or_name: str) -> Dict[str, Any]:
        """Gets deployment, frequency, and alerting status for a detection rule."""
        clean_id = rule_id_or_name.strip()
        if clean_id.startswith("projects/"):
            path = f"/v1alpha/{clean_id}/deployment"
        else:
            path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/{clean_id}/deployment"
        return self._request("GET", path)

    def update_rule_deployment(
        self,
        rule_id_or_name: str,
        enabled: Optional[bool] = None,
        alerting: Optional[bool] = None,
        run_frequency: Optional[str] = None,
        update_mask: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates deployment properties (enabled, alerting, runFrequency) of a rule."""
        clean_id = rule_id_or_name.strip()
        if clean_id.startswith("projects/"):
            deployment_name = f"{clean_id}/deployment"
            path = f"/v1alpha/{deployment_name}"
        else:
            deployment_name = f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/{clean_id}/deployment"
            path = f"/v1alpha/{deployment_name}"

        body: Dict[str, Any] = {"name": deployment_name}
        mask_parts = []
        if enabled is not None:
            body["enabled"] = enabled
            mask_parts.append("enabled")
        if alerting is not None:
            body["alerting"] = alerting
            mask_parts.append("alerting")
        if run_frequency is not None:
            body["runFrequency"] = run_frequency
            mask_parts.append("runFrequency")

        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = update_mask
        elif mask_parts:
            params["updateMask"] = ",".join(mask_parts)

        return self._request("PATCH", path, params=params if params else None, body=body)

    def list_rule_execution_errors(
        self,
        rule_id_or_name: Optional[str] = None,
        page_size: int = 100,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Lists runtime / execution errors for Chronicle detection rules."""
        path = f"/v1alpha/projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/ruleExecutionErrors"
        params: Dict[str, Any] = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        if rule_id_or_name:
            if "curatedRules/" in rule_id_or_name:
                filter_key = "curated_rule"
                full_name = rule_id_or_name
            elif rule_id_or_name.startswith("projects/"):
                filter_key = "rule"
                full_name = rule_id_or_name
            else:
                filter_key = "rule"
                clean_id = rule_id_or_name.split("/")[-1]
                full_name = f"projects/{self.project_id}/locations/{self.location}/instances/{self.customer_id}/rules/{clean_id}"
            params["filter"] = f'{filter_key} = "{full_name}"'
        return self._request("GET", path, params=params)

    def query_cloud_logging(
        self,
        filter_str: str,
        project_ids: Optional[List[str]] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
        order_by: str = "timestamp desc",
    ) -> Dict[str, Any]:
        """Queries Google Cloud Logging API (v2/entries:list) via OAuth token."""
        url = "https://logging.googleapis.com/v2/entries:list"
        projects = project_ids or [self.project_id]
        body: Dict[str, Any] = {
            "resourceNames": [f"projects/{p}" for p in projects],
            "filter": filter_str,
            "orderBy": order_by,
            "pageSize": page_size,
        }
        if page_token:
            body["pageToken"] = page_token
        return self._request("POST", url, body=body)

    def query_cloud_monitoring_time_series(
        self,
        filter_str: str,
        start_time: str,
        end_time: str,
        project_id: Optional[str] = None,
        alignment_period: Optional[str] = None,
        per_series_aligner: Optional[str] = None,
        cross_series_reducer: Optional[str] = None,
        group_by_fields: Optional[List[str]] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries Google Cloud Monitoring API (v3/projects/{project_id}/timeSeries) via OAuth token."""
        proj = project_id or self.project_id
        url = f"https://monitoring.googleapis.com/v3/projects/{proj}/timeSeries"
        params: Dict[str, Any] = {
            "filter": filter_str,
            "interval.startTime": start_time,
            "interval.endTime": end_time,
            "pageSize": page_size,
        }
        if alignment_period:
            params["aggregation.alignmentPeriod"] = alignment_period
        if per_series_aligner:
            params["aggregation.perSeriesAligner"] = per_series_aligner
        if cross_series_reducer:
            params["aggregation.crossSeriesReducer"] = cross_series_reducer
        if group_by_fields:
            params["aggregation.groupByFields"] = group_by_fields
        if page_token:
            params["pageToken"] = page_token
        return self._request("GET", url, params=params)

















