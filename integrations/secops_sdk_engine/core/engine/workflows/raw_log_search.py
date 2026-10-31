"""Workflows for Raw Log Discovery, Query Syntax Validation, and Log Search."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from engine.domain import (
    ProductSourceStat,
    ProductSourceStatsBatch,
    RawLogSearchResult,
    RawLogSnippet,
    RawLogValidationResult,
)

logger = logging.getLogger(__name__)


def _format_iso_timestamp(dt: Union[datetime, str, None]) -> str:
    """Formats datetime or string into RFC 3339 / ISO 8601 UTC timestamp."""
    if not dt:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    s = str(dt).strip()
    if s.endswith("Z") or ("+" in s and "T" in s):
        return s
    return f"{s}Z" if "T" in s else s


class QueryProductSourceStatsWorkflow:
    """Queries product source statistics and ingested data volumes across the evaluation window."""

    def __init__(self, adapter: Any = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        lookback_hours: int = 24,
    ) -> ProductSourceStatsBatch:
        """Executes product source stats discovery."""
        now = datetime.now(timezone.utc)
        end_iso = _format_iso_timestamp(end_time) if end_time else _format_iso_timestamp(now)
        start_iso = _format_iso_timestamp(start_time) if start_time else _format_iso_timestamp(now - timedelta(hours=lookback_hours))

        raw_res = self.adapter.query_product_source_stats(
            start_time=start_iso,
            end_time=end_iso,
        )

        stats_list: List[ProductSourceStat] = []
        raw_stats = raw_res.get("productSourceStats", []) if isinstance(raw_res, dict) else []

        for item in raw_stats:
            if not isinstance(item, dict):
                continue
            src = str(item.get("productSource", "")).strip()
            size_raw = item.get("dataSizeBytes", 0)
            try:
                size_bytes = int(size_raw)
            except (ValueError, TypeError):
                size_bytes = 0
            if src:
                stats_list.append(ProductSourceStat(
                    product_source=src,
                    data_size_bytes=size_bytes,
                ))

        # Sort descending by data size
        stats_list.sort(key=lambda s: s.data_size_bytes, reverse=True)

        return ProductSourceStatsBatch(
            stats=stats_list,
            start_time=start_iso,
            end_time=end_iso,
            total_sources=len(stats_list),
        )


class ValidateRawLogQueryWorkflow:
    """Validates raw log query syntax against Chronicle query engine."""

    def __init__(self, adapter: Any = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str,
        allow_unreplaced_placeholders: bool = False,
    ) -> RawLogValidationResult:
        """Validates a raw log query expression."""
        if not query or not str(query).strip():
            return RawLogValidationResult(
                query_type="",
                is_valid=False,
                error_message="Query string cannot be empty.",
            )

        clean_query = str(query).strip()
        # HTTP failures (network, auth, 429, 5xx) propagate: only a compile
        # error reported by the server is an invalid query.
        raw_res = self.adapter.validate_raw_log_query(
            raw_query=clean_query,
            allow_unreplaced_placeholders=allow_unreplaced_placeholders,
        )
        if not isinstance(raw_res, dict):
            raise RuntimeError(f"Unexpected :validateQuery response shape: {type(raw_res).__name__}")
        q_type = str(raw_res.get("queryType", "")).strip()
        error_text = raw_res.get("errorText") or raw_res.get("error")
        error_type = raw_res.get("errorType")
        if error_type == "BACKEND_ERROR_TYPE":
            from adapters.google_secops import QueryValidationUnavailableError

            raise QueryValidationUnavailableError(str(error_text or error_type), "DIALECT_UDM_SEARCH")

        if error_text or error_type:
            msg = f"[{error_type}] {error_text}" if error_type and error_text else str(error_text or error_type)
            pos_raw = raw_res.get("errorPosition")
            position = None
            if isinstance(pos_raw, dict) and pos_raw:
                position = {
                    "start_line": int(pos_raw.get("startLine", 0) or 0),
                    "start_column": int(pos_raw.get("startColumn", 0) or 0),
                    "end_line": int(pos_raw.get("endLine", 0) or 0),
                    "end_column": int(pos_raw.get("endColumn", 0) or 0),
                }
            return RawLogValidationResult(
                query_type=q_type,
                is_valid=False,
                error_message=msg,
                error_position=position,
            )

        return RawLogValidationResult(
            query_type=q_type,
            is_valid=True,
            error_message=None,
        )


class SearchRawLogsWorkflow:
    """Executes enterprise raw log search across ingested unparsed or unnormalized logs."""

    def __init__(self, adapter: Any = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str,
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        lookback_hours: int = 24,
        log_types: Optional[Union[str, List[str]]] = None,
        case_sensitive: bool = False,
        page_size: int = 1000,
        max_aggregations: int = 60,
    ) -> RawLogSearchResult:
        """Searches unparsed raw logs."""
        if not query or not str(query).strip():
            raise ValueError("Raw log search query cannot be empty.")

        clean_query = str(query).strip()

        now = datetime.now(timezone.utc)
        end_iso = _format_iso_timestamp(end_time) if end_time else _format_iso_timestamp(now)
        start_iso = _format_iso_timestamp(start_time) if start_time else _format_iso_timestamp(now - timedelta(hours=lookback_hours))

        # Coerce log_types (flexible collection input)
        types_list: List[str] = []
        if isinstance(log_types, str):
            types_list = [log_types]
        elif isinstance(log_types, (list, tuple, set)):
            types_list = [str(x) for x in log_types]

        raw_chunks = self.adapter.search_raw_logs(
            query=clean_query,
            start_time=start_iso,
            end_time=end_iso,
            log_types=types_list,
            case_sensitive=case_sensitive,
            max_aggregations=max_aggregations,
            page_size=page_size,
        )

        matches: List[RawLogSnippet] = []
        aggregations: Dict[str, Any] = {}
        timeline: Dict[str, Any] = {}
        progress: int = 100
        has_more: bool = False
        next_page_token: Optional[Union[str, bool]] = None

        seen_ids = set()

        for chunk in raw_chunks:
            if not isinstance(chunk, dict):
                continue

            if "progress" in chunk and isinstance(chunk["progress"], (int, float)):
                progress = int(chunk["progress"])

            if "nextPageToken" in chunk:
                next_page_token = chunk["nextPageToken"]
                if next_page_token:
                    has_more = True

            if "timeline" in chunk and isinstance(chunk["timeline"], dict):
                timeline = chunk["timeline"]

            if "aggregations" in chunk and isinstance(chunk["aggregations"], dict):
                aggregations = chunk["aggregations"]

            chunk_matches = chunk.get("matches", [])
            if isinstance(chunk_matches, list):
                for m in chunk_matches:
                    if not isinstance(m, dict):
                        continue
                    m_id = str(m.get("id", "")).strip()
                    if m_id and m_id in seen_ids:
                        continue
                    if m_id:
                        seen_ids.add(m_id)

                    snippet_obj = m.get("snippet", {}) if isinstance(m.get("snippet"), dict) else {}
                    snippet_text = str(snippet_obj.get("snippet", m.get("summary", "")))
                    ingestion_time = snippet_obj.get("ingestionTime")

                    log_type_obj = m.get("logType", {}) if isinstance(m.get("logType"), dict) else {}
                    display_type = str(log_type_obj.get("displayName", ""))

                    matches.append(RawLogSnippet(
                        id=m_id,
                        summary=str(m.get("summary", "")),
                        snippet=snippet_text,
                        log_type=display_type,
                        ingestion_time=ingestion_time,
                    ))

        return RawLogSearchResult(
            matches=matches,
            total_matches=len(matches),
            progress=progress,
            has_more=has_more,
            next_page_token=next_page_token,
            aggregations=aggregations,
            timeline=timeline,
            retrieved_at=datetime.now(timezone.utc),
        )
