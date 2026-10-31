"""Workflow implementations for Ingestion Feeds and Feed Schemas."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    FeedBatch,
    FeedDetail,
    FeedLogTypeBatch,
    FeedLogTypeSchema,
    FeedSourceTypeBatch,
    FeedSourceTypeSchema,
    FeedSummary,
)


def _normalize_feed_summary(raw: Dict[str, Any]) -> FeedSummary:
    """Transforms raw feed JSON into typed FeedSummary."""
    name = raw.get("name", "")
    fid = name.split("/")[-1] if name else ""
    details = raw.get("details", {})
    feed_source_type = details.get("feedSourceType", "UNKNOWN") if isinstance(details, dict) else "UNKNOWN"
    raw_log_type = details.get("logType", "UNKNOWN") if isinstance(details, dict) else "UNKNOWN"
    clean_log_type = raw_log_type.split("/")[-1] if raw_log_type else "UNKNOWN"
    state = raw.get("state") or raw.get("feedState") or "UNKNOWN"

    return FeedSummary(
        id=fid,
        name=name,
        display_name=raw.get("displayName", fid),
        state=state,
        feed_source_type=feed_source_type,
        log_type=clean_log_type,
        reference_id=raw.get("referenceId", fid),
        raw=raw,
    )


def _normalize_feed_source_type_schema(raw: Dict[str, Any]) -> FeedSourceTypeSchema:
    """Transforms raw feedSourceTypeSchema JSON into typed FeedSourceTypeSchema."""
    name = raw.get("name", "")
    source_type = raw.get("feedSourceType", name.split("/")[-1] if name else "")
    return FeedSourceTypeSchema(
        name=name,
        feed_source_type=source_type,
        display_name=raw.get("displayName", source_type),
        description=raw.get("description", ""),
        raw=raw,
    )


def _normalize_feed_log_type_schema(raw: Dict[str, Any]) -> FeedLogTypeSchema:
    """Transforms raw logTypeSchema JSON into typed FeedLogTypeSchema."""
    name = raw.get("name", "")
    log_type = raw.get("logType", name.split("/")[-1] if name else "")
    field_count = raw.get("detailsFieldSchemasCount", 0)
    details_fields = raw.get("detailsFieldSchemas")
    if details_fields and isinstance(details_fields, list):
        field_count = len(details_fields)

    return FeedLogTypeSchema(
        name=name,
        log_type=log_type,
        display_name=raw.get("displayName", log_type),
        supporting_documentation=raw.get("supportingDocumentation", ""),
        details_field_schemas_count=field_count,
        details_field_schemas=details_fields,
        raw=raw,
    )


class SearchFeedsWorkflow:
    """Workflow to list and filter ingestion feeds."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        feed_source_type: Optional[str] = None,
        log_type: Optional[str] = None,
        state: Optional[str] = None,
        limit: int = 50,
    ) -> FeedBatch:
        raw_res = self.adapter.list_feeds(page_size=1000)
        items = raw_res.get("feeds", [])
        summaries = [_normalize_feed_summary(item) for item in items]

        if query:
            q_lower = query.lower()
            summaries = [
                s
                for s in summaries
                if q_lower in s.display_name.lower()
                or q_lower in s.id.lower()
                or q_lower in s.log_type.lower()
                or q_lower in s.feed_source_type.lower()
            ]

        if feed_source_type:
            fst_lower = feed_source_type.lower()
            summaries = [s for s in summaries if fst_lower in s.feed_source_type.lower()]

        if log_type:
            lt_lower = log_type.lower()
            summaries = [s for s in summaries if lt_lower in s.log_type.lower()]

        if state:
            st_lower = state.lower()
            summaries = [s for s in summaries if st_lower == s.state.lower()]

        limited = summaries[:limit]
        return FeedBatch(
            feeds=limited,
            total_count=len(summaries),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetFeedDetailWorkflow:
    """Workflow to retrieve full feed configuration details."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(self, identifier_or_title: str) -> FeedDetail:
        clean_id = identifier_or_title.split("/")[-1]
        if not clean_id.startswith("projects/") and len(clean_id.split("-")) < 4:
            # Search by display name
            search_wf = SearchFeedsWorkflow(self.adapter)
            batch = search_wf.execute(query=identifier_or_title, limit=10)
            for f in batch.feeds:
                if (
                    f.display_name.lower() == identifier_or_title.lower()
                    or f.id.lower() == identifier_or_title.lower()
                ):
                    clean_id = f.id
                    break

        raw = self.adapter.get_feed(clean_id)
        summary = _normalize_feed_summary(raw)
        return FeedDetail(
            summary=summary,
            details=raw.get("details", {}),
            raw=raw,
        )


class ListFeedSourceTypeSchemasWorkflow:
    """Workflow to list supported feed source types."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(self, limit: int = 100) -> FeedSourceTypeBatch:
        raw_res = self.adapter.list_feed_source_type_schemas(page_size=1000)
        items = raw_res.get("feedSourceTypeSchemas", [])
        schemas = [_normalize_feed_source_type_schema(item) for item in items]
        limited = schemas[:limit]
        return FeedSourceTypeBatch(
            source_types=limited,
            total_count=len(schemas),
            retrieved_at=datetime.now(timezone.utc),
        )


class ListFeedLogTypeSchemasWorkflow:
    """Workflow to list log type schemas for a specific feed source with lean payload handling."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(
        self,
        feed_source_type: str,
        limit: int = 100,
        include_field_schemas: bool = False,
    ) -> FeedLogTypeBatch:
        raw_res = self.adapter.list_feed_log_type_schemas(
            feed_source_type=feed_source_type,
            page_size=min(limit, 500),
            omit_details_fields=not include_field_schemas,
        )
        items = raw_res.get("logTypeSchemas", [])
        schemas = [_normalize_feed_log_type_schema(item) for item in items]
        limited = schemas[:limit]
        return FeedLogTypeBatch(
            feed_source_type=feed_source_type,
            log_types=limited,
            total_count=len(schemas),
            retrieved_at=datetime.now(timezone.utc),
        )
