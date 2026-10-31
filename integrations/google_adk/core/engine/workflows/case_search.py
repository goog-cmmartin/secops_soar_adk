"""SOAR Case Search Workflow (`case.search`)."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    CasePriority,
    CaseSearchBatch,
    CaseSearchQuery,
    CaseSearchResultItem,
)
from engine.parsing import (
    parse_priority as _parse_priority,
    parse_timestamp as _parse_timestamp,
)


class SearchCasesWorkflow:
    """Executes free-form and faceted case search via SecOps legacy search endpoints."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(self, query: CaseSearchQuery) -> CaseSearchBatch:
        """Executes case search and returns typed CaseSearchBatch."""
        raw_res = self.adapter.search_cases(
            query_text=query.query_text,
            start_time=query.start_time,
            end_time=query.end_time,
            tags=query.tags,
            priorities=query.priorities,
            stages=query.stages,
            environments=query.environments,
            assigned_users=query.assigned_users,
            is_important=query.is_important,
            page_size=query.page_size,
            page_number=query.page_number,
        )

        raw_items = raw_res.get("results", []) if isinstance(raw_res, dict) else []
        total_count = int(raw_res.get("totalCount", len(raw_items))) if isinstance(raw_res, dict) else len(raw_items)
        page_size = int(raw_res.get("pageSize", query.page_size)) if isinstance(raw_res, dict) else query.page_size

        items: List[CaseSearchResultItem] = []
        for r in raw_items:
            if not isinstance(r, dict):
                continue
            case_id = str(r.get("id", ""))
            title = r.get("title", "")
            create_time = _parse_timestamp(r.get("time"))
            priority = _parse_priority(r.get("priority"))
            stage = r.get("stage", "Unknown")
            tags = r.get("tags", []) or []
            products = r.get("products", []) or []
            user_assigned = r.get("userAssigned")
            is_important = bool(r.get("isImportant", False))
            is_incident = bool(r.get("isIncident", False))
            is_closed = bool(r.get("isCaseClosed", False))
            alerts_count = int(r.get("alertsCount", 0))
            environment = r.get("environment", "")
            ticket_ids = r.get("ticketIds", []) or []
            ports = [str(p) for p in r.get("ports", [])]

            items.append(
                CaseSearchResultItem(
                    case_id=case_id,
                    title=title,
                    create_time=create_time,
                    priority=priority,
                    stage=stage,
                    tags=tags,
                    products=products,
                    user_assigned=user_assigned,
                    is_important=is_important,
                    is_incident=is_incident,
                    is_closed=is_closed,
                    alerts_count=alerts_count,
                    environment=environment,
                    ticket_ids=ticket_ids,
                    ports=ports,
                    raw=r,
                )
            )

        provenance = {
            "endpoint": "legacySearches:legacyCaseSearchEverything",
            "query_text": query.query_text,
            "page_size": page_size,
            "page_number": query.page_number,
            "total_count": total_count,
            "returned_count": len(items),
        }

        return CaseSearchBatch(
            results=items,
            total_count=total_count,
            page_size=page_size,
            page_number=query.page_number,
            provenance=provenance,
        )
