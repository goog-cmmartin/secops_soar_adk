"""Data RBAC Workflows (Milestone 5.12).

Orchestrates discovery and deep inspection of Data Access Scopes, Data Access Labels,
and SOAR multi-tenant environment RBAC bindings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    DataAccessLabelBatch,
    DataAccessLabelDetail,
    DataAccessLabelSummary,
    DataAccessScopeBatch,
    DataAccessScopeDetail,
    DataAccessScopeSummary,
    EnvironmentScopeBatch,
    EnvironmentScopeSummary,
)


def _normalize_scope_summary(raw: Dict[str, Any]) -> DataAccessScopeSummary:
    """Normalizes raw Data Access Scope JSON into DataAccessScopeSummary."""
    name = raw.get("name", "")
    sid = name.split("/")[-1] if "/" in name else name
    allowed = raw.get("allowedDataAccessLabels", [])
    denied = raw.get("deniedDataAccessLabels", [])
    return DataAccessScopeSummary(
        name=name,
        id=sid,
        display_name=raw.get("displayName", sid),
        description=raw.get("description", ""),
        allow_all=bool(raw.get("allowAll", False)),
        allowed_labels_count=len(allowed) if isinstance(allowed, list) else 0,
        denied_labels_count=len(denied) if isinstance(denied, list) else 0,
        author=raw.get("author", ""),
        last_editor=raw.get("lastEditor", ""),
        create_time=raw.get("createTime", ""),
        update_time=raw.get("updateTime", ""),
        raw=raw,
    )


def _normalize_label_summary(raw: Dict[str, Any]) -> DataAccessLabelSummary:
    """Normalizes raw Data Access Label JSON into DataAccessLabelSummary."""
    name = raw.get("name", "")
    lid = name.split("/")[-1] if "/" in name else name
    return DataAccessLabelSummary(
        name=name,
        id=lid,
        display_name=raw.get("displayName", lid),
        description=raw.get("description", ""),
        udm_query=raw.get("udmQuery", ""),
        author=raw.get("author", ""),
        last_editor=raw.get("lastEditor", ""),
        create_time=raw.get("createTime", ""),
        update_time=raw.get("updateTime", ""),
        raw=raw,
    )


def _normalize_environment_summary(raw: Dict[str, Any]) -> EnvironmentScopeSummary:
    """Normalizes raw SOAR Environment JSON into EnvironmentScopeSummary."""
    name = raw.get("name", "")
    eid = name.split("/")[-1] if "/" in name else name
    scopes_json = raw.get("dataAccessScopesJson", "[]")
    scopes: List[str] = []
    if isinstance(scopes_json, str) and scopes_json.strip():
        try:
            parsed = json.loads(scopes_json)
            if isinstance(parsed, list):
                scopes = [str(s) for s in parsed]
        except Exception:
            scopes = []
    elif isinstance(scopes_json, list):
        scopes = [str(s) for s in scopes_json]

    return EnvironmentScopeSummary(
        name=name,
        id=eid,
        display_name=raw.get("displayName", eid),
        description=raw.get("description", ""),
        contact=raw.get("contact", ""),
        contact_emails=raw.get("contactEmails", ""),
        data_access_scopes=scopes,
        raw=raw,
    )


class SearchDataAccessScopesWorkflow:
    """Discovers and filters Data Access Scopes."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        limit: int = 100,
    ) -> DataAccessScopeBatch:
        raw_res = self.adapter.list_data_access_scopes(page_size=1000)
        items = raw_res.get("dataAccessScopes", [])
        global_granted = bool(raw_res.get("globalDataAccessScopeGranted", False))

        summaries: List[DataAccessScopeSummary] = []
        for it in items:
            summary = _normalize_scope_summary(it)
            if query:
                q_lower = query.lower()
                if (
                    q_lower not in summary.id.lower()
                    and q_lower not in summary.display_name.lower()
                    and q_lower not in summary.description.lower()
                    and q_lower not in summary.author.lower()
                ):
                    continue
            summaries.append(summary)

        total_count = len(summaries)
        limited = summaries[:limit]
        return DataAccessScopeBatch(
            scopes=limited,
            total_count=total_count,
            global_scope_granted=global_granted,
            next_page_token=raw_res.get("nextPageToken"),
        )


class GetDataAccessScopeWorkflow:
    """Retrieves deep configuration of a Data Access Scope."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, scope_id: str) -> DataAccessScopeDetail:
        raw = self.adapter.get_data_access_scope(scope_id)
        summary = _normalize_scope_summary(raw)
        return DataAccessScopeDetail(
            summary=summary,
            allowed_data_access_labels=raw.get("allowedDataAccessLabels", []),
            denied_data_access_labels=raw.get("deniedDataAccessLabels", []),
            details=raw,
        )


class SearchDataAccessLabelsWorkflow:
    """Discovers and filters Data Access Labels."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        limit: int = 100,
    ) -> DataAccessLabelBatch:
        raw_res = self.adapter.list_data_access_labels(page_size=1000)
        items = raw_res.get("dataAccessLabels", [])

        summaries: List[DataAccessLabelSummary] = []
        for it in items:
            summary = _normalize_label_summary(it)
            if query:
                q_lower = query.lower()
                if (
                    q_lower not in summary.id.lower()
                    and q_lower not in summary.display_name.lower()
                    and q_lower not in summary.description.lower()
                    and q_lower not in summary.udm_query.lower()
                ):
                    continue
            summaries.append(summary)

        total_count = len(summaries)
        limited = summaries[:limit]
        return DataAccessLabelBatch(
            labels=limited,
            total_count=total_count,
            next_page_token=raw_res.get("nextPageToken"),
        )


class GetDataAccessLabelWorkflow:
    """Retrieves deep configuration of a Data Access Label."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, label_id: str) -> DataAccessLabelDetail:
        raw = self.adapter.get_data_access_label(label_id)
        summary = _normalize_label_summary(raw)
        return DataAccessLabelDetail(
            summary=summary,
            details=raw,
        )


class SearchEnvironmentScopesWorkflow:
    """Discovers SOAR environments and inspects bound Data Access Scopes."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        limit: int = 100,
    ) -> EnvironmentScopeBatch:
        raw_res = self.adapter.list_soar_environments(page_size=1000)
        items = raw_res.get("environments", [])

        summaries: List[EnvironmentScopeSummary] = []
        for it in items:
            summary = _normalize_environment_summary(it)
            if query:
                q_lower = query.lower()
                if (
                    q_lower not in summary.id.lower()
                    and q_lower not in summary.display_name.lower()
                    and q_lower not in summary.description.lower()
                    and not any(q_lower in sc.lower() for sc in summary.data_access_scopes)
                ):
                    continue
            summaries.append(summary)

        total_count = len(summaries)
        limited = summaries[:limit]
        return EnvironmentScopeBatch(
            environments=limited,
            total_count=total_count,
            next_page_token=raw_res.get("nextPageToken"),
        )
