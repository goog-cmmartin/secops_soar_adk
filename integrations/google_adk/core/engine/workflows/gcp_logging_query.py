"""Workflow implementation for querying Google Cloud Logging for SecOps events, errors, and audit logs."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional

from engine.domain import GcpLogEntry, GcpLogQueryResult

logger = logging.getLogger(__name__)


def _since_clause(hours: float, now: Optional[datetime] = None) -> str:
    """``timestamp >= "<RFC 3339 start>"`` for the last ``hours``.

    Cloud Logging's query language compares timestamps to literal times only; it has no date
    arithmetic, so ``"<now>" - 24h`` is rejected (or silently matches nothing).
    """
    start = (now or datetime.now(timezone.utc)) - timedelta(hours=hours)
    return f'timestamp >= "{start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}"'


def _normalize_log_entry(raw: Dict[str, Any]) -> GcpLogEntry:
    """Transforms raw Google Cloud Logging JSON entry into a typed GcpLogEntry."""
    resource = raw.get("resource", {})
    resource_type = resource.get("type", "") if isinstance(resource, dict) else ""
    resource_labels = resource.get("labels", {}) if isinstance(resource, dict) else {}

    return GcpLogEntry(
        timestamp=raw.get("timestamp", ""),
        severity=raw.get("severity", "DEFAULT"),
        log_name=raw.get("logName", ""),
        resource_type=resource_type,
        resource_labels=resource_labels,
        insert_id=raw.get("insertId", ""),
        json_payload=raw.get("jsonPayload", {}) if isinstance(raw.get("jsonPayload"), dict) else {},
        text_payload=raw.get("textPayload", "") or "",
        proto_payload=raw.get("protoPayload", {}) if isinstance(raw.get("protoPayload"), dict) else {},
        trace=raw.get("trace", "") or "",
        raw=raw,
    )


class GcpLoggingQueryWorkflow:
    """Executes queries against Google Cloud Logging API for SecOps operational and audit telemetry."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        filter_str: str,
        project_ids: Optional[List[str]] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
        order_by: str = "timestamp desc",
    ) -> GcpLogQueryResult:
        """Executes a Cloud Logging query with pagination and normalization."""
        if not filter_str:
            raise ValueError("Cloud Logging query requires a non-empty filter_str expression.")

        raw_resp = self.adapter.query_cloud_logging(
            filter_str=filter_str,
            project_ids=project_ids,
            page_size=page_size,
            page_token=page_token,
            order_by=order_by,
        )

        entries_raw = raw_resp.get("entries", [])
        entries = [_normalize_log_entry(e) for e in entries_raw]
        next_token = raw_resp.get("nextPageToken")
        queried_projects = project_ids or [getattr(self.adapter, "project_id", "")]

        return GcpLogQueryResult(
            entries=entries,
            next_page_token=next_token,
            total_count=len(entries),
            filter_applied=filter_str,
            projects_queried=queried_projects,
        )

    def query_secops_errors(
        self,
        hours: int = 24,
        component: Optional[str] = None,
        page_size: int = 50,
    ) -> GcpLogQueryResult:
        """Pre-packaged query for SecOps operational errors (Chronicle, forwarders, parsers)."""
        filter_parts = [
            _since_clause(hours),
            'severity >= ERROR',
        ]
        if component:
            filter_parts.append(f'(jsonPayload.component = "{component}" OR textPayload =~ "{component}")')

        combined_filter = " AND ".join(filter_parts)
        return self.execute(filter_str=combined_filter, page_size=page_size)

    def query_secops_audit_logs(
        self,
        hours: int = 24,
        human_only: Optional[bool] = None,
        page_size: int = 50,
    ) -> GcpLogQueryResult:
        """Pre-packaged query for SecOps Cloud Audit logs (cloudaudit.googleapis.com)."""
        filter_parts = [
            'logName =~ "cloudaudit.googleapis.com"',
            _since_clause(hours),
        ]
        if human_only is True:
            # Filter for user accounts vs service accounts
            filter_parts.append('protoPayload.authenticationInfo.principalEmail !~ "gserviceaccount.com"')
        elif human_only is False:
            filter_parts.append('protoPayload.authenticationInfo.principalEmail =~ "gserviceaccount.com"')

        combined_filter = " AND ".join(filter_parts)
        return self.execute(filter_str=combined_filter, page_size=page_size)
