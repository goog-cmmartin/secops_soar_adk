"""Google Chronicle SIEM Dashboard Health & Governance Workflow.

Audits native dashboards across Google SecOps for recent creations, modifications,
broken widget queries, compiler syntax diagnostics, empty placeholders, and staleness.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    DashboardBatch,
    DashboardDetail,
    DashboardHealthFinding,
    DashboardHealthReport,
    DashboardHealthStatus,
    DashboardSearchQuery,
    DashboardSummary,
)
from engine.workflows.dashboards import (
    GetDashboardDetailWorkflow,
    SearchDashboardsWorkflow,
    ValidateDashboardQueryWorkflow,
)

logger = logging.getLogger(__name__)


def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parses RFC 3339 timestamp string into UTC datetime object."""
    if not ts_str:
        return None
    try:
        s = str(ts_str).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


class AuditDashboardHealthWorkflow:
    """Orchestrates comprehensive health and lifecycle audit across all native dashboards."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        lookback_days: int = 14,
        stale_days: int = 180,
        validate_queries: bool = True,
        max_deep_dashboards: int = 50,
    ) -> DashboardHealthReport:
        """Audits dashboards for lifecycle drift, widget query syntax health, and staleness.

        Args:
            lookback_days: Days threshold to classify recently created/modified dashboards.
            stale_days: Days of inactivity to classify stale/abandoned custom dashboards.
            validate_queries: Whether to perform deep query syntax validation on widgets.
            max_deep_dashboards: Maximum number of candidate dashboards to deeply inspect.

        Returns:
            DashboardHealthReport containing aggregated metrics and detailed per-dashboard findings.
        """
        now_utc = datetime.now(timezone.utc)

        # 1. Discover all native dashboards
        search_wf = SearchDashboardsWorkflow(self.adapter)
        batch = search_wf.execute(DashboardSearchQuery(limit=1000))

        findings: List[DashboardHealthFinding] = []
        deep_inspected_count = 0

        for dash in batch.dashboards:
            finding, was_deep_inspected = self._evaluate_dashboard(
                dash=dash,
                now_utc=now_utc,
                lookback_days=lookback_days,
                stale_days=stale_days,
                validate_queries=validate_queries,
                should_deep_inspect=(deep_inspected_count < max_deep_dashboards),
            )
            if was_deep_inspected:
                deep_inspected_count += 1
            findings.append(finding)

        # 2. Aggregate summary counts
        healthy_cnt = sum(1 for f in findings if f.status == DashboardHealthStatus.HEALTHY)
        created_cnt = sum(1 for f in findings if f.status == DashboardHealthStatus.RECENTLY_CREATED)
        modified_cnt = sum(1 for f in findings if f.status == DashboardHealthStatus.RECENTLY_MODIFIED)
        broken_cnt = sum(1 for f in findings if f.status == DashboardHealthStatus.BROKEN_QUERY)
        empty_cnt = sum(1 for f in findings if f.status == DashboardHealthStatus.EMPTY_DASHBOARD)
        stale_cnt = sum(1 for f in findings if f.status == DashboardHealthStatus.STALE)
        custom_cnt = sum(1 for f in findings if f.dashboard_type.upper() == "CUSTOM")
        curated_cnt = sum(1 for f in findings if f.dashboard_type.upper() in ("CURATED", "DEFAULT"))

        return DashboardHealthReport(
            total_dashboards_audited=len(findings),
            healthy_count=healthy_cnt,
            recently_created_count=created_cnt,
            recently_modified_count=modified_cnt,
            broken_query_count=broken_cnt,
            empty_dashboard_count=empty_cnt,
            stale_count=stale_cnt,
            custom_count=custom_cnt,
            curated_count=curated_cnt,
            findings=findings,
            generated_at=now_utc,
        )

    def _evaluate_dashboard(
        self,
        dash: DashboardSummary,
        now_utc: datetime,
        lookback_days: int,
        stale_days: int,
        validate_queries: bool,
        should_deep_inspect: bool,
    ) -> tuple[DashboardHealthFinding, bool]:
        """Evaluates a single dashboard summary and performs widget syntax validation if needed."""
        create_dt = _parse_timestamp(dash.create_time)
        update_dt = _parse_timestamp(dash.update_time)

        is_custom = bool(dash.type.upper() == "CUSTOM")
        days_since_create = (now_utc - create_dt).days if create_dt else None
        days_since_update = (now_utc - update_dt).days if update_dt else None

        is_recently_created = bool(days_since_create is not None and days_since_create <= lookback_days)
        is_recently_modified = bool(
            days_since_update is not None
            and days_since_update <= lookback_days
            and not is_recently_created
        )
        is_stale = bool(is_custom and days_since_update is not None and days_since_update > stale_days)
        broken_query_details: List[Dict[str, Any]] = []
        has_orphan_chart = False
        was_deep_inspected = False
        charts_count = dash.charts_count

        # Deep inspection for custom or recently modified dashboards
        if (
            validate_queries
            and should_deep_inspect
            and (is_custom or is_recently_modified or is_recently_created)
        ):
            was_deep_inspected = True
            broken_query_details, has_orphan_chart, charts_count = self._audit_dashboard_widgets(dash.id)

        raw_def = dash.raw.get("definition", {})
        has_explicit_empty_charts = isinstance(raw_def.get("charts"), list) and len(raw_def.get("charts", [])) == 0 and bool(raw_def)
        is_empty = bool(is_custom and (charts_count == 0 if was_deep_inspected else has_explicit_empty_charts))

        # Status determination hierarchy
        status = DashboardHealthStatus.HEALTHY
        details = "Dashboard is operating normally."
        remediations: List[str] = []

        if broken_query_details:
            status = DashboardHealthStatus.BROKEN_QUERY
            details = f"Dashboard contains {len(broken_query_details)} broken widget query/queries with syntax or compiler errors."
            remediations.append("Inspect broken chart queries and correct invalid UDM field references or statistical syntax.")
            remediations.append("Run ValidateDashboardQuery on failing widgets to verify compiler diagnostics.")
        elif has_orphan_chart:
            status = DashboardHealthStatus.ORPHAN_CHART
            details = "Dashboard contains chart widget(s) without an active query datasource."
            remediations.append("Attach a valid dashboard query datasource to orphaned chart widgets or delete unused charts.")
        elif is_empty:
            status = DashboardHealthStatus.EMPTY_DASHBOARD
            details = "Custom dashboard contains 0 chart widgets."
            remediations.append("Add visualization charts to the dashboard or delete unused placeholder.")
        elif is_recently_created:
            status = DashboardHealthStatus.RECENTLY_CREATED
            details = f"Dashboard was newly created {days_since_create} day(s) ago by {dash.create_user_id or 'unknown'}."
            remediations.append("Verify widget layouts, filter bindings, and share access with the SOC team.")
        elif is_recently_modified:
            status = DashboardHealthStatus.RECENTLY_MODIFIED
            details = f"Dashboard was modified {days_since_update} day(s) ago by {dash.update_user_id or 'unknown'}."
            remediations.append("Review recent widget modifications to confirm metrics align with monitoring objectives.")
        elif is_stale:
            status = DashboardHealthStatus.STALE
            details = f"Custom dashboard has had no updates for {days_since_update} days (owner: {dash.create_user_id or 'unknown'})."
            remediations.append("Confirm with dashboard owner if this dashboard is still in active operational use or should be archived.")

        finding = DashboardHealthFinding(
            dashboard_id=dash.id,
            display_name=dash.display_name or dash.id,
            dashboard_type=dash.type,
            create_user_id=dash.create_user_id,
            update_user_id=dash.update_user_id,
            create_time=create_dt,
            update_time=update_dt,
            charts_count=charts_count,
            broken_queries_count=len(broken_query_details),
            status=status,
            details=details,
            remediation_steps=remediations,
            broken_query_details=broken_query_details,
            raw=dash.raw,
        )
        return finding, was_deep_inspected

    def _audit_dashboard_widgets(self, dashboard_id: str) -> tuple[List[Dict[str, Any]], bool, int]:
        """Deeply inspects charts and validates underlying statistical queries."""
        broken_queries: List[Dict[str, Any]] = []
        has_orphan_chart = False
        charts_count = 0

        try:
            get_dash_wf = GetDashboardDetailWorkflow(self.adapter)
            detail = get_dash_wf.execute(dashboard_id, include_queries=True)
            charts_count = len(detail.charts)
            validate_wf = ValidateDashboardQueryWorkflow(self.adapter)

            for chart in detail.charts:
                if not chart.query and not chart.query_name:
                    has_orphan_chart = True
                    continue

                if chart.query and chart.query.query_text:
                    try:
                        val_res = validate_wf.execute(
                            raw_query=chart.query.query_text,
                            dialect=chart.query.dialect or "DIALECT_STATS",
                        )
                        if not val_res.valid:
                            broken_queries.append(
                                {
                                    "chart_id": chart.id,
                                    "chart_display_name": chart.display_name,
                                    "query_id": chart.query.id,
                                    "query_text": chart.query.query_text,
                                    "error_message": val_res.error_message or "Query validation failed.",
                                }
                            )
                    except Exception as e:
                        logger.debug(f"Query validation exception for chart '{chart.display_name}': {e}")
        except Exception as exc:
            logger.debug(f"Could not deep-audit dashboard '{dashboard_id}': {exc}")

        return broken_queries, has_orphan_chart, charts_count
