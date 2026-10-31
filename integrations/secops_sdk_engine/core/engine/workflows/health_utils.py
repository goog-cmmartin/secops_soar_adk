"""Shared telemetry utilities for Feed, Parser, and Detection Health workflows.

Connects to Google SecOps curated dashboards:
- Health Hub (1b0cb92f-c162-424a-9d31-05b35180c8a5)
- Data Health Deep Dive (5cf5988b-951f-4e54-830d-330ef5ad438a)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.workflows.dashboards import (
    ExecuteDashboardQueryWorkflow,
    GetDashboardDetailWorkflow,
)

logger = logging.getLogger(__name__)

# Dashboard UUIDs
HEALTH_HUB_DASHBOARD_ID = "1b0cb92f-c162-424a-9d31-05b35180c8a5"
DATA_HEALTH_DEEP_DIVE_DASHBOARD_ID = "5cf5988b-951f-4e54-830d-330ef5ad438a"

# Canonical Collector ID Mapping from Data Health Deep Dive
COLLECTOR_UUID_MAP: Dict[str, str] = {
    "aaaa3333-aaaa-3333-aaaa-3333aaaa3333": "Native GCP Ingestion",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb": "/unstructuredlogentries:batchCreate",
    "cccccccc-cccc-cccc-cccc-cccccccccccc": "/udmevents:batchCreate",
    "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee": "/entities:batchCreate",
    "ffffffff-ffff-ffff-ffff-ffffffffffff": "SOAR Alert",
    "aaaa1111-aaaa-1111-aaaa-1111aaaa1111": "Collection Agent",
    "aaaa1111-aaaa-1111-aaaa-1111aaaa1112": "BindPlane Enterprise Google",
    "aaaa1111-aaaa-1111-aaaa-1111aaaa1113": "BindPlane Enterprise Regular",
    "aaaa1111-aaaa-1111-aaaa-1111aaaa1114": "Headless Agent",
    "dddddddd-dddd-dddd-dddd-dddddddddddd": "Internal API / Native Workspace",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": "Feeds",
    "aaaa2222-aaaa-2222-aaaa-2222aaaa2222": "HTTPS Push Feeds",
    "aaaa4444-aaaa-4444-aaaa-4444aaaa4444": "Azure Event Hub Feeds",
}


def resolve_collector_name(collector_id: str, log_type: str = "") -> str:
    """Resolves collector UUID or custom collector string to human-readable taxonomy name."""
    if not collector_id:
        return "Unknown"
    cid = str(collector_id).strip().lower()
    if cid in COLLECTOR_UUID_MAP:
        if cid == "dddddddd-dddd-dddd-dddd-dddddddddddd" and log_type == "WORKSPACE_ACTIVITY":
            return "Native Workspace Ingestion"
        return COLLECTOR_UUID_MAP[cid]
    return collector_id


@dataclass
class DeepDiveTelemetry:
    """Aggregated telemetry from Data Health Deep Dive and Health Hub dashboards.

    ``available`` is True only when the dashboard was read and at least one
    target chart executed. ``errors`` records every dashboard/chart failure so
    callers can distinguish "no anomalies" from "no telemetry".
    """
    collector_by_log_type: Dict[str, str] = field(default_factory=dict)
    parser_errors_by_log_type: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    volume_funnel_by_log_type: Dict[str, Dict[str, int]] = field(default_factory=dict)
    quota_rejected_volume_mb: Dict[str, float] = field(default_factory=dict)
    quota_limit_mb_per_sec: Dict[str, float] = field(default_factory=dict)
    available: bool = False
    errors: List[str] = field(default_factory=list)


@dataclass
class DashboardChartRows:
    """Rows of the target charts of one curated dashboard, plus failures."""
    dashboard_id: str
    dashboard_label: str
    rows_by_key: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    available: bool = False


def _num(value: Any) -> float:
    """Converts a dashboard cell (int/float/numeric string/None) to float."""
    if value is None or value == "":
        return 0.0
    return float(value)


def collect_dashboard_chart_rows(
    adapter: GoogleSecOpsAdapter,
    dashboard_id: str,
    dashboard_label: str,
    chart_keys: List[str],
) -> DashboardChartRows:
    """Executes the dashboard charts whose display name contains one of ``chart_keys``.

    Never raises for a single failed chart: each failure (dashboard unreadable,
    expected chart missing, chart query error) is appended to ``errors`` and
    logged. ``available`` is True when the dashboard was read and at least one
    target chart executed successfully.
    """
    out = DashboardChartRows(dashboard_id=dashboard_id, dashboard_label=dashboard_label)
    try:
        dash_detail = GetDashboardDetailWorkflow(adapter).execute(dashboard_id, include_queries=False)
    except Exception as e:
        msg = f"{dashboard_label} ({dashboard_id}): dashboard unavailable: {type(e).__name__}: {e}"
        logger.warning(msg)
        out.errors.append(msg)
        return out

    exec_wf = ExecuteDashboardQueryWorkflow(adapter)
    matched: Dict[str, bool] = {k: False for k in chart_keys}
    for chart in dash_detail.charts:
        c_name = (chart.display_name or "").lower().strip()
        key = next((k for k in chart_keys if k in c_name), None)
        if key is None or matched[key]:
            continue
        q_name = chart.query_name or chart.raw.get("chartDatasource", {}).get("dashboardQuery")
        matched[key] = True
        if not q_name:
            msg = f"{dashboard_label} chart '{chart.display_name}': no dashboardQuery bound to chart"
            logger.warning(msg)
            out.errors.append(msg)
            continue
        try:
            res = exec_wf.execute(query_name_or_id=q_name)
            out.rows_by_key[key] = list(res.rows)
        except Exception as e:
            msg = f"{dashboard_label} chart '{chart.display_name}' query failed: {type(e).__name__}: {e}"
            logger.warning(msg)
            out.errors.append(msg)

    for key, found in matched.items():
        if not found:
            msg = f"{dashboard_label} ({dashboard_id}): expected chart matching '{key}' not found"
            logger.warning(msg)
            out.errors.append(msg)

    out.available = bool(out.rows_by_key)
    return out


DEEP_DIVE_CHART_KEYS = [
    "log count by collector id",
    "parser error history",
    "ingestion - events by status",
    "burst rejection",
    "burst limit graph",
]


def fetch_deep_dive_telemetry(adapter: GoogleSecOpsAdapter) -> DeepDiveTelemetry:
    """Queries Data Health Deep Dive dashboard and returns structured telemetry.

    Chart/dashboard failures are recorded in ``DeepDiveTelemetry.errors``.
    """
    telemetry = DeepDiveTelemetry()
    charts = collect_dashboard_chart_rows(
        adapter, DATA_HEALTH_DEEP_DIVE_DASHBOARD_ID, "Data Health Deep Dive", DEEP_DIVE_CHART_KEYS
    )
    telemetry.errors.extend(charts.errors)
    telemetry.available = charts.available

    def _map_rows(key: str, mapper) -> None:
        rows = charts.rows_by_key.get(key)
        if rows is None:
            return
        try:
            for row in rows:
                mapper(row)
        except (TypeError, ValueError) as e:
            msg = f"Data Health Deep Dive chart '{key}': unexpected row schema: {type(e).__name__}: {e}"
            logger.warning(msg)
            telemetry.errors.append(msg)

    # 1. Log Count By Collector Id & Log Type
    def _collector(row: Dict[str, Any]) -> None:
        lt = row.get("Log_Type") or row.get("log_type") or ""
        c_name_val = row.get("collector_name") or ""
        if lt and c_name_val and _num(row.get("total_logs")) > 0:
            telemetry.collector_by_log_type[lt] = resolve_collector_name(c_name_val, lt)

    # 2. Parser Error History (Last 200 Errors)
    def _parser_errors(row: Dict[str, Any]) -> None:
        lt = row.get("log") or row.get("log_type") or ""
        if lt:
            telemetry.parser_errors_by_log_type.setdefault(lt, []).append(row)

    # 3. Ingestion - Events by Status (Funnel)
    def _funnel(row: Dict[str, Any]) -> None:
        lt = row.get("log_type") or ""
        if not lt:
            return
        funnel = telemetry.volume_funnel_by_log_type.setdefault(lt, {
            "total_logs": 0,
            "validated_events": 0,
            "normalized_events": 0,
            "parsing_error_events": 0,
            "validation_error_events": 0,
            "indexing_error_events": 0,
        })
        funnel["total_logs"] += int(_num(row.get("Total_Logs")))
        funnel["validated_events"] += int(_num(row.get("Total_Validated_Events")))
        funnel["normalized_events"] += int(_num(row.get("Total_Normalized_Events")))
        funnel["parsing_error_events"] += int(_num(row.get("Total_Parsing_Error_Events")))
        funnel["validation_error_events"] += int(_num(row.get("Total_Validation_Error_Events")))
        funnel["indexing_error_events"] += int(_num(row.get("Total_Indexing_Error_Events")))

    # 4. Burst Rejection Graph
    def _burst_rejection(row: Dict[str, Any]) -> None:
        lt = row.get("log_type") or ""
        vol = _num(row.get("Max_Of_Quota_Rejected_Log_Volume"))
        if lt and vol > 0.0:
            telemetry.quota_rejected_volume_mb[lt] = max(telemetry.quota_rejected_volume_mb.get(lt, 0.0), vol)

    # 5. Burst Limit Graph - Quota Limit ("Qouta" is the live column spelling)
    def _burst_limit(row: Dict[str, Any]) -> None:
        lt = row.get("log_type") or ""
        limit_val = _num(row.get("Max_Qouta_Limit_MB_Per_Second"))
        if lt and limit_val > 0.0:
            telemetry.quota_limit_mb_per_sec[lt] = max(telemetry.quota_limit_mb_per_sec.get(lt, 0.0), limit_val)

    _map_rows("log count by collector id", _collector)
    _map_rows("parser error history", _parser_errors)
    _map_rows("ingestion - events by status", _funnel)
    _map_rows("burst rejection", _burst_rejection)
    _map_rows("burst limit graph", _burst_limit)

    return telemetry
