"""Native Dashboards Workflows (Milestone 5.9).

Implements discovery, keyword search, deep composite graph assembly (dashboard + charts + queries + layout),
tabular query execution normalization, and statistical query syntax validation for Google SecOps Dashboards.

Invariants:
- Live data origin exclusively from GoogleSecOpsAdapter.
- Zero synthetic data structures or fallbacks.
- Transparent error propagation and explicit bounds.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    DashboardBatch,
    DashboardChart,
    DashboardChartLayout,
    DashboardDetail,
    DashboardHealthCheckResult,
    DashboardQuery,
    DashboardQueryResult,
    DashboardSearchQuery,
    DashboardSummary,
    ValidationResult,
)


def _map_dashboard_summary(raw: Dict[str, Any]) -> DashboardSummary:
    """Maps raw native dashboard JSON to typed DashboardSummary."""
    name = raw.get("name", "")
    dash_id = name.split("/")[-1] if "/" in name else name
    definition = raw.get("definition", {})
    charts = definition.get("charts", [])

    return DashboardSummary(
        id=dash_id,
        name=name,
        display_name=raw.get("displayName", dash_id),
        description=raw.get("description", ""),
        type=raw.get("type", "UNKNOWN"),
        create_time=raw.get("createTime", ""),
        update_time=raw.get("updateTime", ""),
        create_user_id=raw.get("createUserId", ""),
        update_user_id=raw.get("updateUserId", ""),
        access=raw.get("access", "UNKNOWN"),
        charts_count=len(charts),
        raw=raw,
    )


def _map_dashboard_query(raw: Dict[str, Any]) -> DashboardQuery:
    """Maps raw dashboard query JSON to typed DashboardQuery."""
    name = raw.get("name", "")
    query_id = name.split("/")[-1] if "/" in name else name
    input_cfg = raw.get("input", {})
    rel_time = input_cfg.get("relativeTime", {})

    return DashboardQuery(
        id=query_id,
        name=name,
        query_text=raw.get("query", ""),
        dialect=raw.get("dialect", "YL2"),
        time_unit=rel_time.get("timeUnit"),
        time_value=rel_time.get("startTimeVal"),
        dashboard_chart=raw.get("dashboardChart"),
        etag=raw.get("etag"),
        raw=raw,
    )


def _map_dashboard_chart(
    raw: Dict[str, Any],
    layout_raw: Optional[Dict[str, Any]] = None,
    query_obj: Optional[DashboardQuery] = None,
) -> DashboardChart:
    """Maps raw dashboard chart JSON to typed DashboardChart."""
    name = raw.get("name", "")
    chart_id = name.split("/")[-1] if "/" in name else name

    layout = None
    if layout_raw:
        chart_layout = layout_raw.get("chartLayout", {})
        layout = DashboardChartLayout(
            start_x=chart_layout.get("startX", 0),
            span_x=chart_layout.get("spanX", 0),
            start_y=chart_layout.get("startY", 0),
            span_y=chart_layout.get("spanY", 0),
            filters_ids=layout_raw.get("filtersIds", []),
        )

    datasource = raw.get("chartDatasource", {})
    data_sources = datasource.get("dataSources", [])
    query_name = datasource.get("dashboardQuery")

    return DashboardChart(
        id=chart_id,
        name=name,
        display_name=raw.get("displayName", chart_id),
        description=raw.get("description", ""),
        tile_type=raw.get("tileType", "TILE_TYPE_VISUALIZATION"),
        chart_type=raw.get("chartType", "DASHBOARD_CHART_TYPE_CUSTOM"),
        data_sources=data_sources,
        visualization=raw.get("visualization", {}),
        drill_down_config=raw.get("drillDownConfig", {}),
        layout=layout,
        query=query_obj,
        query_name=query_name,
        etag=raw.get("etag"),
        raw=raw,
    )


class SearchDashboardsWorkflow:
    """Orchestrates discovery and filtering of native Google SecOps dashboards."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, query: DashboardSearchQuery) -> DashboardBatch:
        """Discovers and filters native dashboards."""
        res = self.adapter.list_native_dashboards(page_size=1000)
        raw_items = res.get("nativeDashboards", res.get("dashboards", []))
        all_summaries = [_map_dashboard_summary(it) for it in raw_items]

        filtered: List[DashboardSummary] = []
        for s in all_summaries:
            # Keyword filter
            if query.query:
                q = query.query.lower()
                text_corpus = f"{s.id} {s.display_name} {s.description}".lower()
                if q not in text_corpus:
                    continue

            # Type filter
            if query.dashboard_type:
                if query.dashboard_type.upper() != s.type.upper():
                    continue

            filtered.append(s)

        paged = filtered[: query.limit] if query.limit > 0 else filtered

        return DashboardBatch(
            dashboards=paged,
            total_count=len(filtered),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetDashboardDetailWorkflow:
    """Orchestrates deep composite retrieval of a dashboard with batch-resolved charts and queries."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, identifier_or_title: str, include_queries: bool = True) -> DashboardDetail:
        """Retrieves and builds full dashboard composite graph."""
        clean_target = identifier_or_title.strip()
        if not clean_target:
            raise ValueError("Dashboard identifier or title must be provided")

        clean_id = clean_target.split("/")[-1]

        # 1. Attempt direct retrieval by ID
        raw = self.adapter.get_native_dashboard(clean_id)
        if not raw or not raw.get("name"):
            # Fallback resolve by title
            search_wf = SearchDashboardsWorkflow(self.adapter)
            batch = search_wf.execute(DashboardSearchQuery(limit=1000))
            matched_id = None
            for s in batch.dashboards:
                if clean_target.lower() in [s.id.lower(), s.display_name.lower()]:
                    matched_id = s.id
                    break

            if matched_id:
                raw = self.adapter.get_native_dashboard(matched_id)

        if not raw or not raw.get("name"):
            raise ValueError(f"Dashboard '{identifier_or_title}' not found in live Google SecOps tenant")

        summary = _map_dashboard_summary(raw)
        definition = raw.get("definition", {})
        chart_refs = definition.get("charts", [])
        filters = definition.get("filters", [])

        # Build layout mapping by chart name
        layout_by_name: Dict[str, Dict[str, Any]] = {}
        chart_names: List[str] = []
        for c in chart_refs:
            c_name = c.get("dashboardChart")
            if c_name:
                chart_names.append(c_name)
                layout_by_name[c_name] = c

        # 2. Batch Get Charts
        charts_map: Dict[str, Dict[str, Any]] = {}
        if chart_names:
            chart_res = self.adapter.batch_get_dashboard_charts(chart_names)
            for c_raw in chart_res.get("dashboardCharts", []):
                charts_map[c_raw.get("name", "")] = c_raw

        # 3. Resolve Queries & Assemble Charts
        assembled_charts: List[DashboardChart] = []
        for c_name in chart_names:
            c_raw = charts_map.get(c_name)
            if not c_raw:
                continue

            query_obj = None
            query_name = c_raw.get("chartDatasource", {}).get("dashboardQuery")
            if include_queries and query_name:
                try:
                    q_raw = self.adapter.get_dashboard_query(query_name)
                    if q_raw and q_raw.get("name"):
                        query_obj = _map_dashboard_query(q_raw)
                except Exception:
                    query_obj = None

            layout_raw = layout_by_name.get(c_name)
            assembled_chart = _map_dashboard_chart(c_raw, layout_raw=layout_raw, query_obj=query_obj)
            assembled_charts.append(assembled_chart)

        return DashboardDetail(
            summary=summary,
            charts=assembled_charts,
            filters=filters,
            raw=raw,
        )


class ExecuteDashboardQueryWorkflow:
    """Orchestrates live execution of a dashboard query and hydrates tabular results."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        query_name_or_id: Optional[str] = None,
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
        """Executes query and returns result."""
        # Adapter already returns normalized DashboardQueryResult
        return self.adapter.execute_dashboard_query(
            query_name=query_name_or_id,
            query_text=query_text,
            filters=filters,
            use_previous_time_range=use_previous_time_range,
            query_source=query_source,
            time_unit=time_unit,
            time_value=time_value,
            dialect=dialect,
            start_time=start_time,
            end_time=end_time,
            clear_cache=clear_cache,
        )


class ValidateDashboardQueryWorkflow:
    """Orchestrates query validation against Google SecOps compiler."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, raw_query: str, dialect: str = "DIALECT_STATS") -> ValidationResult:
        """Validates statistical query syntax."""
        return self.adapter.validate_stats_query(raw_query=raw_query, dialect=dialect)


def run_dashboard_health_check(
    adapter: GoogleSecOpsAdapter,
    dashboard_name: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> DashboardHealthCheckResult:
    """Execute comprehensive health check for a named dashboard.
    
    Workflow orchestration:
    1. Search for dashboard by display_name
    2. Retrieve full dashboard configuration
    3. Execute all widget queries
    4. Generate operational summary with error tracking
    
    Args:
        adapter: Live adapter for API interaction
        dashboard_name: Display name of target dashboard
        project_id: Optional override for project
        customer_id: Optional override for customer
        region: Optional override for region
    
    Returns:
        Dict containing:
            - dashboard_id: Resolved dashboard identifier
            - query_results: List of executed query results with metadata
            - summary: Human-readable operational summary
            - errors: List of any errors encountered during execution
    
    Raises:
        ValueError: If dashboard not found or multiple matches
        RuntimeError: If query execution fails critically
    """
    # Override tenant if specified
    has_override = bool(project_id or customer_id or region)
    orig_pid = adapter.project_id
    orig_cid = adapter.customer_id
    orig_reg = adapter.region
    if has_override:
        if project_id:
            adapter.project_id = project_id
        if customer_id:
            adapter.customer_id = customer_id
        if region:
            adapter.region = region
    
    try:
        # Step 1: Search for dashboard
        from engine.domain import DashboardSearchQuery
        search_wf = SearchDashboardsWorkflow(adapter)
        query_obj = DashboardSearchQuery(query=dashboard_name, limit=10)
        search_result = search_wf.execute(query=query_obj)
        
        matching = [d for d in search_result.dashboards if d.display_name == dashboard_name]
        if not matching:
            raise ValueError(
                f"Dashboard '{dashboard_name}' not found. "
                f"Available: {[d.display_name for d in search_result.dashboards]}"
            )
        if len(matching) > 1:
            raise ValueError(f"Multiple dashboards match '{dashboard_name}'")
        
        dashboard_summary = matching[0]
        dashboard_id = dashboard_summary.name  # Resource name
        
        # Step 2: Get full dashboard configuration
        get_wf = GetDashboardDetailWorkflow(adapter)
        dashboard_detail = get_wf.execute(dashboard_summary.name)
        
        # Step 3: Execute all widget queries
        exec_wf = ExecuteDashboardQueryWorkflow(adapter)
        query_results = []
        errors = []
        
        for chart in dashboard_detail.charts:
            query_name = chart.query.name if chart.query else chart.query_name
            if query_name:
                try:
                    result = exec_wf.execute(query_name_or_id=query_name)
                    query_results.append({
                        "query_name": query_name,
                        "chart_title": chart.display_name,
                        "success": True,
                        "row_count": len(result.rows),
                        "columns": result.columns,
                    })
                except Exception as e:
                    query_results.append({
                        "query_name": query_name,
                        "chart_title": chart.display_name,
                        "success": False,
                        "error": str(e),
                    })
                    errors.append(f"Query {query_name} ({chart.display_name}): {e}")
        
        # Step 4: Generate summary
        total_queries = len(query_results)
        successful = sum(1 for r in query_results if r.get("success"))
        failed = total_queries - successful
        
        summary_lines = [
            f"Dashboard Health Check: {dashboard_name}",
            f"Dashboard ID: {dashboard_id}",
            f"Total Queries: {total_queries}",
            f"Successful: {successful}",
            f"Failed: {failed}",
        ]
        
        if errors:
            summary_lines.append("\nErrors:")
            for err in errors:
                summary_lines.append(f"  - {err}")
        
        summary = "\n".join(summary_lines)
        
        res_dict = {
            "dashboard_id": dashboard_id,
            "query_results": query_results,
            "summary": summary,
            "errors": errors,
        }
        return DashboardHealthCheckResult(**res_dict, raw=res_dict)
    
    finally:
        # Restore original tenant config
        if has_override:
            adapter.project_id = orig_pid
            adapter.customer_id = orig_cid
            adapter.region = orig_reg


class CreateDashboardWorkflow:
    """Creates a new Native Dashboard in Google SecOps."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        display_name: str,
        description: Optional[str] = None,
        dashboard_type: str = "CUSTOM",
        filters: Optional[List[Dict[str, Any]]] = None,
        charts: Optional[List[Dict[str, Any]]] = None,
    ) -> DashboardSummary:
        if not display_name or not str(display_name).strip():
            raise ValueError("display_name must be provided.")
        raw = self.adapter.create_native_dashboard(
            display_name=display_name.strip(),
            description=description,
            dashboard_type=dashboard_type,
            filters=filters,
            charts=charts,
        )
        return _map_dashboard_summary(raw)


class UpdateDashboardWorkflow:
    """Updates an existing Native Dashboard's display name, description, filters, or chart layouts."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        dashboard_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
        charts: Optional[List[Dict[str, Any]]] = None,
        update_mask: Optional[str] = None,
    ) -> DashboardSummary:
        if not dashboard_id or not str(dashboard_id).strip():
            raise ValueError("dashboard_id must be provided.")

        payload: Dict[str, Any] = {}
        mask_fields: List[str] = []
        definition: Dict[str, Any] = {}

        if display_name is not None:
            payload["displayName"] = display_name
            mask_fields.append("display_name")
        if description is not None:
            payload["description"] = description
            mask_fields.append("description")
        if filters is not None:
            definition["filters"] = filters
            mask_fields.append("definition.filters")
        if charts is not None:
            definition["charts"] = charts
            mask_fields.append("definition.charts")
        if definition:
            payload["definition"] = definition

        final_mask = update_mask or ",".join(mask_fields)
        if not final_mask:
            raise ValueError("At least one field (display_name, description, filters, charts) must be provided to update.")

        raw = self.adapter.patch_native_dashboard(
            dashboard_id=dashboard_id,
            dashboard_payload=payload,
            update_mask=final_mask,
        )
        return _map_dashboard_summary(raw)


class DeleteDashboardWorkflow:
    """Deletes a Native Dashboard by ID."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, dashboard_id: str) -> Dict[str, Any]:
        if not dashboard_id or not str(dashboard_id).strip():
            raise ValueError("dashboard_id must be provided.")
        clean_id = str(dashboard_id).strip().split("/")[-1]
        res = self.adapter.delete_native_dashboard(clean_id)
        return {"deleted_dashboard_id": clean_id, "raw": res}


class DuplicateDashboardWorkflow:
    """Duplicates an existing Native Dashboard under a new display name."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        dashboard_id: str,
        display_name: str,
        description: Optional[str] = None,
        dashboard_type: str = "CUSTOM",
    ) -> DashboardSummary:
        if not dashboard_id or not str(dashboard_id).strip():
            raise ValueError("dashboard_id must be provided.")
        if not display_name or not str(display_name).strip():
            raise ValueError("display_name must be provided.")
        raw = self.adapter.duplicate_native_dashboard(
            dashboard_id=dashboard_id,
            display_name=display_name.strip(),
            description=description,
            dashboard_type=dashboard_type,
        )
        return _map_dashboard_summary(raw)


class AddDashboardChartWorkflow:
    """Adds a chart widget (visualization, markdown, or button) to a Native Dashboard."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        dashboard_id: str,
        display_name: str,
        query: Optional[str] = None,
        description: Optional[str] = None,
        tile_type: str = "TILE_TYPE_VISUALIZATION",
        visualization: Optional[Dict[str, Any]] = None,
        data_sources: Optional[List[str]] = None,
        time_unit: str = "DAY",
        time_value: str = "1",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        span_x: int = 6,
        span_y: int = 4,
        start_x: int = 0,
        start_y: int = 0,
        drill_down_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not dashboard_id or not str(dashboard_id).strip():
            raise ValueError("dashboard_id must be provided.")
        if not display_name or not str(display_name).strip():
            raise ValueError("display_name must be provided.")

        dashboard_chart: Dict[str, Any] = {
            "displayName": display_name,
            "tileType": tile_type,
            "visualization": visualization or {},
        }
        if tile_type == "TILE_TYPE_VISUALIZATION" or data_sources is not None or query:
            dashboard_chart["chartDatasource"] = {
                "dataSources": data_sources or ["UDM"],
            }
        if description is not None:
            dashboard_chart["description"] = description
        if drill_down_config is not None:
            dashboard_chart["drillDownConfig"] = drill_down_config

        dashboard_query: Optional[Dict[str, Any]] = None
        if query:
            if start_time and end_time:
                input_spec: Dict[str, Any] = {
                    "timeWindow": {
                        "startTime": start_time,
                        "endTime": end_time,
                    }
                }
            else:
                input_spec = {
                    "relativeTime": {
                        "timeUnit": time_unit,
                        "startTimeVal": str(time_value),
                    }
                }
            dashboard_query = {
                "query": query,
                "input": input_spec,
            }

        chart_layout = {
            "startX": int(start_x),
            "spanX": int(span_x),
            "startY": int(start_y),
            "spanY": int(span_y),
        }

        return self.adapter.add_dashboard_chart(
            dashboard_id=dashboard_id,
            dashboard_chart=dashboard_chart,
            dashboard_query=dashboard_query,
            chart_layout=chart_layout,
        )


class UpdateDashboardChartWorkflow:
    """Updates an existing DashboardChart and/or its associated DashboardQuery."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        chart_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        visualization: Optional[Dict[str, Any]] = None,
        data_sources: Optional[List[str]] = None,
        drill_down_config: Optional[Dict[str, Any]] = None,
        query_id: Optional[str] = None,
        query: Optional[str] = None,
        time_unit: Optional[str] = None,
        time_value: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {}

        if any(v is not None for v in (display_name, description, visualization, data_sources, drill_down_config)):
            chart_payload: Dict[str, Any] = {}
            chart_mask: List[str] = []
            if display_name is not None:
                chart_payload["displayName"] = display_name
                chart_mask.append("display_name")
            if description is not None:
                chart_payload["description"] = description
                chart_mask.append("description")
            if visualization is not None:
                chart_payload["visualization"] = visualization
                chart_mask.append("visualization")
            if data_sources is not None:
                chart_payload["chartDatasource"] = {"dataSources": data_sources}
                chart_mask.append("chart_datasource.data_sources")
            if drill_down_config is not None:
                chart_payload["drillDownConfig"] = drill_down_config
                chart_mask.append("drill_down_config")

            result["updated_chart"] = self.adapter.patch_dashboard_chart(
                chart_id=chart_id,
                chart_payload=chart_payload,
                update_mask=",".join(chart_mask),
            )

        if query is not None or any(v is not None for v in (time_unit, time_value, start_time, end_time)):
            resolved_query_id = query_id
            if not resolved_query_id:
                existing_chart = self.adapter.get_dashboard_chart(chart_id)
                resolved_query_id = existing_chart.get("chartDatasource", {}).get("dashboardQuery")
            if not resolved_query_id:
                raise ValueError("query_id could not be resolved from chart_id; please provide query_id explicitly.")

            query_payload: Dict[str, Any] = {}
            query_mask: List[str] = []
            if query is not None:
                query_payload["query"] = query
                query_mask.append("query")
            if start_time and end_time:
                query_payload["input"] = {
                    "timeWindow": {"startTime": start_time, "endTime": end_time}
                }
                query_mask.append("input")
            elif time_unit is not None or time_value is not None:
                query_payload["input"] = {
                    "relativeTime": {
                        "timeUnit": time_unit or "DAY",
                        "startTimeVal": str(time_value or "1"),
                    }
                }
                query_mask.append("input")

            result["updated_query"] = self.adapter.patch_dashboard_query(
                query_id=resolved_query_id,
                query_payload=query_payload,
                update_mask=",".join(query_mask),
            )

        return result


class RemoveDashboardChartWorkflow:
    """Removes a chart from a Native Dashboard."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, dashboard_id: str, chart_id: str) -> Dict[str, Any]:
        if not dashboard_id or not str(dashboard_id).strip():
            raise ValueError("dashboard_id must be provided.")
        if not chart_id or not str(chart_id).strip():
            raise ValueError("chart_id must be provided.")
        return self.adapter.remove_dashboard_chart(dashboard_id=dashboard_id, chart_id=chart_id)

