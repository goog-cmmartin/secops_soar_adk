"""
Sync Log Source Inventory Job for SecOpsSDKEngine.

Periodically executes the Unified Log Source Inventory & Collector Health workflow:
1. Queries Google SecOps `FROM ingestion` telemetry using GoogleSQL Pipe Syntax (`|>`),
   mapping `collector_id` UUIDs to human-readable Ingestion Mechanisms and source hosts.
2. Queries the Bindplane REST API (`/v1/agents` & `/v1/configs`) to index downstream OTel
   collector configurations, expected log types, and active drop/filter processors,
   automatically flagging `PARTIAL_DROP` and `SILENT_AGENT` anomalies.
3. Queries Chronicle Feeds (`v1alpha/feeds`) and runs Multi-Host Feed UDM Autodetection
   (`FROM events` via GoogleSQL Pipe Syntax) to discover individual child hosts/devices
   behind Syslog/Webhook/S3/API feeds (`log_source_identifier`) and extract `log_source_group`
   tags from `metadata.ingestion_labels`.
4. Reconciles the unified inventory into a Chronicle Data Table (`asoc_log_source_inventory`),
   preserving custom analyst group tags and flagging missing hosts as `SILENT_HOST`.
5. Publishes/updates the Chronicle Native Dashboard (`Log Source Inventory & Collector Health`).
"""

import os
import sys
from typing import Any

# Ensure core directory is on sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
_core_dir = os.path.join(os.path.dirname(_current_dir), "core")
for _p in [_core_dir, _current_dir]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler

try:
    from SecOpsSDKEngineManager import SecOpsSDKEngineManager, SafeLogger
except ImportError:
    from core.SecOpsSDKEngineManager import SecOpsSDKEngineManager, SafeLogger

try:
    from engine.facade import SecOpsEngine
except ImportError:
    try:
        from facade import SecOpsEngine
    except ImportError:
        from core.engine.facade import SecOpsEngine

JOB_NAME = "Sync Log Source Inventory Job"
INTEGRATION_NAME = "SecOpsSDKEngine"


def _safe_extract(siemplify: SiemplifyJob, param_name: str, default: Any = "") -> Any:
    try:
        val = siemplify.extract_job_param(param_name=param_name)
        return val if val is not None and str(val).strip() != "" else default
    except Exception:
        return default


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = f"{INTEGRATION_NAME} - {JOB_NAME}"
    logger = SafeLogger(siemplify.LOGGER)
    logger.info(f"Starting {JOB_NAME} execution")

    # Extract Integration parameters
    customer_id = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME, param_name="SecOps Customer ID", is_mandatory=True
    )
    project_id = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME, param_name="GCP Project ID", is_mandatory=False, default_value=""
    )
    region = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME, param_name="SecOps Region", is_mandatory=False, default_value="us"
    )
    service_account_json = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME, param_name="Service Account JSON", is_mandatory=False, default_value=""
    )
    workload_identity_email = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME, param_name="Workload Identity Email", is_mandatory=False, default_value=""
    )
    verify_ssl = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        is_mandatory=False,
        default_value=True,
        input_type=bool,
    )

    # Extract Job parameters
    data_table_name = str(
        _safe_extract(siemplify, "Data Table Name", "asoc_log_source_inventory")
    ).strip()
    sync_data_table = (
        str(_safe_extract(siemplify, "Sync Data Table", "true")).strip().lower() == "true"
    )
    sync_dashboard = (
        str(_safe_extract(siemplify, "Sync Native Dashboard", "true")).strip().lower() == "true"
    )
    dashboard_title = str(
        _safe_extract(
            siemplify, "Dashboard Title", "Log Source Inventory & Collector Health"
        )
    ).strip()
    dashboard_id_raw = str(_safe_extract(siemplify, "Dashboard ID", "")).strip()
    dashboard_id = dashboard_id_raw if dashboard_id_raw else None
    lookback_days = int(_safe_extract(siemplify, "Lookback Days", 7))
    bindplane_api_url_raw = str(
        _safe_extract(siemplify, "Bindplane API URL", "https://app.bindplane.com/v1")
    ).strip()
    bindplane_api_url = bindplane_api_url_raw if bindplane_api_url_raw else None
    bindplane_api_key_raw = str(_safe_extract(siemplify, "Bindplane API Key", "")).strip()
    bindplane_api_key = bindplane_api_key_raw if bindplane_api_key_raw else None
    bindplane_account_id_raw = str(_safe_extract(siemplify, "Bindplane Account ID", "")).strip()
    if bindplane_account_id_raw:
        os.environ["BINDPLANE_PROJECT_ID"] = bindplane_account_id_raw
    include_multi_host_udm = (
        str(_safe_extract(siemplify, "Include Multi-Host Feed Autodetection", "true"))
        .strip()
        .lower()
        == "true"
    )

    try:
        mgr = SecOpsSDKEngineManager(
            customer_id=customer_id,
            project_id=project_id,
            region=region,
            service_account_json=service_account_json,
            workload_identity_email=workload_identity_email,
            verify_ssl=verify_ssl,
            logger=logger,
        )
        engine = SecOpsEngine(adapter=mgr.adapter)

        logger.info(
            f"Running Log Source Inventory workflow (lookback_days={lookback_days}, "
            f"data_table='{data_table_name}', sync_dashboard={sync_dashboard}, "
            f"include_multi_host_udm={include_multi_host_udm})"
        )

        result = engine.sync_log_source_inventory(
            lookback_days=lookback_days,
            sync_data_table=sync_data_table,
            data_table_name=data_table_name,
            sync_dashboard=sync_dashboard,
            dashboard_title=dashboard_title,
            dashboard_id=dashboard_id,
            bindplane_api_url=bindplane_api_url,
            bindplane_api_key=bindplane_api_key,
            include_multi_host_udm=include_multi_host_udm,
        )

        summary = result.get("summary", {}) or {}
        dt_info = result.get("data_table_sync", {}) or {}
        dash_info = result.get("dashboard_sync", {}) or {}

        summary_msg = (
            f"Log Source Inventory Sync completed: {summary.get('total_inventory_rows', 0)} inventory sources indexed "
            f"(Healthy: {summary.get('healthy_count', 0)}, "
            f"Partial Drop: {summary.get('partial_drop_count', 0)}, "
            f"Silent Agent: {summary.get('silent_agent_count', 0)}, "
            f"Silent Host: {summary.get('silent_host_count', 0)}). "
            f"Bindplane Agents: {result.get('bindplane_agents_count', 0)}. "
            f"Data Table '{dt_info.get('data_table_id', data_table_name)}': "
            f"{dt_info.get('rows_added', 0)} rows written. "
            f"Dashboard: {dash_info.get('dashboard_id', 'N/A')} ({dash_info.get('action', 'SKIPPED')})."
        )
        logger.info(summary_msg)
        siemplify.end(summary_msg, True)

    except Exception as e:
        error_msg = f"Sync Log Source Inventory Job failed: {e}"
        logger.error(error_msg, exc_info=True)
        siemplify.end(error_msg, False)


if __name__ == "__main__":
    main()
