"""
Detect Log Source Drift Job for SecOpsSDKEngine.

Periodically evaluates Google SecOps log source streams against learned baselines,
detecting syntactic raw schema mutations and semantic UDM parser completeness collapses.
Can read baseline profiles directly from a SecOps Data Table (asoc_log_baselines)
with fallback to a JSON parameter string.
"""

from datetime import datetime, timezone
import json
import os
import sys
import time
from typing import Any, Dict, List

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
    from engine.drift import evaluate_stream_drift
except ImportError:
    try:
        from drift import evaluate_stream_drift
    except ImportError:
        from core.engine.drift import evaluate_stream_drift

try:
    from engine.facade import SecOpsEngine
except ImportError:
    try:
        from facade import SecOpsEngine
    except ImportError:
        from core.engine.facade import SecOpsEngine

JOB_NAME = "Detect Log Source Drift Job"
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
    data_table_name = _safe_extract(siemplify, "Data Table Name", "asoc_log_baselines")
    update_table_status = str(_safe_extract(siemplify, "Update Drift Status in Table", "true")).lower() == "true"
    baselines_json_raw = _safe_extract(siemplify, "Target Baselines JSON", "[]")
    evaluation_window_minutes = int(_safe_extract(siemplify, "Evaluation Window Minutes", 15))
    max_udm_events = int(_safe_extract(siemplify, "Max UDM Events Per Partition", 100))
    max_raw_samples = int(_safe_extract(siemplify, "Max Raw Samples Per Partition", 15))
    drift_tolerance = float(_safe_extract(siemplify, "Drift Tolerance Threshold", 0.15))
    min_events_required = int(_safe_extract(siemplify, "Min Events Required", 10))

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

        # Baseline profiles to monitor: list of (baseline_dict, table_row_data_or_None)
        monitored_baselines = []

        # 1. Attempt loading from Data Table
        if data_table_name:
            clean_table_id = data_table_name.strip().split("/")[-1]
            try:
                logger.info(f"Fetching baseline profiles from Chronicle Data Table '{clean_table_id}'...")
                dt_res = mgr.adapter.list_data_table_rows(clean_table_id, page_size=100)
                table_rows = dt_res.get("dataTableRows", [])
                logger.info(f"Found {len(table_rows)} total rows in Data Table '{clean_table_id}'")

                for row in table_rows:
                    vals = row.get("values", [])
                    if len(vals) < 7:
                        continue
                    # Schema: 0: partition_key, 1: log_type, 2: event_type, 3: status, 4: raw_keys, 5: udm_paths, 6: profile_json
                    status = vals[3] if len(vals) > 3 else "ACTIVE"
                    if status != "ACTIVE":
                        logger.info(f"Skipping inactive partition '{vals[0]}' (status={status})")
                        continue

                    try:
                        profile_obj = json.loads(vals[6])
                        monitored_baselines.append((profile_obj, vals))
                    except Exception as p_err:
                        logger.warning(f"Failed to parse profile JSON for row '{vals[0]}': {p_err}")

            except Exception as dt_err:
                logger.warning(f"Could not load baselines from Data Table '{clean_table_id}': {dt_err}")

        # 2. Fallback to Target Baselines JSON if no profiles loaded from Data Table
        if not monitored_baselines and baselines_json_raw:
            try:
                fallback_baselines = json.loads(baselines_json_raw)
                if isinstance(fallback_baselines, dict):
                    fallback_baselines = [fallback_baselines]
                for b in fallback_baselines:
                    monitored_baselines.append((b, None))
                if monitored_baselines:
                    logger.info(f"Loaded {len(monitored_baselines)} baselines from 'Target Baselines JSON' parameter.")
            except Exception as j_err:
                logger.warning(f"Failed to parse 'Target Baselines JSON': {j_err}")

        if not monitored_baselines:
            msg = "No active baselines found to monitor (checked Data Table and Target Baselines JSON)."
            logger.warning(msg)
            siemplify.end(msg, True)
            return

        now_sec = int(time.time())
        start_sec = now_sec - (evaluation_window_minutes * 60)
        start_time = datetime.fromtimestamp(start_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = datetime.fromtimestamp(now_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        evaluated_count = 0
        drifted_count = 0
        results_summary = []
        rows_to_update = []

        for baseline, table_vals in monitored_baselines:
            log_type = baseline.get("log_type")
            event_type = baseline.get("event_type")
            partition_key = baseline.get("partition_key", f"{log_type}:{event_type}")

            if not log_type:
                continue

            query_parts = [f'metadata.log_type = "{log_type.strip()}"']
            if event_type and event_type.strip() and event_type.strip() != "*":
                query_parts.append(f'metadata.event_type = "{event_type.strip()}"')
            query = " and ".join(query_parts)

            logger.info(f"Evaluating partition '{partition_key}' over last {evaluation_window_minutes}m")

            sess = engine.search_udm(
                query=query,
                start_time=start_time,
                end_time=end_time,
                limit=max_udm_events,
            )
            events = sess.events or []

            # Sample raw logs
            raw_log_payloads = []
            for ev in events:
                if len(raw_log_payloads) >= max_raw_samples:
                    break
                meta = ev.to_dict().get("event", {}).get("metadata", {})
                ev_id = meta.get("id")
                token = ev.to_dict().get("eventLogToken")
                if ev_id:
                    try:
                        raw = mgr.adapter.get_raw_log(ev_id, token)
                        raw_text = raw.raw_text if hasattr(raw, "raw_text") else str(raw)
                        raw_log_payloads.append(raw_text)
                    except Exception:
                        pass

            eval_result = evaluate_stream_drift(
                baseline=baseline,
                events=events,
                raw_log_payloads=raw_log_payloads,
                min_events_required=min_events_required,
                drift_tolerance=drift_tolerance,
            )

            evaluated_count += 1
            eval_status = eval_result.get("status", "UNKNOWN")

            if eval_status == "ALERT":
                drifted_count += 1
                logger.error(
                    f"⚠️ DRIFT ALERT on partition '{partition_key}': {eval_result.get('alerts')}"
                )
                results_summary.append(f"ALERT: {partition_key} (Drift: {eval_result.get('syntactic_drift', 0)*100:.1f}%)")
            elif eval_status == "INSUFFICIENT_VOLUME":
                results_summary.append(f"SKIPPED: {partition_key} (Low volume: {len(events)} events)")
            else:
                results_summary.append(f"STABLE: {partition_key} (Key overlap: {eval_result.get('key_overlap', 1.0)*100:.1f}%)")

            # Update row data if from table
            if table_vals and update_table_status:
                updated_row = list(table_vals)
                # Pad to 10 columns if necessary
                while len(updated_row) < 10:
                    updated_row.append("")
                updated_row[8] = now_iso
                updated_row[9] = eval_status
                rows_to_update.append(updated_row)

        # Batch update Data Table statuses
        if rows_to_update and data_table_name:
            clean_table_id = data_table_name.strip().split("/")[-1]
            try:
                mgr.adapter.bulk_create_data_table_rows(clean_table_id, rows=rows_to_update)
                logger.info(f"Updated latest drift status for {len(rows_to_update)} rows in Data Table '{clean_table_id}'")
            except Exception as u_err:
                logger.warning(f"Failed to update drift status in Data Table '{clean_table_id}': {u_err}")

        final_msg = (
            f"Evaluated {evaluated_count} log partition(s) over past {evaluation_window_minutes}m: "
            f"{drifted_count} drift alerts detected. Details: {', '.join(results_summary)}"
        )
        logger.info(final_msg)
        siemplify.end(final_msg, True)

    except Exception as e:
        error_msg = f"Job execution failed: {e}"
        logger.error(error_msg, exc_info=True)
        siemplify.end(error_msg, False)


if __name__ == "__main__":
    main()
