"""
Profile Log Source Action for SecOpsSDKEngine.

Profiles a Google SecOps log source partition (optionally partitioned by event_type or
auto-discovering all active event types), extracts invariant raw log keys and critical UDM
field completion baselines, and persists the profiles into a SecOps Data Table (asoc_log_baselines).
"""

from collections import defaultdict
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

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from SecOpsSDKEngineManager import SecOpsSDKEngineManager, SafeLogger
except ImportError:
    from core.SecOpsSDKEngineManager import SecOpsSDKEngineManager, SafeLogger

try:
    from engine.drift import build_profile_from_events
except ImportError:
    try:
        from drift import build_profile_from_events
    except ImportError:
        from core.engine.drift import build_profile_from_events

try:
    from engine.facade import SecOpsEngine
except ImportError:
    try:
        from facade import SecOpsEngine
    except ImportError:
        from core.engine.facade import SecOpsEngine

ACTION_NAME = "Profile Log Source"
INTEGRATION_NAME = "SecOpsSDKEngine"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {ACTION_NAME}"
    logger = SafeLogger(siemplify.LOGGER)
    logger.info(f"Starting {ACTION_NAME} execution")

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

    # Extract Action parameters
    log_type = siemplify.extract_action_param(param_name="Log Type", is_mandatory=True)
    event_type = siemplify.extract_action_param(param_name="Event Type", is_mandatory=False, default_value="")
    auto_discover = siemplify.extract_action_param(
        param_name="Auto-Discover Event Types", is_mandatory=False, default_value=False, input_type=bool
    )
    save_to_data_table = siemplify.extract_action_param(
        param_name="Save to Data Table", is_mandatory=False, default_value=True, input_type=bool
    )
    data_table_name = siemplify.extract_action_param(
        param_name="Data Table Name", is_mandatory=False, default_value="asoc_log_baselines"
    )
    lookback_hours = siemplify.extract_action_param(
        param_name="Lookback Hours", is_mandatory=False, default_value=24, input_type=int
    )
    max_udm_events = siemplify.extract_action_param(
        param_name="Max UDM Events", is_mandatory=False, default_value=200, input_type=int
    )
    max_raw_samples = siemplify.extract_action_param(
        param_name="Max Raw Samples", is_mandatory=False, default_value=20, input_type=int
    )
    min_key_prevalence = siemplify.extract_action_param(
        param_name="Min Key Prevalence", is_mandatory=False, default_value=0.20, input_type=float
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

        clean_log_type = log_type.strip()
        clean_event_type = event_type.strip() if event_type else ""

        now_sec = int(time.time())
        start_sec = now_sec - (lookback_hours * 3600)
        start_time = datetime.fromtimestamp(start_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = datetime.fromtimestamp(now_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        profiles_generated = []

        if auto_discover and not clean_event_type:
            # Auto-discovery mode: query top-level log_type and partition by discovered event types
            query = f'metadata.log_type = "{clean_log_type}"'
            logger.info(f"Auto-discovering active event types for {query} over last {lookback_hours}h")

            sess = engine.search_udm(
                query=query,
                start_time=start_time,
                end_time=end_time,
                limit=max(max_udm_events, 200),
            )
            all_events = sess.events or []
            if not all_events:
                output_message = f"No events found for '{query}' in the last {lookback_hours} hours."
                siemplify.result.add_result_json({"status": "NO_DATA", "query": query})
                siemplify.end(output_message, False, EXECUTION_STATE_COMPLETED)
                return

            events_by_type = defaultdict(list)
            for ev in all_events:
                ev_dict = ev.to_dict().get("event", {})
                etype = ev_dict.get("metadata", {}).get("eventType", "").strip()
                if etype:
                    events_by_type[etype].append(ev)

            logger.info(f"Discovered {len(events_by_type)} distinct event types for {clean_log_type}")

            for etype, grp_events in events_by_type.items():
                if len(grp_events) < 3:
                    logger.info(f"Skipping event type '{etype}' due to low sample count ({len(grp_events)})")
                    continue

                raw_log_payloads = []
                for ev in grp_events:
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
                        except Exception as ex:
                            logger.warning(f"Failed to fetch raw log for event {ev_id}: {ex}")

                profile = build_profile_from_events(
                    log_type=clean_log_type,
                    event_type=etype,
                    events=grp_events,
                    raw_log_payloads=raw_log_payloads,
                    min_key_prevalence=min_key_prevalence,
                )
                profiles_generated.append(profile)

        else:
            # Single partition (or unpartitioned top-level) profiling
            query_parts = [f'metadata.log_type = "{clean_log_type}"']
            if clean_event_type and clean_event_type != "*":
                query_parts.append(f'metadata.event_type = "{clean_event_type}"')
            query = " and ".join(query_parts)

            logger.info(f"Querying UDM: {query} with lookback {lookback_hours}h")

            sess = engine.search_udm(
                query=query,
                start_time=start_time,
                end_time=end_time,
                limit=max_udm_events,
            )
            events = sess.events or []
            logger.info(f"Retrieved {len(events)} events for profiling")

            if not events:
                output_message = f"No events found for query '{query}' in the last {lookback_hours} hours."
                siemplify.result.add_result_json({"status": "NO_DATA", "query": query})
                siemplify.end(output_message, False, EXECUTION_STATE_COMPLETED)
                return

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
                    except Exception as ex:
                        logger.warning(f"Failed to fetch raw log for event {ev_id}: {ex}")

            profile = build_profile_from_events(
                log_type=clean_log_type,
                event_type=clean_event_type if clean_event_type and clean_event_type != "*" else None,
                events=events,
                raw_log_payloads=raw_log_payloads,
                min_key_prevalence=min_key_prevalence,
            )
            profiles_generated.append(profile)

        # Save to Data Table if enabled
        table_save_count = 0
        if save_to_data_table and data_table_name and profiles_generated:
            clean_table_id = data_table_name.strip().split("/")[-1]
            rows_to_insert = []
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            for prof in profiles_generated:
                row_vals = [
                    prof["partition_key"],
                    prof["log_type"],
                    prof.get("event_type") or "*",
                    "ACTIVE",
                    len(prof.get("qualified_raw_keys", [])),
                    len(prof.get("critical_udm_fields", [])),
                    json.dumps(prof),
                    now_iso,
                    "",
                    "STABLE",
                ]
                rows_to_insert.append(row_vals)

            try:
                mgr.adapter.bulk_create_data_table_rows(clean_table_id, rows=rows_to_insert)
                table_save_count = len(rows_to_insert)
                logger.info(f"Persisted {table_save_count} baseline profile(s) into Data Table '{clean_table_id}'")
            except Exception as e:
                logger.error(f"Failed to persist baselines to Data Table '{clean_table_id}': {e}", exc_info=True)

        partition_keys = [p["partition_key"] for p in profiles_generated]
        output_message = (
            f"Successfully profiled {len(profiles_generated)} partition(s) for '{clean_log_type}': "
            f"{', '.join(partition_keys)}. "
            f"{f'Persisted to Data Table {data_table_name}.' if table_save_count > 0 else ''}"
        )

        logger.info(output_message)
        result_payload = {
            "count": len(profiles_generated),
            "partitions": partition_keys,
            "profiles": profiles_generated,
            "data_table_persisted": table_save_count > 0,
            "data_table_name": data_table_name if table_save_count > 0 else None,
        }
        # If single profile, keep backward compatible top-level profile in result
        if len(profiles_generated) == 1:
            result_payload.update(profiles_generated[0])

        siemplify.result.add_result_json(result_payload)
        siemplify.end(output_message, True, EXECUTION_STATE_COMPLETED)

    except Exception as e:
        error_msg = f"Failed to profile log source: {e}"
        logger.error(error_msg, exc_info=True)
        siemplify.end(error_msg, False, EXECUTION_STATE_FAILED)


if __name__ == "__main__":
    main()
