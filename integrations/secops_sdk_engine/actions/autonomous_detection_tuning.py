import json
import os
import sys
import time
import unicodedata

# Ensure core directory is on sys.path for SOAR runtime
_current_dir = os.path.dirname(os.path.abspath(__file__))
_core_dir = os.path.join(os.path.dirname(_current_dir), "core")
for _p in [_core_dir, _current_dir]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SecOpsSDKEngineManager import SecOpsSDKEngineManager

INTEGRATION_NAME = "SecOpsSDKEngine"
SCRIPT_NAME = "Autonomous Detection Tuning"


def _parse_bool(val, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return default


def _parse_int(val, default: int) -> int:
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return default


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = "Successfully executed Autonomous Detection Tuning."
    result_value = True

    try:
        customer_id = (
            siemplify.extract_configuration_param(
                INTEGRATION_NAME, "SecOps Customer ID", is_mandatory=False, print_value=True
            )
            or siemplify.extract_configuration_param(
                INTEGRATION_NAME, "Customer ID", is_mandatory=False, print_value=True
            )
        )
        project_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "GCP Project ID", default_value="", print_value=True
        )
        region = (
            siemplify.extract_configuration_param(
                INTEGRATION_NAME, "SecOps Region", default_value="", print_value=True
            )
            or siemplify.extract_configuration_param(
                INTEGRATION_NAME, "Region", default_value="us", print_value=True
            )
            or "us"
        )
        sa_json = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Service Account JSON", default_value="", print_value=False
        )
        workload_identity_email = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Workload Identity Email", default_value="", print_value=True
        )
        verify_ssl_raw = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Verify SSL", default_value="true", print_value=True
        )
        verify_ssl = _parse_bool(verify_ssl_raw, default=True)

        case_id_param = siemplify.extract_action_param(
            "Case ID", default_value="", print_value=True
        )
        case_id = str(case_id_param).strip() if case_id_param else str(getattr(siemplify, "case_id", "") or "").strip()

        rule_id_param = siemplify.extract_action_param(
            "Rule ID", default_value="", print_value=True
        )
        rule_id = str(rule_id_param or "").strip() or None

        lookback_days = _parse_int(
            siemplify.extract_action_param("Lookback Days", default_value="14", print_value=True),
            default=14,
        )
        ttl_days = _parse_int(
            siemplify.extract_action_param("TTL Days", default_value="30", print_value=True),
            default=30,
        )
        apply_tuning = _parse_bool(
            siemplify.extract_action_param("Apply Tuning", default_value="false", print_value=True),
            default=False,
        )
        record_to_data_table = _parse_bool(
            siemplify.extract_action_param("Record to Data Table", default_value="true", print_value=True),
            default=True,
        )
        post_wall_comment = _parse_bool(
            siemplify.extract_action_param("Post Wall Comment", default_value="true", print_value=True),
            default=True,
        )
        sync_dashboard = _parse_bool(
            siemplify.extract_action_param("Sync Tuning Dashboard", default_value="false", print_value=True),
            default=False,
        )

        manager = SecOpsSDKEngineManager(
            customer_id=customer_id,
            project_id=project_id,
            region=region,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER,
        )

        # Cooldown cache guard so duplicate tag triggers don't blank out the Case Overview widget
        cache_file = f"/tmp/soar_action_cache_detection_tuning_{case_id}.json" if case_id else None
        if cache_file and os.path.exists(cache_file) and not apply_tuning:
            try:
                with open(cache_file, "r", encoding="utf-8") as cf:
                    cached_entry = json.load(cf)
                if isinstance(cached_entry, dict) and (time.time() - float(cached_entry.get("timestamp", 0)) < 120.0):
                    cached_payload = cached_entry.get("json_payload")
                    if isinstance(cached_payload, dict):
                        for trig_tag in ("Tune:Candidate", "Tune:Approve"):
                            try:
                                manager.adapter.remove_case_tag(case_id, trig_tag)
                            except Exception:
                                pass
                        payload_out = dict(cached_payload)
                        payload_out["reused_cached_result"] = True
                        siemplify.result.add_result_json(payload_out)
                        output_message = (
                            f"Reused cached Autonomous Detection Tuning proposal for Case #{case_id} "
                            f"({payload_out.get('proposals_generated_count', 0)} proposal(s))."
                        )
                        siemplify.end(output_message, True, EXECUTION_STATE_COMPLETED)
                        return
            except Exception:
                pass

        res = manager.tune_case_detections(
            case_id=case_id or None,
            rule_id=rule_id,
            lookback_days=lookback_days,
            apply_tuning=apply_tuning,
            ttl_days=ttl_days,
            record_to_data_table=record_to_data_table,
            post_wall_comment=post_wall_comment,
        )

        if sync_dashboard:
            try:
                dash_res = manager.sync_detection_tuning_dashboard(lookback_days=min(lookback_days, 14))
                res["dashboard_sync"] = dash_res
            except Exception as dash_err:
                siemplify.LOGGER.warning(f"Dashboard sync warning: {dash_err}")

        if isinstance(res, dict):
            res.setdefault("project_id", manager.project_id)
            res.setdefault("customer_id", manager.customer_id)
            res.setdefault("region", manager.region)

        if cache_file and isinstance(res, dict):
            try:
                with open(cache_file, "w", encoding="utf-8") as cf:
                    json.dump({"timestamp": time.time(), "json_payload": res}, cf)
            except Exception:
                pass

        siemplify.result.add_result_json(res)
        result_value = bool(res.get("proposals_generated_count", 0) > 0)
        output_message = (
            f"Completed Autonomous Detection Tuning for Case '{case_id or 'Fleet'}': "
            f"analyzed {res.get('rules_analyzed_count', 0)} rule(s), "
            f"synthesized {res.get('proposals_generated_count', 0)} multi-factor proposal(s), "
            f"applied {res.get('applied_count', 0)} live refinement(s), "
            f"and recorded {len(res.get('recorded_tuning_ids') or [])} row(s) to {res.get('data_table_name')}."
        )
        siemplify.LOGGER.info(output_message)

    except Exception as e:
        normalized = unicodedata.normalize("NFKD", str(e))
        clean_msg = normalized.encode("ascii", "ignore").decode("ascii")
        output_message = f"Failed to execute Autonomous Detection Tuning: {clean_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
