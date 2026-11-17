import json
import os
import re
import sys
import time

# Ensure core / Managers directory is on sys.path for SOAR runtime
_current_dir = os.path.dirname(os.path.abspath(__file__))
_core_dir = os.path.join(os.path.dirname(_current_dir), "core")
_mgr_dir = os.path.join(os.path.dirname(_current_dir), "Managers")
for _p in [_core_dir, _mgr_dir, _current_dir]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from GoogleDecisionsManager import GoogleDecisionsManager, safe_ascii
except ImportError:
    from core.GoogleDecisionsManager import GoogleDecisionsManager, safe_ascii

INTEGRATION_NAME = "GoogleDecisions"
SCRIPT_NAME = "Run SOC Decision Preset"


def _parse_bool(val, default: bool = True) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return default


def _parse_float(val, default: float = 0.80) -> float:
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return default


def _parse_int(val, default: int = 60000) -> int:
    try:
        return int(float(str(val).strip()))
    except (ValueError, TypeError):
        return default


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = "Successfully executed SOC Decision Preset."
    result_value = True

    try:
        api_key = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Gemini API Key", default_value="", print_value=False
        )
        workload_identity_email = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Workload Identity Email", default_value="", print_value=True
        )
        sa_json = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Service Account JSON", default_value="", print_value=False
        )
        project_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "GCP Project ID", default_value="", print_value=True
        )
        model_name = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Model Name", default_value="gemini-decision-1", print_value=True
        )
        api_endpoint = siemplify.extract_configuration_param(
            INTEGRATION_NAME,
            "API Endpoint",
            default_value="https://generativelanguage.googleapis.com/v1beta/decisions",
            print_value=True,
        )
        verify_ssl = _parse_bool(
            siemplify.extract_configuration_param(
                INTEGRATION_NAME, "Verify SSL", default_value="true", print_value=True
            ),
            default=True,
        )

        # Action Parameters
        preset_name = siemplify.extract_action_param(
            "Decision Preset",
            default_value="Tier-1 Alert Triage & Routing",
            is_mandatory=True,
            print_value=True,
        )
        additional_context = siemplify.extract_action_param(
            "Additional Context or Telemetry", default_value="", print_value=True
        )
        include_alert_context = _parse_bool(
            siemplify.extract_action_param(
                "Include Alert Context", default_value="true", print_value=True
            ),
            default=True,
        )
        extra_questions_json = siemplify.extract_action_param(
            "Additional Custom Questions JSON", default_value="", print_value=True
        )
        media_input = siemplify.extract_action_param(
            "Media Input (Base64 or HTTPS URI)", default_value="", print_value=False
        )
        media_mime_type = siemplify.extract_action_param(
            "Media MIME Type", default_value="", print_value=True
        )
        confidence_threshold = _parse_float(
            siemplify.extract_action_param(
                "Confidence Threshold", default_value="0.80", print_value=True
            ),
            default=0.80,
        )
        max_input_chars = _parse_int(
            siemplify.extract_action_param(
                "Max Input Characters", default_value="60000", print_value=True
            ),
            default=60000,
        )

        manager = GoogleDecisionsManager(
            api_key=api_key,
            workload_identity_email=workload_identity_email,
            service_account_json=sa_json,
            project_id=project_id,
            model_name=model_name,
            api_endpoint=api_endpoint,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER,
        )

        case_id_str = str(getattr(siemplify, "case_id", "") or "").strip()
        preset_slug = re.sub(r"[^a-z0-9]+", "_", str(preset_name or "").lower()).strip("_")
        cache_file = (
            f"/tmp/soar_action_cache_decisions_{case_id_str}_{preset_slug}.json"
            if case_id_str
            else None
        )
        if cache_file and os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as cf:
                    cached_entry = json.load(cf)
                if isinstance(cached_entry, dict) and (
                    time.time() - float(cached_entry.get("timestamp", 0)) < 90.0
                ):
                    cached_payload = cached_entry.get("json_payload")
                    if isinstance(cached_payload, dict) and cached_payload.get("answers"):
                        payload_out = dict(cached_payload)
                        payload_out["reused_cached_result"] = True
                        siemplify.result.add_result_json(payload_out)
                        output_message = safe_ascii(
                            f"Reused cached '{payload_out.get('preset_name')}' decision result for Case #{case_id_str} "
                            f"(All Confident: {payload_out.get('all_confident')})."
                        )
                        siemplify.end(
                            output_message,
                            json.dumps(payload_out.get("summary", {})),
                            EXECUTION_STATE_COMPLETED,
                        )
                        return
            except Exception:
                pass

        alert_ctx = (
            manager.serialize_soar_context(siemplify) if include_alert_context else ""
        )
        if not str(additional_context or "").strip() and not alert_ctx and not str(media_input or "").strip():
            # Fallback when executed in test/manual mode without alert events or text
            additional_context = (
                f"SOAR Case ID: {getattr(siemplify, 'case_id', 'Unknown')} | "
                f"Preset Evaluation: {preset_name}"
            )

        input_payload = manager.build_input_payload(
            input_text=additional_context,
            alert_context=alert_ctx,
            media_data_or_uri=media_input,
            media_mime_type=media_mime_type,
        )

        decision_result = manager.run_preset(
            preset_name=preset_name,
            input_payload=input_payload,
            additional_questions=extra_questions_json,
            confidence_threshold=confidence_threshold,
            max_input_chars=max_input_chars,
        )
        decision_result["case_id"] = case_id_str

        if cache_file and isinstance(decision_result, dict):
            try:
                with open(cache_file, "w", encoding="utf-8") as cf:
                    json.dump({"timestamp": time.time(), "json_payload": decision_result}, cf)
            except Exception:
                pass

        siemplify.result.add_result_json(decision_result)

        q_count = decision_result.get("question_count", 0)
        all_conf = decision_result.get("all_confident", False)
        in_tok = decision_result.get("usage", {}).get("total_input_tokens", 0)
        lat = decision_result.get("latency_ms", 0)

        output_message = safe_ascii(
            f"Completed '{decision_result.get('preset_name')}' ({q_count} questions) in {lat}ms "
            f"(All Confident >= {confidence_threshold}: {all_conf} | Input Tokens: {in_tok} | Output Tokens: 0)."
        )
        result_value = json.dumps(decision_result.get("summary", {}))

    except Exception as exc:
        clean_err = safe_ascii(exc)
        output_message = f"Failed to execute {SCRIPT_NAME}: {clean_err}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
