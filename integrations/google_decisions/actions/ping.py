import os
import sys

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
SCRIPT_NAME = "Ping"


def _parse_bool(val, default: bool = True) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return default


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = "Successfully connected to the Google Gemini Decisions API (gemini-decision-1)."
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
        model_name = (
            siemplify.extract_action_param("Model Name", default_value=None)
            or siemplify.extract_configuration_param(
                INTEGRATION_NAME, "Model Name", default_value="gemini-decision-1", print_value=True
            )
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

        manager.test_connection()
        siemplify.LOGGER.info("Ping: Gemini Decisions API handshake confirmed.")

    except Exception as exc:
        clean_err = safe_ascii(exc)
        output_message = f"Failed to connect to the Google Gemini Decisions API: {clean_err}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
