import sys
import unicodedata
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from LogJammerManager import LogJammerManager
except ImportError:
    try:
        from core.LogJammerManager import LogJammerManager
    except ImportError:
        from ..core.LogJammerManager import LogJammerManager

INTEGRATION_NAME = "LogJammer"
SCRIPT_NAME = "Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = "Successfully connected to the LogJammer service."
    result_value = True

    try:
        gemini_api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        gti_api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Google Threat Intelligence API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        workload_identity_email = siemplify.extract_configuration_param(INTEGRATION_NAME, "Workload Identity Email")
        gcp_project_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID")
        secops_customer_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Customer ID")
        secops_region = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "SecOps Region", default_value="us"
        )
        model_name = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Model Name", default_value="gemini-3.7-flash"
        )

        manager = LogJammerManager(
            gemini_api_key=gemini_api_key,
            gti_api_key=gti_api_key,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            gcp_project_id=gcp_project_id,
            secops_customer_id=secops_customer_id,
            secops_region=secops_region,
            model_name=model_name,
            logger=siemplify.LOGGER,
        )

        test_res = manager.test_connectivity()
        if not test_res.get("gemini_ok"):
            errs = ", ".join(test_res.get("errors", ["Gemini unreachable"]))
            raise ConnectionError(f"Gemini connectivity check failed: {errs}")

        output_message = (
            f"Successfully connected to LogJammer service. Bundled Guides: {test_res.get('total_guides')}, "
            f"Curated Rules: {test_res.get('total_curated_rules')}."
        )
        siemplify.LOGGER.info(output_message)

    except Exception as e:
        normalized = unicodedata.normalize("NFKD", str(e))
        clean_msg = normalized.encode("ascii", "ignore").decode("ascii")
        output_message = f"Failed to connect to the LogJammer service: {clean_msg}"
        siemplify.LOGGER.error(output_message)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
