import types
import sys

# Pre-inject mock modules for optional private packages
if "google.cloud.agentidentitycredentials_v1" not in sys.modules:
    m1 = types.ModuleType("google.cloud.agentidentitycredentials_v1")
    m1.AuthProviderCredentialsServiceClient = object
    m1.RetrieveCredentialsRequest = object
    m1.RetrieveCredentialsResponse = object
    sys.modules["google.cloud.agentidentitycredentials_v1"] = m1

if "google.cloud.iamconnectorcredentials_v1alpha" not in sys.modules:
    m2 = types.ModuleType("google.cloud.iamconnectorcredentials_v1alpha")
    m2.IAMConnectorCredentialsServiceClient = object
    m2.RetrieveCredentialsMetadata = object
    m2.RetrieveCredentialsRequest = object
    m2.RetrieveCredentialsResponse = object
    sys.modules["google.cloud.iamconnectorcredentials_v1alpha"] = m2

import sys
import unicodedata
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from GoogleADKManager import GoogleADKManager, google_search
except ImportError:
    try:
        from core.GoogleADKManager import GoogleADKManager, google_search
    except ImportError:
        from ..core.GoogleADKManager import GoogleADKManager, google_search

INTEGRATION_NAME = "GoogleADK"
SCRIPT_NAME = "Run Agent Registry Agent"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = False

    try:
        api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        workload_identity_email = siemplify.extract_configuration_param(INTEGRATION_NAME, "Workload Identity Email")
        model_name = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Model Name", default_value="gemini-3.8-flash"
        )
        proj_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "GCP Project ID"
        ) or siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        agent_engine_resource = siemplify.extract_configuration_param(INTEGRATION_NAME, "Agent Engine Resource Name")

        # Action Parameters with resilient fallbacks
        registry_project_raw = siemplify.extract_action_param("Agent Registry Project ID")
        registry_project_id = str(registry_project_raw).strip() if registry_project_raw and str(registry_project_raw).strip() and str(registry_project_raw).strip() != "my-gcp-project" else proj_id

        registry_location = siemplify.extract_action_param("Agent Registry Location", default_value="us-central1")
        agent_name = siemplify.extract_action_param("Agent Name")
        reasoning_engine_name = siemplify.extract_action_param("Reasoning Engine Name")
        user_query = siemplify.extract_action_param("User Query")
        if not user_query or not str(user_query).strip():
            raise ValueError("The 'User Query' parameter is required and cannot be empty.")

        manager = GoogleADKManager(
            api_key=api_key,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            model_name=model_name,
            project_id=registry_project_id or proj_id,
            location=registry_location or region,
            logger=siemplify.LOGGER,
            agent_engine_resource_name=agent_engine_resource,
        )

        siemplify.LOGGER.info(
            f"Invoking remote agent registry in project: {registry_project_id}, location: {registry_location}"
        )

        instructions = (
            f"You are a proxy agent querying remote reasoning engine {reasoning_engine_name or agent_name or 'Default Registry Engine'} "
            f"in project {registry_project_id}."
        )

        results = manager.run_agent(
            agent_name=agent_name or "Remote_Registry_Agent",
            instructions=instructions,
            input_text=user_query,
        )

        result_value = results.get("final_response", "")
        output_message = "Remote agent executed successfully."

        siemplify.result.add_result_json(results)
        siemplify.result.add_json("Agent_Registry_Results", results)

    except Exception as e:
        normalized = unicodedata.normalize("NFKD", str(e))
        clean_msg = normalized.encode("ascii", "ignore").decode("ascii")
        output_message = f"Error executing {SCRIPT_NAME}: {clean_msg}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
