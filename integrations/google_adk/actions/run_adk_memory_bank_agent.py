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
SCRIPT_NAME = "Run Memory Bank Agent"


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
        proj_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "GCP Project ID"
        ) or siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        agent_engine_resource = siemplify.extract_configuration_param(INTEGRATION_NAME, "Agent Engine Resource Name")
        model_name = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Model Name", default_value="gemini-3.8-flash"
        )

        user_prompt = siemplify.extract_action_param("User Prompt")
        if not user_prompt or not str(user_prompt).strip():
            raise ValueError("The 'User Prompt' parameter is required and cannot be empty.")

        raw_session_id = siemplify.extract_action_param("Session ID")
        memory_mode = siemplify.extract_action_param("Memory Mode", default_value="Memory Bank")
        preload = str(siemplify.extract_action_param("Preload Memory", default_value=True)).lower() in ("true", "1")
        agent_engine_id = siemplify.extract_action_param("Agent Engine ID")

        raw_budget = siemplify.extract_action_param("Thinking Budget", default_value=0)
        try:
            thinking_budget = int(raw_budget) if raw_budget else 0
            if thinking_budget < 0:
                raise ValueError()
        except ValueError:
            raise ValueError(f"'Thinking Budget' must be a non-negative integer, got: '{raw_budget}'")

        manager = GoogleADKManager(
            api_key=api_key,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            model_name=model_name,
            logger=siemplify.LOGGER,
            agent_engine_resource_name=agent_engine_resource,
            project_id=proj_id,
            location=region,
        )

        session_id, memory_service, memory_tools = manager.resolve_memory_configuration(
            enable_memory=True,
            session_id=raw_session_id,
            case_id=getattr(siemplify, "case_id", None),
            memory_mode=memory_mode,
            agent_engine_id=agent_engine_id,
            preload=preload,
        )

        agent_instructions = (
            f"You are a Memory Bank Security Agent. Use historical session memories "
            f"to inform your analysis. Current Session ID: {session_id}."
        )

        results = manager.run_agent(
            agent_name="Memory_Bank_Agent",
            instructions=agent_instructions,
            input_text=user_prompt,
            tools=memory_tools,
            thinking_budget=thinking_budget,
            session_id=session_id,
            memory_service=memory_service,
        )

        result_value = results.get("final_response", "")
        output_message = f"Memory Bank Agent executed with session '{session_id}'."

        siemplify.result.add_result_json(results)
        siemplify.result.add_json("Memory_Bank_Results", results)

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
