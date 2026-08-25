from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleADKManager import GoogleADKManager

INTEGRATION_NAME = "Google ADK"
SCRIPT_NAME = "Run GCS ADK Agent"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    
    status = EXECUTION_STATE_COMPLETED 
    output_message = ""
    result_value = False

    try:
        # 1. Fetch Global Configuration (Integration Level)
        api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        proj_id = (
            siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        )
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        model_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "Model Name", default_value="gemini-3.7-flash")

        # 2. Fetch Action-Specific Parameters
        user_prompt = siemplify.extract_action_param("User Prompt")
        allow_write = siemplify.extract_action_param("Allow GCS Write", default_value="false").lower() == "true"
        allow_admin = siemplify.extract_action_param("Allow GCS Admin", default_value="false").lower() == "true"
        enable_memory = siemplify.extract_action_param("Enable Memory", input_type=bool, default_value=False)
        raw_session_id = siemplify.extract_action_param("Session ID")
        raw_budget = siemplify.extract_action_param("Thinking Budget", default_value="0")
        try:
            thinking_budget = int(raw_budget) if raw_budget else 0
            if thinking_budget < 0:
                raise ValueError()
        except ValueError:
            raise ValueError(f"'Thinking Budget' must be a non-negative integer, got: '{raw_budget}'")

        # 3. Initialize Manager
        manager = GoogleADKManager(
            api_key=api_key, 
            service_account_json=sa_json, 
            model_name=model_name, 
            logger=siemplify.LOGGER,
            project_id=proj_id,
            location=region
        )

        # 4. Resolve Memory Configuration
        session_id, memory_service, memory_tools = manager.resolve_memory_configuration(
            enable_memory=enable_memory,
            session_id=raw_session_id,
            case_id=getattr(siemplify, "case_id", None)
        )

        # 5. Build GCS Toolsets
        gcs_tools = manager.init_gcs_toolsets(enable_admin=allow_admin, enable_write=allow_write)
        if memory_tools:
            gcs_tools.extend(memory_tools)

        # 6. Execute Runbook agent
        agent_instructions = f"""
            You are a cloud storage assistant. Resolve the user's storage operations
            (reading, listing, uploading, or organizing buckets/objects) using your GCS tools.
            
            Context details:
            - The active Google Cloud Project ID is: {proj_id or "not-configured"}
            - The active Google Cloud Region/Location is: {region or "us-central1"}
            
            When listing buckets or creating resources, always use this Project ID automatically.
        """

        result = manager.run_agent(
            agent_name="GCS_Storage_Agent",
            instructions=agent_instructions,
            input_text=user_prompt,
            tools=gcs_tools,
            thinking_budget=thinking_budget,
            session_id=session_id,
            memory_service=memory_service
        )

        # Process Results
        output_message = "GCS ADK Agent successfully completed."
        result_value = result.get("final_response", "")

        # ADD JSON RESULTS:
        # 1. Programmatic JSON (for playbook placeholders)
        siemplify.result.add_result_json(result)
        # 2. UI-Visible JSON (for the 'GCS_Agent_Results' tab on the Case Wall)
        siemplify.result.add_json("GCS_Agent_Results", result)

        if result.get("thoughts"):
            thought_str = "\n".join([f"• {t}" for t in result["thoughts"]])
            siemplify.add_comment(f"### Agent Reasoning ###\n{thought_str}")

        siemplify.add_comment(f"### Agent Final Response ###\n\n{result_value}")

    except Exception as e:
        siemplify.LOGGER.error(f"Action failed: {str(e)}")
        output_message = f"GCS ADK Agent failed with error: {str(e)}"
        status = EXECUTION_STATE_FAILED

    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
