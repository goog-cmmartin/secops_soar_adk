from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleADKManager import GoogleADKManager

INTEGRATION_NAME = "Google_ADK"
SCRIPT_NAME = "Run Skill Registry Agent"

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
        proj_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        if not proj_id:
            proj_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        model_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "Model Name", default_value="gemini-3.7-flash")

        # 2. Fetch Action-Specific Parameters
        user_prompt = siemplify.extract_action_param("User Prompt")
        thinking_budget = int(siemplify.extract_action_param("Thinking Budget", default_value=0))

        # 3. Initialize Manager
        manager = GoogleADKManager(
            api_key=api_key, 
            service_account_json=sa_json, 
            model_name=model_name, 
            logger=siemplify.LOGGER,
            project_id=proj_id,
            location=region
        )

        # 4. Build Skill Registry Toolsets
        skill_toolset = manager.init_skill_registry_toolset()

        # 5. Define instructions and register custom creation tools
        agent_instructions = f"""
            You are an active, remote skill registry assistant. You are integrated with the central Google Cloud Skill Registry.
            
            Core Guidelines & Steering:
            - **Listing and Showing Skills:** If the user asks to "list", "show", "display", or "fetch available" skills, do NOT reply statically or assume the registry is empty. You MUST actively invoke the 'search_skills' tool. To list all skills or perform a general fetch, use an empty string "" or a wildcard "*" as the search query.
            - **Searching Skills:** Use the 'search_skills' tool with a relevant search query to locate specific remote capabilities.
            - **Loading Skills:** Load matching remote skills on-demand using the 'load_skill' tool.
            - **Registering/Creating Skills:** If the user asks to register, upload, or create a skill, gather the necessary details (skill ID, display name, description, markdown instructions) and invoke the 'register_gcp_skill' tool.
            
            Context details:
            - The active Google Cloud Project ID is: {proj_id or "not-configured"}
            - The active Google Cloud Region/Location is: {region or "us-central1"}
            
            Always attempt to execute tools to verify active resources before making any claims or replying to the user.
        """

        # We pass both the skill_toolset and the custom register_gcp_skill tool!
        tools = [skill_toolset, manager.register_gcp_skill]

        # 6. Run Runbook agent
        result = manager.run_agent(
            agent_name="Skill_Registry_Agent",
            instructions=agent_instructions,
            input_text=user_prompt,
            tools=tools,
            thinking_budget=thinking_budget
        )

        # Process Results
        output_message = "Skill Registry Agent successfully completed."
        result_value = result.get("final_response", "")

        # ADD JSON RESULTS:
        # 1. Programmatic JSON (for playbook placeholders)
        siemplify.result.add_result_json(result)
        # 2. UI-Visible JSON (for the 'Skill_Registry_Agent_Results' tab on the Case Wall)
        siemplify.result.add_json("Skill_Registry_Agent_Results", result)

        if result.get("thoughts"):
            thought_str = "\n".join([f"• {t}" for t in result["thoughts"]])
            siemplify.add_comment(f"### Agent Reasoning ###\n{thought_str}")

        siemplify.add_comment(f"### Agent Final Response ###\n\n{result_value}")

    except ModuleNotFoundError as e:
        import unicodedata
        missing_module = str(e.name) if hasattr(e, 'name') else str(e)
        if "vertexai" in missing_module or "aiplatform" in missing_module or "skill_registry" in missing_module:
            error_msg = (
                "Dependency Error: The required 'google-cloud-aiplatform' library is not installed on your live SecOps SOAR agent container. "
                "Please add 'google-cloud-aiplatform>=1.160.0' to your integration dependencies inside the Google SecOps SOAR Platform UI and restart the instance."
            )
        else:
            normalized_str = unicodedata.normalize('NFKD', f"Missing Python dependency: {missing_module}")
            error_msg = normalized_str.encode('ascii', 'ignore').decode('ascii')
        
        output_message = f"Python Dependency Error: {error_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        import unicodedata
        # Prevent .NET serialization errors by force-converting the error to a clean ASCII string
        normalized_str = unicodedata.normalize('NFKD', str(e))
        error_msg = normalized_str.encode('ascii', 'ignore').decode('ascii')
        output_message = f"Skill Registry Agent failed with error: {error_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Action Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
