from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleADKManager import GoogleADKManager

INTEGRATION_NAME = "Google_ADK"
SCRIPT_NAME = "Run Memory Bank Agent"

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
        session_id = siemplify.extract_action_param("Session ID", default_value="default")
        memory_mode = siemplify.extract_action_param("Memory Mode", default_value="Memory Bank") # Memory Bank or InMemory
        preload_memory = siemplify.extract_action_param("Preload Memory", default_value="True").lower() == "true"
        thinking_budget = int(siemplify.extract_action_param("Thinking Budget", default_value=0))
        agent_engine_id = siemplify.extract_action_param("Agent Engine ID", default_value="")

        # 3. Initialize Manager
        manager = GoogleADKManager(
            api_key=api_key, 
            service_account_json=sa_json, 
            model_name=model_name, 
            logger=siemplify.LOGGER,
            project_id=proj_id,
            location=region
        )

        # 4. Initialize Memory Service and Select Tools
        memory_service = None
        if memory_mode == "Memory Bank":
            # Resolves from parameters or falls back to globally configured Agent Engine
            memory_service = manager.init_memory_bank_service(agent_engine_id=agent_engine_id)
        else:
            memory_service = manager.init_in_memory_memory_service()

        # Get appropriate pre-built memory tool (preload_memory or load_memory)
        memory_tools = manager.get_memory_tools(preload=preload_memory)

        # 5. Define instructions
        agent_instructions = f"""
            You are a helpful long-term memory assistant.
            You have access to a persistent, long-term memory service allowing you to remember important details from past conversations.
            
            Core Behavior:
            - If you are asked questions about past interactions, or if you need context from previous conversations, use your pre-equipped memory tools to lookup historical snippets.
            - Answer the user's question accurately.
            - When saving information, you do not need to do anything extra; your completed session details are automatically consolidated into long-term memory by the system at the end of the run.
        """

        # 6. Run Runbook agent with Memory Service and Memory Tools
        result = manager.run_agent(
            agent_name="Memory_Bank_Agent",
            instructions=agent_instructions,
            input_text=user_prompt,
            tools=memory_tools,
            session_id=session_id,
            thinking_budget=thinking_budget,
            memory_service=memory_service
        )

        # Process Results
        output_message = "Memory Bank Agent successfully completed."
        result_value = result.get("final_response", "")

        # ADD JSON RESULTS:
        siemplify.result.add_result_json(result)
        siemplify.result.add_json("Memory_Bank_Agent_Results", result)

        if result.get("thoughts"):
            thought_str = "\n".join([f"• {t}" for t in result["thoughts"]])
            siemplify.add_comment(f"### Agent Reasoning ###\n{thought_str}")

        siemplify.add_comment(f"### Agent Final Response ###\n\n{result_value}")

    except ModuleNotFoundError as e:
        import unicodedata
        missing_module = str(e.name) if hasattr(e, 'name') else str(e)
        if "vertexai" in missing_module or "aiplatform" in missing_module:
            error_msg = (
                "Dependency Error: The required 'google-cloud-aiplatform' library is not installed on your live SecOps SOAR agent container. "
                "Please add 'google-cloud-aiplatform>=1.160.0' to your integration dependencies inside the Google SecOps SOAR Platform UI and restart the instance."
                " Note that the Memory Bank feature requires Google Cloud Agent Platform / Vertex AI API dependencies to function."
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
        output_message = f"Memory Bank Agent failed with error: {error_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Action Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
