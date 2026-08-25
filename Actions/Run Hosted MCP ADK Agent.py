from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleADKManager import GoogleADKManager

INTEGRATION_NAME = "Google_ADK"
SCRIPT_NAME = "Run Google Hosted MCP Agent"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    
    # Initialize default states
    status = EXECUTION_STATE_COMPLETED 
    output_message = ""
    result_value = False

    try:
        # 1. Fetch Global Configuration (Integration Level)
        api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        
        # Verify Service Account JSON is populated or ADC fallback is available
        if not sa_json or str(sa_json).strip() in ("", "{}"):
            try:
                import google.auth
                _, _ = google.auth.default()
                siemplify.LOGGER.info("Service Account JSON is empty, but local Application Default Credentials (ADC) are available. Proceeding with ADC fallback.")
            except Exception:
                raise ValueError(
                    "Integration configuration 'Service Account JSON' is missing, empty, or unpopulated. "
                    "This service account key is required for dynamic OAuth/OIDC token generation to connect to "
                    "the Google Hosted MCP server."
                )
            
        mcp_url = siemplify.extract_configuration_param(INTEGRATION_NAME, "MCP Server URL")
        
        # Optional Environment Context
        cust_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Customer ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        proj_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        
        model_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "Model Name", default_value="gemini-3.7-flash")

        # 2. Fetch Action-Specific Parameters
        user_prompt = siemplify.extract_action_param("User Prompt")
        thinking_budget = int(siemplify.extract_action_param("Thinking Budget", default_value=0))
        tool_filter_raw = siemplify.extract_action_param("Tool Filter")

        tool_filter = None
        if tool_filter_raw and str(tool_filter_raw).strip():
            tool_filter = [t.strip().strip("'").strip('"').strip() for t in str(tool_filter_raw).split(",") if t.strip()]

        # 3. Manager Setup
        manager = GoogleADKManager(
            api_key=api_key, 
            service_account_json=sa_json, 
            model_name=model_name, 
            logger=siemplify.LOGGER,
            project_id=proj_id,
            location=region
        )

        # Initialize the MCP Toolset
        mcp_toolset = manager.init_mcp_toolset(mcp_url=mcp_url, user_project=proj_id, tool_filter=tool_filter)

        # 4. Build a Generic Contextual Instruction
        env_context = ""
        # Robust check for environmental IDs
        safe_cust_id = str(cust_id).strip() if cust_id and str(cust_id).strip() else None
        safe_proj_id = str(proj_id).strip() if proj_id and str(proj_id).strip() else None
        
        if safe_cust_id or safe_proj_id:
            env_context = f"\nAVAILABLE ENVIRONMENT CONTEXT:\n- customerId: {safe_cust_id}\n- region: {region}\n- projectId: {safe_proj_id}\nUse these values if required by your tools.\n"

        # 5. Construct Final Specialized Instructions
        agent_instructions = f"""You are a professional Security Assistant powered by Google ADK.
        Your goal is to solve the user's task using your available tools.{env_context}
        
        PROCEDURE & CAPABILITIES: 
        1. You are integrated with external Model Context Protocol (MCP) servers. You have access to a rich set of specialized security tools provided by these MCP servers (such as GCP, BigQuery, Chronicle, or other security tools). You MUST proactively call these MCP tools to fetch live data, search security events, query databases, or execute actions when needed to fulfill the user's request.
        2. IMPORTANT: You do NOT have any tool called "list_tools", "default_mcp_server.list_tools", or similar listing functions. Do NOT try to call a tool to list your tools. Your available tools are already registered and visible to you. If the user asks what tools are available, simply describe the tools that are registered in your active declarations.
        
        Always provide technical reasoning and summarize your findings in Markdown."""

        # 6. Execution
        siemplify.LOGGER.info(f"Launching Hosted MCP Agent against: {mcp_url}")
        
        results = manager.run_agent(
            agent_name="Generic_MCP_Agent",
            instructions=agent_instructions,
            input_text=user_prompt,
            tools=[mcp_toolset],
            thinking_budget=thinking_budget,
            session_id=str(siemplify.case_id)
        )

        # 7. Harvest Results
        result_value = results["final_response"]
        output_message = "Hosted MCP Agent successfully finished its task."
        
        # ADD JSON RESULTS:
        # 1. Programmatic JSON (for playbook placeholders)
        siemplify.result.add_result_json(results)
        # 2. UI-Visible JSON (for the 'MCP_Agent_Results' tab on the Case Wall)
        siemplify.result.add_json("MCP_Agent_Results", results)

        if results["thoughts"]:
            thought_str = "\n".join([f"• {t}" for t in results["thoughts"]])
            siemplify.add_comment(f"### Agent Reasoning ###\n{thought_str}")

        siemplify.add_comment(f"### Agent Final Response ###\n\n{result_value}")

    except Exception as e:
        output_message = f"Error: {str(e)}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Action Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
