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
SCRIPT_NAME = "Run Google Hosted MCP Agent"


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
        mcp_url = siemplify.extract_configuration_param(INTEGRATION_NAME, "MCP Server URL")
        cust_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Customer ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        agent_engine_resource = siemplify.extract_configuration_param(INTEGRATION_NAME, "Agent Engine Resource Name")
        proj_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "SecOps Project ID"
        ) or siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID")
        model_name = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Model Name", default_value="gemini-3.8-flash"
        )

        user_prompt = siemplify.extract_action_param("User Prompt")
        if not user_prompt or not str(user_prompt).strip():
            raise ValueError("The 'User Prompt' parameter is required and cannot be empty.")

        raw_budget = siemplify.extract_action_param("Thinking Budget", default_value=0)
        try:
            thinking_budget = int(raw_budget) if raw_budget else 0
            if thinking_budget < 0:
                raise ValueError()
        except ValueError:
            raise ValueError(f"'Thinking Budget' must be a non-negative integer, got: '{raw_budget}'")

        tool_filter_raw = siemplify.extract_action_param("Tool Filter")
        tool_filter = None
        if tool_filter_raw and str(tool_filter_raw).strip():
            tool_filter = [t.strip().strip("'").strip('"') for t in str(tool_filter_raw).split(",") if t.strip()]

        enable_memory = str(siemplify.extract_action_param("Enable Memory", default_value=False)).lower() in ("true", "1")
        raw_session_id = siemplify.extract_action_param("Session ID")

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
            enable_memory=enable_memory, session_id=raw_session_id, case_id=getattr(siemplify, "case_id", None)
        )

        mcp_toolset = manager.init_mcp_toolset(
            mcp_url=mcp_url,
            user_project=proj_id,
            tool_filter=tool_filter,
            customer_id=cust_id,
            region=region,
        )

        secops_engine_tools = manager.init_secops_engine_toolset(
            customer_id=cust_id,
            project_id=proj_id,
            region=region,
        )

        agent_instructions = (
            f"You are a specialized SecOps Incident Responder & Autonomous Agent. "
            f"Active Project: {proj_id}, Region: {region}, Customer ID: {cust_id}. "
            f"You are equipped with Google SecOps hosted MCP tools (executed via `mcp_executor(tool_name, arguments)`) "
            f"AND direct SecOps SDK Engine tools:\n"
            f"- `correlate_silent_detections(case_id, lookback_hours)`: Hunts for non-alerting detections and matching UDM events on case entities.\n"
            f"- `search_udm_events(query, start_time, end_time, include_detections, receive_limit)`: Queries raw UDM telemetry and detection objects.\n"
            f"- `get_detection_rule(rule_id)`: Fetches YARA-L 2.0 rule syntax and detection logic.\n"
            f"- `mcp_executor(tool_name, arguments)`: Interacts with Google SecOps hosted MCP tools (e.g. get_case, list_case_alerts, add_case_comment).\n"
            f"When investigating a case, start by checking the case and alerts, and ALWAYS correlate silent detections "
            f"using `correlate_silent_detections` to discover the underlying payloads, execution logs, and full attack path."
        )

        tools = [mcp_toolset]
        if secops_engine_tools:
            tools.extend(secops_engine_tools)
        if memory_tools:
            tools.extend(memory_tools)

        results = manager.run_agent(
            agent_name="Hosted_MCP_Agent",
            instructions=agent_instructions,
            input_text=user_prompt,
            tools=tools,
            thinking_budget=thinking_budget,
            session_id=session_id,
            memory_service=memory_service,
        )

        result_value = results.get("final_response", "")
        if not result_value:
            result_value = "Hosted MCP Agent completed analysis. (Check JSON Result for execution thoughts and metadata)."
        output_message = "Hosted MCP Agent successfully processed query."

        siemplify.result.add_result_json(results)
        siemplify.result.add_json("MCP_Agent_Results", results)

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
