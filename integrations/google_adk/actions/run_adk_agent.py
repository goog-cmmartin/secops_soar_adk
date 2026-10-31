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
SCRIPT_NAME = "Run ADK Agent"


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

        raw_agent_name = siemplify.extract_action_param("Agent Name", default_value="Logic_Analyst_Agent")
        sanitized_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(raw_agent_name).strip())
        case_id_tag = f"_{siemplify.case_id}" if getattr(siemplify, "case_id", None) else ""
        agent_name = f"{sanitized_name}{case_id_tag}"

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

        enable_search = str(siemplify.extract_action_param("Enable Google Search", default_value=False)).lower() in ("true", "1")
        enable_memory = str(siemplify.extract_action_param("Enable Memory", default_value=False)).lower() in ("true", "1")
        raw_session_id = siemplify.extract_action_param("Session ID")

        manager = GoogleADKManager(
            api_key=api_key,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            model_name=model_name,
            project_id=proj_id,
            location=region,
            logger=siemplify.LOGGER,
            agent_engine_resource_name=agent_engine_resource,
        )

        session_id, memory_service, memory_tools = manager.resolve_memory_configuration(
            enable_memory=enable_memory, session_id=raw_session_id, case_id=getattr(siemplify, "case_id", None)
        )

        base_instructions = (
            "You are a Senior SecOps Incident Responder powered by Google ADK. "
            "Provide rigorous technical reasoning and summarize findings in Markdown.\n\n"
            "### MANDATORY 3-TIER TRIAGE TAXONOMY ###\n"
            "At the very top of your report (immediately below the main `# Title` heading), you MUST output a "
            "single blockquote triage classification line in this exact format:\n"
            "> **Verdict:** `<Level 1 Primary Verdict>` | **Disposition:** `<Level 2 Sub-Classification>` | **Confidence:** `<HIGH / MEDIUM / LOW>`\n\n"
            "**1. Primary Verdict (Level 1 — Detection Validity & Intent):**\n"
            "- `True Positive (Malicious)` — Confirmed or suspected threat actor activity requiring containment.\n"
            "- `Benign Positive (BTP)` — Detection rule fired accurately on real activity, but the activity is non-malicious (e.g., authorized admin/automation, red team/pentest, or non-malicious policy violation).\n"
            "- `False Positive (FP)` — Detection rule misfired due to rule logic, log parser/normalization flaw, or noisy threshold.\n"
            "- `Inconclusive / Undetermined` — Cannot be proven malicious or benign from available telemetry alone.\n\n"
            "**2. Disposition / Sub-Classification (Level 2 — Root Cause & Routing Trigger):**\n"
            "- Under `True Positive (Malicious)`: `Malicious — Active Compromise / Intrusion`, `Malicious — Automated Opportunistic Scanning / Blocked Exploit`, or `Malicious — PUP / Greyware`.\n"
            "- Under `Benign Positive (BTP)`: `Authorized Admin / Business Activity`, `Authorized Security Testing / Red Team / BAS`, or `Policy Violation / Misconfiguration (Non-Malicious)`.\n"
            "- Under `False Positive (FP)`: `Rule Logic / Threshold Too Broad` or `Log Parser / Telemetry Artifact`.\n"
            "- Under `Inconclusive / Undetermined`: `Insufficient Telemetry / Needs Human Input`.\n\n"
            "**3. Investigative Confidence (Level 3 — Anchored to Evidence):**\n"
            "- `HIGH` — Corroborated across multiple independent signals/events.\n"
            "- `MEDIUM` — Consistent with the verdict, but relies on a single data source or lacks definitive intent proof.\n"
            "- `LOW` — Circumstantial or missing key context.\n\n"
            "**4. Tailored Next Steps by Disposition:**\n"
            "- If `True Positive (Malicious)` -> Provide **Containment, Eradication & Recovery CLI/SOAR Steps**.\n"
            "- If `Benign Positive (BTP)` + `Policy Violation / Misconfiguration` -> Skip aggressive IR containment and provide **IAM/Configuration Hardening & User Coaching Steps**.\n"
            "- If `Benign Positive (BTP)` + `Authorized Admin / Business Activity` or `Security Testing` -> Provide **Scope Verification & Detection Tuning / Allowlisting Recommendations**.\n"
            "- If `False Positive (FP)` -> Provide **YARA-L Rule / Parser Bug Tuning Recommendations** for Detection Engineering."
        )

        # Add SecOps SDK Engine tools (silent detection correlation, UDM search, detection rules)
        cust_id = (
            siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, param_name="Customer ID")
            or "a556547c-1cff-43ef-a2e4-cf5b12a865df"
        )
        secops_engine_tools = manager.init_secops_engine_toolset(
            customer_id=cust_id,
            project_id=proj_id,
            region=region,
        )

        agent_tools = []
        if enable_search:
            agent_tools.append(google_search)
        if secops_engine_tools:
            agent_tools.extend(secops_engine_tools)
        if memory_tools:
            agent_tools.extend(memory_tools)

        results = manager.run_agent(
            agent_name=agent_name,
            instructions=base_instructions,
            input_text=user_prompt,
            tools=agent_tools,
            thinking_budget=thinking_budget,
            session_id=session_id,
            memory_service=memory_service,
            enable_google_search=enable_search,
        )

        result_value = results.get("final_response", "")
        if not result_value:
            result_value = f"ADK Agent '{agent_name}' completed analysis. (Check JSON Result for execution thoughts and metadata)."
        output_message = f"ADK Agent '{agent_name}' completed successfully."

        siemplify.result.add_result_json(results)
        siemplify.result.add_json("ADK_Agent_Results", results)

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
