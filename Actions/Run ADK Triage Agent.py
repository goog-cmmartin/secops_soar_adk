import os
import json
import datetime
import traceback
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleADKManager import GoogleADKManager

INTEGRATION_NAME = "Google ADK"
SCRIPT_NAME = "Run Triage Agent (WF-TRIAGE-001)"
SKILL_VERSION = "1.2.0"

ENTITY_FIELD_MAP = {
    "hostname": "detection.collection_elements.references.event.principal.hostname",
    "ip": "detection.collection_elements.references.event.principal.ip",
    "userid": "detection.collection_elements.references.event.principal.user.userid",
    "sha256": "detection.collection_elements.references.event.principal.process.file.sha256",
    "command_line": "detection.collection_elements.references.event.target.process.command_line",
    "dns_query": "detection.collection_elements.references.event.network.dns.questions.name"
}

def extract_json_block(text):
    """Extracts and parses a JSON block from LLM output, handling markdown wrappers."""
    text = text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()
    return json.loads(text)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    
    # Initialize default states
    status = EXECUTION_STATE_COMPLETED 
    output_message = ""
    result_value = False

    try:
        # ---------------------------------------------------------------------
        # 1. Fetch Global and Action Configuration
        # ---------------------------------------------------------------------
        api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        mcp_url = siemplify.extract_configuration_param(INTEGRATION_NAME, "MCP Server URL")
        
        cust_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Customer ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        proj_id = (
            siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID")
        )
        model_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "Model Name", default_value="gemini-3.7-flash")

        # Action parameters
        dry_run_raw = siemplify.extract_action_param("Dry Run", default_value="False")
        dry_run = str(dry_run_raw).lower() in ("true", "yes", "1")
        triage_identity = siemplify.extract_action_param("Triage Identity", default_value="@Tier1")
        enable_memory = siemplify.extract_action_param("Enable Memory", input_type=bool, default_value=False)
        raw_session_id = siemplify.extract_action_param("Session ID")

        case_id = str(siemplify.case_id)
        if not case_id.isdigit():
            raise ValueError(f"Triage requires a numeric caseId. Received: {case_id}")

        siemplify.LOGGER.info(f"Starting Triage sequential pipeline for Case: {case_id} (Dry Run: {dry_run}, Memory: {enable_memory})")

        # Initialize the ADK Manager
        manager = GoogleADKManager(
            api_key=api_key, 
            service_account_json=sa_json, 
            model_name=model_name, 
            logger=siemplify.LOGGER,
            project_id=proj_id,
            location=region
        )

        # Resolve Memory Configuration
        session_id, memory_service, memory_tools = manager.resolve_memory_configuration(
            enable_memory=enable_memory,
            session_id=raw_session_id,
            case_id=case_id
        )

        # Equip read-only toolset
        read_toolset = manager.init_mcp_toolset(
            mcp_url=mcp_url, 
            user_project=proj_id, 
            tool_filter=[
                "get_case", "list_case_alerts", "get_alert_latest_investigation",
                "list_involved_entities", "list_connector_events", "udm_search", "summarize_entity"
            ]
        )

        # ---------------------------------------------------------------------
        # 2. Pre-flight Validation & Pre-CLAIM Reads (Deterministic)
        # ---------------------------------------------------------------------
        siemplify.LOGGER.info("Executing pre-flight validation...")
        
        # We can run a micro-agent to do the validation or fetch case details first.
        # To be highly robust and fast, we run an explicit data gathering agent.
        case_info_prompt = f"Call get_case(caseId='{case_id}') and return its result in JSON."
        case_info_res = manager.run_agent(
            agent_name="Triage_Preflight_Fetcher",
            instructions="You are a read-only metadata fetcher. Call get_case and format as JSON.",
            input_text=case_info_prompt,
            tools=[read_toolset]
        )
        
        case_data = extract_json_block(case_info_res["final_response"])
        siemplify.LOGGER.info(f"Retrieved case data: {json.dumps(case_data)}")

        # Enforce state validations programmatically
        case_status = case_data.get("status", "OPEN").upper()
        if case_status == "CLOSED":
            msg = f"Case {case_id} is CLOSED; nothing to triage."
            siemplify.add_comment(f"### Triage Canceled ###\n{msg}")
            siemplify.end(msg, True, EXECUTION_STATE_COMPLETED)
            return

        case_stage = case_data.get("stage", "Triage")
        if case_stage != "Triage" and not dry_run:
            msg = f"Case {case_id} is already in stage '{case_stage}'; skipping triage to prevent clobbering later-stage work."
            siemplify.add_comment(f"### Triage Canceled ###\n{msg}")
            siemplify.end(msg, True, EXECUTION_STATE_COMPLETED)
            return

        # ---------------------------------------------------------------------
        # 3. CLAIM State Phase (Programmatic Write)
        # ---------------------------------------------------------------------
        if not dry_run:
            siemplify.LOGGER.info(f"Claiming case {case_id} for identity {triage_identity}...")
            write_toolset = manager.init_mcp_toolset(mcp_url=mcp_url, user_project=proj_id, tool_filter=["update_case"])
            manager.run_agent(
                agent_name="Triage_Claim_Writer",
                instructions="You are a state-update agent. Call update_case to assign the case assignee.",
                input_text=f"Call update_case(caseId='{case_id}', assignee='{triage_identity}')",
                tools=[write_toolset]
            )

        # ---------------------------------------------------------------------
        # 4. GATHER Phase 1: Alerts, Entities, Investigations, Events (Sequential Agent)
        # ---------------------------------------------------------------------
        siemplify.LOGGER.info("Phase 1 GATHER: Extracting alert metadata, local entities, and prior investigations...")
        
        gather_instructions = f"""You are a Security Data Gathering Agent.
Your goal is to collect all local facts and alerts for Case {case_id}.

You MUST execute the following sequence of read actions:
1. Call list_case_alerts(caseId='{case_id}') to fetch all alerts.
2. For EACH alert returned:
   a. Call get_alert_latest_investigation(alertId=...) using its siemAlertId.
   b. Call list_involved_entities(caseId='{case_id}', caseAlertId=...) using its caseAlertId.
   c. Call list_connector_events(caseId='{case_id}', caseAlertId=..., expandEventJsonData=true) to get raw event context.

Output your gathered facts in a well-structured JSON format inside a single ```json block.
Do NOT attempt to write comments or change the case stage. ONLY retrieve and dump the raw JSON."""

        gather_res = manager.run_agent(
            agent_name="Triage_Data_Gatherer",
            instructions=gather_instructions,
            input_text="Gather all alert and event metadata.",
            tools=[read_toolset]
        )
        
        local_facts = extract_json_block(gather_res["final_response"])
        siemplify.LOGGER.info(f"Gathered local facts: {json.dumps(local_facts)}")

        # ---------------------------------------------------------------------
        # 5. GATHER Phase 2: Historical Prevalence & Prior Disposition (Programmatic Construct)
        # ---------------------------------------------------------------------
        siemplify.LOGGER.info("Phase 2 GATHER: Compiling historical context queries...")
        
        # Parse output to extract active rules, entities, and compute time lookbacks
        alerts_list = local_facts.get("alerts", [])
        if not alerts_list:
            # Fallback if no alerts returned
            alerts_list = [{"siemAlertId": "unknown", "ruleGenerator": "unknown", "caseAlertId": "unknown"}]

        # Resolve suspicious pivot entity
        pivot_entity = None
        pivot_type = "unknown"
        rule_id = "unknown"

        for alert in alerts_list:
            rule_id = alert.get("ruleId") or alert.get("detectionRuleId") or rule_id
            entities = alert.get("entities", [])
            for ent in entities:
                if ent.get("pivot") or ent.get("suspicious") or pivot_entity is None:
                    pivot_entity = ent.get("value") or ent.get("name")
                    pivot_type = ent.get("type", "hostname").lower()

        # Safely extract first rule ID
        if not rule_id or rule_id == "unknown":
            rule_id = "ur_unknown"

        # Calculate time windows: Exactly 30 days lookback to prevent "invalid argument" on wide ranges
        now = datetime.datetime.now(datetime.timezone.utc)
        start_time = (now - datetime.timedelta(days=30)).isoformat().replace("+00:00", "Z")
        end_time = now.isoformat().replace("+00:00", "Z")

        # Select corresponding Family B prevalence field
        entity_field = ENTITY_FIELD_MAP.get(pivot_type, ENTITY_FIELD_MAP["hostname"])

        historical_results = {
            "prevalence_entity": "unavailable",
            "prevalence_rule": "unavailable",
            "prior_dispositions": "unavailable"
        }

        if pivot_entity:
            # Build Family A Prior Disposition Query (Case Table)
            family_a_query = f"""
$case_name                       = case.name
$case_id                         = case.response_platform_info.response_platform_id
$case_display_name               = case.display_name
$case_status                     = case.status
$case_closure_details_reason     = case.closure_details.reason
$rule_id                         = case.alerts.metadata.detection.rule_id

$entity = group(
    case.alerts.metadata.collection_elements.references.event.principal.user.userid,
    case.alerts.metadata.collection_elements.references.event.target.user.userid,
    case.alerts.metadata.collection_elements.references.event.src.user.userid
)

$entity = "{pivot_entity}"

match:
    $case_name, $case_id, $case_display_name, $case_status, $case_closure_details_reason, $rule_id, $entity
limit:
    10
"""

            # Build Family B Entity Prevalence Query (Detections Table)
            family_b_query = f"""
$entity = {entity_field}
$entity = "{pivot_entity}"
$ruleId = detection.detection.rule_id
$ruleId = "{rule_id}"
match:
    $entity
outcome:
    $count = count(detection.id)
order:
    $count desc
limit: 10
"""

            historical_instructions = f"""You are a Security History Gathering Agent.
Your job is to fetch historical prevalence and prior case dispositions.

You MUST use your available tools to run:
1. Call summarize_entity(entityType='{pivot_type}', entityValue='{pivot_entity}') to check global prevalence.
2. Call udm_search(query=\"\"\"{family_a_query}\"\"\", startTime='{start_time}', endTime='{end_time}') to query prior cases.
3. Call udm_search(query=\"\"\"{family_b_query}\"\"\", startTime='{start_time}', endTime='{end_time}') to query detections prevalence.

Format your responses inside a single ```json block. Handle any empty values or errors gracefully (just record the error inside the JSON)."""

            siemplify.LOGGER.info(f"Running historical queries for Pivot: {pivot_entity} ({pivot_type}) and Rule: {rule_id}")
            try:
                hist_res = manager.run_agent(
                    agent_name="Triage_Historical_Gatherer",
                    instructions=historical_instructions,
                    input_text="Execute historical udm searches.",
                    tools=[read_toolset]
                )
                historical_results = extract_json_block(hist_res["final_response"])
            except Exception as hist_err:
                siemplify.LOGGER.warn(f"Failed to gather historical context: {hist_err}")

        # ---------------------------------------------------------------------
        # 6. DECIDE & RECONCILE Phase (Isolated LLM Node - ZERO TOOLS)
        # ---------------------------------------------------------------------
        siemplify.LOGGER.info("DECIDE Phase: Launching isolated decision agent...")
        
        # Prepare aggregated payload for the isolated model
        decision_payload = {
            "case_id": case_id,
            "local_facts": local_facts,
            "historical_results": historical_results,
            "pivot_entity": pivot_entity,
            "pivot_type": pivot_type,
            "rule_id": rule_id
        }

        # Build strict isolated decision instructions
        decision_instructions = """You are the Case Triage Decision Agent.
Your sole responsibility is to analyze security evidence and formulate an accurate, case-level triage verdict.
You are completely offline and have NO active tools, so you cannot execute actions or go off-piste.

EVALUATE THE DECIDE GATE (v1.2.0):
1. Independent Corpus Signal Check:
   Verify if there is at least one active, corpus-scoped signal (from summarize_entity or udm_search) present in the historical_results.
   If none is present (or both are empty/errored), you MUST return an 'INCONCLUSIVE' verdict and note the missing requirement.
2. Provenance and Zero Hallucination:
   Do NOT invent or hallucinate any numbers (prevalence counts, lookback windows, sightings). Every single quantitative metric must be directly traceable to the historical_results.
   If any number is missing, label it as 'unavailable'.
3. Worst-Case Wins Reconciliation:
   If any alert's raw event or prior investigation evaluates as TRUE_POSITIVE -> Case Verdict is TRUE_POSITIVE.
   If all alerts are FALSE_POSITIVE with clear benign explanations -> Case Verdict is FALSE_POSITIVE.
   Otherwise, if content is ambiguous, return INCONCLUSIVE.

Analyze the raw event payload in the evidence against these seed lists:
- Known-bad: Cobalt Strike named pipes (MSSE-*-server, msagent_*, postex_*, status_*), 'cmd.exe /c echo ... > \\\\.\\pipe\\', wevtutil/auditpol tampering, registry execution.
- Known-benign: Standard signed OS utilities, documented admin tooling.

Output your final verdict and rationale in a strict, parsed JSON structure matching this schema:
{
  "verdict": "FALSE_POSITIVE" | "TRUE_POSITIVE" | "INCONCLUSIVE",
  "simulated": true | false,
  "rationale": "<technical justification connecting raw indicators and reconciliation>",
  "disposition": "recommend close NOT_MALICIOUS" | "escalate to Assessment" | "hold for data/human",
  "next_steps": "<specific, actionable action items>",
  "prevalence_entity": "<extracted seen count or 'unavailable'>",
  "prevalence_rule": "<extracted detections count or 'unavailable'>"
}
Do not write any other text outside the json block."""

        decision_res = manager.run_agent(
            agent_name="Triage_Decision_Node",
            instructions=decision_instructions,
            input_text=json.dumps(decision_payload, indent=2),
            tools=memory_tools if memory_tools else [],
            session_id=session_id,
            memory_service=memory_service
        )

        decision = extract_json_block(decision_res["final_response"])
        siemplify.LOGGER.info(f"Decision output: {json.dumps(decision)}")

        # ---------------------------------------------------------------------
        # 7. RECORD Phase (Deterministic Python Comment Formatting)
        # ---------------------------------------------------------------------
        siemplify.LOGGER.info("RECORD Phase: Constructing Case Wall Comment report...")
        
        # Enforce provenance of numbers programmatically in Python
        pe = decision.get("prevalence_entity", "unavailable")
        pr = decision.get("prevalence_rule", "unavailable")
        
        # Double-check that we are not attaching "for rule" to an entity count
        if "for rule" in str(pe):
            pe = "unavailable"

        # Build per-alert prior investigation summary block
        alert_investigations_markdown = ""
        for alert in alerts_list:
            sal_id = alert.get("siemAlertId") or alert.get("alertId") or "unknown"
            inv = alert.get("latest_investigation") or alert.get("investigation") or {}
            if inv and inv.get("status"):
                alert_investigations_markdown += f"- {sal_id}: {inv.get('verdict')} ({inv.get('confidence')}, {inv.get('triggerType')}, {inv.get('status')})\n"
            else:
                alert_investigations_markdown += f"- {sal_id}: none run ({{}})\n"

        # Construct final structured report using the exact 1.2.0 Markdown template
        report_comment = f"""[TRIAGE] VERDICT: {decision.get('verdict')}  SIMULATED: {str(decision.get('simulated')).lower()}
SKILL_VERSION: {SKILL_VERSION}
Case: {case_id} "{case_data.get('displayName', 'Unknown Case')}"  |  Rule: {alerts_list[0].get('ruleGenerator', 'Unknown Rule')} ({rule_id})  |  Priority: {case_data.get('priority', 'Medium')}

Prior investigations (per alert):
{alert_investigations_markdown.strip()}

Evidence:
- Host/Asset: {pivot_entity if pivot_type == 'hostname' else 'unknown/unspecified'}
- User: {pivot_entity if pivot_type == 'userid' else 'unknown/unspecified'}
- Indicator: {pivot_entity} ({pivot_type})
- Event type: {local_facts.get('event_type', 'unknown')}
- Provenance: Ingestion labels: {local_facts.get('ingestion_labels', 'none')} | Simulated: {str(decision.get('simulated')).lower()}
- Prevalence (entity): {pivot_type}={pivot_entity} seen {pe}
- Prevalence (rule): rule {rule_id} detections={pr}

Rationale: {decision.get('rationale')}

Disposition: {decision.get('disposition')}
Next: {decision.get('next_steps')}"""

        # Write Case Wall comment
        if not dry_run:
            siemplify.LOGGER.info("Posting triage report comment...")
            comment_toolset = manager.init_mcp_toolset(mcp_url=mcp_url, user_project=proj_id, tool_filter=["create_case_comment"])
            manager.run_agent(
                agent_name="Triage_Comment_Writer",
                instructions="You are a comment writer. Call create_case_comment with the exact text provided.",
                input_text=f"Call create_case_comment(caseId='{case_id}', comment=\"\"\"{report_comment}\"\"\")",
                tools=[comment_toolset]
            )
        else:
            siemplify.add_comment(f"### [DRY RUN] Structured Report Draft ###\n{report_comment}")

        # ---------------------------------------------------------------------
        # 8. ROUTE Phase (Programmatic Stage Updates)
        # ---------------------------------------------------------------------
        final_verdict = decision.get("verdict", "INCONCLUSIVE")
        target_stage = "Triage"
        
        if final_verdict == "TRUE_POSITIVE":
            target_stage = "Assessment" # Escalate to Assessment
        else:
            target_stage = "Triage"     # Stay on Triage (Hold)

        if not dry_run:
            siemplify.LOGGER.info(f"Routing Case {case_id} to Stage: {target_stage}...")
            route_toolset = manager.init_mcp_toolset(mcp_url=mcp_url, user_project=proj_id, tool_filter=["update_case"])
            manager.run_agent(
                agent_name="Triage_Router",
                instructions="You are a routing agent. Call update_case to change the stage.",
                input_text=f"Call update_case(caseId='{case_id}', stage='{target_stage}')",
                tools=[route_toolset]
            )
            output_message = f"Triage complete. Case routed to '{target_stage}' with verdict '{final_verdict}'."
        else:
            output_message = f"Dry Run Triage complete. Projected Stage: '{target_stage}' with verdict '{final_verdict}'."

        triage_summary = {
            "case_id": case_id,
            "final_verdict": final_verdict,
            "target_stage": target_stage,
            "dry_run": dry_run,
            "decision": decision,
            "simulated": decision.get("simulated", False),
            "rationale": decision.get("rationale", "")
        }
        siemplify.result.add_result_json(triage_summary)
        siemplify.result.add_json("Triage_Agent_Results", triage_summary)

        siemplify.add_comment(f"### Sequential Triage Execution Summary ###\n**Final Verdict**: `{final_verdict}`\n**Simulated**: `{decision.get('simulated')}`\n**Target Stage**: `{target_stage}`\n\n{decision.get('rationale')}")
        result_value = True

    except Exception as e:
        output_message = f"Error executing Triage Agent: {str(e)}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.error(traceback.format_exc())
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Action Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
