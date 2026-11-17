"""
Run ADK Autonomous Agent Job for GoogleADK in Google SecOps SOAR.

Executes an autonomous Google ADK Agent on a recurring schedule or on-demand
with full access to the SecOps SDK Engine toolset:
  - Silent Detection Correlation & Delta Entity Discovery
  - UDM Event Search, Statistical Aggregation, & Entity Investigation
  - YARA-L 2.0 Detection Rules & Noisy Rule Discovery
  - SOAR Cases, Alerts, & Case Wall Comments
  - Chronicle Data Tables (List, Get, Create, Rows CRUD, Health Audit)
  - Chronicle Native Dashboards (Search, Get, Execute Queries, Charts CRUD, Health Audit)
  - SOAR Playbooks (Search, Get, Execution Health & Decay Audits)
 Plus optional Google Search grounding, Code Execution sandbox, Hosted MCP, and Memory Bank.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)

# Ensure core directory is on sys.path for SOAR runtime
_current_dir = os.path.dirname(os.path.abspath(__file__))
_core_dir = os.path.join(os.path.dirname(_current_dir), "core")
for _p in [_core_dir, _current_dir]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler

try:
    from GoogleADKManager import GoogleADKManager, google_search
except ImportError:
    from core.GoogleADKManager import GoogleADKManager, google_search

JOB_NAME = "Run ADK Autonomous Agent Job"
INTEGRATION_NAME = "GoogleADK"
PROCESSED_CASES_CONTEXT_KEY = "adk_job_processed_case_ids_v1"
MAX_STORED_CASE_IDS = 500

DEFAULT_PROMPT = (
    "Execute the 5-Stage Tier 1 Autonomous Triage SOP for each target SOAR case at the T+10m maturity window "
    "(inspect case & T+0m comments, re-run silent detection correlation & delta entity extraction, profile entities "
    "with PipedSQL via query_udm_sql, consult get_soc_triage_sop() for the SOP matrix & tag taxonomy, batch-update "
    "alert status/priority with update_case_alert(alert_id='ALL'), attach standardized case tags including "
    "recommended_detection_tags, invoke tune_case_detections() and tag Tune:Candidate whenever Verdict is False Positive (FP) "
    "or recurring Benign Positive (BTP), and post the structured BLUF triage report to the Case Wall)."
)


def _parse_bool(val, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return default


def _parse_int(val, default: int) -> int:
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return default


def _safe_extract_config(siemplify: SiemplifyJob, param_name: str, default_value: str = "") -> str:
    try:
        val = siemplify.extract_configuration_param(
            INTEGRATION_NAME, param_name, default_value=default_value
        )
        return str(val).strip() if val is not None else default_value
    except Exception:
        return default_value


def _load_processed_case_ids(siemplify: SiemplifyJob) -> list:
    try:
        raw = siemplify.get_scoped_job_context_property(PROCESSED_CASES_CONTEXT_KEY)
        if not raw:
            return []
        parsed = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed if str(x).strip()]
    except Exception as exc:
        siemplify.LOGGER.info(f"Job context property not yet initialized ({exc}); starting fresh.")
    return []


def _save_processed_case_ids(siemplify: SiemplifyJob, case_ids: list) -> None:
    try:
        deduped = []
        seen = set()
        for cid in case_ids:
            s = str(cid).strip()
            if s and s not in seen:
                seen.add(s)
                deduped.append(s)
        bounded = deduped[-MAX_STORED_CASE_IDS:]
        siemplify.set_scoped_job_context_property(
            PROCESSED_CASES_CONTEXT_KEY, json.dumps(bounded)
        )
    except Exception as exc:
        siemplify.LOGGER.info(f"Could not persist processed case IDs to job context: {exc}")


def _parse_iso_timestamp(ts_str: str):
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        cleaned = ts_str.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = JOB_NAME
    siemplify.LOGGER.info("================= Run ADK Autonomous Agent Job Started =================")

    try:
        # 1. Extract Integration Configuration Parameters
        api_key = _safe_extract_config(siemplify, "Gemini API Key")
        sa_json = _safe_extract_config(siemplify, "Service Account JSON")
        workload_identity_email = _safe_extract_config(siemplify, "Workload Identity Email")
        model_name = _safe_extract_config(siemplify, "Model Name", default_value="gemini-3.8-flash") or "gemini-3.8-flash"
        proj_id = (
            _safe_extract_config(siemplify, "GCP Project ID")
            or _safe_extract_config(siemplify, "SecOps Project ID")
            or os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or ""
        )
        region = (
            _safe_extract_config(siemplify, "SecOps Region", default_value="us")
            or os.environ.get("SECOPS_REGION")
            or "us"
        )
        cust_id = (
            _safe_extract_config(siemplify, "SecOps Customer ID")
            or _safe_extract_config(siemplify, "Customer ID")
            or os.environ.get("SECOPS_CUSTOMER_ID")
            or ""
        )
        agent_engine_resource = _safe_extract_config(siemplify, "Agent Engine Resource Name")
        mcp_url = _safe_extract_config(siemplify, "MCP Server URL")
        skills_gcs_path = _safe_extract_config(siemplify, "Skills GCS Path")

        # 2. Extract Job Parameters
        raw_agent_name = siemplify.extract_job_param(
            param_name="Agent Name",
            default_value="Autonomous_SecOps_ADK_Job_Agent",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        agent_name = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in str(raw_agent_name or "Autonomous_SecOps_ADK_Job_Agent").strip()
        )

        user_prompt = siemplify.extract_job_param(
            param_name="User Prompt",
            default_value=DEFAULT_PROMPT,
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        if not user_prompt or not str(user_prompt).strip():
            user_prompt = DEFAULT_PROMPT

        target_case_ids_raw = siemplify.extract_job_param(
            param_name="Target Case IDs",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        explicit_case_ids = [
            c.strip() for c in str(target_case_ids_raw or "").split(",") if c.strip()
        ]

        sweep_open_cases = _parse_bool(
            siemplify.extract_job_param(
                param_name="Sweep Recent Open Cases",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        post_to_wall = _parse_bool(
            siemplify.extract_job_param(
                param_name="Post Report to Case Wall",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        lookback_minutes = max(
            0,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Lookback Minutes",
                    default_value="60",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=60,
            ),
        )

        min_case_age_minutes = max(
            0,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Min Case Age Minutes",
                    default_value="10",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=10,
            ),
        )

        max_cases = max(
            1,
            min(
                25,
                _parse_int(
                    siemplify.extract_job_param(
                        param_name="Max Cases Per Run",
                        default_value="5",
                        input_type=str,
                        is_mandatory=False,
                        print_value=True,
                    ),
                    default=5,
                ),
            ),
        )

        priority_filter_raw = siemplify.extract_job_param(
            param_name="Priority Filter",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )

        force_recheck = _parse_bool(
            siemplify.extract_job_param(
                param_name="Force Re-Check Processed Cases",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        enable_secops_engine = _parse_bool(
            siemplify.extract_job_param(
                param_name="Enable SecOps Engine Toolset",
                default_value="true",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=True,
        )

        enable_hosted_mcp = _parse_bool(
            siemplify.extract_job_param(
                param_name="Enable Hosted MCP Toolset",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        enable_search = _parse_bool(
            siemplify.extract_job_param(
                param_name="Enable Google Search",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        enable_code_exec = _parse_bool(
            siemplify.extract_job_param(
                param_name="Enable Code Execution",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        enable_memory = _parse_bool(
            siemplify.extract_job_param(
                param_name="Enable Memory",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        thinking_budget = max(
            0,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Thinking Budget",
                    default_value="0",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=0,
            ),
        )

        # 3. Initialize GoogleADKManager & Toolsets
        manager = GoogleADKManager(
            api_key=api_key,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            model_name=model_name,
            project_id=proj_id,
            location=region,
            logger=siemplify.LOGGER,
            agent_engine_resource_name=agent_engine_resource,
            skills_gcs_path=skills_gcs_path,
        )

        secops_engine_tools = []
        tool_map = {}
        if enable_secops_engine:
            secops_engine_tools = manager.init_secops_engine_toolset(
                customer_id=cust_id,
                project_id=proj_id,
                region=region,
            )
            tool_map = {t.__name__: t for t in secops_engine_tools}

        session_id, memory_service, memory_tools = manager.resolve_memory_configuration(
            enable_memory=enable_memory,
            session_id=f"job_{agent_name}" if enable_memory else None,
        )

        agent_tools = []
        if enable_search:
            agent_tools.append(google_search)
        if secops_engine_tools:
            agent_tools.extend(secops_engine_tools)
        if enable_hosted_mcp:
            mcp_executor = manager.init_mcp_toolset(
                mcp_url=mcp_url or None,
                user_project=proj_id,
                customer_id=cust_id,
                region=region,
            )
            agent_tools.append(mcp_executor)
        if memory_tools:
            agent_tools.extend(memory_tools)

        base_instructions = (
            "You are a Tier 1 Autonomous SecOps & SOAR Triage Agent powered by Google ADK.\n"
            "You are executing inside a scheduled or on-demand Google SecOps SOAR Job (`T+10m` Maturity Window) with direct tool access to:\n"
            "- SOAR Case & Alert Management (`list_soar_cases`, `investigate_soar_case`, `add_soar_case_comment`, `list_soar_case_comments`, `update_soar_case`, `update_case_alert`, `add_soar_case_tag`, `remove_soar_case_tag`)\n"
            "- Silent Detection Correlation & GoogleSQL / Pipe Syntax (`|>`) UDM Hunting (`correlate_silent_detections`, `query_udm_sql`, `validate_udm_sql`, `search_udm_events`, `aggregate_udm_events`, `investigate_entity`)\n"
            "- Authoritative Governance & SOP Data Tables (`get_soc_triage_sop`, `list_data_tables`, `get_data_table`, `list_data_table_rows`, `add_data_table_rows`, `delete_data_table_row`, `audit_data_table_health`)\n"
            "  - `soc_triage_sop_matrix`: Authoritative SOC Triage SOP mapping 3-Tier Verdicts & Dispositions to Alert Status (`OPEN` / `CLOSE`), Priority, Case Stage, Incident flag, Required Tags, and COA steps.\n"
            "  - `soc_case_tag_taxonomy`: Approved SOAR Case Tag taxonomy (`Tier1:Triaged`, `SilentDetections:Found`, `SilentDetections:DeltaAdded`, `Verdict:*`, `Disp:*`, `Escalated:*`, `NeedsTuning`, `Tune:Candidate`, `Tune:Proposed`, `Tune:Approve`, `Tune:Applied`).\n"
            "- YARA-L 2.0 Detection Rules & Closed-Loop Autonomous Tuning (`tune_case_detections`, `propose_rule_tuning`, `test_findings_refinement`, `create_findings_refinement`, `get_detection_rule`, `list_detection_rules`, `find_top_noisy_rules`, `sync_detection_tuning_dashboard`)\n"
            "- Chronicle Native Dashboards & SOAR Playbooks (`search_dashboards`, `get_dashboard`, `execute_dashboard_query`, `search_playbooks`, `get_playbook`)\n\n"
            "### MANDATORY 3-TIER TRIAGE TAXONOMY ###\n"
            "1. **Primary Verdict (Level 1)**:\n"
            "   - `True Positive (Malicious)`\n"
            "   - `Benign Positive (BTP)`\n"
            "   - `False Positive (FP)`\n"
            "   - `Inconclusive / Undetermined`\n"
            "2. **Disposition / Sub-Classification (Level 2)**:\n"
            "   - Under `True Positive (Malicious)`: `Malicious — Active Compromise / Intrusion`, `Malicious — Automated Opportunistic Scanning / Blocked Exploit`, or `Malicious — PUP / Greyware`\n"
            "   - Under `Benign Positive (BTP)`: `Authorized Admin / Business Activity`, `Authorized Security Testing / Red Team / BAS`, or `Policy Violation / Misconfiguration (Non-Malicious)`\n"
            "   - Under `False Positive (FP)`: `Rule Logic / Threshold Too Broad` or `Log Parser / Telemetry Artifact`\n"
            "   - Under `Inconclusive / Undetermined`: `Insufficient Telemetry / Needs Human Input`\n"
            "3. **Investigative Confidence (Level 3)**: `HIGH`, `MEDIUM`, or `LOW`.\n\n"
            "### 5-STAGE TIER 1 AUTONOMOUS CASE TRIAGE SOP (`T+10m` MATURITY WINDOW) ###\n"
            "When triaging target SOAR Case ID(s), execute these 5 stages in order:\n"
            "- **Stage 1 (Case & T+0m Context Inspection)**:\n"
            "  Call `investigate_soar_case(case_id=...)` to inspect the case metadata, existing tags, alerts (`identifier`, `rule_name`, `status`, `priority`), involved entities, and Case Wall comments posted by `T+0m` playbooks.\n"
            "- **Stage 2 (T+10m Silent Detection Re-Correlation, Delta Entity Attachment & PipedSQL Hunting)**:\n"
            "  1. Always run `correlate_silent_detections(case_id=..., lookback_hours=48, attach_to_case=True, post_wall_comment=False)` at `T+10m` to capture any delayed streaming YARA-L silent detections, extract & attach newly discovered delta entities (such as external C2 IPs/URLs/hashes from command lines), and inspect `prior_detections_count`, `delta_detections_count`, `attached_entities`, and `recommended_detection_tags` in the tool output.\n"
            "  2. Use `query_udm_sql(sql_query=...)` with GoogleSQL Pipe Syntax (`FROM events |> WHERE ... |> AGGREGATE ...`) to summarize process executions, command lines, network connections, and authentication events for the involved host(s)/user(s)/IP(s). Remember `secops-nl2sql` invariants: every expression in `|> EXTEND`, `|> AGGREGATE`, and `GROUP BY` MUST have an `AS alias`; use `NULLIF(col, '') IS NOT NULL` for empty proto3 strings; use `[SAFE_OFFSET(0)]` for repeated fields; never use `PROTO` as an alias.\n"
            "- **Stage 3 (Governance Data Table Lookup & Disposition Rubric)**:\n"
            "  Call `get_soc_triage_sop()` in a single tool call to retrieve both `soc_triage_sop_matrix` and `soc_case_tag_taxonomy`, and map your evidence-backed 3-Tier Verdict, Disposition, and Confidence to the required Alert Status (`OPEN` or `CLOSE`), Alert/Case Priority, Case Stage, Incident escalation flag, and standardized Case Tags.\n"
            "- **Stage 4 (Autonomous SOAR Case & Alert Mutations + Closed-Loop Detection Tuning)**:\n"
            "  1. Call `update_case_alert(case_id=..., alert_id='ALL', status=..., priority=...)` to batch-update all alerts in the case in a single tool call according to the `soc_triage_sop_matrix` row.\n"
            "  2. Call `update_soar_case(case_id=..., priority=..., stage=..., incident=...)` once to align the case priority, stage, and incident status.\n"
            "  3. Call `add_soar_case_tag(case_id=..., tags=...)` with the comma-separated tags from `soc_triage_sop_matrix` (`Tier1:Triaged`, `Verdict:*`, `Disp:*`, `Escalated:*`) PLUS all tags listed in `recommended_detection_tags` from `correlate_silent_detections` (e.g., `SilentDetections:Found`, `SilentDetections:DeltaAdded`). If the Verdict is `False Positive (FP)` or a recurring/noisy `Benign Positive (BTP)`, also include `Tune:Candidate` in the tags.\n"
            "  4. **Closed-Loop Detection Self-Tuning**: Whenever the Verdict is `False Positive (FP)` OR a recurring `Benign Positive (BTP)` (`Rule Logic / Threshold Too Broad`, `Log Parser / Telemetry Artifact`, `Authorized Security Testing / Red Team / BAS`, or `Authorized Admin / Business Activity`), call `tune_case_detections(case_id=..., lookback_days=14, ttl_days=30, apply_tuning=False, record_to_data_table=True, post_wall_comment=True)` to synthesize a compiler-verified multi-factor exclusion proposal, record it to `asoc_detection_tuning` with a 30-day TTL, and post the proposal summary.\n"
            "- **Stage 5 (Structured BLUF Case Wall Report)**:\n"
            "  Call `add_soar_case_comment(case_id=..., comment=...)` for each triaged case (and also return the report in your final response) starting with the top-level heading and mandatory blockquote line:\n"
            "  `### 🛡️ Tier 1 Autonomous Triage Report (T+10m Scheduled Sweep)`\n"
            "  `> **Verdict:** <Level 1> | **Disposition:** <Level 2> | **Confidence:** <Level 3>`\n"
            "  followed by:\n"
            "  1. **Executive Summary (BLUF)**\n"
            "  2. **Silent Detection & T+10m Delta Correlation Summary** (highlighting `prior_detections_count` -> current detections, `delta_detections_count`, and any newly attached delta entities)\n"
            "  3. **Key Evidence & PipedSQL Telemetry Table**\n"
            "  4. **Automated SOAR Actions Taken** (Alert Status, Priority, Case Stage, Incident Flag, Attached Case Tags)\n"
            "  5. **Recommended Course of Action (COA)** aligned with `soc_triage_sop_matrix`."
        )

        # 4. Determine Target Cases if Sweeping Recent Open Cases
        target_cases_to_process = list(explicit_case_ids)
        processed_case_ids = [] if force_recheck else _load_processed_case_ids(siemplify)
        newly_processed_case_ids = []

        if not target_cases_to_process and sweep_open_cases and "list_soar_cases" in tool_map:
            siemplify.LOGGER.info(
                f"Sweeping recent open SOAR cases (lookback={lookback_minutes}m, min_age={min_case_age_minutes}m, max_cases={max_cases}, priorities='{priority_filter_raw}')..."
            )
            cases_resp = tool_map["list_soar_cases"](
                status="OPENED",
                priorities=priority_filter_raw or None,
                limit=max(50, max_cases * 4),
            )
            raw_cases = cases_resp.get("cases", []) if isinstance(cases_resp, dict) else []
            now_utc = datetime.now(timezone.utc)
            cutoff = (
                now_utc - timedelta(minutes=lookback_minutes)
                if lookback_minutes > 0
                else None
            )
            maturity_cutoff = (
                now_utc - timedelta(minutes=min_case_age_minutes)
                if min_case_age_minutes > 0
                else None
            )
            maturing_skipped = []
            already_triaged_skipped = []
            for c in raw_cases:
                if not isinstance(c, dict):
                    continue
                cid = str(c.get("id") or c.get("case_id") or "").strip()
                if not cid or cid in processed_case_ids:
                    continue
                ctime = _parse_iso_timestamp(c.get("create_time") or c.get("createTime") or "")
                if cutoff is not None and ctime is not None and ctime < cutoff:
                    continue
                if maturity_cutoff is not None and ctime is not None and ctime > maturity_cutoff:
                    maturing_skipped.append(cid)
                    continue
                case_tags = [
                    str(t).strip()
                    for t in (c.get("tags") or [])
                    if str(t).strip()
                ]
                if not case_tags and not force_recheck and hasattr(manager, "secops_engine") and manager.secops_engine:
                    try:
                        full_case = manager.secops_engine.get_case(cid)
                        case_tags = [
                            str(t).strip()
                            for t in (getattr(full_case, "tags", None) or (full_case if isinstance(full_case, dict) else {}).get("tags") or [])
                            if str(t).strip()
                        ]
                    except Exception:
                        pass
                if not force_recheck and "Tier1:Triaged" in case_tags:
                    already_triaged_skipped.append(cid)
                    continue
                target_cases_to_process.append(cid)
                if len(target_cases_to_process) >= max_cases:
                    break
            if already_triaged_skipped:
                siemplify.LOGGER.info(
                    f"Skipped {len(already_triaged_skipped)} open case(s) that already carry 'Tier1:Triaged' tag: {already_triaged_skipped}"
                )
            if maturing_skipped:
                siemplify.LOGGER.info(
                    f"Deferred {len(maturing_skipped)} open case(s) still within the T+{min_case_age_minutes}m maturity window: {maturing_skipped}"
                )
            siemplify.LOGGER.info(
                f"Discovered {len(target_cases_to_process)} mature open case(s) to process: {target_cases_to_process}"
            )

        # 5. Execute ADK Agent
        if sweep_open_cases and not explicit_case_ids and not target_cases_to_process:
            siemplify.LOGGER.info(
                "No new unprocessed open cases matched the sweep criteria in this window. Skipping agent invocation."
            )
        else:
            effective_prompt = str(user_prompt).strip()
            if target_cases_to_process:
                effective_prompt += (
                    f"\n\n### Target SOAR Case IDs for this Run ###\n"
                    f"Focus your investigation and tool calls on SOAR Case ID(s): {', '.join(target_cases_to_process)}."
                )

            results = manager.run_agent(
                agent_name=agent_name,
                instructions=base_instructions,
                input_text=effective_prompt,
                tools=agent_tools,
                thinking_budget=thinking_budget,
                session_id=session_id,
                memory_service=memory_service,
                enable_code_execution=enable_code_exec,
                enable_google_search=enable_search,
            )

            final_response = results.get("final_response", "")
            thoughts = results.get("thoughts", [])
            for t in thoughts:
                siemplify.LOGGER.info(f"[ADK Thought] {t}")
            siemplify.LOGGER.info(
                f"ADK Agent '{agent_name}' Final Report ({len(final_response)} chars):\n{final_response[:4000]}"
            )

            # 6. Optionally Post Report to Target Case Wall(s) (with deduplication if agent already posted in Stage 5)
            if post_to_wall and target_cases_to_process and final_response and "add_soar_case_comment" in tool_map:
                executed_tools = [
                    str(t).strip()
                    for t in results.get("thoughts", [])
                    if "add_soar_case_comment" in str(t)
                ]
                if "### 🛡️ Tier 1 Autonomous Triage Report" in final_response:
                    comment_body = final_response.strip()
                else:
                    comment_body = (
                        f"### 🛡️ Tier 1 Autonomous Triage Report (T+10m Scheduled Sweep)\n\n"
                        f"{final_response.strip()}"
                    )
                for cid in target_cases_to_process:
                    already_posted = bool(executed_tools)
                    if not already_posted and "list_soar_case_comments" in tool_map:
                        try:
                            existing_comments = tool_map["list_soar_case_comments"](case_id=str(cid), limit=5)
                            for cm in (existing_comments.get("comments", []) if isinstance(existing_comments, dict) else []):
                                cm_text = str(cm.get("comment") or "")
                                if "Tier 1 Autonomous Triage Report (T+10m Scheduled Sweep)" in cm_text:
                                    already_posted = True
                                    break
                        except Exception:
                            pass
                    if already_posted:
                        siemplify.LOGGER.info(
                            f"Agent already posted structured Stage 5 BLUF report to Case #{cid} Wall during tool execution; skipping duplicate post."
                        )
                        continue
                    res_comment = tool_map["add_soar_case_comment"](
                        case_id=str(cid),
                        comment=comment_body,
                    )
                    siemplify.LOGGER.info(f"Posted ADK Job report to Case #{cid} Wall: {res_comment}")

            if len(target_cases_to_process) == 1 and isinstance(results, dict) and final_response:
                single_cid = str(target_cases_to_process[0]).strip()
                try:
                    if hasattr(siemplify, "set_context_property"):
                        siemplify.set_context_property(
                            1,
                            single_cid,
                            "ADK_AGENT_CACHED_RESULT",
                            json.dumps({"timestamp": time.time(), "results": results}),
                        )
                except Exception:
                    pass

            if sweep_open_cases and target_cases_to_process:
                newly_processed_case_ids.extend(target_cases_to_process)
                _save_processed_case_ids(siemplify, processed_case_ids + newly_processed_case_ids)

    except Exception as e:
        siemplify.LOGGER.error(f"Error during {JOB_NAME}: {e}")
        raise

    siemplify.LOGGER.info("================= Run ADK Autonomous Agent Job Ended =================")


if __name__ == "__main__":
    main()
