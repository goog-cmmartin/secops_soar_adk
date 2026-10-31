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
    "Inspect recent open SOAR cases, correlate any unattached silent detections, "
    "check Data Tables and Native Dashboards for key findings, and produce a concise "
    "Markdown operational summary."
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
            or "sdl-preview-americas"
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
            or "a556547c-1cff-43ef-a2e4-cf5b12a865df"
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
            "You are an Autonomous Senior SecOps & SOAR Engineering Agent powered by Google ADK.\n"
            "You are executing inside a scheduled or on-demand Google SecOps SOAR Job with direct tool access to:\n"
            "- SOAR Case & Alert Management (`list_soar_cases`, `investigate_soar_case`, `add_soar_case_comment`, `list_soar_case_comments`, `update_soar_case`)\n"
            "- Silent Detection Correlation & UDM/Entity Hunting (`correlate_silent_detections`, `search_udm_events`, `aggregate_udm_events`, `investigate_entity`)\n"
            "- YARA-L 2.0 Detection Rules & Tuning (`get_detection_rule`, `list_detection_rules`, `find_top_noisy_rules`)\n"
            "- Chronicle Data Tables (`list_data_tables`, `get_data_table`, `create_data_table`, `list_data_table_rows`, `add_data_table_rows`, `delete_data_table_row`, `audit_data_table_health`)\n"
            "- Chronicle Native Dashboards (`search_dashboards`, `get_dashboard`, `execute_dashboard_query`, `create_dashboard`, `update_dashboard`, `add_dashboard_chart`, `update_dashboard_chart`, `remove_dashboard_chart`, `audit_dashboard_health`, `sync_secops_homepage_dashboard`)\n"
            "- SOAR Playbooks (`search_playbooks`, `get_playbook`, `audit_playbook_health`, `audit_playbook_decay`)\n\n"
            "Execute the user's mission systematically using the available tools, verify every finding with real telemetry, "
            "and synthesize a well-structured, actionable Markdown report."
        )

        # 4. Determine Target Cases if Sweeping Recent Open Cases
        target_cases_to_process = list(explicit_case_ids)
        processed_case_ids = [] if force_recheck else _load_processed_case_ids(siemplify)
        newly_processed_case_ids = []

        if not target_cases_to_process and sweep_open_cases and "list_soar_cases" in tool_map:
            siemplify.LOGGER.info(
                f"Sweeping recent open SOAR cases (lookback={lookback_minutes}m, max_cases={max_cases}, priorities='{priority_filter_raw}')..."
            )
            cases_resp = tool_map["list_soar_cases"](
                status="OPENED",
                priorities=priority_filter_raw or None,
                limit=max(50, max_cases * 3),
            )
            raw_cases = cases_resp.get("cases", []) if isinstance(cases_resp, dict) else []
            cutoff = (
                datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
                if lookback_minutes > 0
                else None
            )
            for c in raw_cases:
                if not isinstance(c, dict):
                    continue
                cid = str(c.get("id") or c.get("case_id") or "").strip()
                if not cid or cid in processed_case_ids:
                    continue
                if cutoff is not None:
                    ctime = _parse_iso_timestamp(c.get("create_time") or c.get("createTime") or "")
                    if ctime is not None and ctime < cutoff:
                        continue
                target_cases_to_process.append(cid)
                if len(target_cases_to_process) >= max_cases:
                    break
            siemplify.LOGGER.info(
                f"Discovered {len(target_cases_to_process)} candidate open case(s) to process: {target_cases_to_process}"
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

            # 6. Optionally Post Report to Target Case Wall(s)
            if post_to_wall and target_cases_to_process and final_response and "add_soar_case_comment" in tool_map:
                comment_body = (
                    f"### 🤖 Autonomous Google ADK Job Report (`{agent_name}`)\n\n"
                    f"{final_response}"
                )
                for cid in target_cases_to_process:
                    res_comment = tool_map["add_soar_case_comment"](
                        case_id=str(cid),
                        comment=comment_body,
                    )
                    siemplify.LOGGER.info(f"Posted ADK Job report to Case #{cid} Wall: {res_comment}")

            if sweep_open_cases and target_cases_to_process:
                newly_processed_case_ids.extend(target_cases_to_process)
                _save_processed_case_ids(siemplify, processed_case_ids + newly_processed_case_ids)

    except Exception as e:
        siemplify.LOGGER.error(f"Error during {JOB_NAME}: {e}")
        raise

    siemplify.LOGGER.info("================= Run ADK Autonomous Agent Job Ended =================")


if __name__ == "__main__":
    main()
