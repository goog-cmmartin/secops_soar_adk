"""
Sync SecOps Homepage Dashboard Job for GoogleADK in Google SecOps SOAR.

Executes on a recurring schedule (default: every 1 hour / 3600s) or on-demand to synchronize
the 'Google SecOps Homepage' Native Dashboard with:
  1. Google Cloud Security Status (status.cloud.google.com/security)
  2. Google SecOps Release Notes Atom Feed
  3. Google Cloud Security Community RSS Feed
  4. Live Tenant Health & Operations Pulse (24h UDM volume, active log sources, 7d detections,
     open SOAR cases by priority, custom YARA-L rule posture, top noisy rules, feeds, and data tables)
  5. AI Executive Summary & Actionable Advisories (synthesized by the Google ADK Gemini Agent
     with automatic deterministic fallback)
  6. Three Native Live Telemetry KPI Counter Cards (24h UDM Events, Active Log Sources, 7d Detections)
"""

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
    from GoogleADKManager import GoogleADKManager
except ImportError:
    from core.GoogleADKManager import GoogleADKManager

JOB_NAME = "Sync SecOps Homepage Dashboard Job"
INTEGRATION_NAME = "GoogleADK"
DEFAULT_DASHBOARD_NAME = "Google SecOps Homepage"
DEFAULT_DASHBOARD_ID = "e99fee21-4f9b-4b6f-848d-4ba0a28be1c0"
DEFAULT_COMMUNITY_FILTERS = "community-blog-42,news-announcements-9"


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


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = JOB_NAME
    siemplify.LOGGER.info(f"================= {JOB_NAME} Started =================")

    try:
        # 1. Extract Integration Configuration Parameters
        api_key = _safe_extract_config(siemplify, "Gemini API Key")
        sa_json = _safe_extract_config(siemplify, "Service Account JSON")
        workload_identity_email = _safe_extract_config(siemplify, "Workload Identity Email")
        model_name = (
            _safe_extract_config(siemplify, "Model Name", default_value="gemini-3.8-flash")
            or "gemini-3.8-flash"
        )
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
        skills_gcs_path = _safe_extract_config(siemplify, "Skills GCS Path")

        # 2. Extract Job Parameters
        dashboard_name = (
            siemplify.extract_job_param(
                param_name="Dashboard Name",
                default_value=DEFAULT_DASHBOARD_NAME,
                input_type=str,
                is_mandatory=False,
                print_value=True,
            )
            or DEFAULT_DASHBOARD_NAME
        ).strip()

        dashboard_id = (
            siemplify.extract_job_param(
                param_name="Dashboard ID",
                default_value=DEFAULT_DASHBOARD_ID,
                input_type=str,
                is_mandatory=False,
                print_value=True,
            )
            or ""
        ).strip()

        status_lookback_days = max(
            1,
            min(
                365,
                _parse_int(
                    siemplify.extract_job_param(
                        param_name="Status Lookback Days",
                        default_value="30",
                        input_type=str,
                        is_mandatory=False,
                        print_value=True,
                    ),
                    default=30,
                ),
            ),
        )

        max_release_notes = max(
            1,
            min(
                10,
                _parse_int(
                    siemplify.extract_job_param(
                        param_name="Max Release Notes",
                        default_value="4",
                        input_type=str,
                        is_mandatory=False,
                        print_value=True,
                    ),
                    default=4,
                ),
            ),
        )

        max_community_posts = max(
            1,
            min(
                15,
                _parse_int(
                    siemplify.extract_job_param(
                        param_name="Max Community Posts",
                        default_value="6",
                        input_type=str,
                        is_mandatory=False,
                        print_value=True,
                    ),
                    default=6,
                ),
            ),
        )

        community_categories = (
            siemplify.extract_job_param(
                param_name="Community Category Filters",
                default_value=DEFAULT_COMMUNITY_FILTERS,
                input_type=str,
                is_mandatory=False,
                print_value=True,
            )
            or DEFAULT_COMMUNITY_FILTERS
        ).strip()

        include_tenant_health = _parse_bool(
            siemplify.extract_job_param(
                param_name="Include Live Tenant Health",
                default_value="true",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=True,
        )

        generate_ai_summary = _parse_bool(
            siemplify.extract_job_param(
                param_name="Generate AI Executive Summary via ADK Agent",
                default_value="true",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=True,
        )

        # 3. Initialize GoogleADKManager & SecOps SDK Engine Toolset
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

        secops_tools = manager.init_secops_engine_toolset(
            customer_id=cust_id,
            project_id=proj_id,
            region=region,
        )
        tool_map = {t.__name__: t for t in secops_tools}
        if "sync_secops_homepage_dashboard" not in tool_map:
            raise RuntimeError("sync_secops_homepage_dashboard tool is not registered in GoogleADKManager.")

        # 4. Execute Initial Sync (fetches live external feeds + tenant health and updates dashboard)
        community_categories_list = [
            c.strip() for c in str(community_categories).split(",") if c.strip()
        ] or ["community-blog-42", "news-announcements-9"]

        siemplify.LOGGER.info(
            f"Synchronizing Native Dashboard '{dashboard_name}' (id={dashboard_id or 'auto'}) "
            f"with community_categories={community_categories_list}, include_tenant_health={include_tenant_health}..."
        )
        sync_result = tool_map["sync_secops_homepage_dashboard"](
            dashboard_name=dashboard_name,
            dashboard_id=dashboard_id or None,
            community_categories=community_categories_list,
            status_lookback_days=status_lookback_days,
            max_release_notes=max_release_notes,
            max_community_posts=max_community_posts,
            include_tenant_health=include_tenant_health,
            ai_executive_summary=None,
        )
        if isinstance(sync_result, dict) and sync_result.get("error"):
            raise RuntimeError(f"Dashboard sync returned error: {sync_result['error']}")

        resolved_dash_id = sync_result.get("dashboard_id") or dashboard_id
        feeds_summary = sync_result.get("feeds_summary", {})
        tenant_summary = sync_result.get("tenant_health_summary", {})

        # 5. Optionally enrich the AI Executive Summary tile with Gemini ADK Agent commentary
        if generate_ai_summary:
            try:
                prompt = (
                    "Synthesize a concise, high-signal 2-bullet executive operational commentary "
                    "(maximum 350 characters total, plain Markdown bullets starting with `- `) "
                    "correlating the following live Google SecOps tenant telemetry and external feeds:\n"
                    f"- Feeds Summary: {json.dumps(feeds_summary)}\n"
                    f"- Tenant Health Summary: {json.dumps(tenant_summary)}\n"
                    "Focus on actionable SOC priorities (critical/high open cases, detection posture, "
                    "and relevant platform updates)."
                )
                adk_res = manager.run_agent(
                    agent_name="SecOps_Homepage_Executive_Briefing_Agent",
                    instructions=(
                        "You are a Principal SecOps Executive Briefing Agent. Output ONLY 2 concise Markdown bullet "
                        "points (under 350 characters total) with bold lead-ins and concrete numbers. Do not include "
                        "headings or preamble."
                    ),
                    input_text=prompt,
                    tools=[],
                    thinking_budget=0,
                )
                ai_commentary = str(adk_res.get("final_response") or "").strip()
                if (
                    ai_commentary
                    and "Error" not in ai_commentary[:40]
                    and len(ai_commentary) <= 1200
                ):
                    siemplify.LOGGER.info(
                        f"Generated ADK AI Executive Commentary ({len(ai_commentary)} chars); updating dashboard tile..."
                    )
                    second_sync = tool_map["sync_secops_homepage_dashboard"](
                        dashboard_name=dashboard_name,
                        dashboard_id=resolved_dash_id,
                        community_categories=community_categories_list,
                        status_lookback_days=status_lookback_days,
                        max_release_notes=max_release_notes,
                        max_community_posts=max_community_posts,
                        include_tenant_health=include_tenant_health,
                        ai_executive_summary=ai_commentary,
                    )
                    if isinstance(second_sync, dict) and not second_sync.get("error"):
                        sync_result = second_sync
            except Exception as adk_exc:
                siemplify.LOGGER.info(
                    f"Using built-in deterministic AI Executive Summary (ADK LLM synthesis skipped: {adk_exc})."
                )

        siemplify.LOGGER.info(
            f"Homepage Dashboard Sync Complete: status={sync_result.get('status')}, "
            f"action={sync_result.get('action')}, dashboard_id={sync_result.get('dashboard_id')}, "
            f"last_synced_utc={sync_result.get('last_synced_utc')}, "
            f"tiles_synced={len(sync_result.get('tiles', []))}."
        )

    except Exception as e:
        siemplify.LOGGER.error(f"Error during {JOB_NAME}: {e}")
        raise

    siemplify.LOGGER.info(f"================= {JOB_NAME} Ended =================")


if __name__ == "__main__":
    main()
