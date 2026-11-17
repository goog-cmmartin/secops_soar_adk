"""
Auto Group Cases by Entity Job for GoogleADK in Google SecOps SOAR.

Scans open SOAR cases within a configurable lookback and grouping timeframe (default 24h),
scoped by SOAR Environment (default 'Default Environment'), extracts high-signal alert
entities (HOSTNAME, IP, non-generic USER, non-generic FILEHASH), enforces multi-host magnet
guardrails, and either outputs a Dry-Run merge plan or executes native SOAR case merges
(POST /v1beta/{parent}/cases:merge) with optional ADK Agent correlation commentary.
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

JOB_NAME = "Auto Group Cases by Entity Job"
INTEGRATION_NAME = "GoogleADK"
PROFILE_CACHE_CONTEXT_KEY = "auto_group_cases_profile_cache_v1"
MAX_CACHED_PROFILES = 200


def _load_profile_cache(siemplify: SiemplifyJob) -> dict:
    try:
        raw = siemplify.get_scoped_job_context_property(PROFILE_CACHE_CONTEXT_KEY)
        if not raw:
            return {}
        parsed = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(parsed, dict):
            return parsed
    except Exception as exc:
        siemplify.LOGGER.info(f"Job context profile cache read notice (non-fatal): {exc}")
    return {}


def _save_profile_cache(siemplify: SiemplifyJob, cache: dict) -> None:
    try:
        if not isinstance(cache, dict):
            return
        # Retain up to MAX_CACHED_PROFILES newest entries
        items = list(cache.items())
        if len(items) > MAX_CACHED_PROFILES:
            items = items[-MAX_CACHED_PROFILES:]
        trimmed = dict(items)
        siemplify.set_scoped_job_context_property(
            PROFILE_CACHE_CONTEXT_KEY, json.dumps(trimmed)
        )
    except Exception as exc:
        siemplify.LOGGER.info(f"Job context profile cache write notice (non-fatal): {exc}")


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
        skills_gcs_path = _safe_extract_config(siemplify, "Skills GCS Path")

        # 2. Extract Job Parameters
        env_filter_raw = siemplify.extract_job_param(
            param_name="Environment Filter",
            default_value="Default Environment",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        environments = (
            [e.strip() for e in str(env_filter_raw).split(",") if e.strip()]
            if env_filter_raw and str(env_filter_raw).strip()
            else None
        )

        dry_run = _parse_bool(
            siemplify.extract_job_param(
                param_name="Dry Run",
                default_value="true",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=True,
        )

        lookback_hours = max(
            1,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Lookback Hours",
                    default_value="24",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=24,
            ),
        )

        grouping_window_hours = max(
            1,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Grouping Window Hours",
                    default_value="24",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=24,
            ),
        )

        min_shared_entities = max(
            1,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Min Shared High-Signal Entities",
                    default_value="1",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=1,
            ),
        )

        max_distinct_hosts = max(
            1,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Max Distinct Hosts Per Case",
                    default_value="1",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=1,
            ),
        )

        min_case_age_minutes = max(
            0,
            _parse_int(
                siemplify.extract_job_param(
                    param_name="Min Case Age Minutes",
                    default_value="5",
                    input_type=str,
                    is_mandatory=False,
                    print_value=True,
                ),
                default=5,
            ),
        )

        max_cases = max(
            1,
            min(
                500,
                _parse_int(
                    siemplify.extract_job_param(
                        param_name="Max Cases Per Run",
                        default_value="100",
                        input_type=str,
                        is_mandatory=False,
                        print_value=True,
                    ),
                    default=100,
                ),
            ),
        )

        include_enriched_entities = _parse_bool(
            siemplify.extract_job_param(
                param_name="Include Enriched Entities",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        post_wall_comment = _parse_bool(
            siemplify.extract_job_param(
                param_name="Post Merge Summary to Target Case Wall",
                default_value="true",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=True,
        )

        trigger_correlation_tag = _parse_bool(
            siemplify.extract_job_param(
                param_name="Trigger Case Correlation Tag After Merge",
                default_value="true",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=True,
        )

        generate_ai_narrative = _parse_bool(
            siemplify.extract_job_param(
                param_name="Generate AI Merge Narrative via ADK Agent",
                default_value="false",
                input_type=str,
                is_mandatory=False,
                print_value=True,
            ),
            default=False,
        )

        target_case_ids_raw = siemplify.extract_job_param(
            param_name="Target Case IDs",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        target_case_ids = (
            [t.strip() for t in str(target_case_ids_raw).split(",") if t.strip()]
            if target_case_ids_raw and str(target_case_ids_raw).strip()
            else None
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
        if "group_cases_by_entity" not in tool_map:
            raise RuntimeError("group_cases_by_entity tool is not registered in GoogleADKManager.")

        mode_banner = "DRY RUN" if dry_run else "LIVE MERGE"
        profile_cache = _load_profile_cache(siemplify)
        cache_before = len(profile_cache)
        siemplify.LOGGER.info(
            f"[{mode_banner}] Running High-Signal Case Grouping for environments={environments or 'ALL'}, "
            f"lookback_hours={lookback_hours}, grouping_window_hours={grouping_window_hours}, "
            f"min_shared_entities={min_shared_entities}, max_distinct_hosts_per_case={max_distinct_hosts} "
            f"(cached_profiles={cache_before})..."
        )

        from dataclasses import asdict

        wf_res = manager.secops_engine.group_cases_by_entity(
            environments=environments,
            lookback_hours=lookback_hours,
            grouping_window_hours=grouping_window_hours,
            min_shared_entities=min_shared_entities,
            max_cases=max_cases,
            max_distinct_hosts_per_case=max_distinct_hosts,
            min_case_age_minutes=min_case_age_minutes,
            include_enriched_entities=include_enriched_entities,
            dry_run=dry_run,
            post_wall_comment=post_wall_comment,
            trigger_correlation_tag=trigger_correlation_tag,
            target_case_ids=target_case_ids,
            profile_cache=profile_cache,
        )
        _save_profile_cache(siemplify, profile_cache)
        result = asdict(wf_res) if hasattr(wf_res, "__dataclass_fields__") else (wf_res if isinstance(wf_res, dict) else {})

        clusters = result.get("merge_clusters", [])
        skipped_magnets = result.get("skipped_multi_host_cases", [])
        skipped_settling = result.get("skipped_settling_cases", [])
        siemplify.LOGGER.info(
            f"[{mode_banner}] Scanned {result.get('scanned_cases_count', 0)} cases "
            f"({result.get('eligible_cases_count', 0)} eligible, {len(skipped_magnets)} multi-host magnets skipped, "
            f"{len(skipped_settling)} settling/in-flight cases deferred). "
            f"Found {len(clusters)} merge cluster(s) from {result.get('overlap_pairs_count', 0)} overlapping pair(s)."
        )

        for idx, cl in enumerate(clusters, 1):
            src_ids = cl.get("source_case_ids", [])
            siemplify.LOGGER.info(
                f"  Cluster #{idx}: Target Case #{cl.get('target_case_id')} ('{cl.get('target_case_title')}') "
                f"<-- Merge Source Cases {src_ids} | Shared Entities: {json.dumps(cl.get('shared_entities', {}))}"
            )

        for mh in skipped_magnets:
            siemplify.LOGGER.info(
                f"  Skipped Multi-Host Magnet Case #{mh.get('case_id')} ('{mh.get('display_name')}'): "
                f"{mh.get('distinct_hostnames_count')} distinct hosts {mh.get('hostnames')}"
            )

        # 4. Optional ADK Agent Merge Narrative
        if generate_ai_narrative and clusters:
            try:
                prompt = (
                    "You are a Senior Google SecOps Detection & Correlation Architect.\n"
                    "Review the following High-Signal Entity Case Grouping Clusters discovered in "
                    f"SOAR ({mode_banner} mode) and write a concise 1-paragraph correlation summary for each cluster "
                    "explaining how the alerts connect across the attack lifecycle:\n\n"
                    f"```json\n{json.dumps(clusters, indent=2)}\n```"
                )
                agent_res = manager.run_agent(
                    prompt=prompt,
                    agent_name="Case_Grouping_Correlation_Agent",
                    custom_tools=[],
                    thinking_budget=0,
                )
                ai_text = str(agent_res.get("response") or "").strip()
                if ai_text:
                    siemplify.LOGGER.info(f"ADK Agent Correlation Narrative:\n{ai_text}")
            except Exception as ai_exc:
                siemplify.LOGGER.info(f"Optional ADK narrative skipped: {ai_exc}")

        siemplify.LOGGER.info(f"\n{result.get('summary_markdown', '')}")

    except Exception as e:
        siemplify.LOGGER.error(f"Error during {JOB_NAME}: {e}")
        raise

    siemplify.LOGGER.info(f"================= {JOB_NAME} Completed =================")


if __name__ == "__main__":
    main()
