"""
Pre-Warm Case Triage Summaries Job for SecOpsSDKEngine in Google SecOps SOAR.

Polls for newly created open SOAR cases on a recurring schedule and initiates
the Gemini AI Case Triage Summary (:getOrCreateCaseSummary) in advance so that
the summary is already generated and cached when an analyst opens the Case in the GUI.
"""

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
    from SecOpsSDKEngineManager import SecOpsSDKEngineManager
except ImportError:
    from core.SecOpsSDKEngineManager import SecOpsSDKEngineManager

JOB_NAME = "Pre-Warm Case Triage Summaries Job"
INTEGRATION_NAME = "SecOpsSDKEngine"
PROCESSED_CASES_CONTEXT_KEY = "prewarmed_case_ids_v1"
MAX_STORED_CASE_IDS = 500


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


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = JOB_NAME
    siemplify.LOGGER.info("================= Pre-Warm Case Triage Summaries Job Started =================")

    try:
        # 1. Extract Job Parameters
        lookback_raw = siemplify.extract_job_param(
            param_name="Lookback Minutes",
            default_value="60",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        lookback_minutes = max(0, _parse_int(lookback_raw, default=60))

        max_cases_raw = siemplify.extract_job_param(
            param_name="Max Cases Per Run",
            default_value="25",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        max_cases = max(1, min(200, _parse_int(max_cases_raw, default=25)))

        priority_filter_raw = siemplify.extract_job_param(
            param_name="Priority Filter",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        priorities = (
            [p.strip().upper() for p in str(priority_filter_raw).split(",") if p.strip()]
            if priority_filter_raw and str(priority_filter_raw).strip()
            else None
        )

        env_filter_raw = siemplify.extract_job_param(
            param_name="Environment Filter",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        environments = (
            [e.strip() for e in str(env_filter_raw).split(",") if e.strip()]
            if env_filter_raw and str(env_filter_raw).strip()
            else None
        )

        prewarm_alerts_raw = siemplify.extract_job_param(
            param_name="Pre-Warm Alert Recommendations",
            default_value="false",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        include_alert_recommendations = _parse_bool(prewarm_alerts_raw, default=False)

        force_recheck_raw = siemplify.extract_job_param(
            param_name="Force Re-Check Processed Cases",
            default_value="false",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        force_recheck = _parse_bool(force_recheck_raw, default=False)

        job_customer_id = siemplify.extract_job_param(
            param_name="SecOps Customer ID",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        job_project_id = siemplify.extract_job_param(
            param_name="GCP Project ID",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        job_wif_email = siemplify.extract_job_param(
            param_name="Workload Identity Email",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )

        # 2. Extract Integration Configuration Parameters (with fallbacks)
        customer_id = (
            str(job_customer_id).strip()
            or _safe_extract_config(siemplify, "SecOps Customer ID")
            or os.environ.get("SECOPS_CUSTOMER_ID")
            or "a556547c-1cff-43ef-a2e4-cf5b12a865df"
        )
        project_id = (
            str(job_project_id).strip()
            or _safe_extract_config(siemplify, "GCP Project ID")
            or os.environ.get("GCP_PROJECT_ID")
            or "sdl-preview-americas"
        )
        region = _safe_extract_config(siemplify, "SecOps Region", default_value="us") or "us"
        sa_json = _safe_extract_config(siemplify, "Service Account JSON")
        workload_identity_email = (
            str(job_wif_email).strip()
            or _safe_extract_config(siemplify, "Workload Identity Email")
        )
        verify_ssl = _parse_bool(
            _safe_extract_config(siemplify, "Verify SSL", default_value="true"),
            default=True,
        )

        # 3. Load Processed Case IDs from Job Context
        processed_case_ids = [] if force_recheck else _load_processed_case_ids(siemplify)

        # 4. Initialize Manager & Pre-Warm Case Summaries
        manager = SecOpsSDKEngineManager(
            customer_id=customer_id,
            project_id=project_id,
            region=region,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER,
        )

        summary = manager.prewarm_case_summaries(
            lookback_minutes=lookback_minutes,
            max_cases=max_cases,
            priorities=priorities,
            environments=environments,
            include_alert_recommendations=include_alert_recommendations,
            processed_case_ids=processed_case_ids,
        )

        # 5. Persist updated processed Case IDs
        newly_processed = summary.get("newly_processed_case_ids", [])
        if newly_processed:
            _save_processed_case_ids(siemplify, processed_case_ids + newly_processed)

        siemplify.LOGGER.info(
            f"Pre-Warm Summary Complete: evaluated={summary.get('candidates_evaluated', 0)}, "
            f"initiated_in_progress={summary.get('initiated_in_progress_count', 0)}, "
            f"already_cached={summary.get('already_cached_count', 0)}, "
            f"alert_recommendations_triggered={summary.get('alert_recommendations_triggered', 0)}, "
            f"errors={summary.get('error_count', 0)}."
        )
        for c in summary.get("cases", []):
            siemplify.LOGGER.info(
                f"  - Case #{c.get('case_id')} ({c.get('priority')} | '{c.get('display_name')}'): "
                f"state={c.get('summary_state')}"
                + (f", error={c.get('error')}" if c.get("error") else "")
            )

    except Exception as e:
        siemplify.LOGGER.error(f"Error during Pre-Warm Case Triage Summaries Job: {e}")
        raise

    siemplify.LOGGER.info("================= Pre-Warm Case Triage Summaries Job Ended =================")


if __name__ == "__main__":
    main()
