import os
import sys
import unicodedata

# Ensure core directory is on sys.path for SOAR runtime
_current_dir = os.path.dirname(os.path.abspath(__file__))
_core_dir = os.path.join(os.path.dirname(_current_dir), "core")
for _p in [_core_dir, _current_dir]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler
from SecOpsSDKEngineManager import SecOpsSDKEngineManager

INTEGRATION_NAME = "SecOpsSDKEngine"
SCRIPT_NAME = "Sync Detection Tuning Dashboard Job"


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


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(f"================= {SCRIPT_NAME} Started =================")

    try:
        customer_id = (
            siemplify.extract_job_param("Customer ID", default_value="")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Customer ID", default_value="")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "Customer ID", default_value="")
        )
        project_id = (
            siemplify.extract_job_param("GCP Project ID", default_value="")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID", default_value="")
        )
        region = (
            siemplify.extract_job_param("Region", default_value="")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region", default_value="")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "Region", default_value="us")
            or "us"
        )
        sa_json = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Service Account JSON", default_value="", print_value=False
        )
        workload_identity_email = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Workload Identity Email", default_value="", print_value=True
        )

        dashboard_title = siemplify.extract_job_param(
            "Dashboard Title",
            default_value="Detection Tuning & FP Reduction Command Center",
            print_value=True,
        )
        dashboard_id = siemplify.extract_job_param(
            "Dashboard ID", default_value="", print_value=True
        )
        lookback_days = _parse_int(
            siemplify.extract_job_param("Lookback Days", default_value="7", print_value=True),
            default=7,
        )
        ttl_days = _parse_int(
            siemplify.extract_job_param("TTL Days", default_value="30", print_value=True),
            default=30,
        )
        sweep_fp_cases = _parse_bool(
            siemplify.extract_job_param("Sweep FP Cases", default_value="true", print_value=True),
            default=True,
        )
        auto_apply_approved = _parse_bool(
            siemplify.extract_job_param("Auto Apply Approved Cases", default_value="false", print_value=True),
            default=False,
        )

        manager = SecOpsSDKEngineManager(
            customer_id=customer_id,
            project_id=project_id,
            region=region,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            logger=siemplify.LOGGER,
        )

        # 1. Sweep recent FP / Tune:Candidate / Tune:Approve cases if enabled
        swept_cases = []
        if sweep_fp_cases:
            try:
                cases_res = manager.adapter.list_cases(page_size=30)
                raw_cases = getattr(cases_res, "cases", None) or (
                    cases_res.get("cases") if isinstance(cases_res, dict) else []
                )
                for c in raw_cases[:25]:
                    raw = getattr(c, "raw", c) if not isinstance(c, dict) else c
                    cid = str(raw.get("name", "")).split("/")[-1]
                    if not cid:
                        continue
                    try:
                        c_detail = manager.adapter.get_case(cid, expand="tags")
                        c_tags = [
                            str(t.get("displayName") or t.get("tag") if isinstance(t, dict) else t).strip()
                            for t in (c_detail.get("tags") or [])
                        ]
                        needs_proposal = (
                            any(t in c_tags for t in ("Verdict:FP", "Tune:Candidate", "Disp:BenignAdmin", "Disp:BenignActivity"))
                            and "Tune:Proposed" not in c_tags
                            and "Tune:Applied" not in c_tags
                        )
                        needs_approval = "Tune:Approve" in c_tags and "Tune:Applied" not in c_tags
                        if needs_proposal or needs_approval:
                            res = manager.tune_case_detections(
                                case_id=cid,
                                lookback_days=max(7, lookback_days),
                                apply_tuning=bool(needs_approval and auto_apply_approved),
                                ttl_days=ttl_days,
                                record_to_data_table=True,
                                post_wall_comment=True,
                            )
                            swept_cases.append({"case_id": cid, "proposals": res.get("proposals_generated_count", 0)})
                    except Exception as ce:
                        siemplify.LOGGER.info(f"Case #{cid} tuning check skipped: {ce}")
            except Exception as sweep_err:
                siemplify.LOGGER.warning(f"FP Case sweep warning: {sweep_err}")

        # 2. Also ensure fleet-wide top noisy rules have proposals recorded in asoc_detection_tuning
        fleet_res = manager.tune_case_detections(
            case_id=None,
            rule_id=None,
            lookback_days=max(7, lookback_days),
            apply_tuning=False,
            ttl_days=ttl_days,
            record_to_data_table=True,
            post_wall_comment=False,
        )

        # 3. Sync the Native SecOps Dashboard
        dash_res = manager.sync_detection_tuning_dashboard(
            dashboard_title=str(dashboard_title or "Detection Tuning & FP Reduction Command Center").strip(),
            dashboard_id=str(dashboard_id).strip() if dashboard_id else None,
            lookback_days=lookback_days,
        )

        siemplify.LOGGER.info(
            f"Synced '{dash_res.get('dashboard_title')}' (ID: {dash_res.get('dashboard_id')}): "
            f"swept {len(swept_cases)} FP case(s), audited {fleet_res.get('rules_analyzed_count', 0)} fleet noisy rule(s), "
            f"and rendered {len(dash_res.get('tiles') or [])} Native Dashboard tiles."
        )

    except Exception as e:
        normalized = unicodedata.normalize("NFKD", str(e))
        clean_msg = normalized.encode("ascii", "ignore").decode("ascii")
        siemplify.LOGGER.error(f"Error in {SCRIPT_NAME}: {clean_msg}")

    siemplify.LOGGER.info(f"================= {SCRIPT_NAME} Completed =================")
    siemplify.end_script()


if __name__ == "__main__":
    main()
