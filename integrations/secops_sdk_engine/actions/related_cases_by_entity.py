import os
import sys
import unicodedata

# Ensure core directory is on sys.path for SOAR runtime
_current_dir = os.path.dirname(os.path.abspath(__file__))
_core_dir = os.path.join(os.path.dirname(_current_dir), "core")
for _p in [_core_dir, _current_dir]:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SecOpsSDKEngineManager import SecOpsSDKEngineManager

INTEGRATION_NAME = "SecOpsSDKEngine"
SCRIPT_NAME = "Related Cases by Entity"


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
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = "Successfully searched related cases by entity."
    result_value = True

    try:
        # 1. Integration configuration parameters
        customer_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "SecOps Customer ID"
        )
        project_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "GCP Project ID"
        )
        region = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "SecOps Region", default_value="us"
        )
        sa_json = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Service Account JSON"
        )
        workload_identity_email = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Workload Identity Email"
        )
        verify_ssl_param = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Verify SSL", default_value="true"
        )
        verify_ssl = _parse_bool(verify_ssl_param, default=True)

        # 2. Action parameters (always use string default_value for Siemplify compatibility)
        case_id = siemplify.extract_action_param("Case ID", default_value="")
        if not case_id or not str(case_id).strip():
            case_id = str(siemplify.case_id) if hasattr(siemplify, "case_id") and siemplify.case_id else ""

        if not case_id:
            raise ValueError("No Case ID provided in action parameters and no active case context found.")

        lookback_days_raw = siemplify.extract_action_param(
            "Lookback Days", default_value="90", print_value=True
        )
        lookback_days = _parse_int(lookback_days_raw, default=90)

        case_status_scope = siemplify.extract_action_param(
            "Case Status Scope", default_value="ALL", print_value=True
        )
        case_status_scope = str(case_status_scope or "ALL").strip().upper()

        min_shared_raw = siemplify.extract_action_param(
            "Min Shared Entities", default_value="1", print_value=True
        )
        min_shared_entities = _parse_int(min_shared_raw, default=1)

        max_related_raw = siemplify.extract_action_param(
            "Max Related Cases", default_value="50", print_value=True
        )
        max_related_cases = _parse_int(max_related_raw, default=50)

        entity_filter_param = siemplify.extract_action_param(
            "Entity Filter", default_value="", print_value=True
        )
        entity_filter = None
        if entity_filter_param and str(entity_filter_param).strip():
            entity_filter = [
                e.strip() for e in str(entity_filter_param).split(",") if e.strip()
            ]

        entity_filter_mode = siemplify.extract_action_param(
            "Entity Filter Mode", default_value="Filter Out (Exclude)", print_value=True
        )
        entity_filter_mode = str(entity_filter_mode or "Filter Out (Exclude)").strip()

        include_threat_actors_raw = siemplify.extract_action_param(
            "Include Threat Actor Entities", default_value="false", print_value=True
        )
        include_threat_actors = _parse_bool(include_threat_actors_raw, default=False)

        post_wall_comment_raw = siemplify.extract_action_param(
            "Post Wall Comment", default_value="false", print_value=True
        )
        post_wall_comment = _parse_bool(post_wall_comment_raw, default=False)

        secops_ui_base_url = siemplify.extract_action_param(
            "SecOps UI Base URL", default_value="", print_value=True
        )
        secops_ui_base_url = str(secops_ui_base_url or "").strip()

        # 3. Initialize Manager & execute workflow
        manager = SecOpsSDKEngineManager(
            customer_id=customer_id,
            project_id=project_id,
            region=region,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER,
        )

        res = manager.related_cases_by_entity(
            case_id=case_id,
            lookback_days=lookback_days,
            case_status_scope=case_status_scope,
            min_shared_entities=min_shared_entities,
            max_related_cases=max_related_cases,
            include_threat_actors=include_threat_actors,
            entity_filter=entity_filter,
            entity_filter_mode=entity_filter_mode,
            post_wall_comment=post_wall_comment,
            secops_ui_base_url=secops_ui_base_url,
        )

        # 4. Build JsonResult payload
        markdown_summary = manager.related_cases_workflow._build_wall_comment(res)
        json_payload = {
            "case_id": res.case_id,
            "case_title": res.case_title,
            "case_status": res.case_status,
            "case_priority": res.case_priority,
            "lookback_days": res.lookback_days,
            "case_status_scope": res.case_status_scope,
            "min_shared_entities": res.min_shared_entities,
            "has_related_cases": res.has_related_cases,
            "total_related_cases": res.total_related_cases,
            "active_related_cases_count": res.active_related_cases_count,
            "closed_related_cases_count": res.closed_related_cases_count,
            "incident_related_cases_count": res.incident_related_cases_count,
            "entities_searched_count": res.entities_searched_count,
            "entities_with_hits_count": res.entities_with_hits_count,
            "entities_searched": res.entities_searched,
            "entity_precedents": res.entity_precedents,
            "related_cases": res.related_cases,
            "comment_id": res.comment_id,
            "secops_ui_base_url": res.secops_ui_base_url,
            "summary_markdown": markdown_summary,
            "provenance": res.provenance,
        }

        siemplify.result.add_result_json(json_payload)
        result_value = bool(res.has_related_cases)

        output_message = (
            f"Completed Related Cases by Entity search for Case #{res.case_id}: "
            f"scanned {res.entities_searched_count} entities across {res.lookback_days} days "
            f"and discovered {res.total_related_cases} related cases "
            f"({res.active_related_cases_count} open, {res.closed_related_cases_count} closed)."
        )
        siemplify.LOGGER.info(output_message)

    except Exception as e:
        normalized = unicodedata.normalize("NFKD", str(e))
        clean_msg = normalized.encode("ascii", "ignore").decode("ascii")
        output_message = f"Failed to search related cases by entity: {clean_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Related Cases by Entity Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
