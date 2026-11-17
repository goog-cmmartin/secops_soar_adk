import json
import os
import sys
import time
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

        # Idempotency & multi-alert fan-in cooldown guard:
        # Preserves full cached JsonResult so Case Overview HTML widgets are never blanked out by duplicate queued runs.
        cache_file = f"/tmp/soar_action_cache_related_cases_{case_id}.json"
        current_alert_count = 0
        try:
            existing_case = manager.adapter.get_case(str(case_id), expand="tags")
            raw_tags = (
                getattr(existing_case, "tags", None)
                or (existing_case.get("tags") if isinstance(existing_case, dict) else None)
                or []
            )
            existing_tags = []
            for rt in raw_tags:
                if isinstance(rt, dict):
                    dn = rt.get("displayName") or rt.get("tag")
                    if dn and str(dn).strip():
                        existing_tags.append(str(dn).strip())
                elif str(rt).strip():
                    existing_tags.append(str(rt).strip())

            current_alert_count = int(
                getattr(existing_case, "alert_count", 0)
                or (
                    (existing_case.get("alertCount") or existing_case.get("alertsCount"))
                    if isinstance(existing_case, dict)
                    else 0
                )
                or 0
            )
            cached_entry = None
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, "r", encoding="utf-8") as cf:
                        cached_entry = json.load(cf)
                except Exception:
                    cached_entry = None
            if not isinstance(cached_entry, dict):
                try:
                    raw_ctx = None
                    if hasattr(siemplify, "get_case_context_property"):
                        raw_ctx = siemplify.get_case_context_property("RELATED_CASES_CACHED_RESULT")
                    elif hasattr(siemplify, "get_context_property"):
                        raw_ctx = siemplify.get_context_property(1, str(case_id), "RELATED_CASES_CACHED_RESULT")
                    if isinstance(raw_ctx, dict):
                        cached_entry = raw_ctx
                    elif isinstance(raw_ctx, str) and raw_ctx.strip().startswith("{"):
                        cached_entry = json.loads(raw_ctx.strip())
                except Exception:
                    cached_entry = None

            cache_age = (time.time() - float(cached_entry.get("timestamp", 0))) if isinstance(cached_entry, dict) else 999999.0
            cached_payload = cached_entry.get("json_payload") if isinstance(cached_entry, dict) else None
            logjammer_newly_simulated = (
                "LogJammer:Simulated" in existing_tags
                and not (isinstance(cached_entry, dict) and bool(cached_entry.get("has_logjammer_simulated")))
            )
            is_recent_same_alerts = (
                isinstance(cached_payload, dict)
                and not logjammer_newly_simulated
                and cache_age < 180.0
                and int(cached_entry.get("alert_count", -1)) == current_alert_count
            )

            if (
                (("Tier1:Triaged" in existing_tags and not logjammer_newly_simulated) or is_recent_same_alerts)
                and isinstance(cached_payload, dict)
            ):
                skip_reason = (
                    f"already carries 'Tier1:Triaged' tag ({existing_tags})"
                    if "Tier1:Triaged" in existing_tags
                    else f"already searched related cases {cache_age:.1f}s ago with unchanged alert count ({current_alert_count})"
                )
                output_message = (
                    f"Case '{case_id}' {skip_reason}; "
                    f"reusing cached Related Cases payload to preserve Case Overview widget."
                )
                siemplify.LOGGER.info(output_message)
                payload_out = dict(cached_payload)
                payload_out["reused_cached_result"] = True
                payload_out["existing_tags"] = existing_tags
                siemplify.result.add_result_json(payload_out)
                siemplify.end(output_message, bool(payload_out.get("has_related_cases", False)), EXECUTION_STATE_COMPLETED)
                return
        except Exception as tag_check_err:
            siemplify.LOGGER.info(f"Pre-flight tag/cache check skipped: {tag_check_err}")

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

        cache_entry_to_save = {
            "timestamp": time.time(),
            "alert_count": current_alert_count,
            "has_logjammer_simulated": (
                "LogJammer:Simulated" in (existing_tags if "existing_tags" in locals() else [])
            ),
            "json_payload": json_payload,
        }
        try:
            if hasattr(siemplify, "set_case_context_property"):
                siemplify.set_case_context_property("RELATED_CASES_CACHED_RESULT", json.dumps(cache_entry_to_save))
            elif hasattr(siemplify, "set_context_property"):
                siemplify.set_context_property(1, str(case_id), "RELATED_CASES_CACHED_RESULT", json.dumps(cache_entry_to_save))
        except Exception:
            pass
        try:
            with open(cache_file, "w", encoding="utf-8") as cf:
                json.dump(cache_entry_to_save, cf)
        except Exception:
            pass

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
        try:
            if "manager" in locals() and "case_id" in locals() and case_id:
                manager.engine.remove_case_tag(str(case_id), "Run_Case_Correlation")
        except Exception:
            pass
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
