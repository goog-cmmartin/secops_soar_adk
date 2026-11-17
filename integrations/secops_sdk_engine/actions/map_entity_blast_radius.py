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
from engine.workflows.case_attack_graph import (
    SHARED_ATTACK_CORR_CACHE_KEY,
    read_soar_case_context_json,
    write_soar_case_context_json,
)

INTEGRATION_NAME = "SecOpsSDKEngine"
SCRIPT_NAME = "Map Entity Blast Radius"
BLAST_RADIUS_CACHE_KEY = "ENTITY_BLAST_RADIUS_CACHED_RESULT"
MAX_JSON_PAYLOAD_BYTES = 140_000


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


def _safe_ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode("ascii")


def _enforce_blast_radius_ceiling(payload: dict, max_bytes: int = MAX_JSON_PAYLOAD_BYTES) -> dict:
    out = dict(payload)
    serialized = json.dumps(out, default=str)
    if len(serialized.encode("utf-8")) <= max_bytes:
        return out
    nodes = list(out.get("nodes") or [])
    edges = list(out.get("edges") or [])
    while len(nodes) > 6 and len(json.dumps(out, default=str).encode("utf-8")) > max_bytes:
        nodes = nodes[:-2]
        valid_ids = {n.get("id") for n in nodes}
        edges = [e for e in edges if e.get("from") in valid_ids and e.get("to") in valid_ids]
        out["nodes"] = nodes
        out["edges"] = edges
    return out


def _read_tmp_json(path: str):
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return None


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = "Successfully mapped Case Entity Blast Radius."
    result_value = True

    try:
        customer_id = (
            siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Customer ID")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "Customer ID")
        )
        project_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID", default_value="")
        region = (
            siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region", default_value="us")
            or "us"
        )
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON", default_value="")
        workload_identity_email = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Workload Identity Email", default_value=""
        )
        verify_ssl = _parse_bool(
            siemplify.extract_configuration_param(INTEGRATION_NAME, "Verify SSL", default_value="true"),
            default=True,
        )

        case_id = siemplify.extract_action_param("Case ID", default_value="")
        if not case_id or not str(case_id).strip():
            case_id = str(siemplify.case_id) if hasattr(siemplify, "case_id") and siemplify.case_id else ""
        case_id = str(case_id or "").strip()
        if not case_id:
            raise ValueError("No Case ID provided in action parameters and no active SOAR case context found.")

        lookback_hours = _parse_int(
            siemplify.extract_action_param("Lookback Hours", default_value="48", print_value=True),
            default=48,
        )
        include_udm_precursors = _parse_bool(
            siemplify.extract_action_param("Include UDM Precursor Events", default_value="true", print_value=True),
            default=True,
        )
        include_related_cases = _parse_bool(
            siemplify.extract_action_param("Include Related Cases", default_value="true", print_value=True),
            default=True,
        )
        max_nodes = _parse_int(
            siemplify.extract_action_param("Max Nodes", default_value="28", print_value=True),
            default=28,
        )
        entity_filter_raw = siemplify.extract_action_param("Entity Filter", default_value="", print_value=True)
        entity_filter = (
            [e.strip() for e in str(entity_filter_raw).split(",") if e.strip()]
            if entity_filter_raw and str(entity_filter_raw).strip()
            else None
        )
        entity_filter_mode = str(
            siemplify.extract_action_param(
                "Entity Filter Mode", default_value="Filter Out (Exclude)", print_value=True
            )
            or "Filter Out (Exclude)"
        ).strip()
        adk_result_param = siemplify.extract_action_param("ADK Result JSON", default_value="", print_value=False)
        post_wall_comment = _parse_bool(
            siemplify.extract_action_param("Post Wall Comment", default_value="false", print_value=True),
            default=False,
        )
        secops_ui_base_url = str(
            siemplify.extract_action_param("SecOps UI Base URL", default_value="", print_value=True) or ""
        ).strip()

        manager = SecOpsSDKEngineManager(
            customer_id=customer_id,
            project_id=project_id,
            region=region,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER,
        )

        # Discover cross-action caches (ADK Agent, Correlate Silent Detections, Related Cases, Shared Telemetry)
        adk_cached = adk_result_param if (adk_result_param and str(adk_result_param).strip()) else None
        if not adk_cached:
            adk_cached = (
                read_soar_case_context_json(siemplify, case_id, "ADK_AGENT_CACHED_RESULT")
                or _read_tmp_json(f"/tmp/soar_action_cache_adk_agent_{case_id}.json")
            )

        shared_corr = (
            read_soar_case_context_json(siemplify, case_id, SHARED_ATTACK_CORR_CACHE_KEY)
            or _read_tmp_json(f"/tmp/soar_attack_telemetry_{case_id}.json")
        )
        if isinstance(shared_corr, dict) and (time.time() - float(shared_corr.get("timestamp", 0))) < 300:
            cached_corr_payload = shared_corr.get("corr_dict")
        else:
            corr_ctx = (
                read_soar_case_context_json(siemplify, case_id, "CORRELATE_SILENT_CACHED_RESULT")
                or _read_tmp_json(f"/tmp/soar_action_cache_correlate_{case_id}.json")
            )
            cached_corr_payload = corr_ctx.get("results") if isinstance(corr_ctx, dict) and "results" in corr_ctx else corr_ctx

        rel_ctx = (
            read_soar_case_context_json(siemplify, case_id, "RELATED_CASES_CACHED_RESULT")
            or _read_tmp_json(f"/tmp/soar_action_cache_related_cases_{case_id}.json")
        )
        cached_rel_payload = rel_ctx.get("results") if isinstance(rel_ctx, dict) and "results" in rel_ctx else rel_ctx

        # Idempotency guard for duplicate queued Case Playbook triggers
        action_cache_file = f"/tmp/soar_action_cache_blast_radius_{case_id}.json"
        current_alert_count = 0
        existing_tags = []
        try:
            existing_case = manager.adapter.get_case(str(case_id), expand="tags")
            raw_tags = (
                getattr(existing_case, "tags", None)
                or (existing_case.get("tags") if isinstance(existing_case, dict) else None)
                or []
            )
            for rt in raw_tags:
                dn = (rt.get("displayName") or rt.get("tag")) if isinstance(rt, dict) else rt
                if dn and str(dn).strip():
                    existing_tags.append(str(dn).strip())
            current_alert_count = int(
                getattr(existing_case, "alert_count", 0)
                or ((existing_case.get("alertCount") or existing_case.get("alertsCount")) if isinstance(existing_case, dict) else 0)
                or 0
            )
            prior_entry = _read_tmp_json(action_cache_file) or read_soar_case_context_json(
                siemplify, case_id, BLAST_RADIUS_CACHE_KEY
            )
            if isinstance(prior_entry, dict) and isinstance(prior_entry.get("results"), dict):
                age_s = time.time() - float(prior_entry.get("timestamp", 0))
                has_adk_now = bool(adk_cached) or ("Tier1:Triaged" in existing_tags)
                had_adk_before = bool(prior_entry["results"].get("adk_overlay", {}).get("has_adk_analysis"))
                logjammer_changed = ("LogJammer:Simulated" in existing_tags) != bool(
                    prior_entry.get("has_logjammer_simulated")
                )
                if (
                    age_s < 180.0
                    and int(prior_entry.get("alert_count", -1)) == current_alert_count
                    and not logjammer_changed
                    and not (has_adk_now and not had_adk_before)
                ):
                    cached_out = dict(prior_entry["results"])
                    cached_out["reused_cached_result"] = True
                    siemplify.result.add_result_json(cached_out)
                    output_message = (
                        f"Case #{case_id} Blast Radius topology reused from recent cache "
                        f"({len(cached_out.get('nodes') or [])} nodes, {len(cached_out.get('edges') or [])} edges)."
                    )
                    siemplify.end(_safe_ascii(output_message), True, EXECUTION_STATE_COMPLETED)
                    return
        except Exception as pre_err:
            siemplify.LOGGER.info(f"Pre-flight cache check skipped: {pre_err}")

        res = manager.map_entity_blast_radius(
            case_id=case_id,
            lookback_hours=lookback_hours,
            include_udm_precursors=include_udm_precursors,
            include_related_cases=include_related_cases,
            max_nodes=max_nodes,
            entity_filter=entity_filter,
            entity_filter_mode=entity_filter_mode,
            adk_result=adk_cached,
            cached_correlation=cached_corr_payload if isinstance(cached_corr_payload, dict) else None,
            cached_related_cases=cached_rel_payload if isinstance(cached_rel_payload, dict) else None,
            post_wall_comment=post_wall_comment,
            secops_ui_base_url=secops_ui_base_url,
        )

        # Save shared correlation + UDM telemetry so Build Kill Chain Timeline reuses it with 0 duplicate queries
        corr_export = getattr(res, "_corr_export", None)
        if isinstance(corr_export, dict) and corr_export:
            shared_bundle = {"timestamp": time.time(), "case_id": case_id, "corr_dict": corr_export}
            write_soar_case_context_json(siemplify, case_id, SHARED_ATTACK_CORR_CACHE_KEY, shared_bundle)
            try:
                with open(f"/tmp/soar_attack_telemetry_{case_id}.json", "w", encoding="utf-8") as sf:
                    json.dump(shared_bundle, sf, default=str)
            except Exception:
                pass

        json_payload = _enforce_blast_radius_ceiling(dict(res))
        cache_entry = {
            "timestamp": time.time(),
            "alert_count": current_alert_count,
            "has_logjammer_simulated": "LogJammer:Simulated" in existing_tags,
            "results": json_payload,
        }
        write_soar_case_context_json(siemplify, case_id, BLAST_RADIUS_CACHE_KEY, cache_entry)
        try:
            with open(action_cache_file, "w", encoding="utf-8") as cf:
                json.dump(cache_entry, cf, default=str)
        except Exception:
            pass

        siemplify.result.add_result_json(json_payload)
        metrics = json_payload.get("metrics") or {}
        output_message = (
            f"Mapped Blast Radius for Case #{case_id}: {metrics.get('entity_nodes_count', 0)} entities, "
            f"{metrics.get('detection_nodes_count', 0)} YARA-L rules, "
            f"{metrics.get('related_case_nodes_count', 0)} related cases, and {metrics.get('total_edges', 0)} edges."
        )
        result_value = True

    except Exception as e:
        clean_err = _safe_ascii(str(e))
        output_message = f"Error executing {SCRIPT_NAME}: {clean_err}"
        siemplify.LOGGER.error(output_message)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(_safe_ascii(output_message), result_value, status)


if __name__ == "__main__":
    main()
