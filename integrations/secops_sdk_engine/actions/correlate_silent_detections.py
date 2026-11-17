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
SCRIPT_NAME = "Correlate Silent Detections"

DEFAULT_MAX_RESULT_RECORDS = 50
MAX_MARKDOWN_TABLE_ROWS = 25
MAX_STRING_VALUE_LEN = 500
MAX_JSON_PAYLOAD_BYTES = 140_000

_NESTED_BLOB_KEYS = frozenset({
    "raw",
    "raw_log",
    "rawLog",
    "protobuf",
    "udm",
    "detectionFields",
    "detection_fields",
    "about",
    "labels",
})


def _extract_rules_triggered(detections) -> list:
    """Extracts an order-preserving list of unique rule names across all detections."""
    seen = set()
    rules = []
    for d in detections or []:
        if not isinstance(d, dict):
            continue
        rname = str(d.get("rule_name") or d.get("ruleName") or "").strip()
        if rname and rname not in seen:
            seen.add(rname)
            rules.append(rname)
    return rules


def _select_diverse_detections(detections: list, max_records: int) -> list:
    """Selects up to max_records detections interleaved round-robin across rules to preserve rule diversity."""
    if max_records <= 0:
        return []
    if len(detections) <= max_records:
        return list(detections)
    queues = {}
    rule_order = []
    for d in detections:
        rname = str(d.get("rule_name") or "Unknown Rule") if isinstance(d, dict) else "Unknown Rule"
        if rname not in queues:
            queues[rname] = []
            rule_order.append(rname)
        queues[rname].append(d)

    selected = []
    idx = 0
    max_q_len = max((len(q) for q in queues.values()), default=0)
    while idx < max_q_len and len(selected) < max_records:
        for rname in rule_order:
            q = queues[rname]
            if idx < len(q):
                selected.append(q[idx])
                if len(selected) >= max_records:
                    break
        idx += 1
    return selected


def _compact_value(
    val,
    max_str_len: int = MAX_STRING_VALUE_LEN,
    max_list_len: int = 10,
    depth: int = 0,
    max_depth: int = 3,
):
    """Recursively strips deeply nested UDM/protobuf blobs and truncates oversized strings."""
    if isinstance(val, str):
        if len(val) > max_str_len:
            return val[:max_str_len] + "...[truncated]"
        return val
    if isinstance(val, (int, float, bool)) or val is None:
        return val
    if isinstance(val, dict):
        if depth >= max_depth:
            out_leaf = {}
            for k, v in val.items():
                if k in _NESTED_BLOB_KEYS:
                    continue
                if isinstance(v, (str, int, float, bool)) and v not in ("", None):
                    out_leaf[k] = _compact_value(v, max_str_len=max_str_len, depth=depth + 1, max_depth=max_depth)
            return out_leaf
        out_dict = {}
        for k, v in val.items():
            if k in _NESTED_BLOB_KEYS:
                continue
            compacted = _compact_value(
                v,
                max_str_len=max_str_len,
                max_list_len=max_list_len,
                depth=depth + 1,
                max_depth=max_depth,
            )
            if compacted not in (None, "", [], {}):
                out_dict[k] = compacted
        return out_dict
    if isinstance(val, list):
        if depth >= max_depth:
            return [
                _compact_value(x, max_str_len=max_str_len, depth=depth + 1, max_depth=max_depth)
                for x in val[:max_list_len]
                if isinstance(x, (str, int, float, bool))
            ]
        return [
            _compact_value(
                x,
                max_str_len=max_str_len,
                max_list_len=max_list_len,
                depth=depth + 1,
                max_depth=max_depth,
            )
            for x in val[:max_list_len]
        ]
    return str(val)[:max_str_len]


def _compact_attached_evidence(ev) -> dict:
    """Normalizes and compacts an attached evidence item without retaining raw API blobs."""
    if isinstance(ev, dict):
        ev_id = str(ev.get("evidence_id") or ev.get("evidenceId") or "")[:200]
        ev_type = str(ev.get("evidence_type") or ev.get("evidenceType") or "EVIDENCE")[:100]
        att_time = ev.get("attach_time") or ev.get("attachTime") or ""
        out = {
            "evidence_id": ev_id,
            "evidenceId": ev_id,
            "evidence_type": ev_type,
            "evidenceType": ev_type,
        }
        if att_time:
            out["attach_time"] = str(att_time)[:100]
        return out
    if hasattr(ev, "evidence_id") or hasattr(ev, "evidence_type"):
        ev_id = str(getattr(ev, "evidence_id", "") or "")[:200]
        ev_type = str(getattr(ev, "evidence_type", "") or "EVIDENCE")[:100]
        out = {
            "evidence_id": ev_id,
            "evidenceId": ev_id,
            "evidence_type": ev_type,
            "evidenceType": ev_type,
        }
        att_time = getattr(ev, "attach_time", None)
        if att_time:
            out["attach_time"] = str(att_time)[:100]
        return out
    if hasattr(ev, "__dict__"):
        return _compact_value({k: v for k, v in vars(ev).items() if not k.startswith("_") and k != "raw"})
    ev_str = str(ev)[:200]
    return {"evidence_id": ev_str, "evidenceId": ev_str, "evidence_type": "EVIDENCE", "evidenceType": "EVIDENCE"}


def _enforce_payload_ceiling(
    json_payload: dict,
    max_result_records: int = DEFAULT_MAX_RESULT_RECORDS,
    max_bytes: int = MAX_JSON_PAYLOAD_BYTES,
) -> dict:
    """Guarantees json_payload is compacted, capped at max_result_records, and serialized < max_bytes."""
    payload = dict(json_payload)
    cap = max(1, int(max_result_records or DEFAULT_MAX_RESULT_RECORDS))

    raw_detections = payload.get("detections_found") or []
    raw_events = payload.get("events_found") or []
    raw_attached = payload.get("attached_evidences") or []
    raw_entities_searched = payload.get("entities_searched") or []

    if "detections_count" not in payload:
        payload["detections_count"] = len(raw_detections)
    if "silent_detections_count" not in payload:
        payload["silent_detections_count"] = sum(
            1 for d in raw_detections if isinstance(d, dict) and not d.get("is_alerting")
        )
    if "events_count" not in payload:
        payload["events_count"] = len(raw_events)
    if "attached_count" not in payload:
        payload["attached_count"] = len(raw_attached)
    if not payload.get("rules_triggered"):
        payload["rules_triggered"] = _extract_rules_triggered(raw_detections)

    capped_detections = _select_diverse_detections(raw_detections, cap)
    payload["detections_found"] = [_compact_value(d) for d in capped_detections]
    payload["events_found"] = [_compact_value(e) for e in raw_events[:cap]]
    payload["attached_evidences"] = [_compact_attached_evidence(a) for a in raw_attached[:cap]]
    payload["entities_searched"] = [_compact_value(ent) for ent in raw_entities_searched[:100]]
    payload["detections_truncated"] = int(payload.get("detections_count", 0)) > len(payload["detections_found"])
    payload["events_truncated"] = int(payload.get("events_count", 0)) > len(payload["events_found"])
    payload["max_result_records"] = cap

    if isinstance(payload.get("query_used"), str) and len(payload["query_used"]) > 4000:
        payload["query_used"] = payload["query_used"][:4000] + "...[truncated]"
    if isinstance(payload.get("evidence_markdown"), str) and len(payload["evidence_markdown"]) > 15000:
        payload["evidence_markdown"] = payload["evidence_markdown"][:15000] + "\n\n*...[report truncated]*"

    # Progressive size guard to ensure serialized payload stays strictly below max_bytes (< 150 KB)
    serialized = json.dumps(payload)
    while len(serialized) > max_bytes:
        if len(payload.get("events_found") or []) > 5:
            payload["events_found"] = payload["events_found"][: max(5, len(payload["events_found"]) // 2)]
            payload["events_truncated"] = True
        elif len(payload.get("attached_evidences") or []) > 10:
            payload["attached_evidences"] = payload["attached_evidences"][: max(10, len(payload["attached_evidences"]) // 2)]
        elif len(payload.get("detections_found") or []) > 10:
            payload["detections_found"] = payload["detections_found"][: max(10, len(payload["detections_found"]) // 2)]
            payload["detections_truncated"] = True
        elif len(payload.get("entities_searched") or []) > 20:
            payload["entities_searched"] = payload["entities_searched"][:20]
        else:
            break
        serialized = json.dumps(payload)

    return payload


def _format_markdown_report(res, max_rows: int = MAX_MARKDOWN_TABLE_ROWS) -> str:
    detections_all = getattr(res, "detections_found", None) or []
    rules_triggered = _extract_rules_triggered(detections_all)
    lines = [
        f"## [SecOps SDK Engine] Silent Detection Correlation Report",
        f"- **Case ID**: `{res.case_id}`",
        f"- **Lookback Window**: `{res.lookback_hours} hours`",
        f"- **Entities Searched**: `{len(res.entities_searched)}`",
        f"- **Detections Discovered**: `{len(detections_all)}`",
        f"- **Unique Rules Triggered**: `{len(rules_triggered)}`",
        f"- **Evidence Items Attached**: `{len(res.attached_evidences)}`",
        f"- **Entities Attached to Case**: `{len(getattr(res, 'attached_entities', []))}`",
    ]
    if getattr(res, "events_found", None):
        lines.append(f"- **UDM Events Correlated**: `{len(res.events_found)}`")

    if res.comment_id:
        lines.append(f"- **Case Wall Comment**: `{res.comment_id}`")

    if detections_all:
        lines.append("\n### Discovered Detections")
        lines.append("| Rule Name | Alert State | Severity | Event ID |")
        lines.append("| :--- | :--- | :--- | :--- |")
        displayed_detections = _select_diverse_detections(detections_all, max_rows)
        for d in displayed_detections:
            rule_name = d.get("rule_name") or "Unknown Rule"
            alert_state = d.get("alert_state") or ("ALERTING" if d.get("is_alerting") else "SILENT")
            severity = d.get("severity") or "N/A"
            event_id = d.get("event_id") or "N/A"
            if len(event_id) > 20:
                event_id = f"{event_id[:16]}..."
            lines.append(f"| {rule_name} | {alert_state} | {severity} | `{event_id}` |")
        if len(detections_all) > len(displayed_detections):
            rem = len(detections_all) - len(displayed_detections)
            lines.append(f"\n*...and {rem} more detections across {len(rules_triggered)} unique rules.*")

    if getattr(res, "events_found", None):
        lines.append("\n### Discovered UDM Events (Sample)")
        lines.append("| Event ID | Event Type | Product Log ID |")
        lines.append("| :--- | :--- | :--- |")
        for ev in res.events_found[:10]:
            ev_id = ev.get("event_id") or "N/A"
            if len(ev_id) > 24:
                ev_id = f"{ev_id[:20]}..."
            ev_type = ev.get("event_type") or "UNKNOWN"
            p_id = ev.get("product_log_id") or "N/A"
            lines.append(f"| `{ev_id}` | {ev_type} | `{p_id}` |")
        if len(res.events_found) > 10:
            lines.append(f"\n*...and {len(res.events_found) - 10} more UDM events.*")

    if res.attached_evidences:
        lines.append("\n### Attached Case Evidence")
        lines.append("| Evidence Type | Evidence ID | Attach Time |")
        lines.append("| :--- | :--- | :--- |")
        for ev in res.attached_evidences[:max_rows]:
            ev_type = getattr(ev, "evidence_type", "") or (ev.get("evidence_type") if isinstance(ev, dict) else "") or ""
            ev_id = getattr(ev, "evidence_id", "") or (ev.get("evidence_id") if isinstance(ev, dict) else "") or ""
            if len(ev_id) > 24:
                ev_id = f"{ev_id[:20]}..."
            att_time = getattr(ev, "attach_time", "") or (ev.get("attach_time") if isinstance(ev, dict) else "") or "Just now"
            lines.append(f"| {ev_type} | `{ev_id}` | {att_time} |")
        if len(res.attached_evidences) > max_rows:
            lines.append(f"\n*...and {len(res.attached_evidences) - max_rows} more attached evidence items.*")

    if getattr(res, "attached_entities", None):
        lines.append("\n### Attached Case Entities")
        lines.append("| Identifier | Type | Entity ID | Status |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for ent in res.attached_entities[:max_rows]:
            lines.append(f"| `{ent.get('identifier')}` | {ent.get('type')} | `{ent.get('entity_id') or 'N/A'}` | {ent.get('status')} |")

    return "\n".join(lines)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = "Correlated silent detections successfully."
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
        if isinstance(verify_ssl_param, str):
            verify_ssl = verify_ssl_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(verify_ssl_param, bool):
            verify_ssl = verify_ssl_param
        else:
            verify_ssl = True

        # 2. Action parameters
        case_id = siemplify.extract_action_param("Case ID", default_value="")
        if not case_id or not str(case_id).strip():
            case_id = str(siemplify.case_id) if hasattr(siemplify, "case_id") else ""

        if not case_id:
            raise ValueError("No Case ID provided in action parameters and no active case context found.")

        lookback_hours = siemplify.extract_action_param("Lookback Hours", default_value="48", print_value=True)
        try:
            lookback_hours = int(lookback_hours)
        except (ValueError, TypeError):
            lookback_hours = 48

        attach_to_case_param = siemplify.extract_action_param("Attach to Case", default_value="false", print_value=True)
        if isinstance(attach_to_case_param, str):
            attach_to_case = attach_to_case_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(attach_to_case_param, bool):
            attach_to_case = attach_to_case_param
        else:
            attach_to_case = False

        attach_entities_param = siemplify.extract_action_param("Attach Entities", default_value="true", print_value=True)
        if isinstance(attach_entities_param, str):
            attach_entities = attach_entities_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(attach_entities_param, bool):
            attach_entities = attach_entities_param
        else:
            attach_entities = True

        post_wall_comment_param = siemplify.extract_action_param("Post Wall Comment", default_value="true", print_value=True)
        if isinstance(post_wall_comment_param, str):
            post_wall_comment = post_wall_comment_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(post_wall_comment_param, bool):
            post_wall_comment = post_wall_comment_param
        else:
            post_wall_comment = True

        entity_filter_param = siemplify.extract_action_param("Entity Filter", default_value="", print_value=True)
        entity_filter = None
        if entity_filter_param and str(entity_filter_param).strip():
            entity_filter = [e.strip() for e in str(entity_filter_param).split(",") if e.strip()]

        entity_filter_mode = siemplify.extract_action_param(
            "Entity Filter Mode", default_value="Filter Out (Exclude)", print_value=True
        )
        entity_filter_mode = str(entity_filter_mode or "Filter Out (Exclude)").strip()

        max_events = siemplify.extract_action_param("Max Events", default_value="1000")
        try:
            max_events = int(max_events)
        except (ValueError, TypeError):
            max_events = 1000

        correlate_detections_param = siemplify.extract_action_param("Correlate Detections", default_value="true", print_value=True)
        if isinstance(correlate_detections_param, str):
            correlate_detections = correlate_detections_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(correlate_detections_param, bool):
            correlate_detections = correlate_detections_param
        else:
            correlate_detections = True

        correlate_udm_events_param = siemplify.extract_action_param("Correlate UDM Events", default_value="false", print_value=True)
        if isinstance(correlate_udm_events_param, str):
            correlate_udm_events = correlate_udm_events_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(correlate_udm_events_param, bool):
            correlate_udm_events = correlate_udm_events_param
        else:
            correlate_udm_events = False

        attach_udm_events_param = siemplify.extract_action_param("Attach UDM Events", default_value="false", print_value=True)
        if isinstance(attach_udm_events_param, str):
            attach_udm_events = attach_udm_events_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(attach_udm_events_param, bool):
            attach_udm_events = attach_udm_events_param
        else:
            attach_udm_events = False

        extract_entities_events_param = siemplify.extract_action_param("Extract Entities From Events", default_value="false", print_value=True)
        if isinstance(extract_entities_events_param, str):
            extract_entities_from_events = extract_entities_events_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(extract_entities_events_param, bool):
            extract_entities_from_events = extract_entities_events_param
        else:
            extract_entities_from_events = False

        alert_vendor_filter = siemplify.extract_action_param("Alert Vendor Filter", default_value="Google Chronicle", print_value=True)
        if alert_vendor_filter:
            alert_vendor_filter = str(alert_vendor_filter).strip()

        max_entities_to_attach = siemplify.extract_action_param("Max Entities to Attach", default_value="5", print_value=True)
        try:
            max_entities_to_attach = int(max_entities_to_attach)
        except (ValueError, TypeError):
            max_entities_to_attach = 5

        max_result_records_param = siemplify.extract_action_param(
            "Max Result Records in JsonResult", default_value=str(DEFAULT_MAX_RESULT_RECORDS), print_value=True
        )
        try:
            max_result_records = max(1, int(max_result_records_param))
        except (ValueError, TypeError):
            max_result_records = DEFAULT_MAX_RESULT_RECORDS

        # 3. Initialize manager and execute workflow
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
        cache_file = f"/tmp/soar_action_cache_correlate_silent_{case_id}.json"
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
                        raw_ctx = siemplify.get_case_context_property("CORRELATE_SILENT_CACHED_RESULT")
                    elif hasattr(siemplify, "get_context_property"):
                        raw_ctx = siemplify.get_context_property(1, str(case_id), "CORRELATE_SILENT_CACHED_RESULT")
                    if isinstance(raw_ctx, dict):
                        cached_entry = raw_ctx
                    elif isinstance(raw_ctx, str) and raw_ctx.strip().startswith("{"):
                        cached_entry = json.loads(raw_ctx.strip())
                except Exception:
                    cached_entry = None

            cache_age = (time.time() - float(cached_entry.get("timestamp", 0))) if isinstance(cached_entry, dict) else 999999.0
            cached_payload = cached_entry.get("json_payload") if isinstance(cached_entry, dict) else None
            has_non_empty_cache = (
                isinstance(cached_payload, dict)
                and (
                    int(cached_payload.get("detections_count", 0) or 0) > 0
                    or int(cached_payload.get("events_count", 0) or 0) > 0
                )
            )
            logjammer_newly_simulated = (
                "LogJammer:Simulated" in existing_tags
                and not (isinstance(cached_entry, dict) and bool(cached_entry.get("has_logjammer_simulated")))
            )
            is_recent_same_alerts = (
                has_non_empty_cache
                and not logjammer_newly_simulated
                and cache_age < 180.0
                and int(cached_entry.get("alert_count", -1)) == current_alert_count
            )

            if (
                ("Tier1:Triaged" in existing_tags and has_non_empty_cache and not logjammer_newly_simulated)
                or is_recent_same_alerts
            ):
                skip_reason = (
                    f"already carries 'Tier1:Triaged' tag ({existing_tags})"
                    if "Tier1:Triaged" in existing_tags
                    else f"already correlated {cache_age:.1f}s ago with unchanged alert count ({current_alert_count})"
                )
                output_message = (
                    f"Case '{case_id}' {skip_reason}; "
                    f"reusing cached correlation payload to preserve Case Overview widget."
                )
                siemplify.LOGGER.info(output_message)
                payload_out = _enforce_payload_ceiling(
                    dict(cached_payload), max_result_records=max_result_records
                )
                payload_out["reused_cached_result"] = True
                payload_out["existing_tags"] = existing_tags
                siemplify.result.add_result_json(payload_out)
                siemplify.end(output_message, True, EXECUTION_STATE_COMPLETED)
                return
        except Exception as tag_check_err:
            siemplify.LOGGER.info(f"Pre-flight tag/cache check skipped: {tag_check_err}")

        res = manager.correlate_silent_detections(
            case_id=case_id,
            lookback_hours=lookback_hours,
            attach_to_case=attach_to_case,
            attach_entities=attach_entities,
            post_wall_comment=post_wall_comment,
            entity_filter=entity_filter,
            entity_filter_mode=entity_filter_mode,
            max_events=max_events,
            correlate_detections=correlate_detections,
            correlate_udm_events=correlate_udm_events,
            attach_udm_events=attach_udm_events,
            extract_entities_from_events=extract_entities_from_events,
            alert_vendor_filter=alert_vendor_filter,
            max_entities_to_attach=max_entities_to_attach,
        )

        # 4. Process results
        detections = res.detections_found or []
        silent_detections = [d for d in detections if not d.get("is_alerting")]
        has_silent = len(silent_detections) > 0
        events = getattr(res, "events_found", []) or []
        rules_triggered = _extract_rules_triggered(detections)

        attached_dicts = [_compact_attached_evidence(ev) for ev in (res.attached_evidences or [])]

        markdown_report = _format_markdown_report(res)

        raw_json_payload = {
            "case_id": res.case_id,
            "lookback_hours": res.lookback_hours,
            "has_silent_detections": has_silent,
            "detections_count": len(detections),
            "silent_detections_count": len(silent_detections),
            "events_count": len(events),
            "attached_count": len(res.attached_evidences or []),
            "attached_entities_count": len(getattr(res, "attached_entities", [])),
            "entities_count": len(res.entities_searched or []),
            "rules_triggered": rules_triggered,
            "comment_id": res.comment_id,
            "query_used": res.query_used,
            "detections_found": detections,
            "events_found": events,
            "attached_evidences": attached_dicts,
            "attached_entities": getattr(res, "attached_entities", []),
            "entities_searched": res.entities_searched or [],
            "evidence_markdown": markdown_report,
            "correlate_detections": correlate_detections,
            "correlate_udm_events": correlate_udm_events,
            "attach_udm_events": attach_udm_events,
        }
        json_payload = _enforce_payload_ceiling(
            raw_json_payload, max_result_records=max_result_records
        )

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
                siemplify.set_case_context_property("CORRELATE_SILENT_CACHED_RESULT", json.dumps(cache_entry_to_save))
            elif hasattr(siemplify, "set_context_property"):
                siemplify.set_context_property(1, str(case_id), "CORRELATE_SILENT_CACHED_RESULT", json.dumps(cache_entry_to_save))
        except Exception:
            pass
        try:
            with open(cache_file, "w", encoding="utf-8") as cf:
                json.dump(cache_entry_to_save, cf)
        except Exception:
            pass

        siemplify.result.add_result_json(json_payload)

        attached_ents = getattr(res, "attached_entities", [])
        output_message = (
            f"Successfully correlated Case '{res.case_id}': scanned {len(res.entities_searched or [])} entities, "
            f"discovered {len(detections)} detections ({len(silent_detections)} silent), "
            f"{len(events)} UDM events, "
            f"attached {len(res.attached_evidences or [])} evidence records, "
            f"and attached {len(attached_ents)} entities."
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
        output_message = f"Failed to correlate silent detections: {clean_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Correlate Silent Detections Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
