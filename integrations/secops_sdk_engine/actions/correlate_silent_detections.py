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
SCRIPT_NAME = "Correlate Silent Detections"


def _format_markdown_report(res) -> str:
    lines = [
        f"## [SecOps SDK Engine] Silent Detection Correlation Report",
        f"- **Case ID**: `{res.case_id}`",
        f"- **Lookback Window**: `{res.lookback_hours} hours`",
        f"- **Entities Searched**: `{len(res.entities_searched)}`",
        f"- **Detections Discovered**: `{len(res.detections_found)}`",
        f"- **Evidence Items Attached**: `{len(res.attached_evidences)}`",
        f"- **Entities Attached to Case**: `{len(getattr(res, 'attached_entities', []))}`",
    ]
    if getattr(res, "events_found", None):
        lines.append(f"- **UDM Events Correlated**: `{len(res.events_found)}`")

    if res.comment_id:
        lines.append(f"- **Case Wall Comment**: `{res.comment_id}`")

    if res.detections_found:
        lines.append("\n### Discovered Detections")
        lines.append("| Rule Name | Alert State | Severity | Event ID |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for d in res.detections_found:
            rule_name = d.get("rule_name") or "Unknown Rule"
            alert_state = d.get("alert_state") or ("ALERTING" if d.get("is_alerting") else "SILENT")
            severity = d.get("severity") or "N/A"
            event_id = d.get("event_id") or "N/A"
            if len(event_id) > 20:
                event_id = f"{event_id[:16]}..."
            lines.append(f"| {rule_name} | {alert_state} | {severity} | `{event_id}` |")

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

    if res.attached_evidences:
        lines.append("\n### Attached Case Evidence")
        lines.append("| Evidence Type | Evidence ID | Attach Time |")
        lines.append("| :--- | :--- | :--- |")
        for ev in res.attached_evidences:
            ev_type = getattr(ev, "evidence_type", "") or ""
            ev_id = getattr(ev, "evidence_id", "") or ""
            if len(ev_id) > 24:
                ev_id = f"{ev_id[:20]}..."
            att_time = getattr(ev, "attach_time", "") or "Just now"
            lines.append(f"| {ev_type} | `{ev_id}` | {att_time} |")

    if getattr(res, "attached_entities", None):
        lines.append("\n### Attached Case Entities")
        lines.append("| Identifier | Type | Entity ID | Status |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for ent in res.attached_entities:
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

        lookback_hours = siemplify.extract_action_param("Lookback Hours", default_value="24", print_value=True)
        try:
            lookback_hours = int(lookback_hours)
        except (ValueError, TypeError):
            lookback_hours = 24

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

        attached_dicts = []
        for ev in res.attached_evidences or []:
            if hasattr(ev, "raw") and ev.raw:
                attached_dicts.append(ev.raw)
            elif hasattr(ev, "__dict__"):
                attached_dicts.append({k: v for k, v in vars(ev).items() if not k.startswith("_")})
            else:
                attached_dicts.append(str(ev))

        markdown_report = _format_markdown_report(res)

        json_payload = {
            "case_id": res.case_id,
            "lookback_hours": res.lookback_hours,
            "has_silent_detections": has_silent,
            "detections_count": len(detections),
            "silent_detections_count": len(silent_detections),
            "events_count": len(events),
            "attached_count": len(res.attached_evidences or []),
            "attached_entities_count": len(getattr(res, "attached_entities", [])),
            "entities_count": len(res.entities_searched or []),
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
