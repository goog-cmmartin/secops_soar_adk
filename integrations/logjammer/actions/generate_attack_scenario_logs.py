import json
import sys
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from LogJammerManager import LogJammerManager
    from templates import extract_timestamp_from_text, parse_base_timestamp
except ImportError:
    try:
        from core.LogJammerManager import LogJammerManager
        from core.templates import extract_timestamp_from_text, parse_base_timestamp
    except ImportError:
        from ..core.LogJammerManager import LogJammerManager
        from ..core.templates import extract_timestamp_from_text, parse_base_timestamp

INTEGRATION_NAME = "LogJammer"
SCRIPT_NAME = "Generate Attack Scenario Logs"


def _extract_alert_timestamp_and_context(siemplify, explicit_base_timestamp=None, scenario_prompt=""):
    """
    Resolves the anchor base timestamp (backdating target) and structured SOAR alert context.
    Priority for timestamp:
      1. Explicit `Base Timestamp` action parameter (ISO-8601 or epoch sec/ms/us/ns)
      2. Current SOAR Alert properties (`WindowStartTime`, `StartTime`, `event_min_timestamp`, `start_time`, or security event timestamps)
      3. Embedded ISO-8601 timestamp in `Scenario Prompt`
    """
    resolved_dt = parse_base_timestamp(explicit_base_timestamp)
    alert_context_lines = []

    try:
        alert = getattr(siemplify, "current_alert", None)
        if alert:
            alert_vars = vars(alert) if hasattr(alert, "__dict__") else {}
            # 1. Inspect alert top-level and additional_properties / additional_data
            props = {}
            for attr_name in ("additional_properties", "additional_data", "raw_data"):
                val = getattr(alert, attr_name, None) or alert_vars.get(attr_name)
                if isinstance(val, dict):
                    props.update(val)
                elif isinstance(val, str) and val.strip().startswith("{"):
                    try:
                        props.update(json.loads(val))
                    except Exception:
                        pass

            # Extract timestamp from alert if not explicitly provided
            if not resolved_dt:
                ts_candidates = [
                    props.get("WindowStartTime"),
                    props.get("WindowEndTime"),
                    props.get("StartTime"),
                    props.get("EndTime"),
                    props.get("event_min_timestamp"),
                    props.get("result_time"),
                    props.get("EstimatedStartTime"),
                    getattr(alert, "start_time", None),
                    getattr(alert, "creation_time", None),
                    alert_vars.get("start_time"),
                ]
                for cand in ts_candidates:
                    parsed = parse_base_timestamp(cand)
                    if parsed:
                        resolved_dt = parsed
                        break

            # Build concise structured Alert Context to ground entities/timeline
            alert_name = props.get("name_override") or props.get("Name") or getattr(alert, "name", None) or getattr(alert, "rule_generator", None)
            product = props.get("product_name") or props.get("vendor_name") or getattr(alert, "product", None)
            rule_id = props.get("rule_id") or props.get("SourceRuleIdentifier")
            primary_entity = props.get("entity")
            if alert_name:
                alert_context_lines.append(f"- Alert Name: {alert_name}")
            if product:
                alert_context_lines.append(f"- Detection Source / Product: {product}")
            if rule_id:
                alert_context_lines.append(f"- Detection Rule ID: {rule_id}")
            if primary_entity:
                alert_context_lines.append(f"- Primary Alert Entity: {primary_entity}")

            # Extract involved SOAR entities
            entities = getattr(alert, "entities", None) or []
            if entities:
                ent_strs = []
                for ent in entities[:15]:
                    e_id = getattr(ent, "identifier", None)
                    e_type = getattr(ent, "entity_type", None)
                    if e_id:
                        ent_strs.append(f"{e_id} ({e_type})" if e_type else str(e_id))
                if ent_strs:
                    alert_context_lines.append(f"- Involved SOAR Entities: {', '.join(ent_strs)}")

            # Inspect security_events for key fields & timestamps
            sec_events = getattr(alert, "security_events", None) or []
            event_highlights = []
            for ev in sec_events[:3]:
                ev_props = getattr(ev, "additional_properties", None) or {}
                if isinstance(ev_props, str) and ev_props.strip().startswith("{"):
                    try:
                        ev_props = json.loads(ev_props)
                    except Exception:
                        ev_props = {}
                if not resolved_dt:
                    for k in ("event_timestamp", "timestamp", "start_time", "StartTime", "end_time"):
                        if k in ev_props:
                            parsed = parse_base_timestamp(ev_props[k])
                            if parsed:
                                resolved_dt = parsed
                                break
                if isinstance(ev_props, dict):
                    interesting = {}
                    for k, v in ev_props.items():
                        if v is not None and str(v).strip() and any(
                            tok in k.lower()
                            for tok in ("host", "ip", "user", "instance", "resource", "command", "process", "threat", "description", "principal", "target")
                        ):
                            val_str = str(v).strip()
                            if len(val_str) <= 300:
                                interesting[k] = val_str
                    if interesting:
                        event_highlights.append(json.dumps(interesting))
            if event_highlights:
                alert_context_lines.append("- Underlying Event Attributes: " + " | ".join(event_highlights))
    except Exception as e:
        siemplify.LOGGER.warn(f"Non-fatal warning extracting alert timestamp/context: {e}")

    if not resolved_dt:
        resolved_dt = extract_timestamp_from_text(scenario_prompt)

    if resolved_dt:
        alert_context_lines.insert(
            0, f"- Alert Anchor Timestamp (0d0h0m0s): {resolved_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )

    return resolved_dt, "\n".join(alert_context_lines)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = False

    try:
        # 1. Integration configuration parameters
        gemini_api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        gti_api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Google Threat Intelligence API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        workload_identity_email = siemplify.extract_configuration_param(INTEGRATION_NAME, "Workload Identity Email")
        gcp_project_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID")
        secops_customer_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Customer ID")
        secops_region = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "SecOps Region", default_value="us"
        )
        model_name = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Model Name", default_value="gemini-3.7-flash"
        )

        # 2. Action parameters
        scenario_prompt = siemplify.extract_action_param("Scenario Prompt")
        if not scenario_prompt or not str(scenario_prompt).strip():
            raise ValueError("The 'Scenario Prompt' parameter is required.")

        raw_log_types = siemplify.extract_action_param("Log Types", default_value="")
        log_types = [t.strip().upper() for t in raw_log_types.split(",") if t.strip()] if raw_log_types else None

        rule_identifier = siemplify.extract_action_param("Rule Identifier", default_value="")
        rule_outcome = siemplify.extract_action_param("Rule Outcome", default_value="fire")
        if rule_outcome not in ("fire", "evade", "full-chain"):
            rule_outcome = "fire"

        raw_count = siemplify.extract_action_param("Event Count", default_value="5")
        try:
            event_count = max(1, min(100, int(raw_count)))
        except (ValueError, TypeError):
            event_count = 5

        custom_scenario_name = siemplify.extract_action_param("Scenario Name", default_value="")
        base_timestamp_param = siemplify.extract_action_param("Base Timestamp", default_value="")

        ingest_to_secops_param = siemplify.extract_action_param(
            "Ingest to SecOps", default_value="true", print_value=True
        )
        if isinstance(ingest_to_secops_param, str):
            ingest_to_secops = ingest_to_secops_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(ingest_to_secops_param, bool):
            ingest_to_secops = ingest_to_secops_param
        else:
            ingest_to_secops = True

        enrich_gti_param = siemplify.extract_action_param(
            "Enrich with Google TI", default_value="false", print_value=True
        )
        if isinstance(enrich_gti_param, str):
            enrich_gti = enrich_gti_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(enrich_gti_param, bool):
            enrich_gti = enrich_gti_param
        else:
            enrich_gti = False

        # Resolve anchor timestamp and structured SOAR alert context
        resolved_base_dt, alert_context_str = _extract_alert_timestamp_and_context(
            siemplify,
            explicit_base_timestamp=base_timestamp_param,
            scenario_prompt=str(scenario_prompt).strip(),
        )
        effective_prompt = str(scenario_prompt).strip()
        if alert_context_str:
            effective_prompt = (
                f"{effective_prompt}\n\n"
                f"### Attached SOAR Alert Context & Anchor Timeline:\n{alert_context_str}"
            )

        # 3. Instantiate LogJammer Manager
        manager = LogJammerManager(
            gemini_api_key=gemini_api_key,
            gti_api_key=gti_api_key,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            gcp_project_id=gcp_project_id,
            secops_customer_id=secops_customer_id,
            secops_region=secops_region,
            model_name=model_name,
            logger=siemplify.LOGGER,
        )

        case_id = getattr(siemplify, "case_id", None)
        if custom_scenario_name and str(custom_scenario_name).strip():
            scenario_name = str(custom_scenario_name).strip()
        else:
            scenario_name = f"SOAR_Case_{case_id}_Simulation" if case_id else "SOAR_Simulation"

        # 4. Generate Attack Scenario Logs
        results = manager.generate_scenario(
            scenario_prompt=effective_prompt,
            log_types=log_types,
            rule_identifier=str(rule_identifier).strip() if rule_identifier else None,
            rule_outcome=rule_outcome,
            count=event_count,
            enrich_gti=enrich_gti,
            ingest_to_secops=ingest_to_secops,
            scenario_name=scenario_name,
            base_time=resolved_base_dt,
        )

        # 5. Output and JSON Attachment
        siemplify.result.add_result_json(results)
        result_value = True

        total_events = results.get("total_events", 0)
        types_str = ", ".join(results.get("log_types", []))
        secops_status = results.get("secops_ingestion", {}).get("status", "SKIPPED")
        ingested_count = results.get("secops_ingestion", {}).get("ingested_count", 0)
        udm_query = results.get("udm_query") or results.get("secops_ingestion", {}).get("udm_query", "")
        base_ts_str = results.get("base_timestamp", "")

        output_message = (
            f"Successfully generated {total_events} synthetic security events across log types [{types_str}] "
            f"(Anchor Base Timestamp: {base_ts_str}). "
            f"SecOps Ingestion Status: {secops_status} ({ingested_count} events ingested). "
            f"UDM Search: {udm_query}"
        )

    except Exception as err:
        import traceback
        tb_str = traceback.format_exc()
        siemplify.LOGGER.error(f"Failed to generate synthetic scenario: {err}\n{tb_str}")
        output_message = f"Error generating synthetic scenario logs: {str(err)}"
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
