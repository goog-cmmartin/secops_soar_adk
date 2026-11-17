import fcntl
import json
import os
import re
import sys
import time
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


CASE_CONTEXT_RULES_KEY = "logjammer_processed_rules"
CASE_SIMULATED_TAG = "LogJammer:Simulated"
IN_PROGRESS_TTL_SECONDS = 600.0


def _normalize_rule_signature(raw_name: str) -> str:
    """Strips Chronicle/SOAR detection UUID suffixes to yield the canonical rule name."""
    if not raw_name:
        return ""
    s = str(raw_name).strip()
    # Strip _GCHRONICLE_DE_<uuid>... suffix appended to Alert.Name
    s = re.sub(r"_GCHRONICLE_DE_[0-9A-Fa-f-]+.*$", "", s, flags=re.IGNORECASE)
    # Strip trailing _<uuid> alertGroupIdentifier suffix if present
    s = re.sub(
        r"_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        "",
        s,
    )
    return s.strip()


def _extract_alert_rule_and_loop_check(siemplify, scenario_prompt: str = "", target_rule_ids_str: str = ""):
    """
    Returns (canonical_rule_name, alert_id, is_feedback_loop, loop_reason).
    Prioritizes Alert.RuleGenerator so duplicate detections of the same rule share one signature.
    """
    canonical_rule = ""
    alert_id = ""
    alert_rule_id = ""
    is_loop = False
    loop_reason = ""

    target_rule_ids = {
        r.strip().lower()
        for r in str(target_rule_ids_str or "").split(",")
        if r.strip() and r.strip().upper() != "AUTO_PRECISE"
    }

    try:
        alert = getattr(siemplify, "current_alert", None)
        if alert:
            alert_vars = vars(alert) if hasattr(alert, "__dict__") else {}
            alert_id = str(
                getattr(alert, "identifier", None)
                or getattr(alert, "alert_id", None)
                or alert_vars.get("identifier")
                or ""
            ).strip()
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

            rule_gen = (
                props.get("RuleGenerator")
                or props.get("rule_generator")
                or getattr(alert, "rule_generator", None)
                or alert_vars.get("rule_generator")
            )
            fallback_name = (
                props.get("name_override")
                or props.get("AlertName")
                or props.get("Name")
                or getattr(alert, "name", None)
            )
            canonical_rule = _normalize_rule_signature(rule_gen or fallback_name or "")
            alert_rule_id = str(
                props.get("rule_id")
                or props.get("SourceRuleIdentifier")
                or props.get("sourceRuleIdentifier")
                or ""
            ).strip()

            # Check if this alert was itself fired by one of the target LogJammer rules
            if alert_rule_id and alert_rule_id.lower() in target_rule_ids:
                is_loop = True
                loop_reason = (
                    f"Alert rule_id '{alert_rule_id}' ({canonical_rule}) is one of the target "
                    f"LogJammer simulation rules ({sorted(target_rule_ids)})."
                )

            # Also inspect security_events for LogJammer SCENARIO_TAG ingestion labels
            sec_events = getattr(alert, "security_events", None) or []
            for ev in sec_events[:3]:
                ev_props = getattr(ev, "additional_properties", None) or {}
                ev_str = json.dumps(ev_props) if isinstance(ev_props, dict) else str(ev_props)
                if "SCENARIO_TAG" in ev_str or "SOAR_Case_" in ev_str and "_Simulation" in ev_str:
                    is_loop = True
                    loop_reason = "Alert underlying event contains LogJammer SCENARIO_TAG ingestion label."
                    break
    except Exception as e:
        siemplify.LOGGER.warn(f"Warning extracting canonical alert rule: {e}")

    # Fallback: parse from Scenario Prompt ("Alert Name / Rule: <Name> (<RuleGenerator>)")
    if not canonical_rule and scenario_prompt:
        m = re.search(r"Alert Name\s*/\s*Rule:\s*([^\n\r]+)", str(scenario_prompt))
        if m:
            line_val = m.group(1).strip()
            paren_m = re.search(r"\(([^()]+)\)\s*$", line_val)
            if paren_m and paren_m.group(1).strip():
                canonical_rule = _normalize_rule_signature(paren_m.group(1).strip())
            else:
                canonical_rule = _normalize_rule_signature(line_val)

    return canonical_rule, alert_id, is_loop, loop_reason


def _read_case_context_rules(siemplify, case_id: str) -> list:
    """Reads the JSON list of processed rule signatures from SOAR Case Context."""
    raw_val = None
    try:
        if hasattr(siemplify, "get_case_context_property"):
            raw_val = siemplify.get_case_context_property(CASE_CONTEXT_RULES_KEY)
        elif hasattr(siemplify, "get_context_property"):
            raw_val = siemplify.get_context_property(1, str(case_id), CASE_CONTEXT_RULES_KEY)
    except Exception:
        raw_val = None
    if not raw_val:
        return []
    if isinstance(raw_val, list):
        return [str(x).strip() for x in raw_val if str(x).strip()]
    if isinstance(raw_val, str):
        cleaned = raw_val.strip().strip('"')
        if cleaned.startswith("["):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                pass
        return [s.strip() for s in cleaned.split(",") if s.strip()]
    return []


def _write_case_context_rules(siemplify, case_id: str, rules_list: list) -> None:
    """Writes the JSON list of processed rule signatures to SOAR Case Context."""
    payload = json.dumps(rules_list)
    try:
        if hasattr(siemplify, "set_case_context_property"):
            siemplify.set_case_context_property(CASE_CONTEXT_RULES_KEY, payload)
        elif hasattr(siemplify, "set_context_property"):
            siemplify.set_context_property(1, str(case_id), CASE_CONTEXT_RULES_KEY, payload)
    except Exception as e:
        siemplify.LOGGER.warn(f"Non-fatal warning updating SOAR Case Context '{CASE_CONTEXT_RULES_KEY}': {e}")


def _claim_or_check_case_dedup(
    siemplify,
    case_id: str,
    canonical_rule: str,
    alert_id: str,
    dedup_scope: str,
):
    """
    Atomically checks & claims the simulation slot for (case_id, dedup_key) using:
      1. Exclusive OS file lock (/tmp/logjammer_case_state_{case_id}.lock)
      2. Persistent state file (/tmp/logjammer_case_state_{case_id}.json)
      3. SOAR Case Context list ('logjammer_processed_rules')
    Returns (already_claimed: bool, dedup_key: str, tracked_rules: list, existing_entry: dict).
    """
    scope_norm = str(dedup_scope or "Per Unique Rule in Case").strip().lower()
    if scope_norm in ("disabled", "none", "off", "false"):
        return False, "", [], {}

    effective_rule_label = canonical_rule or "Unknown_Alert_Rule"
    if "once per case" in scope_norm or scope_norm == "per_case":
        dedup_key = "__case__"
    else:
        dedup_key = effective_rule_label.lower()

    lock_path = f"/tmp/logjammer_case_state_{case_id}.lock"
    state_path = f"/tmp/logjammer_case_state_{case_id}.json"
    now = time.time()

    with open(lock_path, "w", encoding="utf-8") as lock_f:
        fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
        try:
            state = {"case_id": str(case_id), "rules": {}}
            if os.path.exists(state_path):
                try:
                    with open(state_path, "r", encoding="utf-8") as sf:
                        loaded = json.load(sf)
                        if isinstance(loaded, dict) and isinstance(loaded.get("rules"), dict):
                            state = loaded
                except Exception:
                    pass

            # Merge any rules already recorded in SOAR Case Context
            context_rules = _read_case_context_rules(siemplify, str(case_id))
            for cr in context_rules:
                cr_key = "__case__" if ("once per case" in scope_norm or scope_norm == "per_case") else cr.lower()
                if cr_key not in state["rules"]:
                    state["rules"][cr_key] = {
                        "rule_name": cr,
                        "status": "COMPLETED",
                        "timestamp": now,
                        "source": "soar_case_context",
                    }

            existing = state["rules"].get(dedup_key)
            if isinstance(existing, dict):
                age = now - float(existing.get("timestamp", 0))
                status = existing.get("status", "COMPLETED")
                if status == "COMPLETED" or (status == "IN_PROGRESS" and age < IN_PROGRESS_TTL_SECONDS):
                    tracked_names = [
                        v.get("rule_name", k) for k, v in state["rules"].items() if isinstance(v, dict)
                    ]
                    return True, dedup_key, tracked_names, existing

            # Claim the slot atomically before releasing the lock
            state["rules"][dedup_key] = {
                "rule_name": effective_rule_label,
                "alert_id": alert_id,
                "status": "IN_PROGRESS",
                "timestamp": now,
            }
            try:
                with open(state_path, "w", encoding="utf-8") as sf:
                    json.dump(state, sf)
            except Exception:
                pass

            tracked_names = [
                v.get("rule_name", k) for k, v in state["rules"].items() if isinstance(v, dict)
            ]
            _write_case_context_rules(siemplify, str(case_id), tracked_names)
            return False, dedup_key, tracked_names, {}
        finally:
            try:
                fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass


def _finalize_case_dedup(
    siemplify,
    case_id: str,
    dedup_key: str,
    canonical_rule: str,
    alert_id: str,
    success: bool,
    results: dict = None,
) -> list:
    """Updates the state file and SOAR Case Context after generation finishes (or rolls back on error)."""
    if not case_id or not dedup_key:
        return []
    lock_path = f"/tmp/logjammer_case_state_{case_id}.lock"
    state_path = f"/tmp/logjammer_case_state_{case_id}.json"
    tracked_names = []
    try:
        with open(lock_path, "w", encoding="utf-8") as lock_f:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
            try:
                state = {"case_id": str(case_id), "rules": {}}
                if os.path.exists(state_path):
                    try:
                        with open(state_path, "r", encoding="utf-8") as sf:
                            loaded = json.load(sf)
                            if isinstance(loaded, dict) and isinstance(loaded.get("rules"), dict):
                                state = loaded
                    except Exception:
                        pass

                if success:
                    summary = {}
                    if isinstance(results, dict):
                        summary = {
                            "scenario_id": results.get("scenario_id"),
                            "scenario_tag": results.get("scenario_tag"),
                            "base_timestamp": results.get("base_timestamp"),
                            "total_events": results.get("total_events"),
                            "log_types": results.get("log_types"),
                            "udm_query": results.get("udm_query"),
                            "secops_ingestion": results.get("secops_ingestion"),
                        }
                    state["rules"][dedup_key] = {
                        "rule_name": canonical_rule or "Unknown_Alert_Rule",
                        "alert_id": alert_id,
                        "status": "COMPLETED",
                        "timestamp": time.time(),
                        "summary": summary,
                    }
                else:
                    # Rollback IN_PROGRESS claim if generation failed so retries can run
                    if state["rules"].get(dedup_key, {}).get("status") == "IN_PROGRESS":
                        state["rules"].pop(dedup_key, None)

                try:
                    with open(state_path, "w", encoding="utf-8") as sf:
                        json.dump(state, sf)
                except Exception:
                    pass

                tracked_names = [
                    v.get("rule_name", k) for k, v in state["rules"].items() if isinstance(v, dict)
                ]
                _write_case_context_rules(siemplify, str(case_id), tracked_names)
            finally:
                try:
                    fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
    except Exception as e:
        siemplify.LOGGER.warn(f"Warning finalizing LogJammer case state: {e}")

    if success:
        try:
            if hasattr(siemplify, "add_tag"):
                siemplify.add_tag(CASE_SIMULATED_TAG)
        except Exception as e:
            siemplify.LOGGER.warn(f"Non-fatal warning attaching tag '{CASE_SIMULATED_TAG}': {e}")

    return tracked_names


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

        dedup_scope = siemplify.extract_action_param(
            "Deduplication Scope", default_value="Per Unique Rule in Case", print_value=True
        )
        dedup_scope = str(dedup_scope or "Per Unique Rule in Case").strip()

        case_id = getattr(siemplify, "case_id", None)
        canonical_rule, alert_id, is_feedback_loop, loop_reason = _extract_alert_rule_and_loop_check(
            siemplify,
            scenario_prompt=str(scenario_prompt).strip(),
            target_rule_ids_str=str(rule_identifier or ""),
        )

        if is_feedback_loop:
            output_message = (
                f"Skipped LogJammer generation on Case #{case_id} (feedback loop guard): {loop_reason}"
            )
            siemplify.LOGGER.info(output_message)
            siemplify.result.add_result_json(
                {
                    "skipped_feedback_loop": True,
                    "case_id": str(case_id or ""),
                    "alert_id": alert_id,
                    "canonical_rule": canonical_rule,
                    "reason": loop_reason,
                }
            )
            siemplify.end(output_message, True, EXECUTION_STATE_COMPLETED)
            return

        dedup_key = ""
        if case_id:
            already_claimed, dedup_key, tracked_rules, existing_entry = _claim_or_check_case_dedup(
                siemplify=siemplify,
                case_id=str(case_id),
                canonical_rule=canonical_rule,
                alert_id=alert_id,
                dedup_scope=dedup_scope,
            )
            if already_claimed:
                output_message = (
                    f"Skipped duplicate LogJammer simulation on Case #{case_id}: "
                    f"alert rule '{canonical_rule or dedup_key}' was already claimed/simulated in this case "
                    f"(Deduplication Scope: {dedup_scope}; Tracked Case Rules: {tracked_rules})."
                )
                siemplify.LOGGER.info(output_message)
                skip_payload = {
                    "skipped_duplicate_rule": True,
                    "case_id": str(case_id),
                    "alert_id": alert_id,
                    "canonical_rule": canonical_rule,
                    "deduplication_scope": dedup_scope,
                    "tracked_case_rules": tracked_rules,
                    "previous_simulation": existing_entry.get("summary") if isinstance(existing_entry, dict) else {},
                }
                if isinstance(existing_entry, dict) and isinstance(existing_entry.get("summary"), dict):
                    for k, v in existing_entry["summary"].items():
                        if v is not None and k not in skip_payload:
                            skip_payload[k] = v
                siemplify.result.add_result_json(skip_payload)
                siemplify.end(output_message, True, EXECUTION_STATE_COMPLETED)
                return

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

        tracked_rules = []
        if case_id and dedup_key:
            tracked_rules = _finalize_case_dedup(
                siemplify=siemplify,
                case_id=str(case_id),
                dedup_key=dedup_key,
                canonical_rule=canonical_rule,
                alert_id=alert_id,
                success=True,
                results=results if isinstance(results, dict) else {},
            )
            if isinstance(results, dict):
                results["canonical_rule"] = canonical_rule
                results["deduplication_scope"] = dedup_scope
                results["tracked_case_rules"] = tracked_rules

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
            f"for rule '{canonical_rule or 'N/A'}' (Anchor Base Timestamp: {base_ts_str}). "
            f"SecOps Ingestion Status: {secops_status} ({ingested_count} events ingested). "
            f"Tracked Case Rules: {tracked_rules}. UDM Search: {udm_query}"
        )

    except Exception as err:
        try:
            if "case_id" in locals() and case_id and "dedup_key" in locals() and dedup_key:
                _finalize_case_dedup(
                    siemplify=siemplify,
                    case_id=str(case_id),
                    dedup_key=dedup_key,
                    canonical_rule=canonical_rule if "canonical_rule" in locals() else "",
                    alert_id=alert_id if "alert_id" in locals() else "",
                    success=False,
                )
        except Exception:
            pass
        import traceback
        tb_str = traceback.format_exc()
        siemplify.LOGGER.error(f"Failed to generate synthetic scenario: {err}\n{tb_str}")
        output_message = f"Error generating synthetic scenario logs: {str(err)}"
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
