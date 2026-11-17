import json
import os
import sys
import time
import unicodedata
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from GoogleADKManager import GoogleADKManager, google_search
except ImportError:
    try:
        from core.GoogleADKManager import GoogleADKManager, google_search
    except ImportError:
        from ..core.GoogleADKManager import GoogleADKManager, google_search

INTEGRATION_NAME = "GoogleADK"
SCRIPT_NAME = "Run ADK Agent"
CASE_CONTEXT_ADK_CACHE_KEY = "ADK_AGENT_CACHED_RESULT"


def _is_valid_adk_report(text: str) -> bool:
    """Checks that a cached or recovered final_response is a real report and not a skip status or simulation echo."""
    if not text or not isinstance(text, str):
        return False
    stripped = text.strip()
    if not stripped:
        return False
    if "reusing cached ADK Agent result to preserve Case Overview widget" in stripped:
        return False
    if "Processed request:" in stripped and "All validation checks passed." in stripped:
        return False
    if "**Verdict:** `<Level 1>`" in stripped or "**Verdict:** <Level 1>" in stripped:
        return False
    return True


def _read_case_context_adk_cache(siemplify, case_id: str):
    """Reads the cached ADK Agent entry from SOAR's persistent Case Context DB."""
    if not case_id:
        return None
    raw_val = None
    try:
        if hasattr(siemplify, "get_case_context_property"):
            raw_val = siemplify.get_case_context_property(CASE_CONTEXT_ADK_CACHE_KEY)
        elif hasattr(siemplify, "get_context_property"):
            raw_val = siemplify.get_context_property(1, str(case_id), CASE_CONTEXT_ADK_CACHE_KEY)
    except Exception:
        raw_val = None
    if not raw_val:
        return None
    if isinstance(raw_val, dict):
        return raw_val
    if isinstance(raw_val, str):
        cleaned = raw_val.strip()
        if cleaned.startswith("{"):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
    return None


def _write_case_context_adk_cache(siemplify, case_id: str, cache_entry: dict) -> None:
    """Persists the ADK Agent cache entry to SOAR's Case Context DB across ephemeral workers."""
    if not case_id or not isinstance(cache_entry, dict):
        return
    try:
        payload = json.dumps(cache_entry)
        if hasattr(siemplify, "set_case_context_property"):
            siemplify.set_case_context_property(CASE_CONTEXT_ADK_CACHE_KEY, payload)
        elif hasattr(siemplify, "set_context_property"):
            siemplify.set_context_property(1, str(case_id), CASE_CONTEXT_ADK_CACHE_KEY, payload)
    except Exception as e:
        siemplify.LOGGER.info(f"Non-fatal warning saving Case Context '{CASE_CONTEXT_ADK_CACHE_KEY}': {e}")


def _recover_adk_report_from_case_comments(
    secops_engine,
    case_id: str,
    agent_name: str,
    model_name: str,
    session_id: str,
):
    """
    Recovers the most recent ADK Triage Report Markdown from the SOAR Case Wall comments
    when ephemeral /tmp or Case Context was not yet populated (e.g., existing cases or job-triaged cases).
    """
    if not secops_engine or not case_id:
        return None
    try:
        comments = secops_engine.list_case_comments(str(case_id)) or []
    except Exception:
        try:
            comments = secops_engine.adapter.list_case_comments(str(case_id)) or []
        except Exception:
            comments = []

    report_markers = (
        "**Verdict:**",
        "Tier 1 Autonomous Triage Report",
        "# Incident Triage Report",
        "# Incident Investigation Report",
    )
    for cm in comments:
        if isinstance(cm, dict):
            text = str(cm.get("comment") or "").strip()
            cm_id = str(cm.get("name") or cm.get("id") or "").split("/")[-1]
        else:
            text = str(getattr(cm, "comment", "") or "").strip()
            cm_id = str(getattr(cm, "comment_id", "") or getattr(cm, "name", "") or "").split("/")[-1]

        if not _is_valid_adk_report(text):
            continue
        if text.startswith("### [Automated Correlation]"):
            continue
        if any(marker in text for marker in report_markers):
            return {
                "case_id": str(case_id),
                "agent_name": agent_name,
                "model": model_name,
                "session_id": session_id or f"case_{case_id}",
                "final_response": text,
                "thoughts": [
                    f"Recovered prior ADK Triage Report from Case #{case_id} Wall"
                    + (f" (Comment #{cm_id})" if cm_id else "")
                    + " to preserve Case Overview widget on playbook re-run."
                ],
                "recovered_from_case_wall": True,
            }
    return None


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = False

    try:
        api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        workload_identity_email = siemplify.extract_configuration_param(INTEGRATION_NAME, "Workload Identity Email")
        model_name = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "Model Name", default_value="gemini-3.8-flash"
        )
        proj_id = siemplify.extract_configuration_param(
            INTEGRATION_NAME, "GCP Project ID"
        ) or siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        agent_engine_resource = siemplify.extract_configuration_param(INTEGRATION_NAME, "Agent Engine Resource Name")

        raw_agent_name = siemplify.extract_action_param("Agent Name", default_value="Logic_Analyst_Agent")
        sanitized_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(raw_agent_name).strip())
        case_id_tag = f"_{siemplify.case_id}" if getattr(siemplify, "case_id", None) else ""
        agent_name = f"{sanitized_name}{case_id_tag}"

        user_prompt = siemplify.extract_action_param("User Prompt")
        if not user_prompt or not str(user_prompt).strip():
            raise ValueError("The 'User Prompt' parameter is required and cannot be empty.")

        raw_budget = siemplify.extract_action_param("Thinking Budget", default_value=0)
        try:
            thinking_budget = int(raw_budget) if raw_budget else 0
            if thinking_budget < 0:
                raise ValueError()
        except ValueError:
            raise ValueError(f"'Thinking Budget' must be a non-negative integer, got: '{raw_budget}'")

        enable_search = str(siemplify.extract_action_param("Enable Google Search", default_value=False)).lower() in ("true", "1")
        enable_memory = str(siemplify.extract_action_param("Enable Memory", default_value=False)).lower() in ("true", "1")
        raw_session_id = siemplify.extract_action_param("Session ID")

        manager = GoogleADKManager(
            api_key=api_key,
            service_account_json=sa_json,
            workload_identity_email=workload_identity_email,
            model_name=model_name,
            project_id=proj_id,
            location=region,
            logger=siemplify.LOGGER,
            agent_engine_resource_name=agent_engine_resource,
        )

        session_id, memory_service, memory_tools = manager.resolve_memory_configuration(
            enable_memory=enable_memory, session_id=raw_session_id, case_id=getattr(siemplify, "case_id", None)
        )

        base_instructions = (
            "You are a Senior SecOps Incident Responder powered by Google ADK. "
            "Provide rigorous technical reasoning and summarize findings in Markdown.\n\n"
            "### MANDATORY 3-TIER TRIAGE TAXONOMY ###\n"
            "At the very top of your report (immediately below the main `# Title` heading), you MUST output a "
            "single blockquote triage classification line in this exact format:\n"
            "> **Verdict:** `<Level 1 Primary Verdict>` | **Disposition:** `<Level 2 Sub-Classification>` | **Confidence:** `<HIGH / MEDIUM / LOW>`\n\n"
            "**1. Primary Verdict (Level 1 — Detection Validity & Intent):**\n"
            "- `True Positive (Malicious)` — Confirmed or suspected threat actor activity requiring containment.\n"
            "- `Benign Positive (BTP)` — Detection rule fired accurately on real activity, but the activity is non-malicious (e.g., authorized admin/automation, red team/pentest, or non-malicious policy violation).\n"
            "- `False Positive (FP)` — Detection rule misfired due to rule logic, log parser/normalization flaw, or noisy threshold.\n"
            "- `Inconclusive / Undetermined` — Cannot be proven malicious or benign from available telemetry alone.\n\n"
            "**2. Disposition / Sub-Classification (Level 2 — Root Cause & Routing Trigger):**\n"
            "- Under `True Positive (Malicious)`: `Malicious — Active Compromise / Intrusion`, `Malicious — Automated Opportunistic Scanning / Blocked Exploit`, or `Malicious — PUP / Greyware`.\n"
            "- Under `Benign Positive (BTP)`: `Authorized Admin / Business Activity`, `Authorized Security Testing / Red Team / BAS`, or `Policy Violation / Misconfiguration (Non-Malicious)`.\n"
            "- Under `False Positive (FP)`: `Rule Logic / Threshold Too Broad` or `Log Parser / Telemetry Artifact`.\n"
            "- Under `Inconclusive / Undetermined`: `Insufficient Telemetry / Needs Human Input`.\n\n"
            "**3. Investigative Confidence (Level 3 — Anchored to Evidence):**\n"
            "- `HIGH` — Corroborated across multiple independent signals/events.\n"
            "- `MEDIUM` — Consistent with the verdict, but relies on a single data source or lacks definitive intent proof.\n"
            "- `LOW` — Circumstantial or missing key context.\n\n"
            "**4. Authoritative SOC Governance Data Tables & Token-Efficient Hunting Tools:**\n"
            "- **PipedSQL Hunting (`query_udm_sql` / `validate_udm_sql`)**: Prefer `query_udm_sql` with GoogleSQL Pipe Syntax (`FROM events |> WHERE ... |> AGGREGATE ...`) over raw event dumps to profile entities with minimal token overhead. Always alias expressions in `|> EXTEND`, `|> AGGREGATE`, and `GROUP BY` (`AS alias`), use `NULLIF(col, '') IS NOT NULL` for empty proto3 strings, `[SAFE_OFFSET(0)]` for repeated fields, and never use `PROTO` as an alias.\n"
            "- **Governance Data Tables (`get_soc_triage_sop`)**: When mapping your 3-Tier Verdict & Disposition to Alert Status (`OPEN` / `CLOSE`), Priority, Case Stage, Incident flag, Case Tags (`add_soar_case_tag`), or Courses of Action (COA), call `get_soc_triage_sop()` (or `list_data_table_rows` on `soc_triage_sop_matrix` & `soc_case_tag_taxonomy`) as the single source of truth.\n\n"
            "**5. Tailored Next Steps by Disposition:**\n"
            "- If `True Positive (Malicious)` -> Provide **Containment, Eradication & Recovery CLI/SOAR Steps**.\n"
            "- If `Benign Positive (BTP)` + `Policy Violation / Misconfiguration` -> Skip aggressive IR containment and provide **IAM/Configuration Hardening & User Coaching Steps**.\n"
            "- If `Benign Positive (BTP)` + `Authorized Admin / Business Activity` or `Security Testing` -> Provide **Scope Verification & Detection Tuning / Allowlisting Recommendations**.\n"
            "- If `False Positive (FP)` -> Provide **YARA-L Rule / Parser Bug Tuning Recommendations** for Detection Engineering."
        )

        # Add SecOps SDK Engine tools (silent detection correlation, UDM search, detection rules)
        cust_id = (
            siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, param_name="SecOps Customer ID")
            or siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, param_name="Customer ID")
            or os.environ.get("SECOPS_CUSTOMER_ID")
            or ""
        )
        secops_engine_tools = manager.init_secops_engine_toolset(
            customer_id=cust_id,
            project_id=proj_id,
            region=region,
        )

        # Idempotency & multi-alert fan-in cooldown guard:
        # Preserves full cached JsonResult so Case Overview HTML widgets are never blanked out by duplicate queued runs.
        active_case_id = getattr(siemplify, "case_id", None)
        cache_file = f"/tmp/soar_action_cache_adk_agent_{active_case_id}.json" if active_case_id else None
        current_alert_count = 0
        if active_case_id and hasattr(manager, "secops_engine") and manager.secops_engine:
            try:
                existing_case = manager.secops_engine.adapter.get_case(str(active_case_id), expand="tags")
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
                if cache_file and os.path.exists(cache_file):
                    try:
                        with open(cache_file, "r", encoding="utf-8") as cf:
                            cached_entry = json.load(cf)
                    except Exception:
                        cached_entry = None

                cached_results = cached_entry.get("results") if isinstance(cached_entry, dict) else None
                if not (isinstance(cached_results, dict) and _is_valid_adk_report(cached_results.get("final_response"))):
                    ctx_entry = _read_case_context_adk_cache(siemplify, str(active_case_id))
                    if isinstance(ctx_entry, dict):
                        ctx_res = ctx_entry.get("results") if isinstance(ctx_entry.get("results"), dict) else ctx_entry
                        if isinstance(ctx_res, dict) and _is_valid_adk_report(ctx_res.get("final_response")):
                            cached_entry = ctx_entry if "results" in ctx_entry else {
                                "timestamp": time.time(),
                                "alert_count": current_alert_count,
                                "has_logjammer_simulated": "LogJammer:Simulated" in existing_tags,
                                "results": ctx_res,
                            }
                            cached_results = ctx_res

                cache_age = (time.time() - float(cached_entry.get("timestamp", 0))) if isinstance(cached_entry, dict) else 999999.0
                logjammer_newly_simulated = (
                    "LogJammer:Simulated" in existing_tags
                    and not (isinstance(cached_entry, dict) and bool(cached_entry.get("has_logjammer_simulated")))
                )
                is_recent_same_alerts = (
                    isinstance(cached_results, dict)
                    and _is_valid_adk_report(cached_results.get("final_response"))
                    and not logjammer_newly_simulated
                    and cache_age < 180.0
                    and int(cached_entry.get("alert_count", -1)) == current_alert_count
                )

                if ("Tier1:Triaged" in existing_tags and not logjammer_newly_simulated) or is_recent_same_alerts:
                    # Tier 2 fallback: If ephemeral /tmp and Case Context both missed, recover report from Case Wall comments
                    if not (isinstance(cached_results, dict) and _is_valid_adk_report(cached_results.get("final_response"))):
                        recovered = _recover_adk_report_from_case_comments(
                            secops_engine=manager.secops_engine,
                            case_id=str(active_case_id),
                            agent_name=agent_name,
                            model_name=model_name,
                            session_id=session_id,
                        )
                        if isinstance(recovered, dict) and _is_valid_adk_report(recovered.get("final_response")):
                            cached_results = recovered
                            recovered_entry = {
                                "timestamp": time.time(),
                                "alert_count": current_alert_count,
                                "has_logjammer_simulated": "LogJammer:Simulated" in existing_tags,
                                "results": recovered,
                            }
                            _write_case_context_adk_cache(siemplify, str(active_case_id), recovered_entry)
                            if cache_file:
                                try:
                                    with open(cache_file, "w", encoding="utf-8") as cf:
                                        json.dump(recovered_entry, cf)
                                except Exception:
                                    pass

                    if isinstance(cached_results, dict) and _is_valid_adk_report(cached_results.get("final_response")):
                        skip_reason = (
                            f"already carries 'Tier1:Triaged' tag ({existing_tags})"
                            if "Tier1:Triaged" in existing_tags
                            else f"already executed ADK Agent {cache_age:.1f}s ago with unchanged alert count ({current_alert_count})"
                        )
                        output_message = (
                            f"Case '{active_case_id}' {skip_reason}; "
                            f"reusing cached ADK Agent result to preserve Case Overview widget."
                        )
                        siemplify.LOGGER.info(output_message)
                        payload_out = dict(cached_results)
                        payload_out["reused_cached_result"] = True
                        payload_out["existing_tags"] = existing_tags
                        final_resp = str(payload_out.get("final_response"))
                        siemplify.result.add_result_json(payload_out)
                        siemplify.result.add_json("ADK_Agent_Results", payload_out)
                        siemplify.end(output_message, final_resp, EXECUTION_STATE_COMPLETED)
                        return
                    else:
                        siemplify.LOGGER.info(
                            f"Case '{active_case_id}' carries 'Tier1:Triaged' tag, but no prior ADK report was found in "
                            f"/tmp, Case Context, or Case Wall comments; proceeding with ADK Agent execution."
                        )
            except Exception as tag_check_err:
                siemplify.LOGGER.info(f"Pre-flight tag/cache check skipped: {tag_check_err}")

        agent_tools = []
        if enable_search:
            agent_tools.append(google_search)
        if secops_engine_tools:
            agent_tools.extend(secops_engine_tools)
        if memory_tools:
            agent_tools.extend(memory_tools)

        results = manager.run_agent(
            agent_name=agent_name,
            instructions=base_instructions,
            input_text=user_prompt,
            tools=agent_tools,
            thinking_budget=thinking_budget,
            session_id=session_id,
            memory_service=memory_service,
            enable_google_search=enable_search,
        )

        result_value = results.get("final_response", "")
        if not result_value:
            result_value = f"ADK Agent '{agent_name}' completed analysis. (Check JSON Result for execution thoughts and metadata)."
        output_message = f"ADK Agent '{agent_name}' completed successfully."

        if isinstance(results, dict) and _is_valid_adk_report(results.get("final_response")):
            cache_entry_to_save = {
                "timestamp": time.time(),
                "alert_count": current_alert_count,
                "has_logjammer_simulated": (
                    "LogJammer:Simulated" in (existing_tags if "existing_tags" in locals() else [])
                ),
                "results": results,
            }
            if active_case_id:
                _write_case_context_adk_cache(siemplify, str(active_case_id), cache_entry_to_save)
            if cache_file:
                try:
                    with open(cache_file, "w", encoding="utf-8") as cf:
                        json.dump(cache_entry_to_save, cf)
                except Exception:
                    pass

        siemplify.result.add_result_json(results)
        siemplify.result.add_json("ADK_Agent_Results", results)

    except Exception as e:
        try:
            if "active_case_id" in locals() and active_case_id and "manager" in locals() and hasattr(manager, "secops_engine") and manager.secops_engine:
                manager.secops_engine.remove_case_tag(str(active_case_id), "Run_Case_Correlation")
        except Exception:
            pass
        normalized = unicodedata.normalize("NFKD", str(e))
        clean_msg = normalized.encode("ascii", "ignore").decode("ascii")
        output_message = f"Error executing {SCRIPT_NAME}: {clean_msg}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
