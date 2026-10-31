"""
Scheduled Scenario Generator Job for LogJammer in Google SecOps SOAR.

Runs on a recurring schedule (Jobs Scheduler) to continuously generate and inject
synthetic attack telemetry into Google SecOps for automated detection pipeline testing,
detection regression validation, and purple team simulations.
"""

import sys
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler

try:
    from LogJammerManager import LogJammerManager
except ImportError:
    try:
        from core.LogJammerManager import LogJammerManager
    except ImportError:
        from ..core.LogJammerManager import LogJammerManager

JOB_NAME = "Scheduled Scenario Generator Job"
INTEGRATION_NAME = "LogJammer"


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = JOB_NAME
    siemplify.LOGGER.info("================= LogJammer Job Started =================")

    try:
        # 1. Job Parameters
        scenario_prompt = siemplify.extract_job_param(
            param_name="Scenario Prompt",
            default_value="Simulate unauthorized credential dumping and staging activity on workstation oscar.wild.desktop",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        rule_identifier = siemplify.extract_job_param(
            param_name="Rule Identifier",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        rule_outcome = siemplify.extract_job_param(
            param_name="Rule Outcome",
            default_value="fire",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        if rule_outcome not in ("fire", "evade", "full-chain"):
            rule_outcome = "fire"

        custom_scenario_name = siemplify.extract_job_param(
            param_name="Scenario Name",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        raw_log_types = siemplify.extract_job_param(
            param_name="Log Types",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        log_types = [t.strip().upper() for t in raw_log_types.split(",") if t.strip()] if raw_log_types else None

        raw_count = siemplify.extract_job_param(
            param_name="Event Count",
            default_value="5",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        try:
            event_count = max(1, min(100, int(raw_count)))
        except (ValueError, TypeError):
            event_count = 5

        ingest_param = siemplify.extract_job_param(
            param_name="Ingest to SecOps",
            default_value="true",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        if isinstance(ingest_param, str):
            ingest_to_secops = ingest_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(ingest_param, bool):
            ingest_to_secops = ingest_param
        else:
            ingest_to_secops = True

        enrich_param = siemplify.extract_job_param(
            param_name="Enrich with Google TI",
            default_value="false",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        if isinstance(enrich_param, str):
            enrich_gti = enrich_param.strip().lower() in ("true", "1", "yes")
        elif isinstance(enrich_param, bool):
            enrich_gti = enrich_param
        else:
            enrich_gti = False

        # 2. Extract configuration from LogJammer integration parameters
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

        scenario_name = (
            str(custom_scenario_name).strip()
            if custom_scenario_name and str(custom_scenario_name).strip()
            else "Scheduled_Pipeline_Validation"
        )

        # 4. Execute Scenario Generation & Ingestion
        results = manager.generate_scenario(
            scenario_prompt=str(scenario_prompt).strip(),
            log_types=log_types,
            rule_identifier=str(rule_identifier).strip() if rule_identifier else None,
            rule_outcome=rule_outcome,
            count=event_count,
            enrich_gti=enrich_gti,
            ingest_to_secops=ingest_to_secops,
            scenario_name=scenario_name,
        )

        total_events = results.get("total_events", 0)
        types_str = ", ".join(results.get("log_types", []))
        secops_status = results.get("secops_ingestion", {}).get("status", "SKIPPED")
        ingested_count = results.get("secops_ingestion", {}).get("ingested_count", 0)
        udm_query = results.get("udm_query") or results.get("secops_ingestion", {}).get("udm_query", "")

        siemplify.LOGGER.info(
            f"Scheduled run complete: generated {total_events} events [{types_str}]. "
            f"SecOps Ingestion: {secops_status} ({ingested_count} ingested). "
            f"UDM Search: {udm_query}"
        )

    except Exception as e:
        siemplify.LOGGER.error(f"Error during scheduled scenario execution: {e}")

    siemplify.LOGGER.info("================= LogJammer Job Ended =================")


if __name__ == "__main__":
    main()
