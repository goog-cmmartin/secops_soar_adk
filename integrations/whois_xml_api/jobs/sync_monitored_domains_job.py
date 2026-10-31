"""
Scheduled Job: Sync Monitored Domains

Periodically pulls updated registration details for high-risk or monitored domain names
and refreshes local cache or context for threat intelligence analysts.
"""
import sys
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, unix_now

try:
    from core.whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException
except ImportError:
    from whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException

JOB_NAME = "Sync Monitored Domains"


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = JOB_NAME
    siemplify.LOGGER.info("================= Job Started =================")

    try:
        # 1. Extract job parameters
        api_key = siemplify.extract_job_param(
            param_name="API Key",
            is_mandatory=True,
            input_type=str,
        )
        verify_ssl = siemplify.extract_job_param(
            param_name="Verify SSL",
            default_value=True,
            input_type=bool,
        )
        domains_str = siemplify.extract_job_param(
            param_name="Domains to Monitor",
            default_value="",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )

        domains = [d.strip() for d in domains_str.split(",") if d.strip()]
        if not domains:
            siemplify.LOGGER.info("No domains specified to monitor. Job finished.")
            return

        # 2. Track incremental checkpoints using timestamps
        last_run_timestamp = siemplify.fetch_timestamp()
        siemplify.LOGGER.info(f"Last execution timestamp: {last_run_timestamp}")

        # 3. Instantiate Manager
        manager = WhoisXMLManager(api_key=api_key, verify_ssl=verify_ssl)

        # 4. Process domains
        success_count = 0
        for domain in domains:
            try:
                siemplify.LOGGER.info(f"Querying WHOIS records for: {domain}")
                details = manager.get_domain_details(domain_name=domain)
                created_date = details.get("created_date", "Unknown")
                expires_date = details.get("expires_date", "Unknown")
                registrar = details.get("registrar_name", "Unknown")
                siemplify.LOGGER.info(
                    f"Domain {domain} details: Created={created_date}, Expires={expires_date}, Registrar={registrar}"
                )
                success_count += 1
            except Exception as e:
                siemplify.LOGGER.error(f"Failed to fetch details for {domain}: {e}")

        siemplify.LOGGER.info(f"Successfully processed {success_count}/{len(domains)} domains.")

        # 5. Persist checkpoint timestamp
        now_ts = unix_now()
        siemplify.save_timestamp(new_timestamp=now_ts)
        siemplify.LOGGER.info(f"Checkpoint saved: {now_ts}")

    except Exception as err:
        siemplify.LOGGER.error(f"Job failed: {err}")
        raise

    siemplify.LOGGER.info("================= Job Finished =================")


if __name__ == "__main__":
    main()
