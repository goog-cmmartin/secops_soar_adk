"""
Template Scheduled Job for Google SecOps SOAR.

Performs periodic background tasks (e.g. synchronization, cache cleanup, IOC ingestion)
on a configured schedule (configured under Response > Jobs Scheduler).
"""
import sys
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, unix_now

try:
    from core.client_manager import ClientManager, ClientManagerException
except ImportError:
    from client_manager import ClientManager, ClientManagerException

JOB_NAME = "Sync Indicators Job"


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = JOB_NAME
    siemplify.LOGGER.info("================= Job Started =================")

    try:
        # 1. Extract job parameters
        environment = siemplify.extract_job_param(
            param_name="Environment",
            default_value="Default",
            input_type=str,
            is_mandatory=False,
            print_value=True,
        )
        batch_size = siemplify.extract_job_param(
            param_name="Batch Size",
            default_value=100,
            input_type=int,
            is_mandatory=False,
            print_value=True,
        )

        # 2. Retrieve integration credentials from marketplace instance or parameters
        # Example: config = siemplify.get_configuration(provider="Template Integration", environment=environment)
        api_root = siemplify.extract_job_param(
            param_name="API Root",
            default_value="https://api.example.com",
            input_type=str,
        )
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

        # 3. Retrieve the last execution timestamp for incremental processing
        last_run_timestamp = siemplify.fetch_timestamp(datetime_format=False)
        siemplify.LOGGER.info(f"Last execution timestamp: {last_run_timestamp}")

        # 4. Instantiate manager and perform work
        manager = ClientManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl)
        manager.test_connectivity()

        # In a real job, you would query recent items since last_run_timestamp:
        # indicators = manager.get_indicators_since(last_run_timestamp, limit=batch_size)
        # process_indicators(indicators)
        siemplify.LOGGER.info(f"Processed sync routine for environment '{environment}' with batch size {batch_size}.")

        # 5. Save the updated timestamp for the next scheduled execution
        new_timestamp = unix_now()
        siemplify.save_timestamp(new_timestamp=new_timestamp)
        siemplify.LOGGER.info(f"Updated job checkpoint to: {new_timestamp}")

    except Exception as err:
        siemplify.LOGGER.error(f"Job execution failed: {str(err)}")
        raise

    siemplify.LOGGER.info("================= Job Finished =================")


if __name__ == "__main__":
    main()
