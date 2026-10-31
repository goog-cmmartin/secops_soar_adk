"""
Mandatory Ping Action for WHOIS XML API Integration.

Tests connectivity and credentials with the WHOIS XML API.
This action is executed when clicking 'Test' in the Google SecOps Content Hub / IDE.
"""
import sys
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from core.whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException
except ImportError:
    from whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException

INTEGRATION_NAME = "My first Integration - Whois XML API"
SCRIPT_NAME = "Whois XML API Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Ping - Started =================")

    # 1. Extract integration-level configuration parameters
    api_key = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="API Key",
        is_mandatory=True,
    )
    verify_ssl = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        default_value=True,
        input_type=bool,
    )

    # 2. Initialize manager and test connectivity
    try:
        manager = WhoisXMLManager(api_key=api_key, verify_ssl=verify_ssl)
        manager.test_connectivity()

        output_message = "Successful Connection"
        result_value = True
        siemplify.LOGGER.info(output_message)

    except Exception as e:
        output_message = f"Failed to connect to WHOIS XML API: {str(e)}"
        siemplify.LOGGER.error(output_message)
        raise

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
