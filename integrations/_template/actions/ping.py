"""
Ping Action for Template Integration.

Mandatory action executed when clicking the 'Test' button in Google SecOps Content Hub / IDE.
"""
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from core.client_manager import ClientManager, ClientManagerException
except ImportError:
    from client_manager import ClientManager, ClientManagerException

INTEGRATION_NAME = "Template Integration"
SCRIPT_NAME = "Template Integration Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Ping - Started =================")

    # 1. Extract integration-level configuration parameters
    api_root = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="API Root",
        is_mandatory=True,
    )
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

    # 2. Test connectivity via Manager
    manager = ClientManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl)
    manager.test_connectivity()

    output_message = "Successful Connection"
    siemplify.LOGGER.info(output_message)
    siemplify.end(output_message, True)


if __name__ == "__main__":
    main()
