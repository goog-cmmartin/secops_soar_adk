"""
Get Domain Details Action for WHOIS XML API Integration.

Retrieves detailed registration information and optional availability for a given domain name.
"""
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

try:
    from core.whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException
except ImportError:
    from whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException

INTEGRATION_NAME = "My first Integration - Whois XML API"
SCRIPT_NAME = "Whois XML API GetDomainDetails"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Get Domain Details - Started =================")

    # 1. Extract integration configuration parameters
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

    # 2. Extract action parameters
    domain = siemplify.extract_action_param(
        param_name="Domain Name",
        is_mandatory=True,
        print_value=True,
    )
    check_availability = siemplify.extract_action_param(
        param_name="Check availability",
        default_value=False,
        input_type=bool,
        print_value=True,
    )

    # 3. Execute query via Manager
    manager = WhoisXMLManager(api_key=api_key, verify_ssl=verify_ssl)
    result = manager.get_domain_details(domain_name=domain, check_availability=check_availability)

    # 4. Add structured JSON results
    # add_result_json allows downstream playbook blocks to read specific fields
    siemplify.result.add_result_json(result)
    # add_json surfaces the result in the alert/case context view in the SOAR UI
    siemplify.result.add_json("WhoisDetails", result)

    output_message = f"Successfully fetched WHOIS data for domain: {domain}"
    siemplify.LOGGER.info(output_message)
    siemplify.end(output_message, True)


if __name__ == "__main__":
    main()
