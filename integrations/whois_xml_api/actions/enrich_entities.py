"""
Enrich Entities Action for WHOIS XML API Integration.

Iterates over alert target entities (HOSTNAME and URL), extracts domain details via WHOIS XML API,
and enriches each entity with registrant and registrar information.
"""
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes

try:
    from core.whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException
except ImportError:
    from whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException

INTEGRATION_NAME = "My first Integration - Whois XML API"
SCRIPT_NAME = "Whois XML API EnrichEntities"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

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

    manager = WhoisXMLManager(api_key=api_key, verify_ssl=verify_ssl)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    successful_entities = []
    failed_entities = []
    json_results = {}

    for entity in siemplify.target_entities:
        siemplify.LOGGER.info(f"Evaluating entity: {entity.identifier} (Type: {entity.entity_type})")

        # Process external Hostnames and URLs
        is_external_host = (entity.entity_type == EntityTypes.HOSTNAME and not entity.is_internal)
        is_url = (entity.entity_type == EntityTypes.URL)

        if not (is_external_host or is_url):
            siemplify.LOGGER.info(f"Skipping entity {entity.identifier} - not an external hostname or URL.")
            continue

        domain_to_query = entity.identifier
        # If entity is URL, strip scheme/path if needed
        if "://" in domain_to_query:
            domain_to_query = domain_to_query.split("://")[1].split("/")[0]

        try:
            data = manager.get_domain_details(domain_name=domain_to_query)
            whois_record = data.get("WhoisRecord", {})

            # Extract registrant details
            registrant = whois_record.get("registrant", {})
            additional_props = {}
            if registrant:
                if "organization" in registrant:
                    additional_props["whois_registrant_org"] = registrant["organization"]
                if "country" in registrant:
                    additional_props["whois_registrant_country"] = registrant["country"]
                if "email" in registrant:
                    additional_props["whois_registrant_email"] = registrant["email"]

            registrar_name = whois_record.get("registrarName")
            if registrar_name:
                additional_props["whois_registrar_name"] = registrar_name

            created_date = whois_record.get("createdDate")
            if created_date:
                additional_props["whois_created_date"] = created_date

            if additional_props:
                entity.additional_properties.update(additional_props)

            json_results[entity.identifier] = data
            successful_entities.append(entity.identifier)
            siemplify.LOGGER.info(f"Successfully enriched entity: {entity.identifier}")

        except Exception as err:
            siemplify.LOGGER.error(f"Error enriching {entity.identifier}: {str(err)}")
            failed_entities.append(entity.identifier)

    # 4. Finalize results
    if successful_entities:
        output_message = f"Successfully enriched {len(successful_entities)} entities:\n" + "\n".join(f" - {e}" for e in successful_entities)
        if failed_entities:
            output_message += f"\nFailed entities ({len(failed_entities)}):\n" + "\n".join(f" - {e}" for e in failed_entities)
        result_value = True
    else:
        output_message = "No entities were enriched."
        result_value = False

    if json_results:
        siemplify.result.add_result_json(json_results)
        siemplify.result.add_json("EnrichedWhoisDetails", json_results)

    siemplify.LOGGER.info(output_message)
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
