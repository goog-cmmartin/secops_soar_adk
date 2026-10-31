"""
Unit tests for Enrich Entities action.
Validates entity type filtering, internal host exclusion, and additional_properties updates.
"""
from unittest.mock import patch
from SiemplifyAction import SiemplifyAction
from actions.enrich_entities import main


def test_enrich_entities_success(mock_whois_response, mock_target_entities):
    SiemplifyAction.set_mock_configuration({
        "API Key": "mock-api-key",
        "Verify SSL": "true",
    })
    SiemplifyAction.set_mock_entities(mock_target_entities)

    with patch(
        "core.whois_xml_manager.WhoisXMLManager.get_domain_details",
        return_value=mock_whois_response,
    ):
        main()

    # Check google.com entity was enriched
    google_entity = next(e for e in mock_target_entities if e.identifier == "google.com")
    assert "whois_registrant_org" in google_entity.additional_properties
    assert google_entity.additional_properties["whois_registrant_org"] == "Google LLC"
    assert google_entity.additional_properties["whois_registrar_name"] == "MarkMonitor, Inc."

    # Check internal host was skipped
    internal_entity = next(e for e in mock_target_entities if e.identifier == "corp.local")
    assert not internal_entity.additional_properties

    # Check IP was skipped
    ip_entity = next(e for e in mock_target_entities if e.identifier == "192.168.1.1")
    assert not ip_entity.additional_properties


def test_enrich_entities_no_matching_entities():
    SiemplifyAction.set_mock_configuration({
        "API Key": "mock-api-key",
        "Verify SSL": "true",
    })
    # Empty entities
    SiemplifyAction.set_mock_entities([])
    main()
    assert True
