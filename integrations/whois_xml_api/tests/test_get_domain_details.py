"""
Unit tests for Get Domain Details action.
"""
import pytest
from unittest.mock import patch
from SiemplifyAction import SiemplifyAction
from actions.get_domain_details import main


def test_get_domain_details_success(mock_whois_response):
    SiemplifyAction.set_mock_configuration({
        "API Key": "mock-api-key",
        "Verify SSL": "true",
    })
    SiemplifyAction.set_mock_action_params({
        "Domain Name": "google.com",
        "Check availability": "false",
    })

    with patch(
        "core.whois_xml_manager.WhoisXMLManager.get_domain_details",
        return_value=mock_whois_response,
    ):
        main()

    assert True


def test_get_domain_details_missing_mandatory_domain():
    SiemplifyAction.set_mock_configuration({
        "API Key": "mock-api-key",
    })
    SiemplifyAction.set_mock_action_params({
        "Check availability": "false",
    })

    with pytest.raises(ValueError, match="Mandatory action parameter 'Domain Name' is missing"):
        main()
