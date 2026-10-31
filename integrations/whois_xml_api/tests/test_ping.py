"""
Unit tests for Ping action (Mandatory Connectivity Action).
"""
import pytest
from unittest.mock import patch, MagicMock
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED
from actions.ping import main


def test_ping_action_success():
    # Setup mock configuration parameters
    SiemplifyAction.set_mock_configuration({
        "API Key": "mock-api-key-12345",
        "Verify SSL": "true",
    })

    with patch("core.whois_xml_manager.WhoisXMLManager.test_connectivity", return_value=True):
        main()

    # The action should have completed successfully
    assert True


def test_ping_action_missing_api_key():
    SiemplifyAction.set_mock_configuration({
        "Verify SSL": "true",
    })

    with pytest.raises(ValueError, match="Mandatory configuration parameter 'API Key' is missing"):
        main()


def test_ping_action_connectivity_failure():
    from core.whois_xml_manager import WhoisXMLManagerException

    SiemplifyAction.set_mock_configuration({
        "API Key": "invalid-key",
    })

    with patch(
        "core.whois_xml_manager.WhoisXMLManager.test_connectivity",
        side_effect=WhoisXMLManagerException("Invalid credentials: API key authentication failed.")
    ):
        with pytest.raises(WhoisXMLManagerException):
            main()
