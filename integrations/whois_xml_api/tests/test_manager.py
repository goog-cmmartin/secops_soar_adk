"""
Unit tests for WhoisXMLManager (Manager Pattern Validation).
Validates that the Manager operates correctly without any SOAR SDK dependencies.
"""
import pytest
from unittest.mock import patch, MagicMock
from core.whois_xml_manager import WhoisXMLManager, WhoisXMLManagerException


def test_manager_init_requires_api_key():
    with pytest.raises(WhoisXMLManagerException, match="API Key must be provided"):
        WhoisXMLManager(api_key="")


@patch("requests.Session.get")
def test_test_connectivity_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"WhoisRecord": {"domainName": "google.com"}}
    mock_resp.text = '{"WhoisRecord": {"domainName": "google.com"}}'
    mock_get.return_value = mock_resp

    manager = WhoisXMLManager(api_key="valid-test-key")
    result = manager.test_connectivity("google.com")

    assert result is True
    mock_get.assert_called_once()
    assert mock_get.call_args[1]["params"]["apiKey"] == "valid-test-key"


@patch("requests.Session.get")
def test_test_connectivity_invalid_key(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}
    mock_resp.text = "ApiKey authenticate failed"
    mock_get.return_value = mock_resp

    manager = WhoisXMLManager(api_key="bad-key")
    with pytest.raises(WhoisXMLManagerException, match="Invalid credentials"):
        manager.test_connectivity("google.com")


@patch("requests.Session.get")
def test_get_domain_details_success(mock_get, mock_whois_response):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_whois_response
    mock_get.return_value = mock_resp

    manager = WhoisXMLManager(api_key="valid-test-key")
    data = manager.get_domain_details("google.com", check_availability=True)

    assert data["WhoisRecord"]["domainName"] == "google.com"
    params = mock_get.call_args[1]["params"]
    assert params["domainName"] == "google.com"
    assert params["da"] == 1


@patch("requests.Session.get")
def test_get_domain_details_api_error_message(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"ErrorMessage": {"msg": "Daily limit exceeded"}}
    mock_get.return_value = mock_resp

    manager = WhoisXMLManager(api_key="valid-test-key")
    with pytest.raises(WhoisXMLManagerException, match="Daily limit exceeded"):
        manager.get_domain_details("example.com")
