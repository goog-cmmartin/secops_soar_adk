"""
Tests for Template Integration Ping action and ClientManager.
"""
import pytest
from unittest.mock import patch, MagicMock
from SiemplifyAction import SiemplifyAction
from core.client_manager import ClientManager, ClientManagerException
from actions.ping import main


def test_client_manager_test_connectivity():
    with patch("requests.Session.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        manager = ClientManager(api_root="https://api.example.com", api_key="secret-token")
        assert manager.test_connectivity() is True


def test_ping_action_execution():
    SiemplifyAction.set_mock_configuration({
        "API Root": "https://api.example.com",
        "API Key": "secret-token",
        "Verify SSL": "true",
    })

    with patch("core.client_manager.ClientManager.test_connectivity", return_value=True):
        main()

    assert True
