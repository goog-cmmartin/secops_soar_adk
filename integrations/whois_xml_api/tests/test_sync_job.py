"""
Unit tests for whois_xml_api sync_monitored_domains_job.
"""
import pytest
from unittest.mock import patch
from SiemplifyJob import SiemplifyJob
from jobs.sync_monitored_domains_job import main


def test_sync_monitored_domains_success():
    SiemplifyJob.reset_mocks()
    SiemplifyJob.set_mock_job_params({
        "API Key": "mock-api-key",
        "Verify SSL": "true",
        "Domains to Monitor": "google.com, github.com",
    })
    SiemplifyJob.set_mock_timestamp(1600000000000)

    mock_details = {
        "domain_name": "google.com",
        "created_date": "1997-09-15T04:00:00Z",
        "expires_date": "2028-09-14T04:00:00Z",
        "registrar_name": "MarkMonitor Inc.",
    }

    with patch("core.whois_xml_manager.WhoisXMLManager.get_domain_details", return_value=mock_details) as mock_get:
        main()
        assert mock_get.call_count == 2

    # Checkpoint timestamp must have advanced
    assert SiemplifyJob().fetch_timestamp() > 1600000000000


def test_sync_monitored_domains_empty_list():
    SiemplifyJob.reset_mocks()
    SiemplifyJob.set_mock_job_params({
        "API Key": "mock-api-key",
        "Domains to Monitor": "",
    })

    with patch("core.whois_xml_manager.WhoisXMLManager.get_domain_details") as mock_get:
        main()
        mock_get.assert_not_called()
