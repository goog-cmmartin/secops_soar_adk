"""
Unit tests for template sync_indicators_job.
"""
import pytest
from unittest.mock import patch
from SiemplifyJob import SiemplifyJob
from jobs.sync_indicators_job import main


def test_sync_job_success():
    SiemplifyJob.reset_mocks()
    SiemplifyJob.set_mock_job_params({
        "Environment": "Production",
        "Batch Size": "50",
        "API Root": "https://api.example.com",
        "API Key": "dummy-token",
        "Verify SSL": "true",
    })
    SiemplifyJob.set_mock_timestamp(1600000000000)

    with patch("core.client_manager.ClientManager.test_connectivity", return_value=True):
        main()

    # Verify that timestamp was updated
    new_ts = SiemplifyJob().fetch_timestamp()
    assert new_ts > 1600000000000


def test_sync_job_missing_mandatory_api_key():
    SiemplifyJob.reset_mocks()
    SiemplifyJob.set_mock_job_params({
        "API Root": "https://api.example.com",
    })

    with pytest.raises(ValueError, match="Mandatory job parameter 'API Key' is missing"):
        main()
