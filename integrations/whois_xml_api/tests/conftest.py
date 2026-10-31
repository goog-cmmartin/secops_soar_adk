"""
Pytest configuration and shared fixtures for WHOIS XML API integration tests.
"""
import pytest
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import Entity, EntityTypes


@pytest.fixture(autouse=True)
def clean_siemplify_environment():
    """Reset mock configuration and action parameters before each test."""
    SiemplifyAction.reset_mocks()
    yield
    SiemplifyAction.reset_mocks()


@pytest.fixture
def mock_whois_response():
    """Sample raw response from WHOIS XML API."""
    return {
        "WhoisRecord": {
            "domainName": "google.com",
            "createdDate": "1997-09-15T04:00:00Z",
            "registrarName": "MarkMonitor, Inc.",
            "registrant": {
                "organization": "Google LLC",
                "country": "UNITED STATES",
                "email": "dns-admin@google.com",
            },
        }
    }


@pytest.fixture
def mock_target_entities():
    """Sample target entities for enrichment tests."""
    return [
        Entity(
            identifier="google.com",
            entity_type=EntityTypes.HOSTNAME,
            is_internal=False,
        ),
        Entity(
            identifier="https://evil.com/login",
            entity_type=EntityTypes.URL,
            is_internal=False,
        ),
        Entity(
            identifier="corp.local",
            entity_type=EntityTypes.HOSTNAME,
            is_internal=True,  # Internal should be skipped
        ),
        Entity(
            identifier="192.168.1.1",
            entity_type=EntityTypes.IPADDRESS,  # IP should be skipped
            is_internal=False,
        ),
    ]
