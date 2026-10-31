"""
Pytest configuration for Template Integration.
"""
import pytest
from SiemplifyAction import SiemplifyAction


@pytest.fixture(autouse=True)
def clean_siemplify_environment():
    SiemplifyAction.reset_mocks()
    yield
    SiemplifyAction.reset_mocks()
