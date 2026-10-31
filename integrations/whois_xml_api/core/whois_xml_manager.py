"""
Manager class for WHOIS XML API.

Best practice:
- Managers act as client wrappers for external APIs.
- Managers SHOULD NOT import Siemplify SDK modules.
- Managers must be 100% testable independently of the SOAR execution environment.
"""
import requests


class WhoisXMLManagerException(Exception):
    """Custom exception raised for WHOIS XML API errors."""
    pass


class WhoisXMLManager:
    """Wrapper client for WHOIS XML API requests."""

    BASE_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    def __init__(self, api_key: str, verify_ssl: bool = True):
        """
        Initialize the manager with credentials and connection settings.

        :param api_key: The WHOIS XML API key.
        :param verify_ssl: Whether to verify SSL certificates.
        """
        if not api_key:
            raise WhoisXMLManagerException("API Key must be provided.")

        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def test_connectivity(self, test_domain: str = "google.com") -> bool:
        """
        Test API authentication and connectivity.
        Used by the mandatory Ping action.

        :param test_domain: Domain to use for connectivity test.
        :return: True if authentication succeeds.
        :raises WhoisXMLManagerException: If credentials are invalid or connection fails.
        """
        params = {
            "apiKey": self.api_key,
            "domainName": test_domain,
            "outputFormat": "JSON",
        }

        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            self.validate_response(response, "Connectivity test failed")

            data = response.json()
            if "ErrorMessage" in data:
                err_msg = data["ErrorMessage"].get("msg", "Unknown error")
                raise WhoisXMLManagerException(f"WHOIS XML API Error: {err_msg}")

            raw_text = response.text
            if "ApiKey authenticate failed" in raw_text:
                raise WhoisXMLManagerException("Invalid credentials: API key authentication failed.")

            return True

        except requests.RequestException as e:
            raise WhoisXMLManagerException(f"Failed to connect to WHOIS XML API: {str(e)}") from e

    def get_domain_details(self, domain_name: str, check_availability: bool = False) -> dict:
        """
        Fetch WHOIS domain information and optional availability.

        :param domain_name: The domain name to inspect.
        :param check_availability: Whether to query domain availability.
        :return: Parsed JSON dictionary of domain details.
        :raises WhoisXMLManagerException: If query fails.
        """
        if not domain_name:
            raise WhoisXMLManagerException("Domain Name parameter cannot be empty.")

        params = {
            "apiKey": self.api_key,
            "domainName": domain_name,
            "outputFormat": "JSON",
            "da": 1 if check_availability else 0,
        }

        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            self.validate_response(response, f"Failed to retrieve WHOIS details for domain: {domain_name}")

            data = response.json()
            if "ErrorMessage" in data:
                err_msg = data["ErrorMessage"].get("msg", "Unknown error")
                raise WhoisXMLManagerException(f"WHOIS API Error for '{domain_name}': {err_msg}")

            return data

        except requests.RequestException as e:
            raise WhoisXMLManagerException(f"Request failed for domain '{domain_name}': {str(e)}") from e

    @staticmethod
    def validate_response(response: requests.Response, error_msg: str = "An error occurred"):
        """
        Validate HTTP response status code.

        :param response: requests.Response object.
        :param error_msg: Contextual message to include on failure.
        :raises WhoisXMLManagerException: If status code is non-2xx.
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            error_content = response.text if response.content else "No response body"
            raise WhoisXMLManagerException(
                f"{error_msg} | Status: {response.status_code} | Details: {error_content}"
            ) from error
