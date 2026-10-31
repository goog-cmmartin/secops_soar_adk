"""
Client Manager template for external service interaction.

Best Practice:
- Encapsulate all API communication inside this class.
- Never import Siemplify SDK modules in this file.
- Implement test_connectivity() to support the mandatory Ping action.
"""
import requests


class ClientManagerException(Exception):
    """Custom exception raised for client manager errors."""
    pass


class ClientManager:
    """Wrapper client for target service API."""

    def __init__(self, api_root: str, api_key: str, verify_ssl: bool = True):
        if not api_root:
            raise ClientManagerException("API Root is required.")
        if not api_key:
            raise ClientManagerException("API Key is required.")

        self.api_root = api_root.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        })

    def test_connectivity(self) -> bool:
        """
        Verify connection and authentication.
        Called by the mandatory Ping action.
        """
        url = f"{self.api_root}/health"
        try:
            response = self.session.get(url, timeout=15)
            self.validate_response(response, "Ping failed")
            return True
        except requests.RequestException as e:
            raise ClientManagerException(f"Failed to connect to {self.api_root}: {str(e)}") from e

    @staticmethod
    def validate_response(response: requests.Response, error_msg: str = "An error occurred"):
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            raise ClientManagerException(
                f"{error_msg} | Status: {response.status_code} | Body: {response.text}"
            ) from error
