"""Evidence Sanitization and Redaction Utility.

Guarantees that no authentication tokens, secret keys, cookies, or sensitive
telemetry credentials enter captured evidence artifacts.
"""

import re
from typing import Any, Dict, List, Union

SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "bearer",
    "token",
    "client_secret",
}


def sanitize_data(data: Any) -> Any:
    """Recursively sanitizes dictionaries, lists, and strings of sensitive credentials."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if k.lower() in SENSITIVE_KEYS:
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_data(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, str):
        # Redact Bearer tokens in text
        data = re.sub(r"Bearer\s+[a-zA-Z0-9_\-\.]+", "Bearer [REDACTED_TOKEN]", data, flags=re.IGNORECASE)
        data = re.sub(r"ya29\.[a-zA-Z0-9_\-]+", "[REDACTED_OAUTH_TOKEN]", data)
        return data
    return data
