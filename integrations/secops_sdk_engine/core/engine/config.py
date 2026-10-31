"""Google SecOps SDK & Engine Configuration Module.

Provides centralized, prioritized configuration resolution:
1. Explicit constructor arguments
2. Environment variables (e.g. SECOPS_CUSTOMER_ID, GCP_PROJECT_ID)
3. Local `.env` file key-value definitions

Fails loudly with `SecOpsConfigurationError` if required tenant identity parameters are absent.
"""

from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SecOpsConfigurationError(Exception):
    """Raised when required Google SecOps tenant or project configuration is missing."""
    pass


def _strip_env_value(raw_val: str) -> str:
    """Strips surrounding quotes or unquoted inline comments from a .env value."""
    val = raw_val.strip()
    if not val:
        return ""
    if (val.startswith('"') and val.endswith('"')) or (
        val.startswith("'") and val.endswith("'")
    ):
        return val[1:-1]
    # Strip unquoted inline comment (preceded by whitespace)
    for idx, ch in enumerate(val):
        if ch == "#" and (idx == 0 or val[idx - 1].isspace()):
            val = val[:idx].rstrip()
            break
    return val


def _load_env_file(env_path: Optional[Path] = None) -> None:
    """Lightweight .env file parser that populates os.environ without external dependencies."""
    if env_path is None:
        # Check current working directory and parent directories
        candidate = Path.cwd() / ".env"
        if not candidate.is_file():
            # Check directory of this module
            candidate = Path(__file__).resolve().parent.parent / ".env"
        env_path = candidate

    if not env_path.is_file():
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].strip()
                key, val = line.split("=", 1)
                key = key.strip()
                if not key:
                    continue
                val = _strip_env_value(val)
                # Do not overwrite already exported environment variables
                if key not in os.environ:
                    os.environ[key] = val
    except OSError as e:
        logger.warning("Failed to read .env configuration file at %s: %s", env_path, e)


@dataclass
class SecOpsConfig:
    """Holds authenticated Google SecOps tenant identity and runtime endpoints."""

    project_id: str
    customer_id: str
    project_number: str
    location: str = "us"
    api_base: Optional[str] = None

    def __post_init__(self):
        if not self.api_base:
            self.api_base = f"https://{self.location}-chronicle.googleapis.com"


def load_config(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    project_number: Optional[str] = None,
    location: Optional[str] = None,
    api_base: Optional[str] = None,
    env_file: Optional[Path] = None,
) -> SecOpsConfig:
    """Resolves SecOpsConfig from arguments, environment variables, or .env file."""
    _load_env_file(env_file)

    resolved_project_id = (
        project_id
        or os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
    )
    resolved_customer_id = (
        customer_id
        or os.environ.get("SECOPS_CUSTOMER_ID")
    )
    resolved_project_number = (
        project_number
        or os.environ.get("SECOPS_PROJECT_NUMBER")
        or resolved_project_id
        or ""
    )
    resolved_location = (
        location
        or os.environ.get("SECOPS_REGION")
        or "us"
    )
    resolved_api_base = (
        api_base
        or os.environ.get("SECOPS_API_BASE")
        or f"https://{resolved_location}-chronicle.googleapis.com"
    )

    missing = []
    if not resolved_project_id:
        missing.append("GCP_PROJECT_ID / GOOGLE_CLOUD_PROJECT")
    if not resolved_customer_id:
        missing.append("SECOPS_CUSTOMER_ID")

    if missing:
        raise SecOpsConfigurationError(
            f"Missing required Google SecOps configuration: {', '.join(missing)}. "
            "Please provide them as arguments, set the corresponding environment variables, "
            "or define them in a local .env file (see .env.example)."
        )

    return SecOpsConfig(
        project_id=resolved_project_id,
        customer_id=resolved_customer_id,
        project_number=resolved_project_number,
        location=resolved_location,
        api_base=resolved_api_base,
    )
