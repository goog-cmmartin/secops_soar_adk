"""Google SecOps Credential Provider.

Centralizes Google Cloud OAuth2 access-token acquisition for the SecOps adapter
behind a single, testable seam. Tenant *identity* resolution (project/customer/
region) lives in `engine.config`; this module is concerned exclusively with
*Google Cloud IAM token lifecycle*.

Resolution order (highest priority first)
-----------------------------------------
1. **Static token override** — an explicit token passed to the provider, or the
   ``SECOPS_AUTH_TOKEN`` environment variable. Zero I/O; intended for tests, CI,
   and constrained runners where neither ``google-auth`` nor ``gcloud`` is
   available. No refresh is attempted for static tokens.
2. **Library ADC (``google-auth``)** — the enterprise default. Resolves
   Application Default Credentials with the explicit ``cloud-platform`` scope and
   transparently refreshes the credential when expired. No subprocess, no
   dependency on ``gcloud`` being on ``PATH``.
3. **gcloud ADC subprocess** — fallback for environments without ``google-auth``
   installed. Shells out to
   ``gcloud auth application-default print-access-token``.

   IMPORTANT: this is ``application-default print-access-token``, NOT the bare
   ``print-access-token``. The latter reads the *core* ``gcloud`` login
   credential, which for user accounts is emitted UNSCOPED (``scope: (none)``)
   and is rejected by the SecOps API with HTTP 401. Only the
   application-default credential store carries the ``cloud-platform`` scope.

Mode override
-------------
``SECOPS_AUTH_MODE`` may pin a specific strategy:
  - ``auto``    (default) — try the chain above in order.
  - ``adc``     — library ADC only; error if ``google-auth`` is unavailable.
  - ``gcloud``  — gcloud subprocess only.
  - ``static``  — static token only; error if none is configured.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from typing import Optional

from engine.config import SecOpsConfigurationError

logger = logging.getLogger(__name__)

# OAuth scope required by the Google SecOps (Chronicle) REST APIs.
AUTH_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

_ENV_TOKEN = "SECOPS_AUTH_TOKEN"
_ENV_MODE = "SECOPS_AUTH_MODE"

_VALID_MODES = ("auto", "adc", "gcloud", "static")

# Default in-memory TTL (seconds) for tokens minted via the gcloud subprocess
# fallback. Google Cloud OAuth2 access tokens have a 3600s lifetime; caching for
# 50 minutes (3000s) avoids spawning a subprocess on every REST request while
# leaving a 10-minute safety buffer before expiration.
DEFAULT_GCLOUD_CACHE_TTL_SECONDS = 3000.0


class CredentialProvider:
    """Acquires Google Cloud access tokens via a prioritized strategy chain.

    A single instance is safe to reuse across many requests and threads:
    the library-ADC strategy caches the underlying credential object and only
    performs a network refresh when the token has expired, and the gcloud
    subprocess strategy caches its token in memory until ``gcloud_cache_ttl``
    elapses.
    """

    def __init__(
        self,
        static_token: Optional[str] = None,
        mode: Optional[str] = None,
        scopes: Optional[list] = None,
        gcloud_cache_ttl: float = DEFAULT_GCLOUD_CACHE_TTL_SECONDS,
    ):
        self._scopes = list(scopes) if scopes else list(AUTH_SCOPES)
        self._static_token = static_token or os.environ.get(_ENV_TOKEN) or None

        raw_mode = (mode or os.environ.get(_ENV_MODE) or "auto").strip().lower()
        if raw_mode not in _VALID_MODES:
            raise SecOpsConfigurationError(
                f"Invalid {_ENV_MODE}={raw_mode!r}; expected one of {_VALID_MODES}."
            )
        self._mode = raw_mode
        self._gcloud_cache_ttl = float(gcloud_cache_ttl)

        self._lock = threading.Lock()
        # Lazily-initialized google-auth credential object (library ADC strategy).
        self._adc_credentials = None
        # Cached token and monotonic expiry timestamp for gcloud subprocess strategy.
        self._gcloud_cached_token: Optional[str] = None
        self._gcloud_token_expiry: float = 0.0

    # ------------------------------------------------------------------ public

    def invalidate(self) -> None:
        """Clears cached tokens so the next get_token() call forces a refresh."""
        with self._lock:
            self._gcloud_cached_token = None
            self._gcloud_token_expiry = 0.0
            if self._adc_credentials is not None:
                self._adc_credentials = None

    def get_token(self) -> str:
        """Returns a valid bearer token, honoring the configured mode.

        Raises:
            SecOpsConfigurationError: if no strategy can produce a token.
        """
        if self._mode == "static":
            return self._require(self._from_static(), "static token")
        if self._mode == "adc":
            return self._require(self._from_library_adc(), "library ADC (google-auth)")
        if self._mode == "gcloud":
            return self._require(self._from_gcloud_adc(), "gcloud ADC subprocess")

        # auto: static -> library ADC -> gcloud subprocess
        token = self._from_static()
        if token:
            return token

        errors = []
        try:
            token = self._from_library_adc()
            if token:
                return token
        except Exception as e:  # noqa: BLE001 - aggregated for a single clear error
            errors.append(f"library ADC (google-auth): {e}")
            logger.debug("Library ADC strategy failed: %s", e)

        try:
            token = self._from_gcloud_adc()
            if token:
                return token
        except Exception as e:  # noqa: BLE001
            errors.append(f"gcloud ADC subprocess: {e}")
            logger.debug("gcloud ADC strategy failed: %s", e)

        detail = "; ".join(errors) if errors else "no credential source available"
        raise SecOpsConfigurationError(
            "Unable to acquire a Google Cloud access token. Tried: "
            f"{detail}. Configure Application Default Credentials via "
            "`gcloud auth application-default login`, set SECOPS_AUTH_TOKEN, "
            "or set SECOPS_AUTH_MODE to a specific strategy."
        )

    # --------------------------------------------------------------- strategies

    def _from_static(self) -> Optional[str]:
        """Strategy 1: explicit/static token. No refresh, no I/O."""
        return self._static_token or None

    def _from_library_adc(self) -> Optional[str]:
        """Strategy 2: google-auth Application Default Credentials (scoped)."""
        try:
            import google.auth
            from google.auth.transport.requests import Request as GoogleAuthRequest
        except ImportError as e:
            raise SecOpsConfigurationError(
                "google-auth is not installed; cannot use library ADC strategy."
            ) from e

        with self._lock:
            if self._adc_credentials is None:
                self._adc_credentials, _ = google.auth.default(scopes=self._scopes)

            if not self._adc_credentials.valid:
                self._adc_credentials.refresh(GoogleAuthRequest())

            return self._adc_credentials.token or None

    def _from_gcloud_adc(self) -> Optional[str]:
        """Strategy 3: `gcloud auth application-default print-access-token`.

        Uses the application-default credential store (scoped), NOT the bare
        `print-access-token` (unscoped -> HTTP 401). Caches the acquired token
        in memory for ``gcloud_cache_ttl`` seconds to avoid spawning a new
        subprocess on every API call.
        """
        with self._lock:
            now = time.monotonic()
            if (
                self._gcloud_cached_token
                and self._gcloud_cache_ttl > 0
                and now < self._gcloud_token_expiry
            ):
                return self._gcloud_cached_token

            try:
                result = subprocess.run(
                    ["gcloud", "auth", "application-default", "print-access-token"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
            except FileNotFoundError as e:
                raise SecOpsConfigurationError(
                    "`gcloud` executable not found on PATH."
                ) from e
            except subprocess.TimeoutExpired as e:
                raise SecOpsConfigurationError(
                    "`gcloud auth application-default print-access-token` timed out."
                ) from e
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or "").strip()
                raise SecOpsConfigurationError(
                    f"gcloud token command failed: {stderr}"
                ) from e

            token = result.stdout.strip() or None
            if token and self._gcloud_cache_ttl > 0:
                self._gcloud_cached_token = token
                self._gcloud_token_expiry = time.monotonic() + self._gcloud_cache_ttl
            return token

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _require(token: Optional[str], source: str) -> str:
        if not token:
            raise SecOpsConfigurationError(
                f"Configured auth source ({source}) did not yield a token."
            )
        return token
