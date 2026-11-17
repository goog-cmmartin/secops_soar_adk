"""
GoogleDecisionsManager.py - Manager layer for Google Gemini Decisions API (gemini-decision-1)
SecOps SOAR Integration.

Completely decoupled from SOAR SDK following the Content Hub Manager Pattern.
Provides:
  - 3-tier hybrid authentication:
      1. Explicit Gemini API Key (`x-goog-api-key`)
      2. Keyless Workload Identity Federation (WIF) / Service Account JSON / ADC
         with automatic GCP API Keys discovery (`apikeys.googleapis.com`)
      3. Scoped OAuth2 Bearer Token fallback (`auth/generative-language` + `x-goog-user-project`)
  - Question schema normalization (`noul`, `choice`, `score`, plus OpenAI `predicate` compatibility)
  - Multimodal shared input assembly (Text, JSON, SOAR Alert/Case context, Image/Audio/Video/PDF)
  - Calibrated probability parsing, confidence gating, and preset catalog loading
"""
import json
import logging
import os
import re
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/decisions"
DEFAULT_MODEL = "gemini-decision-1"
DEFAULT_PROJECT_ID = ""
INPUT_COST_PER_MILLION_USD = 0.10
MAX_API_INPUT_TOKENS = 262144
SAFE_API_TOKEN_BUDGET = 210000
CHARS_PER_TOKEN_ESTIMATE = 3.0
DEFAULT_MAX_INPUT_CHARS = 60000

logger_default = logging.getLogger("GoogleDecisionsManager")


def safe_ascii(text: Any) -> str:
    """Sanitizes strings to clean ASCII for legacy SOAR runner serialization."""
    if text is None:
        return ""
    return unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode("ascii")


class SafeLogger:
    """
    Wrapper for SiemplifyLogger and standard logging.Logger.
    Ensures that .warning(), .error(), .info(), and .debug() never fail
    due to missing .warning() on SiemplifyLogger.
    """

    def __init__(self, logger: Any = None):
        self._logger = logger or logger_default

    def info(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "info"):
            self._logger.info(msg, *args, **kwargs)
        elif hasattr(self._logger, "log"):
            self._logger.log(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "warning"):
            self._logger.warning(msg, *args, **kwargs)
        elif hasattr(self._logger, "warn"):
            self._logger.warn(msg, *args, **kwargs)
        elif hasattr(self._logger, "info"):
            self._logger.info(f"[WARNING] {msg}", *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "error"):
            self._logger.error(msg, *args, **kwargs)
        elif hasattr(self._logger, "info"):
            self._logger.info(f"[ERROR] {msg}", *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "debug"):
            self._logger.debug(msg, *args, **kwargs)
        elif hasattr(self._logger, "info"):
            self._logger.info(f"[DEBUG] {msg}", *args, **kwargs)


def resolve_asset_path(filename: str) -> Path:
    """
    Resolves bundled static assets across both local development (`core/`)
    and `mp build` packaged SOAR containers (`Managers/`).
    """
    base_dir = Path(__file__).resolve().parent
    candidates = [
        base_dir / filename,
        base_dir.parent / "core" / filename,
        base_dir.parent / "Managers" / filename,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Bundled asset '{filename}' not found in {candidates}")


class GoogleDecisionsManager:
    """
    Client & orchestration manager for the Google Gemini Decisions API (`/v1beta/decisions`).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        workload_identity_email: Optional[str] = None,
        service_account_json: Optional[Union[str, Dict[str, Any]]] = None,
        project_id: Optional[str] = None,
        model_name: Optional[str] = DEFAULT_MODEL,
        api_endpoint: Optional[str] = DEFAULT_ENDPOINT,
        verify_ssl: bool = True,
        logger: Optional[Any] = None,
    ):
        self.logger = SafeLogger(logger)
        self.api_key = (
            str(api_key).strip()
            if api_key and str(api_key).strip()
            else os.environ.get("GEMINI_API_KEY", "").strip() or None
        )
        self.workload_identity_email = (
            str(workload_identity_email).strip()
            if workload_identity_email and str(workload_identity_email).strip()
            else None
        )
        self.service_account_json = service_account_json
        self.project_id = (
            str(project_id).strip()
            if project_id and str(project_id).strip()
            else os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("SECOPS_PROJECT_ID")
            or DEFAULT_PROJECT_ID
        )

        # Infer project_id from Workload Identity service account email if needed
        if (
            not self.project_id
            and self.workload_identity_email
            and "@" in self.workload_identity_email
        ):
            domain = self.workload_identity_email.split("@", 1)[1]
            if ".iam.gserviceaccount.com" in domain:
                self.project_id = domain.replace(".iam.gserviceaccount.com", "")

        # Infer project_id from Service Account JSON if needed
        if not self.project_id and self.service_account_json:
            try:
                sa_dict = (
                    json.loads(self.service_account_json)
                    if isinstance(self.service_account_json, str)
                    else self.service_account_json
                )
                if isinstance(sa_dict, dict) and sa_dict.get("project_id"):
                    self.project_id = sa_dict["project_id"]
            except Exception:
                pass

        self.model_name = (
            str(model_name).strip()
            if model_name and str(model_name).strip()
            else DEFAULT_MODEL
        )
        self.api_endpoint = (
            str(api_endpoint).strip()
            if api_endpoint and str(api_endpoint).strip()
            else DEFAULT_ENDPOINT
        )
        self.verify_ssl = bool(verify_ssl)
        self._credentials = None
        self._resolved_api_key: Optional[str] = None
        self._auth_method: str = "uninitialized"

    # =========================================================================
    # Authentication & Credential Resolution (3-Tier Hybrid Chain)
    # =========================================================================

    def _get_oauth_credentials(self) -> Optional[Any]:
        """
        Obtains Google OAuth2 credentials via:
          1. Workload Identity Federation (TIPCommon or google.auth ImpersonatedCredentials)
          2. Service Account JSON key
          3. Application Default Credentials (ADC)
        Requests both `cloud-platform` and `generative-language` scopes.
        """
        if self._credentials is not None:
            return self._credentials

        scopes = [
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/generative-language",
        ]

        # 1. Workload Identity Federation / Service Account Impersonation
        if self.workload_identity_email:
            try:
                from TIPCommon.rest.auth import build_credentials_from_sa

                self._credentials = build_credentials_from_sa(
                    target_principal=self.workload_identity_email,
                    scopes=scopes,
                    quota_project_id=self.project_id,
                )
                self.logger.info(
                    f"Established Workload Identity credentials for {self.workload_identity_email} via TIPCommon."
                )
                return self._credentials
            except ImportError:
                pass
            except Exception as exc:
                self.logger.warning(
                    f"TIPCommon Workload Identity failed ({exc}); falling back to google.auth impersonation."
                )

            try:
                import google.auth
                from google.auth import impersonated_credentials
                import google.auth.transport.requests

                source_creds, default_proj = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                if not self.project_id and default_proj:
                    self.project_id = default_proj
                target_creds = impersonated_credentials.Credentials(
                    source_credentials=source_creds,
                    target_principal=self.workload_identity_email,
                    target_scopes=scopes,
                    lifetime=3600,
                    quota_project_id=self.project_id,
                )
                target_creds.refresh(google.auth.transport.requests.Request())
                self._credentials = target_creds
                self.logger.info(
                    f"Generated impersonated Workload Identity token for {self.workload_identity_email}."
                )
                return self._credentials
            except Exception as exc:
                self.logger.warning(
                    f"Workload Identity impersonation for '{self.workload_identity_email}' failed: {exc}"
                )

        # 2. Service Account JSON Key
        if self.service_account_json and str(self.service_account_json).strip() not in ("", "{}"):
            try:
                from google.oauth2 import service_account
                import google.auth.transport.requests

                info = (
                    json.loads(self.service_account_json)
                    if isinstance(self.service_account_json, str)
                    else self.service_account_json
                )
                creds = service_account.Credentials.from_service_account_info(
                    info, scopes=scopes
                )
                creds.refresh(google.auth.transport.requests.Request())
                self._credentials = creds
                self.logger.info("Authenticated via Service Account JSON credentials.")
                return self._credentials
            except Exception as exc:
                self.logger.warning(f"Failed to load Service Account JSON credentials: {exc}")

        # 3. Application Default Credentials (ADC)
        try:
            import google.auth
            import google.auth.transport.requests

            creds, default_proj = google.auth.default(scopes=scopes)
            if not self.project_id and default_proj:
                self.project_id = default_proj
            if not creds.valid:
                creds.refresh(google.auth.transport.requests.Request())
            if getattr(creds, "token", None):
                self._credentials = creds
                return self._credentials
        except Exception as exc:
            self.logger.debug(f"Application Default Credentials unavailable: {exc}")

        return None

    def _discover_api_key_via_gcp(self, oauth_token: str) -> Optional[str]:
        """
        Uses a WIF / OAuth2 Bearer token to query the GCP API Keys API
        (`apikeys.googleapis.com`) in `self.project_id` and retrieve the `keyString`
        of an active key restricted to `generativelanguage.googleapis.com` (or unrestricted).
        """
        if not self.project_id or not oauth_token:
            return None

        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "x-goog-user-project": self.project_id,
            "Accept": "application/json",
        }
        list_url = f"https://apikeys.googleapis.com/v2/projects/{self.project_id}/locations/global/keys"
        try:
            resp = requests.get(list_url, headers=headers, timeout=10, verify=self.verify_ssl)
            if resp.status_code != 200:
                self.logger.debug(
                    f"GCP API Keys discovery returned HTTP {resp.status_code}: {resp.text[:200]}"
                )
                return None

            keys = resp.json().get("keys", [])
            # Prioritize keys explicitly restricted to generativelanguage.googleapis.com
            candidate_names: List[str] = []
            fallback_names: List[str] = []
            for key_obj in keys:
                key_name = key_obj.get("name")
                if not key_name:
                    continue
                targets = [
                    t.get("service", "")
                    for t in key_obj.get("restrictions", {}).get("apiTargets", [])
                ]
                if "generativelanguage.googleapis.com" in targets:
                    candidate_names.append(key_name)
                elif not targets:
                    fallback_names.append(key_name)

            for target_key_name in candidate_names + fallback_names:
                ks_url = f"https://apikeys.googleapis.com/v2/{target_key_name}/keyString"
                ks_resp = requests.get(
                    ks_url, headers=headers, timeout=10, verify=self.verify_ssl
                )
                if ks_resp.status_code == 200:
                    key_str = ks_resp.json().get("keyString")
                    if key_str:
                        self.logger.info(
                            f"Resolved Gemini API Key dynamically from GCP API Keys service ({target_key_name})."
                        )
                        return key_str
        except Exception as exc:
            self.logger.debug(f"GCP API Keys auto-discovery failed: {exc}")

        return None

    def get_auth_headers(self) -> Dict[str, str]:
        """
        Constructs HTTP authentication headers using the 3-tier resolution chain:
          1. Explicit `Gemini API Key` -> `x-goog-api-key`
          2. WIF / SA / ADC OAuth -> auto-discover key via `apikeys.googleapis.com` -> `x-goog-api-key`
          3. WIF / SA / ADC OAuth -> `Authorization: Bearer <token>` + `x-goog-user-project`
        """
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        # Tier 1: Explicit API Key
        if self.api_key:
            self._auth_method = "api_key"
            headers["x-goog-api-key"] = self.api_key
            return headers

        # Cached auto-discovered API Key
        if self._resolved_api_key:
            self._auth_method = (
                "wif_apikeys_auto" if self.workload_identity_email else "oauth_apikeys_auto"
            )
            headers["x-goog-api-key"] = self._resolved_api_key
            return headers

        # Tier 2 & 3: OAuth Credentials (WIF / SA JSON / ADC)
        creds = self._get_oauth_credentials()
        if creds and getattr(creds, "token", None):
            token = creds.token
            discovered_key = self._discover_api_key_via_gcp(token)
            if discovered_key:
                self._resolved_api_key = discovered_key
                self._auth_method = (
                    "wif_apikeys_auto"
                    if self.workload_identity_email
                    else "oauth_apikeys_auto"
                )
                headers["x-goog-api-key"] = discovered_key
                return headers

            # Tier 3: Direct Scoped OAuth Bearer Token fallback
            self._auth_method = "wif_oauth" if self.workload_identity_email else "oauth_bearer"
            headers["Authorization"] = f"Bearer {token}"
            if self.project_id:
                headers["x-goog-user-project"] = self.project_id
            return headers

        raise ValueError(
            "Authentication failed: No Gemini API Key, Workload Identity credentials, "
            "Service Account JSON, or Application Default Credentials were available."
        )

    # =========================================================================
    # Preset Catalog & Question Normalization
    # =========================================================================

    def load_presets(self) -> Dict[str, Dict[str, Any]]:
        """Loads bundled SecOps decision presets from `soc_decision_presets.json`."""
        preset_path = resolve_asset_path("soc_decision_presets.json")
        with open(preset_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_preset_questions(self, preset_name: str) -> Tuple[str, Dict[str, Any]]:
        """
        Retrieves the question map for a named preset (case-insensitive / partial match fallback).
        Returns (canonical_preset_name, questions_dict).
        """
        presets = self.load_presets()
        if preset_name in presets:
            return preset_name, dict(presets[preset_name]["questions"])

        target_lower = str(preset_name or "").strip().lower()
        for name, data in presets.items():
            if name.lower() == target_lower or target_lower in name.lower():
                return name, dict(data["questions"])

        available = ", ".join(presets.keys())
        raise ValueError(
            f"Unknown Decision Preset '{preset_name}'. Available presets: {available}"
        )

    @staticmethod
    def normalize_questions(
        questions_input: Union[str, Dict[str, Any], List[Dict[str, Any]]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Normalizes user-supplied questions into the native `/v1beta/decisions` map format:
          {
            "<question_key>": {
              "type": "noul" | "choice" | "score",
              "instructions": "...",
              "criteria": ... (optional for noul, dict for choice, list for score)
            }
          }
        Also accepts OpenAI Decisions array format (`[{"name": "...", "type": "predicate"|"choice"|"score", ...}]`)
        and converts it automatically.
        """
        if isinstance(questions_input, str):
            raw_str = questions_input.strip()
            if not raw_str:
                raise ValueError("Questions JSON cannot be empty.")
            parsed = json.loads(raw_str)
        else:
            parsed = questions_input

        # Convert list of question objects into a keyed dict
        if isinstance(parsed, list):
            converted: Dict[str, Any] = {}
            for idx, item in enumerate(parsed):
                if not isinstance(item, dict):
                    raise ValueError(f"Question list item at index {idx} must be an object.")
                q_key = (
                    item.get("name")
                    or item.get("id")
                    or item.get("key")
                    or f"question_{idx + 1}"
                )
                converted[str(q_key)] = item
            parsed = converted

        if not isinstance(parsed, dict) or not parsed:
            raise ValueError("Questions must be a non-empty JSON object mapping keys to questions.")

        normalized: Dict[str, Dict[str, Any]] = {}
        key_pattern = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

        for raw_key, q_spec in parsed.items():
            clean_key = re.sub(r"[^A-Za-z0-9_-]", "_", str(raw_key).strip())[:64]
            if not clean_key or not key_pattern.match(clean_key):
                raise ValueError(
                    f"Invalid question key '{raw_key}'. Keys must match [A-Za-z0-9_-]{{1,64}}."
                )
            if not isinstance(q_spec, dict):
                raise ValueError(f"Question '{clean_key}' definition must be a JSON object.")

            q_type = str(q_spec.get("type", "noul")).strip().lower()
            if q_type in ("predicate", "boolean", "yes_no", "yes/no", "binary"):
                q_type = "noul"
            if q_type not in ("noul", "choice", "score"):
                raise ValueError(
                    f"Question '{clean_key}' has unsupported type '{q_type}'. "
                    "Supported types: 'noul', 'choice', 'score'."
                )

            instructions = (
                q_spec.get("instructions")
                or q_spec.get("question")
                or q_spec.get("prompt")
                or q_spec.get("description")
            )
            if not instructions or not str(instructions).strip():
                raise ValueError(f"Question '{clean_key}' requires a non-empty 'instructions' field.")

            norm_q: Dict[str, Any] = {
                "type": q_type,
                "instructions": str(instructions).strip(),
            }

            criteria = (
                q_spec.get("criteria")
                or q_spec.get("choices")
                or q_spec.get("options")
                or q_spec.get("levels")
            )

            if q_type == "choice":
                if isinstance(criteria, list):
                    # Convert list of strings or [{"value": "...", "description": "..."}] to map
                    crit_map: Dict[str, str] = {}
                    for opt in criteria:
                        if isinstance(opt, dict):
                            k = str(opt.get("value") or opt.get("id") or opt.get("key") or "").strip()
                            v = str(opt.get("description") or opt.get("label") or "")
                            if k:
                                crit_map[k] = v
                        elif isinstance(opt, str) and opt.strip():
                            crit_map[opt.strip()] = ""
                    criteria = crit_map
                if not isinstance(criteria, dict) or len(criteria) < 2:
                    raise ValueError(
                        f"Choice question '{clean_key}' requires 'criteria' with at least 2 options."
                    )
                norm_q["criteria"] = {str(k).strip(): str(v) for k, v in criteria.items()}

            elif q_type == "score":
                if isinstance(criteria, dict):
                    # Sort by numeric key if passed as {"0": "...", "1": "..."}
                    sorted_items = sorted(
                        criteria.items(),
                        key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else str(kv[0]),
                    )
                    criteria = [str(v) for _, v in sorted_items]
                elif isinstance(criteria, list):
                    criteria = [
                        str(item.get("label") or item.get("description") or item)
                        if isinstance(item, dict)
                        else str(item)
                        for item in criteria
                    ]
                if not isinstance(criteria, list) or len(criteria) < 2:
                    raise ValueError(
                        f"Score question '{clean_key}' requires 'criteria' array with at least 2 rubric levels."
                    )
                norm_q["criteria"] = criteria

            elif q_type == "noul" and isinstance(criteria, dict):
                noul_crit = {}
                if "true_description" in criteria:
                    noul_crit["true_description"] = str(criteria["true_description"])
                if "false_description" in criteria:
                    noul_crit["false_description"] = str(criteria["false_description"])
                if noul_crit:
                    norm_q["criteria"] = noul_crit

            normalized[clean_key] = norm_q

        return normalized

    # =========================================================================
    # Input Assembly (Text, Alert Context, Multimodal Blocks)
    # =========================================================================

    @staticmethod
    def serialize_soar_context(siemplify: Any) -> str:
        """
        Extracts and serializes active SOAR Case and Alert telemetry (Alert metadata,
        Involved Entities, Security Events, and any cached Autonomous Detection Tuning
        proposals) into a compact JSON context block.
        Works across both ALERT-scoped and CASE-scoped playbooks.
        """
        if siemplify is None:
            return ""

        context_obj: Dict[str, Any] = {}
        try:
            case_id = getattr(siemplify, "case_id", None)
            if case_id:
                context_obj["case_id"] = case_id

            def _serialize_alert_obj(alert_obj: Any, max_events: int = 12) -> Dict[str, Any]:
                info: Dict[str, Any] = {
                    "identifier": getattr(alert_obj, "identifier", None),
                    "name": getattr(alert_obj, "name", None)
                    or getattr(alert_obj, "rule_generator", None),
                    "rule_generator": getattr(alert_obj, "rule_generator", None),
                    "priority": getattr(alert_obj, "priority", None),
                    "device_vendor": getattr(alert_obj, "device_vendor", None),
                    "device_product": getattr(alert_obj, "device_product", None),
                }
                sec_events = getattr(alert_obj, "security_events", None) or []
                serialized_events = []
                for ev in list(sec_events)[:max_events]:
                    raw_data = getattr(ev, "additional_properties", None) or getattr(
                        ev, "raw_data", None
                    )
                    if isinstance(raw_data, dict):
                        compact_ev = {
                            k: str(v)[:500]
                            for k, v in list(raw_data.items())[:25]
                            if v not in (None, "", [], {})
                        }
                        serialized_events.append(compact_ev)
                if serialized_events:
                    info["security_events"] = serialized_events
                return info

            alert = getattr(siemplify, "current_alert", None)
            if alert:
                alert_serialized = _serialize_alert_obj(alert, max_events=15)
                if "security_events" in alert_serialized:
                    context_obj["security_events"] = alert_serialized.pop("security_events")
                context_obj["alert"] = alert_serialized

            # In CASE-scoped playbooks, also inspect siemplify.case.alerts if present
            case_obj = getattr(siemplify, "case", None)
            case_alerts = getattr(case_obj, "alerts", None) if case_obj else None
            if case_alerts and isinstance(case_alerts, (list, tuple)):
                context_obj["case_alerts"] = [
                    _serialize_alert_obj(ca, max_events=8)
                    for ca in list(case_alerts)[:5]
                ]

            # Extract target entities (or fall back to entities across case alerts)
            entities = getattr(siemplify, "target_entities", None) or []
            if not entities and case_alerts and isinstance(case_alerts, (list, tuple)):
                agg_entities = []
                for ca in list(case_alerts)[:5]:
                    agg_entities.extend(getattr(ca, "entities", None) or [])
                entities = agg_entities

            if entities:
                context_obj["entities"] = [
                    {
                        "identifier": getattr(ent, "identifier", ""),
                        "type": getattr(ent, "entity_type", ""),
                        "is_suspicious": getattr(ent, "is_suspicious", False),
                        "is_internal": getattr(ent, "is_internal", False),
                    }
                    for ent in list(entities)[:30]
                ]

            # Include recent Correlated Silent Detections, Related Cases, and Detection Tuning summaries if cached for this case
            if case_id:
                silent_cache = f"/tmp/soar_action_cache_correlate_silent_{case_id}.json"
                if os.path.exists(silent_cache):
                    try:
                        with open(silent_cache, "r", encoding="utf-8") as sf:
                            silent_entry = json.load(sf)
                        silent_payload = (
                            silent_entry.get("json_payload")
                            if isinstance(silent_entry, dict) and "json_payload" in silent_entry
                            else silent_entry
                        )
                        if isinstance(silent_payload, dict):
                            dets_found = list(silent_payload.get("detections_found") or [])
                            rules_list = list(silent_payload.get("rules_triggered") or [])
                            if not rules_list and dets_found:
                                seen_r = []
                                for d in dets_found[:50]:
                                    rn = d.get("rule_name") if isinstance(d, dict) else None
                                    if rn and rn not in seen_r:
                                        seen_r.append(rn)
                                rules_list = seen_r[:10]
                            context_obj["correlated_silent_detections"] = {
                                "detections_count": silent_payload.get("detections_count", silent_payload.get("total_detections")),
                                "silent_detections_count": silent_payload.get("silent_detections_count"),
                                "has_silent_detections": silent_payload.get("has_silent_detections"),
                                "events_count": silent_payload.get("events_count", silent_payload.get("total_udm_events")),
                                "rules_triggered": rules_list[:10],
                            }
                    except Exception:
                        pass

                related_cache = f"/tmp/soar_action_cache_related_cases_{case_id}.json"
                if os.path.exists(related_cache):
                    try:
                        with open(related_cache, "r", encoding="utf-8") as rf:
                            rel_entry = json.load(rf)
                        rel_payload = (
                            rel_entry.get("json_payload")
                            if isinstance(rel_entry, dict) and "json_payload" in rel_entry
                            else rel_entry
                        )
                        if isinstance(rel_payload, dict):
                            context_obj["related_cases_summary"] = {
                                "total_related_cases": rel_payload.get("total_related_cases"),
                                "active_related_cases": rel_payload.get("active_related_cases"),
                                "closed_related_cases": rel_payload.get("closed_related_cases"),
                                "incident_related_cases": rel_payload.get("incident_related_cases"),
                            }
                    except Exception:
                        pass

                tuning_cache = f"/tmp/soar_action_cache_detection_tuning_{case_id}.json"
                if os.path.exists(tuning_cache):
                    try:
                        with open(tuning_cache, "r", encoding="utf-8") as tf:
                            tuning_entry = json.load(tf)
                        tuning_payload = (
                            tuning_entry.get("json_payload")
                            if isinstance(tuning_entry, dict)
                            else None
                        )
                        if isinstance(tuning_payload, dict) and tuning_payload.get("proposals"):
                            context_obj["autonomous_detection_tuning_proposals"] = [
                                {
                                    "rule_id": p.get("rule_id"),
                                    "rule_name": p.get("rule_name"),
                                    "rule_type": p.get("rule_type"),
                                    "exclusion_tuple": p.get("exclusion_tuple"),
                                    "noise_reduction_pct": p.get("noise_reduction_pct")
                                    or p.get("blast_radius_reduction_pct"),
                                    "compiler_verified": p.get("compiler_verified"),
                                    "safety_guardrail_passed": p.get("safety_guardrail_passed"),
                                    "yara_l_condition": p.get("yara_l_condition")
                                    or p.get("udm_refinement_query"),
                                }
                                for p in list(tuning_payload.get("proposals") or [])[:5]
                                if isinstance(p, dict)
                            ]
                    except Exception:
                        pass
        except Exception:
            pass

        if not context_obj:
            return ""
        return json.dumps(context_obj, indent=2, default=str)

    @staticmethod
    def build_input_payload(
        input_text: Optional[str] = None,
        alert_context: Optional[str] = None,
        media_data_or_uri: Optional[str] = None,
        media_mime_type: Optional[str] = None,
    ) -> Union[str, List[Dict[str, Any]]]:
        """
        Builds the `input` field for `/v1beta/decisions`.
        Returns a plain string when only text is present, or a list of typed Content blocks
        when multimodal content (`image`, `audio`, `video`, `document`) is attached.
        """
        text_parts: List[str] = []
        if input_text and str(input_text).strip():
            text_parts.append(str(input_text).strip())
        if alert_context and str(alert_context).strip():
            text_parts.append(f"=== SOAR Alert & Case Telemetry ===\n{alert_context.strip()}")

        combined_text = "\n\n".join(text_parts).strip()

        if not media_data_or_uri or not str(media_data_or_uri).strip():
            if not combined_text:
                raise ValueError(
                    "Input cannot be empty: provide 'Input Text or JSON', enable 'Include Alert Context', or attach media."
                )
            return combined_text

        # Multimodal block construction
        media_val = str(media_data_or_uri).strip()
        mime = str(media_mime_type or "image/png").strip().lower()

        if mime.startswith("image/"):
            block_type = "image"
        elif mime.startswith("audio/"):
            block_type = "audio"
        elif mime.startswith("video/"):
            block_type = "video"
        elif mime == "application/pdf":
            block_type = "document"
        else:
            block_type = "image"

        media_block: Dict[str, Any] = {"type": block_type, "mime_type": mime}
        if media_val.startswith("http://") or media_val.startswith("https://"):
            media_block["uri"] = media_val
        else:
            # Strip optional data URL prefix (e.g. data:image/png;base64,...)
            if ";base64," in media_val:
                media_val = media_val.split(";base64,", 1)[1].strip()
            media_block["data"] = media_val

        blocks: List[Dict[str, Any]] = []
        if combined_text:
            blocks.append({"type": "text", "text": combined_text})
        blocks.append(media_block)
        return blocks

    # =========================================================================
    # API Execution, Token-Budget Guardrails & Result Post-Processing
    # =========================================================================

    @staticmethod
    def _compact_json_obj(obj: Any, max_list_items: int = 5, max_str_len: int = 400, depth: int = 0) -> Tuple[Any, bool]:
        """
        Recursively compacts large arrays and oversized string fields inside JSON telemetry
        (such as raw UDM events or detection dumps) while preserving all top-level summary metrics.
        """
        compacted = False
        if depth > 6:
            return "[...nested_depth_limit...]", True

        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            bulky_array_keys = {
                "udm_events",
                "events",
                "events_found",
                "raw_events",
                "detections",
                "detections_found",
                "silent_detections",
                "alerting_detections",
                "security_events",
                "sample_events",
                "evidence_attached",
                "attached_evidences",
                "entity_results",
                "entities_scanned",
                "entities_searched",
                "related_cases",
            }
            for k, v in obj.items():
                if k == "evidence_markdown" and isinstance(v, str) and len(v) > 1500:
                    out[k] = v[:1500] + f"...[+{len(v) - 1500} chars]"
                    compacted = True
                    continue
                if isinstance(v, list) and (k in bulky_array_keys or len(v) > max_list_items):
                    orig_len = len(v)
                    limit = 3 if k in ("udm_events", "events", "events_found", "raw_events", "detections", "detections_found", "attached_evidences") else max_list_items
                    sliced = v[:limit]
                    comp_items = []
                    for item in sliced:
                        c_item, c_flag = GoogleDecisionsManager._compact_json_obj(
                            item, max_list_items=limit, max_str_len=max_str_len, depth=depth + 1
                        )
                        comp_items.append(c_item)
                        compacted = compacted or c_flag
                    out[k] = comp_items
                    if orig_len > limit:
                        out[f"_{k}_total_count"] = orig_len
                        out[f"_{k}_truncated_items"] = orig_len - limit
                        compacted = True
                else:
                    c_val, c_flag = GoogleDecisionsManager._compact_json_obj(
                        v, max_list_items=max_list_items, max_str_len=max_str_len, depth=depth + 1
                    )
                    out[k] = c_val
                    compacted = compacted or c_flag
            return out, compacted

        if isinstance(obj, list):
            orig_len = len(obj)
            sliced = obj[:max_list_items]
            out_list = []
            for item in sliced:
                c_item, c_flag = GoogleDecisionsManager._compact_json_obj(
                    item, max_list_items=max_list_items, max_str_len=max_str_len, depth=depth + 1
                )
                out_list.append(c_item)
                compacted = compacted or c_flag
            if orig_len > max_list_items:
                out_list.append(f"[...{orig_len - max_list_items} additional items omitted...]")
                compacted = True
            return out_list, compacted

        if isinstance(obj, str) and len(obj) > max_str_len:
            return obj[:max_str_len] + f"...[+{len(obj) - max_str_len} chars]", True

        return obj, False

    @classmethod
    def enforce_input_budget(
        cls,
        input_payload: Union[str, List[Dict[str, Any]]],
        question_count: int = 1,
        max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
    ) -> Tuple[Union[str, List[Dict[str, Any]]], Dict[str, Any]]:
        """
        Enforces a question-aware input size guardrail so `question_count * input_tokens`
        never exceeds the Gemini Decisions API 262,144 token ceiling:
          1. Compacts any large embedded JSON objects (e.g. raw `.JsonResult` dumps from upstream steps).
          2. Applies 70% Head / 30% Tail truncation if the text still exceeds the safe character budget.
        """
        q_count = max(1, int(question_count or 1))
        question_aware_ceiling = int((SAFE_API_TOKEN_BUDGET * CHARS_PER_TOKEN_ESTIMATE) / q_count)
        if max_input_chars and int(max_input_chars) > 0:
            effective_limit = min(int(max_input_chars), question_aware_ceiling)
        else:
            effective_limit = question_aware_ceiling
        effective_limit = max(2000, effective_limit)

        def _compact_and_bound_str(raw_text: str) -> Tuple[str, Dict[str, Any]]:
            orig_len = len(raw_text)
            text = raw_text
            json_compacted = False
            input_truncated = False

            # Step 1: If text exceeds 12,000 chars or effective_limit, compact embedded JSON blobs first
            if orig_len > min(12000, effective_limit):
                decoder = json.JSONDecoder()
                out_segments: List[str] = []
                idx = 0
                n = len(text)
                while idx < n:
                    brace_pos = text.find("{", idx)
                    if brace_pos == -1:
                        out_segments.append(text[idx:])
                        break
                    if brace_pos > idx:
                        out_segments.append(text[idx:brace_pos])
                    try:
                        parsed_obj, end_idx = decoder.raw_decode(text, brace_pos)
                        raw_span_len = end_idx - brace_pos
                        if isinstance(parsed_obj, dict) and raw_span_len > 4000:
                            comp_obj, did_compact = cls._compact_json_obj(parsed_obj)
                            if did_compact:
                                comp_str = json.dumps(comp_obj, indent=2, default=str)
                                if len(comp_str) < raw_span_len:
                                    out_segments.append(comp_str)
                                    json_compacted = True
                                    idx = end_idx
                                    continue
                        out_segments.append(text[brace_pos:end_idx])
                        idx = end_idx
                    except Exception:
                        out_segments.append(text[brace_pos : brace_pos + 1])
                        idx = brace_pos + 1
                if json_compacted:
                    text = "".join(out_segments)

            # Step 2: Enforce hard character ceiling via 70% Head + 30% Tail split
            if len(text) > effective_limit:
                input_truncated = True
                marker_budget = 140
                usable = max(1000, effective_limit - marker_budget)
                head_len = int(usable * 0.70)
                tail_len = usable - head_len
                omitted = len(text) - (head_len + tail_len)
                marker = (
                    f"\n\n[...TRUNCATED {omitted} CHARS TO FIT GEMINI-DECISION-1 "
                    f"262,144 TOKEN BUDGET (QUESTIONS={q_count}, LIMIT={effective_limit} CHARS)...]\n\n"
                )
                text = text[:head_len] + marker + text[-tail_len:]

            meta = {
                "original_input_chars": orig_len,
                "effective_input_chars": len(text),
                "max_allowed_chars": effective_limit,
                "question_count": q_count,
                "json_compacted": json_compacted,
                "input_truncated": input_truncated,
            }
            return text, meta

        if isinstance(input_payload, str):
            bounded_str, meta = _compact_and_bound_str(input_payload)
            return bounded_str, meta

        if isinstance(input_payload, list):
            new_blocks: List[Dict[str, Any]] = []
            agg_meta = {
                "original_input_chars": 0,
                "effective_input_chars": 0,
                "max_allowed_chars": effective_limit,
                "question_count": q_count,
                "json_compacted": False,
                "input_truncated": False,
            }
            for blk in input_payload:
                if isinstance(blk, dict) and blk.get("type") == "text" and isinstance(blk.get("text"), str):
                    b_text, b_meta = _compact_and_bound_str(blk["text"])
                    new_blk = dict(blk)
                    new_blk["text"] = b_text
                    new_blocks.append(new_blk)
                    agg_meta["original_input_chars"] += b_meta["original_input_chars"]
                    agg_meta["effective_input_chars"] += b_meta["effective_input_chars"]
                    agg_meta["json_compacted"] = agg_meta["json_compacted"] or b_meta["json_compacted"]
                    agg_meta["input_truncated"] = agg_meta["input_truncated"] or b_meta["input_truncated"]
                else:
                    new_blocks.append(blk)
            return new_blocks, agg_meta

        return input_payload, {
            "original_input_chars": 0,
            "effective_input_chars": 0,
            "max_allowed_chars": effective_limit,
            "question_count": q_count,
            "json_compacted": False,
            "input_truncated": False,
        }

    def evaluate_decisions(
        self,
        input_payload: Union[str, List[Dict[str, Any]]],
        questions: Union[str, Dict[str, Any], List[Dict[str, Any]]],
        confidence_threshold: float = 0.80,
        preset_name: Optional[str] = None,
        max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
    ) -> Dict[str, Any]:
        """
        Calls `POST /v1beta/decisions` using `gemini-decision-1` and returns a rich,
        SOAR-ready dictionary with calibrated answers, flattened playbook summary keys,
        confidence gating flags, input budget guardrail telemetry, and token usage metrics.
        """
        norm_questions = self.normalize_questions(questions)
        threshold = max(0.0, min(1.0, float(confidence_threshold)))

        bounded_input, guardrail_meta = self.enforce_input_budget(
            input_payload=input_payload,
            question_count=len(norm_questions),
            max_input_chars=max_input_chars,
        )
        if guardrail_meta.get("json_compacted") or guardrail_meta.get("input_truncated"):
            self.logger.info(
                f"Input budget guardrail active: compacted={guardrail_meta.get('json_compacted')}, "
                f"truncated={guardrail_meta.get('input_truncated')} "
                f"({guardrail_meta.get('original_input_chars')} -> {guardrail_meta.get('effective_input_chars')} chars "
                f"across {len(norm_questions)} questions)."
            )

        request_body = {
            "model": self.model_name,
            "input": bounded_input,
            "questions": norm_questions,
        }

        headers = self.get_auth_headers()
        start_ts = time.time()

        resp = requests.post(
            self.api_endpoint,
            headers=headers,
            json=request_body,
            timeout=60,
            verify=self.verify_ssl,
        )

        # Automatic fallback retry if tokenizer density still exceeded 262,144 tokens
        if resp.status_code == 400 and "exceeds the maximum number of tokens" in resp.text:
            retry_limit = max(2000, int(guardrail_meta.get("effective_input_chars", 20000) * 0.40))
            self.logger.warning(
                f"Gemini Decisions API reported token limit exceeded; auto-retrying with reduced limit ({retry_limit} chars)."
            )
            bounded_input, guardrail_meta = self.enforce_input_budget(
                input_payload=bounded_input,
                question_count=len(norm_questions),
                max_input_chars=retry_limit,
            )
            guardrail_meta["auto_retry_shrunk"] = True
            request_body["input"] = bounded_input
            resp = requests.post(
                self.api_endpoint,
                headers=headers,
                json=request_body,
                timeout=60,
                verify=self.verify_ssl,
            )

        latency_ms = int(round((time.time() - start_ts) * 1000))

        if resp.status_code != 200:
            err_detail = resp.text[:600]
            try:
                err_json = resp.json()
                if "error" in err_json:
                    err_detail = json.dumps(err_json["error"])
            except Exception:
                pass
            raise RuntimeError(
                f"Gemini Decisions API HTTP {resp.status_code}: {safe_ascii(err_detail)}"
            )

        raw_result = resp.json()
        answers = raw_result.get("answers", {}) or {}
        usage = raw_result.get("usage", {}) or {}

        # Build flattened summary and evaluate confidence gate
        summary: Dict[str, Any] = {}
        low_confidence_questions: List[str] = []

        for q_key, q_spec in norm_questions.items():
            ans = answers.get(q_key, {})
            if not isinstance(ans, dict):
                continue

            q_type = ans.get("type") or q_spec.get("type")
            conf = float(ans.get("confidence", 0.0))
            if conf < threshold:
                low_confidence_questions.append(q_key)

            if q_type == "noul":
                noul_prob = float(ans.get("noul", 0.0))
                is_yes = noul_prob >= 0.50
                summary[q_key] = is_yes
                summary[f"{q_key}_probability"] = round(noul_prob, 4)
                summary[f"{q_key}_confidence"] = round(conf, 4)
            elif q_type == "choice":
                choice_val = ans.get("choice", "")
                summary[q_key] = choice_val
                summary[f"{q_key}_confidence"] = round(conf, 4)
            elif q_type == "score":
                score_val = float(ans.get("score", 0.0))
                legend = ans.get("legend", {}) or {}
                probs = ans.get("probabilities", {}) or {}
                top_level = (
                    max(probs.items(), key=lambda kv: float(kv[1]))[0]
                    if probs
                    else str(int(round(score_val)))
                )
                summary[q_key] = round(score_val, 4)
                summary[f"{q_key}_level"] = int(top_level) if str(top_level).isdigit() else top_level
                summary[f"{q_key}_label"] = legend.get(str(top_level), "")
                summary[f"{q_key}_confidence"] = round(conf, 4)

        total_input_tokens = int(usage.get("total_input_tokens", 0))
        total_output_tokens = int(usage.get("total_output_tokens", 0))
        estimated_cost_usd = round(
            (total_input_tokens / 1_000_000.0) * INPUT_COST_PER_MILLION_USD, 8
        )

        all_confident = len(low_confidence_questions) == 0 and len(answers) > 0
        escalation_required = not all_confident

        return {
            "status": "success",
            "model": self.model_name,
            "preset_name": preset_name or "Custom Decisions",
            "auth_method": self._auth_method,
            "latency_ms": latency_ms,
            "confidence_threshold": threshold,
            "all_confident": all_confident,
            "escalation_required": escalation_required,
            "question_count": len(norm_questions),
            "low_confidence_questions": low_confidence_questions,
            "summary": summary,
            "questions_metadata": norm_questions,
            "answers": answers,
            "input_guardrail": guardrail_meta,
            "usage": {
                "total_input_tokens": total_input_tokens,
                "total_output_tokens": total_output_tokens,
                "total_tokens": int(usage.get("total_tokens", total_input_tokens)),
                "input_tokens_by_modality": usage.get("input_tokens_by_modality", []),
                "estimated_cost_usd": estimated_cost_usd,
            },
        }

    def run_preset(
        self,
        preset_name: str,
        input_payload: Union[str, List[Dict[str, Any]]],
        additional_questions: Optional[Union[str, Dict[str, Any]]] = None,
        confidence_threshold: float = 0.80,
        max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
    ) -> Dict[str, Any]:
        """
        Loads a bundled SOC Decision Preset, optionally merges custom questions,
        and evaluates all questions in a single `/v1beta/decisions` forward pass.
        """
        canonical_name, questions_map = self.get_preset_questions(preset_name)
        if additional_questions:
            if isinstance(additional_questions, str):
                cleaned_extra = additional_questions.strip()
                if cleaned_extra and not (cleaned_extra.startswith("[") and cleaned_extra.endswith("]")):
                    try:
                        extra_norm = self.normalize_questions(cleaned_extra)
                        questions_map.update(extra_norm)
                    except ValueError as exc:
                        self.logger.warning(f"Skipping invalid additional_questions parameter: {exc}")
            elif isinstance(additional_questions, dict) and additional_questions:
                extra_norm = self.normalize_questions(additional_questions)
                questions_map.update(extra_norm)

        return self.evaluate_decisions(
            input_payload=input_payload,
            questions=questions_map,
            confidence_threshold=confidence_threshold,
            preset_name=canonical_name,
            max_input_chars=max_input_chars,
        )

    def test_connection(self) -> bool:
        """
        Verifies connectivity and credentials by executing a 1-question canary
        decision against `gemini-decision-1`.
        """
        res = self.evaluate_decisions(
            input_payload="Google SecOps SOAR health check canary.",
            questions={
                "service_healthy": {
                    "type": "noul",
                    "instructions": "Is this a health check message?",
                }
            },
            confidence_threshold=0.5,
            preset_name="Ping Canary",
        )
        if "service_healthy" not in res.get("answers", {}):
            raise RuntimeError("Canary decision response did not contain expected answer key.")
        self.logger.info(
            f"GoogleDecisions connectivity verified (auth={res.get('auth_method')}, latency={res.get('latency_ms')}ms)."
        )
        return True
