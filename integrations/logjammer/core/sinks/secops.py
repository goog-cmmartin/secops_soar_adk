"""Google SecOps (Chronicle) ingestion sink for Log Jammer OSS."""

import base64
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
from .base import BaseSink
from ..models import GeneratedScenario, LogEntry

logger = logging.getLogger(__name__)


class SecOpsSink(BaseSink):
  """Emits log events directly into Google SecOps (Chronicle) API.

  Supports the Google SecOps Chronicle API v1alpha endpoints:
    - Raw logs / by logType: `POST .../instances/{customer_id}/logTypes/{log_type}/logs:import`
    - Normalized UDM events: `POST .../instances/{customer_id}/events:import`
    - Fallback: Legacy Chronicle Ingestion API (`v2/unstructuredlogentries:batchCreate`)
  """

  def __init__(
      self,
      customer_id: Optional[str] = None,
      project_number: Optional[str] = None,
      project_id: Optional[str] = None,
      region: Optional[str] = None,
      credentials_file: Optional[str] = None,
      batch_size: int = 50,
      tag: Optional[str] = None,
      scenario_tag: Optional[str] = None,
      simulation_tag: Optional[str] = None,
      scenario_name: Optional[str] = None,
      forwarder_id: Optional[str] = None,
      mode: str = "logs:import",  # 'logs:import' or 'events:import'
      labels: Optional[Dict[str, str]] = None,
      credentials: Optional[Any] = None,
  ):
    self.credentials = credentials
    # Sanitize inputs (convert blank/whitespace strings to None)
    cust = (
        customer_id
        or os.environ.get("CHRONICLE_CUSTOMER_ID")
        or os.environ.get("SECOPS_CUSTOMER_ID")
    )
    self.customer_id = cust.strip() if cust and cust.strip() else None

    proj = (
        project_number
        or os.environ.get("CHRONICLE_PROJECT_NUMBER")
        or os.environ.get("GCP_PROJECT_NUMBER")
        or project_id
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
    )
    self.project_number = proj.strip() if proj and proj.strip() else None
    self.project_id = self.project_number

    reg = region or os.environ.get("CHRONICLE_REGION", "us")
    self.region = reg.strip().lower() if reg and reg.strip() else "us"

    cred = credentials_file or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    self.credentials_file = cred.strip() if cred and cred.strip() else None

    self.batch_size = batch_size
    tg = (
        tag
        or scenario_tag
        or simulation_tag
        or scenario_name
        or os.environ.get("CHRONICLE_TAG")
        or os.environ.get("CHRONICLE_SCENARIO_TAG")
        or os.environ.get("CHRONICLE_SIMULATION_TAG")
        or os.environ.get("CHRONICLE_SCENARIO_NAME")
    )
    self.tag = tg.strip() if tg and tg.strip() else None
    fw_id = forwarder_id or os.environ.get("CHRONICLE_FORWARDER_ID")
    self.forwarder_id = fw_id.strip() if fw_id and fw_id.strip() else None
    self.mode = mode.lower()
    self.labels = labels or {}
    self.last_export_metadata: Dict[str, Any] = {}

    if not self.project_number:
      # Try discovering project from gcloud CLI config
      import subprocess

      try:
        gcloud_proj = subprocess.check_output(
            ["gcloud", "config", "get-value", "project"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if gcloud_proj and gcloud_proj != "(unset)":
          self.project_number = gcloud_proj
          self.project_id = gcloud_proj
      except Exception:
        pass

    if not self.customer_id or self.customer_id == "YOUR_SECOPS_CUSTOMER_ID":
      raise ValueError(
          "[Pre-flight Validation Failed] SecOps destination requires a valid 'customer_id'.\n"
          "Please specify secops://CUSTOMER_ID@REGION or export SECOPS_CUSTOMER_ID=\"your-uuid\""
      )

    if not self.project_number or self.project_number == "YOUR_GCP_PROJECT_ID":
      raise ValueError(
          "[Pre-flight Validation Failed] Google SecOps ingestion requires a valid GCP Project ID or Number.\n"
          "Please specify --project YOUR_PROJECT_ID or export GOOGLE_CLOUD_PROJECT=\"your-project-id\""
      )

  @staticmethod
  def validate_preflight_destination(
      destination: str,
      project: Optional[str] = None,
  ) -> None:
    """Validate SecOps destination parameters and environment variables before starting tasks."""
    uri_clean = destination.replace("secops://", "").replace("chronicle://", "").strip()
    parts = uri_clean.split("@")
    cust_id = parts[0].strip() if parts and parts[0].strip() else ""

    cust_env = (
        cust_id
        or os.environ.get("CHRONICLE_CUSTOMER_ID")
        or os.environ.get("SECOPS_CUSTOMER_ID")
        or ""
    ).strip()

    proj_env = (
        project
        or os.environ.get("CHRONICLE_PROJECT_NUMBER")
        or os.environ.get("GCP_PROJECT_NUMBER")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
        or ""
    ).strip()

    if not cust_env or cust_env == "YOUR_SECOPS_CUSTOMER_ID":
      raise ValueError(
          "[Pre-flight Validation Failed] Google SecOps destination requires a valid Customer ID.\n"
          "Usage: secops://CUSTOMER_ID@REGION or export SECOPS_CUSTOMER_ID=\"your-uuid\""
      )

    if not proj_env or proj_env == "YOUR_GCP_PROJECT_ID":
      import subprocess

      try:
        gcloud_proj = subprocess.check_output(
            ["gcloud", "config", "get-value", "project"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if not gcloud_proj or gcloud_proj == "(unset)":
          raise ValueError()
      except Exception:
        raise ValueError(
            "[Pre-flight Validation Failed] Google SecOps ingestion requires a Google Cloud Project ID.\n"
            "Please specify --project YOUR_PROJECT_ID or export GOOGLE_CLOUD_PROJECT=\"your-project-id\""
        )


  def _get_auth_token(self) -> str:
    """Retrieve Google OAuth2 access token via pre-resolved credentials, google-auth, or gcloud CLI."""
    try:
      import google.auth
      import google.auth.transport.requests

      scopes = ["https://www.googleapis.com/auth/cloud-platform"]
      if self.credentials:
        creds = self.credentials
      elif self.credentials_file:
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(
            self.credentials_file, scopes=scopes
        )
      else:
        creds, _ = google.auth.default(scopes=scopes)
      req = google.auth.transport.requests.Request()
      creds.refresh(req)
      return creds.token
    except Exception as e:
      import subprocess

      try:
        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if token:
          return token
      except Exception:
        pass
      raise RuntimeError(
          f"Failed to obtain GCP authentication credentials for Google SecOps: {e}\n"
          "Please authenticate via: gcloud auth application-default login\n"
          "Or set GOOGLE_APPLICATION_CREDENTIALS to a valid service account JSON."
      ) from None

  def _get_api_endpoint(
      self, action: str = "logs:import", log_type: Optional[str] = None
  ) -> str:
    """Constructs the new v1alpha Chronicle API endpoint URL."""
    proj = self.project_number or self.project_id
    if not proj:
      raise ValueError(
          "SecOpsSink requires a valid Google Cloud project ID or Project"
          " Number.\nPlease set the GOOGLE_CLOUD_PROJECT or"
          " CHRONICLE_PROJECT_NUMBER environment variable."
      )
    if action == "logs:import" and log_type:
      return (
          f"https://{self.region}-chronicle.googleapis.com/v1alpha"
          f"/projects/{proj}/locations/{self.region}"
          f"/instances/{self.customer_id}/logTypes/{log_type}/logs:import"
      )
    return (
        f"https://{self.region}-chronicle.googleapis.com/v1alpha"
        f"/projects/{proj}/locations/{self.region}"
        f"/instances/{self.customer_id}/{action}"
    )

  def _get_legacy_api_endpoint(self) -> str:
    if self.region.lower() in ("us", ""):
      return "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"
    return f"https://{self.region.lower()}-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"

  def emit(self, scenario: GeneratedScenario) -> int:
    """Ingest scenario logs into Google SecOps using the Chronicle v1alpha API."""
    token = self._get_auth_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=UTF-8",
    }

    tag = self.tag or f"logjammer-{scenario.scenario_id[:8]}"
    applied_labels = {
        "SOURCE": "LOGJAMMER",
        "SCENARIO_ID": scenario.scenario_id[:8],
        "SCENARIO_TAG": tag,
    }
    if self.labels:
      applied_labels.update(self.labels)

    self.last_export_metadata = {
        "customer_id": self.customer_id,
        "project": self.project_number or self.project_id,
        "region": self.region,
        "scenario_id": scenario.scenario_id,
        "scenario_tag": tag,
        "labels": applied_labels,
        "udm_query": (
            'metadata.ingestion_labels.key = "SCENARIO_ID" AND'
            f' metadata.ingestion_labels.value = "{scenario.scenario_id[:8]}"'
        ),
        "raw_query": f'"{scenario.scenario_id[:8]}"',
    }
    total_submitted = 0

    if self.mode == "events:import":
      # Ingest UDM events
      endpoint = self._get_api_endpoint("events:import")
      all_entries = scenario.get_flattened_logs()

      for i in range(0, len(all_entries), self.batch_size):
        batch = all_entries[i : i + self.batch_size]
        prepared_events = []
        for entry in batch:
          try:
            udm_obj = (
                json.loads(entry.content)
                if isinstance(entry.content, str)
                else entry.content
            )
          except Exception:
            udm_obj = {"metadata": {"description": entry.content}}

          if isinstance(udm_obj, dict):
            meta = udm_obj.setdefault("metadata", {})
            if "event_timestamp" not in meta and "eventTimestamp" not in meta:
              ts = entry.timestamp or datetime.now(timezone.utc)
              meta["event_timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            labels = meta.setdefault("ingestion_labels", [])
            if isinstance(labels, list):
              for k, v in applied_labels.items():
                if not any(
                    l.get("key") == k for l in labels if isinstance(l, dict)
                ):
                  labels.append({"key": k, "value": v})

          prepared_events.append({"udm": udm_obj})

        payload = {"inlineSource": {"events": prepared_events}}
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint, data=req_data, headers=headers, method="POST"
        )

        try:
          with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 201, 202, 204):
              total_submitted += len(batch)
        except urllib.error.HTTPError as err:
          error_body = err.read().decode("utf-8", errors="ignore")
          raise RuntimeError(
              "Google SecOps events:import returned HTTP"
              f" {err.code}: {error_body}"
          )

    else:
      # Ingest raw logs grouped by logType via .../logTypes/{log_type}/logs:import
      for log_type, entries in scenario.logs.items():
        endpoint = self._get_api_endpoint("logs:import", log_type=log_type)

        for i in range(0, len(entries), self.batch_size):
          batch = entries[i : i + self.batch_size]
          log_records = []
          now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

          for entry in batch:
            raw_content = entry.content
            # Base64 encode the log data as expected by Chronicle REST API
            encoded_data = base64.b64encode(
                raw_content.encode("utf-8")
            ).decode("utf-8")
            entry_ts = (
                entry.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                if entry.timestamp
                else now_iso
            )

            rec = {
                "data": encoded_data,
                "log_entry_time": entry_ts,
                "collection_time": now_iso,
                "labels": {
                    k: {"value": v} for k, v in applied_labels.items()
                },
            }
            log_records.append(rec)

          inline_source = {
              "logs": log_records,
          }
          if self.forwarder_id:
            proj = self.project_number or self.project_id or "default"
            inline_source["forwarder"] = (
                f"projects/{proj}/locations/{self.region}"
                f"/instances/{self.customer_id}/forwarders/{self.forwarder_id}"
            )

          payload = {"inline_source": inline_source}
          req_data = json.dumps(payload).encode("utf-8")
          req = urllib.request.Request(
              endpoint, data=req_data, headers=headers, method="POST"
          )

          try:
            with urllib.request.urlopen(req, timeout=30) as resp:
              if resp.status in (200, 201, 202, 204):
                total_submitted += len(batch)
          except urllib.error.HTTPError as err:
            error_body = err.read().decode("utf-8", errors="ignore")
            # If 404 or 400 on v1alpha, try legacy fallback endpoint
            if err.code in (404, 400):
              try:
                legacy_endpoint = self._get_legacy_api_endpoint()
                legacy_payload = {
                    "customer_id": self.customer_id,
                    "log_type": log_type,
                    "entries": [
                        {
                            "log_text": e.content,
                            "ts": (
                                e.timestamp.isoformat()
                                if e.timestamp
                                else None
                            ),
                        }
                        for e in batch
                    ],
                }
                if self.project_id or self.project_number:
                  legacy_payload["project_id"] = (
                      self.project_id or self.project_number
                  )
                legacy_req = urllib.request.Request(
                    legacy_endpoint,
                    data=json.dumps(legacy_payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(legacy_req, timeout=30) as leg_resp:
                  if leg_resp.status in (200, 201, 202, 204):
                    total_submitted += len(batch)
                    continue
              except Exception:
                pass
            raise RuntimeError(
                f"Google SecOps logs:import returned HTTP {err.code} for"
                f" logType '{log_type}': {error_body}"
            )

    return total_submitted

  def emit_entry(self, entry: LogEntry) -> bool:
    """Emit a single log entry to Google SecOps."""
    scenario = GeneratedScenario(
        title="Single Entry Emission",
        description="Single entry export",
        logs={entry.log_type: [entry]},
    )
    return self.emit(scenario) == 1
