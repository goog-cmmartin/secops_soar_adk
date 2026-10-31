"""Google Threat Intelligence (GTI) Agentic integration for Log Jammer OSS."""

import json
import logging
import os
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
import uuid

logger = logging.getLogger(__name__)

GTI_SESSIONS_ENDPOINT = "https://www.virustotal.com/api/v3/agentspace/sessions"


class GTIClient:
  """Client for interacting with Google Threat Intelligence (GTI) Agentic API."""

  def __init__(self, api_key: Optional[str] = None):
    self.api_key = api_key or os.environ.get("GTI_API_KEY")
    if not self.api_key:
      # Also check VIRUSTOTAL_API_KEY or VT_API_KEY
      self.api_key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get(
          "VT_API_KEY"
      )

  def is_configured(self) -> bool:
    """Check if GTI API key is available."""
    return bool(self.api_key)

  def enrich_scenario(self, scenario_prompt: str, timeout: float = 60.0) -> str:
    """Queries the GTI Agent to enrich a high-level seed prompt with real-world threat intelligence.

    Args:
        scenario_prompt: The user's initial high-level attack prompt.
        timeout: Maximum seconds to wait for GTI agent response.

    Returns:
        A rich threat simulation scenario with real-world IOCs, MITRE TTPs, and
        commands.
    """
    if not self.api_key:
      raise ValueError(
          "Google Threat Intelligence API key is required.\n"
          "Please set the GTI_API_KEY environment variable:\n"
          "  export GTI_API_KEY=\"your_gti_api_key\"\n"
          "Or pass --gti-api-key on the command line."
      )

    message_payload = (
        "Create a realistic, actionable cyber threat simulation scenario with"
        " real-world indicators of compromise (active domains, IPs, URLs,"
        " hashes, process commands, registry keys, and MITRE ATT&CK techniques)"
        " for the following security testing use case:\n\n"
        f"{scenario_prompt}\n\n"
        "Include chronological phases (initial access/delivery, execution/C2,"
        " lateral movement, persistence, data exfiltration/impact) with"
        " specific technical attributes, commands, and indicators that can be"
        " used to generate authentic SIEM and endpoint logs."
    )

    # Encode multipart/form-data
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    body_lines = [
        f"--{boundary}",
        'Content-Disposition: form-data; name="message"',
        "",
        message_payload,
        f"--{boundary}--",
        "",
    ]
    body_bytes = "\r\n".join(body_lines).encode("utf-8")

    headers = {
        "x-apikey": self.api_key,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "application/json",
        "User-Agent": "LogJammer-OSS/1.0",
    }

    req = urllib.request.Request(
        GTI_SESSIONS_ENDPOINT,
        data=body_bytes,
        headers=headers,
        method="POST",
    )

    try:
      with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp_data = resp.read().decode("utf-8")
        data = json.loads(resp_data)
        return self._extract_agent_response(data)
    except urllib.error.HTTPError as err:
      err_body = err.read().decode("utf-8", errors="ignore")
      raise RuntimeError(
          f"Google Threat Intelligence API returned HTTP {err.code}: {err_body}"
      ) from None
    except Exception as e:
      raise RuntimeError(
          f"Failed to communicate with Google Threat Intelligence Agent: {e}"
      ) from e

  def _extract_agent_response(self, data: Dict[str, Any]) -> str:
    """Extracts markdown text widgets from GTI Agent session response."""
    attributes = data.get("data", {}).get("attributes", {})
    events = attributes.get("events", [])

    text_parts = []

    # 1. Look for AGENT_FINAL_RESPONSE
    for event in events:
      if event.get("message_type") == "AGENT_FINAL_RESPONSE":
        response_obj = event.get("agent_final_response", {})
        widgets = response_obj.get("widgets", [])
        for widget in widgets:
          if widget.get("widget_type") == "MARKDOWN_TEXT":
            txt = widget.get("markdown_text_widget", {}).get("text")
            if txt:
              text_parts.append(txt)

    # 2. Fallback: Check any AGENT message or general widgets if AGENT_FINAL_RESPONSE was empty
    if not text_parts:
      for event in events:
        if "agent" in event.get("message_type", "").lower():
          for k in ("agent_final_response", "agent_message", "response"):
            resp_obj = event.get(k, {})
            if isinstance(resp_obj, dict):
              for widget in resp_obj.get("widgets", []):
                txt = widget.get("markdown_text_widget", {}).get("text")
                if txt:
                  text_parts.append(txt)

    if text_parts:
      return "\n\n".join(text_parts).strip()

    # Fallback to session title or raw representation
    return attributes.get(
        "title", "Threat intelligence simulation scenario from GTI Agent."
    )
