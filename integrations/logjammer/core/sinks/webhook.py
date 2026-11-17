"""HTTP Webhook sink for Log Jammer OSS."""

import json
from typing import Any, Dict, Optional
import urllib.error
import urllib.request
from .base import BaseSink
from ..models import GeneratedScenario, LogEntry


class WebhookSink(BaseSink):
  """Emits log events via HTTP POST to a SIEM collector, Webhook, or HTTP Event Collector."""

  def __init__(
      self,
      url: str,
      headers: Optional[Dict[str, str]] = None,
      batch_size: int = 50,
  ):
    self.url = url
    self.headers = headers or {"Content-Type": "application/json"}
    self.batch_size = batch_size

  def _post_payload(self, data: Any) -> bool:
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(self.url, data=payload, headers=self.headers, method="POST")
    try:
      with urllib.request.urlopen(req, timeout=10) as response:
        return response.status in (200, 201, 202, 204)
    except urllib.error.URLError:
      return False

  def emit(self, scenario: GeneratedScenario) -> int:
    logs = scenario.get_flattened_logs()
    count = 0

    # Batch and send
    for i in range(0, len(logs), self.batch_size):
      batch = logs[i : i + self.batch_size]
      payload = {
          "scenario_id": scenario.scenario_id,
          "title": scenario.title,
          "events": [
              {
                  "log_type": entry.log_type,
                  "content": entry.content,
                  "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
              }
              for entry in batch
          ],
      }
      if self._post_payload(payload):
        count += len(batch)

    return count

  def emit_entry(self, entry: LogEntry) -> bool:
    payload = {
        "log_type": entry.log_type,
        "content": entry.content,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
    }
    return self._post_payload(payload)
