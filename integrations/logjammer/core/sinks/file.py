"""File and Stdout sinks for Log Jammer OSS."""

import json
from pathlib import Path
import sys
from typing import Optional, TextIO, Union
from .base import BaseSink
from ..models import GeneratedScenario, LogEntry


class FileSink(BaseSink):
  """Writes generated logs to a file (.jsonl, .log, or .json) or stdout."""

  def __init__(
      self,
      output_path: Optional[Union[str, Path]] = None,
      format_type: str = "auto",  # 'auto', 'jsonl', 'raw', 'json'
  ):
    self.output_path = Path(output_path) if output_path else None
    self.format_type = format_type

  def _get_target_format(self) -> str:
    if self.format_type != "auto":
      return self.format_type
    if self.output_path:
      suffix = self.output_path.suffix.lower()
      if suffix == ".jsonl":
        return "jsonl"
      elif suffix == ".json":
        return "json"
      return "raw"
    return "raw"

  def emit(self, scenario: GeneratedScenario) -> int:
    fmt = self._get_target_format()
    logs = scenario.get_flattened_logs()

    if fmt == "json":
      # Dump full scenario JSON
      content = scenario.to_json(indent=2)
      if self.output_path:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
          f.write(content)
      else:
        sys.stdout.write(content + "\n")
      return len(logs)

    # Line-by-line output
    output_lines = []
    for entry in logs:
      if fmt == "jsonl":
        output_lines.append(json.dumps({
            "log_type": entry.log_type,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "log": entry.content,
        }))
      else:  # raw lines
        output_lines.append(entry.content)

    full_output = "\n".join(output_lines) + "\n"

    if self.output_path:
      self.output_path.parent.mkdir(parents=True, exist_ok=True)
      with open(self.output_path, "w", encoding="utf-8") as f:
        f.write(full_output)
    else:
      sys.stdout.write(full_output)

    return len(logs)

  def emit_entry(self, entry: LogEntry) -> bool:
    if self.output_path:
      with open(self.output_path, "a", encoding="utf-8") as f:
        f.write(entry.content + "\n")
    else:
      sys.stdout.write(entry.content + "\n")
    return True
