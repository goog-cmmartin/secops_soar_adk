"""Base class for pluggable log output sinks."""

from abc import ABC, abstractmethod
from typing import List
from ..models import GeneratedScenario, LogEntry


class BaseSink(ABC):
  """Abstract base class for all output destinations."""

  @abstractmethod
  def emit(self, scenario: GeneratedScenario) -> int:
    """Emit all logs in the scenario to the destination. Returns count of logs emitted."""
    pass

  @abstractmethod
  def emit_entry(self, entry: LogEntry) -> bool:
    """Emit a single log entry. Returns True on success."""
    pass
