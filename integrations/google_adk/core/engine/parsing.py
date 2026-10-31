"""Centralized parsing, normalization, and type conversion helpers for SecOps workflows."""

from datetime import datetime, timezone
from typing import Any, Optional

from engine.domain import CasePriority, CaseStatus


def parse_timestamp(val: Any) -> Optional[datetime]:
    """Parses timestamps in ISO-8601 strings, millisecond epochs, or second epochs into UTC datetime."""
    if not val:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    if isinstance(val, (int, float)):
        # Milliseconds or seconds epoch
        if val > 1e11:
            return datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(float(val), tz=timezone.utc)
    if isinstance(val, str):
        try:
            if val.isdigit():
                num = int(val)
                if num > 1e11:
                    return datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
                return datetime.fromtimestamp(float(num), tz=timezone.utc)
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def parse_status(status_str: Optional[str]) -> CaseStatus:
    """Parses raw case status strings into CaseStatus enum."""
    if not status_str:
        return CaseStatus.UNKNOWN
    s = status_str.upper()
    if "OPEN" in s:
        return CaseStatus.OPEN
    if "CLOSE" in s:
        return CaseStatus.CLOSED
    return CaseStatus.UNKNOWN


def parse_priority(priority_str: Optional[str]) -> CasePriority:
    """Parses raw case priority strings into CasePriority enum."""
    if not priority_str:
        return CasePriority.UNKNOWN
    p = priority_str.upper()
    if "CRITICAL" in p:
        return CasePriority.CRITICAL
    if "HIGH" in p:
        return CasePriority.HIGH
    if "MEDIUM" in p:
        return CasePriority.MEDIUM
    if "LOW" in p:
        return CasePriority.LOW
    return CasePriority.UNKNOWN


_TRUE_STRINGS = frozenset({"true", "1"})
_FALSE_STRINGS = frozenset({"false", "0"})


def parse_strict_bool(value: Any, field_name: str = "value") -> Optional[bool]:
    """Coerces LLM/UI/JSON input to bool, rejecting anything ambiguous.

    Accepts None (unset), bool, int 0/1 and the strings "true"/"false"/"1"/"0"
    (case-insensitive). Anything else raises ValueError so a toggle can never
    silently do the opposite of what was approved.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        norm = value.strip().lower()
        if norm in _TRUE_STRINGS:
            return True
        if norm in _FALSE_STRINGS:
            return False
    raise ValueError(f"{field_name} must be a boolean (true/false), got {value!r}")


def parse_id_list(value: Any, field_name: str = "ids") -> list:
    """Coerces a single ID, comma-separated string or iterable of IDs to a clean list of strings.

    Prevents a bare string from being iterated character by character.
    """
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        raise ValueError(f"{field_name} must be a string or list of strings, got {type(value).__name__}")
    out: list = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} entries must be strings, got {item!r}")
        clean = item.strip()
        if clean and clean not in out:
            out.append(clean)
    return out
