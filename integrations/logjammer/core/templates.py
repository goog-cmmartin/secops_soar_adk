"""Relative time template parser and dynamic timestamp generator."""

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, List, Optional, Tuple, Union


# Regex to match relative timestamp templates:
# Examples: ##$TimeStamp-0d2h15m0s$##, ##$Epoch-0d0h5m0s$##, ##$SyslogTime-0d1h0m0s$##
TEMPLATE_PATTERN = re.compile(
    r"##\$(TimeStamp|Epoch|EpochMillis|Date|SyslogTime)([+-])(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?\$##"
)

# Regex to match ISO-8601 UTC/offset timestamps in free text
ISO_TIMESTAMP_PATTERN = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\b"
)


def parse_base_timestamp(value: Any) -> Optional[datetime]:
  """Parse a base timestamp from datetime, ISO-8601 string, or Unix epoch (sec/ms/us/ns)."""
  if value is None:
    return None
  if isinstance(value, datetime):
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)

  raw = str(value).strip()
  if not raw or raw.lower() in ("none", "null", "auto", "") or (raw.startswith("[") and raw.endswith("]")):
    return None

  # 1. Check numeric Unix epoch (seconds, milliseconds, microseconds, nanoseconds)
  if re.fullmatch(r"\d+(?:\.\d+)?", raw):
    try:
      num = float(raw)
      if num > 1e17:      # nanoseconds
        num /= 1e9
      elif num > 1e14:    # microseconds
        num /= 1e6
      elif num > 1e11:    # milliseconds
        num /= 1e3
      if 946684800 <= num <= 4102444800:  # 2000-01-01 to 2100-01-01
        return datetime.fromtimestamp(num, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
      pass

  # 2. Check ISO-8601 format
  iso_candidate = raw
  if iso_candidate.endswith("Z"):
    iso_candidate = iso_candidate[:-1] + "+00:00"
  try:
    dt = datetime.fromisoformat(iso_candidate)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
  except ValueError:
    pass

  # 3. Search for embedded ISO-8601 timestamp inside string
  match = ISO_TIMESTAMP_PATTERN.search(raw)
  if match:
    found = match.group(1)
    if found.endswith("Z"):
      found = found[:-1] + "+00:00"
    try:
      dt = datetime.fromisoformat(found)
      return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
      pass

  return None


def extract_timestamp_from_text(text: Optional[str]) -> Optional[datetime]:
  """Extract the first valid ISO-8601 timestamp found in a scenario prompt or summary."""
  if not text:
    return None
  match = ISO_TIMESTAMP_PATTERN.search(str(text))
  if match:
    return parse_base_timestamp(match.group(1))
  return None


class TimeTemplateService:
  """Resolves relative timestamp templates into real date/time strings."""

  def __init__(self, base_time: Optional[datetime] = None):
    parsed = parse_base_timestamp(base_time)
    self.base_time = parsed or datetime.now(timezone.utc)

  def parse_offset(
      self,
      sign: str,
      days: Optional[str],
      hours: Optional[str],
      minutes: Optional[str],
      seconds: Optional[str],
  ) -> timedelta:
    """Parse regex match groups into a timedelta object."""
    d = int(days) if days else 0
    h = int(hours) if hours else 0
    m = int(minutes) if minutes else 0
    s = int(seconds) if seconds else 0
    delta = timedelta(days=d, hours=h, minutes=m, seconds=s)
    return delta if sign == "+" else -delta

  def format_timestamp(self, template_type: str, target_dt: datetime) -> str:
    """Format the target datetime according to the template type."""
    if template_type == "Epoch":
      return str(int(target_dt.timestamp()))
    elif template_type == "EpochMillis":
      return str(int(target_dt.timestamp() * 1000))
    elif template_type == "Date":
      return target_dt.strftime("%Y-%m-%d")
    elif template_type == "SyslogTime":
      # Traditional syslog timestamp format: Aug 24 09:15:30 (handles single digit day spacing)
      day_str = f"{target_dt.day:2d}"
      return target_dt.strftime(f"%b {day_str} %H:%M:%S")
    else:  # Default "TimeStamp" -> ISO 8601 UTC format
      return target_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"

  def replace_templates_with_timestamp(self, text: str) -> Tuple[str, datetime]:
    """Replace all ##$...$## templates in a text string and return (resolved_text, resolved_datetime)."""
    resolved_dt: Optional[datetime] = None

    def _replacer(match: re.Match) -> str:
      nonlocal resolved_dt
      template_type, sign, d, h, m, s = match.groups()
      offset = self.parse_offset(sign, d, h, m, s)
      target_dt = self.base_time + offset
      if resolved_dt is None:
        resolved_dt = target_dt
      return self.format_timestamp(template_type, target_dt)

    resolved_text = TEMPLATE_PATTERN.sub(_replacer, text)
    if resolved_dt is None:
      # If the LLM emitted an ISO timestamp inside the log line, extract it if within reasonable bounds
      extracted = extract_timestamp_from_text(resolved_text)
      resolved_dt = extracted or self.base_time
    return resolved_text, resolved_dt

  def replace_templates(self, text: str) -> str:
    """Replace all ##$...$## templates in a text string."""
    resolved_text, _ = self.replace_templates_with_timestamp(text)
    return resolved_text


def replace_time_templates(
    text: str, base_time: Optional[datetime] = None
) -> str:
  """Helper function to replace time templates in a string."""
  service = TimeTemplateService(base_time)
  return service.replace_templates(text)


def replace_time_templates_in_logs(
    logs_data: Union[Dict[str, Any], List[Any], str],
    base_time: Optional[datetime] = None,
) -> Any:
  """Recursively replaces time templates across nested dictionaries, lists, and strings."""
  service = TimeTemplateService(base_time)

  if isinstance(logs_data, str):
    return service.replace_templates(logs_data)
  elif isinstance(logs_data, list):
    return [replace_time_templates_in_logs(item, base_time) for item in logs_data]
  elif isinstance(logs_data, dict):
    return {
        key: replace_time_templates_in_logs(value, base_time)
        for key, value in logs_data.items()
    }
  return logs_data
