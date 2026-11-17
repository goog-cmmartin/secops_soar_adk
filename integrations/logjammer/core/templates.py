"""Relative time template parser and dynamic timestamp generator.

Template tags have the form

    ##$<Name>[<offset>][|<format>[|<utc offset>]]$##

and are replaced with a time relative to a base time, normally "now".

Names
    TimeStamp           ISO 8601 UTC with milliseconds, or any layout given by <format>
    Epoch               Unix seconds
    EpochMS             Unix milliseconds. EpochMillis is accepted as an alias.
    EpochMicroseconds   Unix microseconds
    EpochNanoseconds    Unix nanoseconds
    Date                YYYY-MM-DD
    SyslogTime          Traditional syslog, such as "Aug 24 09:15:30"

Offset
    + or - followed by any of <n>d <n>h <n>m <n>s, such as -0d2h15m0s. Optional. Without it the base time is used.

Format, for TimeStamp only
    Either Python strftime directives, such as %Y/%m/%d %H:%M:%S, with two extras: %3f for milliseconds and %:z for
    a UTC offset with a colon. Or date-pattern tokens: yyyy yy MMM Mon MM dd HH mm ss SSS. Upper-case YYYY, YY, and DD
    are accepted too. Text inside single quotes is literal, and so is any other character, including Z.
    The format must not contain "|" or "$##". A format given to an Epoch tag is ignored.

UTC offset, with a format only
    Such as -08:00. Renders the time in that zone.

This is the same tag syntax as the original LogJammer web app, with Date, SyslogTime, and the UTC offset added.

Examples, with a base time of 2026-08-24T12:00:00Z
    ##$TimeStamp-0d2h15m0s$##                                   2026-08-24T09:45:00.000Z
    ##$EpochMS-0d0h10m0s$##                                     Unix milliseconds for 11:50:00
    ##$TimeStamp-0d0h5m0s|%Y/%m/%d %H:%M:%S$##                  2026/08/24 11:55:00
    ##$TimeStamp-0d0h5m0s|yyyy/MM/dd HH:mm:ss$##                2026/08/24 11:55:00
    ##$TimeStamp-0d0h5m0s|%Y-%m-%dT%H:%M:%S%:z|-08:00$##        2026-08-24T03:55:00-08:00
"""

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import warnings


TEMPLATE_PATTERN = re.compile(
    r"##\$(TimeStamp|EpochMS|EpochMillis|EpochMicroseconds|EpochNanoseconds|Epoch|Date|SyslogTime)"
    r"(?:([+-])(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?)?"
    r"(?:\|((?:(?!\$##)[^|])+))?"
    r"(?:\|([+-]\d{2}:?\d{2}))?"
    r"\$##"
)

# Anything that still looks like a template after substitution, such as a tag name this module does not know.
UNRESOLVED_TEMPLATE_PATTERN = re.compile(r"##\$.{0,120}?\$##")

# Regex to match ISO-8601 UTC/offset timestamps in free text
ISO_TIMESTAMP_PATTERN = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\b"
)

# Date-pattern tokens accepted in a format that has no % directives, longest first.
_PATTERN_TOKENS = [
    ("yyyy", "%Y"), ("YYYY", "%Y"), ("MMM", "%b"), ("Mon", "%b"), ("SSS", "%3f"), ("yy", "%y"), ("YY", "%y"), ("MM", "%m"),
    ("dd", "%d"), ("DD", "%d"), ("HH", "%H"), ("mm", "%M"), ("ss", "%S"),
]
_PATTERN_TOKEN_RE = re.compile("'([^']*)'|" + "|".join(re.escape(t) for t, _ in _PATTERN_TOKENS))
_PATTERN_TOKEN_MAP = dict(_PATTERN_TOKENS)

# Shared by the guide-learning and scenario-generation prompts so both describe exactly the tags that exist here.
SUPPORTED_TIME_TAGS_PROMPT = """Only these relative time template tags exist. Do not invent other tag names or other argument styles:
     * ISO 8601 UTC with milliseconds: `##$TimeStamp-0d2h15m0s$##` -> 2026-08-24T09:45:00.000Z
     * Unix epoch seconds: `##$Epoch-0d1h30m0s$##`
     * Unix epoch milliseconds: `##$EpochMS-0d1h30m0s$##`
     * Unix epoch microseconds: `##$EpochMicroseconds-0d1h30m0s$##`
     * Unix epoch nanoseconds: `##$EpochNanoseconds-0d1h30m0s$##`
     * Date only: `##$Date-0d0h0m0s$##` -> 2026-08-24
     * Syslog: `##$SyslogTime-0d0h45m0s$##` -> Aug 24 11:15:00
     * Any other layout: add a strftime format after a pipe, `##$TimeStamp-0d0h45m0s|%Y/%m/%d %H:%M:%S$##`
       -> 2026/08/24 11:15:00. Use %3f for milliseconds, as in `##$TimeStamp-0d0h45m0s|%Y%m%d%H%M%S.%3f$##`.
     * Any other layout in a fixed UTC offset: add the offset after a second pipe,
       `##$TimeStamp-0d0h45m0s|%Y-%m-%dT%H:%M:%S%:z|-08:00$##` -> 2026-08-24T03:15:00-08:00.
       Use %z for -0800 and %:z for -08:00, matching the sample exactly.
   The offset after the tag name is written as days, hours, minutes, seconds, with + or - in front.
   The format separator is a pipe. A colon or a dash before the format does not work."""


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
      sign: Optional[str],
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
    elif template_type in ("EpochMS", "EpochMillis"):
      return str(int(target_dt.timestamp() * 1000))
    elif template_type == "EpochMicroseconds":
      return str(int(target_dt.timestamp() * 1000000))
    elif template_type == "EpochNanoseconds":
      return str(int(target_dt.timestamp() * 1000000) * 1000)
    elif template_type == "Date":
      return target_dt.strftime("%Y-%m-%d")
    elif template_type == "SyslogTime":
      # Traditional syslog timestamp format: Aug 24 09:15:30 (handles single digit day spacing)
      day_str = f"{target_dt.day:2d}"
      return target_dt.strftime(f"%b {day_str} %H:%M:%S")
    else:  # Default "TimeStamp" -> ISO 8601 UTC format
      return target_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"

  def format_custom(
      self, target_dt: datetime, fmt: str, utc_offset: Optional[str] = None
  ) -> str:
    """Format the target datetime with a strftime or date-pattern layout and an optional UTC offset."""
    if utc_offset:
      sign = -1 if utc_offset.startswith("-") else 1
      digits = utc_offset[1:].replace(":", "")
      tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
      target_dt = target_dt.astimezone(tz)
    if "%" not in fmt:
      # Date-pattern tokens. Quoted text is literal, and literal % is escaped for strftime.
      fmt = _PATTERN_TOKEN_RE.sub(
          lambda m: m.group(1).replace("%", "%%") if m.group(1) is not None else _PATTERN_TOKEN_MAP[m.group(0)],
          fmt,
      )
    fmt = fmt.replace("%3f", f"{target_dt.microsecond // 1000:03d}")
    if "%:z" in fmt:
      # Offset with a colon, such as -08:00. Handled here because strftime only gained %:z in Python 3.12.
      raw = target_dt.strftime("%z") or "+0000"
      fmt = fmt.replace("%:z", f"{raw[:3]}:{raw[3:5]}")
    return target_dt.strftime(fmt)

  def replace_templates_with_timestamp(self, text: str) -> Tuple[str, datetime]:
    """Replace all ##$...$## templates in a text string and return (resolved_text, resolved_datetime)."""
    resolved_dt: Optional[datetime] = None

    def _replacer(match: re.Match) -> str:
      nonlocal resolved_dt
      template_type, sign, d, h, m, s, fmt, utc_offset = match.groups()
      if utc_offset and not (fmt and template_type == "TimeStamp"):
        return match.group(0)
      target_dt = self.base_time + self.parse_offset(sign, d, h, m, s)
      if resolved_dt is None:
        resolved_dt = target_dt
      if fmt and template_type == "TimeStamp":
        return self.format_custom(target_dt, fmt, utc_offset)
      return self.format_timestamp(template_type, target_dt)

    resolved_text = TEMPLATE_PATTERN.sub(_replacer, text)
    if resolved_dt is None:
      extracted = extract_timestamp_from_text(resolved_text)
      resolved_dt = extracted or self.base_time
    return resolved_text, resolved_dt

  def replace_templates(self, text: str) -> str:
    """Replace all ##$...$## templates in a text string."""
    resolved_text, _ = self.replace_templates_with_timestamp(text)
    return resolved_text


def find_unresolved_templates(text: str) -> List[str]:
  """Return template-like tags that replace_templates would leave untouched."""
  resolved = TimeTemplateService().replace_templates(text)
  return UNRESOLVED_TEMPLATE_PATTERN.findall(resolved)


def find_unsupported_guide_tags(guide_text: str) -> List[str]:
  """Return the distinct template tags in a schema guide that this module cannot fill.

  Tags written as documentation placeholders, such as ##$TimeStamp-<offset>$## or ##$...$##, are ignored.
  """
  seen: List[str] = []
  for tag in find_unresolved_templates(guide_text):
    if "<" in tag or "..." in tag:
      continue
    if tag not in seen:
      seen.append(tag)
  return seen


def replace_time_templates(
    text: str, base_time: Optional[datetime] = None
) -> str:
  """Helper function to replace time templates in a string.

  Warns when a template-like tag is left behind, which means the tag name or its
  arguments are not supported and the log line still contains a placeholder.
  """
  service = TimeTemplateService(base_time)
  resolved = service.replace_templates(text)
  leftover = UNRESOLVED_TEMPLATE_PATTERN.findall(resolved)
  if leftover:
    warnings.warn(
        f"Unresolved time template tag(s) left in log content: {sorted(set(leftover))[:3]}",
        stacklevel=2,
    )
  return resolved


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
