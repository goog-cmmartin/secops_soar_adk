"""Extracts the example log lines from a schema guide.

Used by scripts/check_guide_examples.py, which parses each example with a Google SecOps
parser. Kept here so the extraction logic can be unit tested without network access.
"""

import json
import re
from typing import Callable, List, Optional

_HEADING_RE = re.compile(r"^#{1,3} .*$", re.M)
_FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.M | re.S)


def example_blocks(guide_text: str) -> List[str]:
  """Return the contents of the fenced code blocks in the guide's examples section.

  The examples section is the first level 1 or level 2 heading that contains the word
  "example", up to the next heading of the same or a higher level.
  """
  headings = [(m.start(), m.group(0)) for m in _HEADING_RE.finditer(guide_text)]
  start = level = None
  for pos, heading in headings:
    if re.match(r"^#{1,2} .*example", heading, re.I):
      start, level = pos, len(heading.split(" ")[0])
      break
  if start is None:
    return []
  end = next(
      (pos for pos, heading in headings if pos > start and len(heading.split(" ")[0]) <= level),
      len(guide_text),
  )
  return [m.group(1).strip("\n") for m in _FENCE_RE.finditer(guide_text[start:end])]


def block_to_logs(block: str) -> List[str]:
  """Split one fenced block into individual log records.

  A block is one record when it is a single JSON document, pretty-printed or not, or a
  multi-line XML event. Otherwise each non-empty line is one record.
  """
  stripped = block.strip()
  if not stripped:
    return []
  try:
    obj = json.loads(stripped)
    if isinstance(obj, (dict, list)):
      return [json.dumps(obj, separators=(",", ":"))]
  except ValueError:
    pass
  lines = [line for line in stripped.splitlines() if line.strip()]
  if stripped.startswith(("<Event", "<?xml")):
    return [" ".join(line.strip() for line in lines)]
  if stripped.startswith("{") and len(lines) > 1 and not all(line.strip().startswith("{") for line in lines):
    # A multi-line JSON document that does not parse. Keep it as one record so the
    # caller reports it as one broken example, not as many fragments.
    return [" ".join(line.strip() for line in lines)]
  return lines


def extract_example_logs(
    guide_text: str, resolve: Optional[Callable[[str], str]] = None
) -> List[str]:
  """Return every example log record in a guide.

  Args:
    guide_text: Full text of a schema guide.
    resolve: Optional function applied to each fenced block before it is split, normally
      a time template resolver. Resolving first matters for JSON examples that use an
      unquoted tag as a number, which are not valid JSON until the tag is filled.
  """
  logs: List[str] = []
  for block in example_blocks(guide_text):
    logs.extend(block_to_logs(resolve(block) if resolve else block))
  return logs
