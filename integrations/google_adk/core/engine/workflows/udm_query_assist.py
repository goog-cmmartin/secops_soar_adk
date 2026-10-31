"""Read-only UDM query assistance: field value discovery and natural-language translation.

- ``FindUdmFieldValuesWorkflow`` wraps ``GET :findUdmFieldValues`` (autocomplete:
  which UDM field paths recently held values matching a text fragment).
- ``TranslateUdmQueryWorkflow`` wraps ``POST :translateUdmQuery`` (natural
  language -> UDM search query + optional time range). Neither writes tenant
  state. Whether translateUdmQuery consumes Gemini quota or has per-user limits
  is UNKNOWN: the public API reference does not say, and no quota header or
  error was observed live.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from engine.domain import UdmFieldValueMatch, UdmFieldValueMatches, UdmQueryTranslation

MAX_FIELD_VALUE_PAGE_SIZE = 1000
MAX_TRANSLATE_TEXT_LENGTH = 2000


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if "." in s:
        head, _, tail = s.partition(".")
        digits = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                digits += ch
            else:
                rest = tail[i:]
                break
        s = f"{head}.{digits[:6]}{rest}" if digits else f"{head}{rest}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise RuntimeError(f"Unexpected timestamp from SecOps: {value!r}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class FindUdmFieldValuesWorkflow:
    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(self, query: str, page_size: int = 20, page_token: Optional[str] = None) -> UdmFieldValueMatches:
        text = (query or "").strip()
        if not text:
            raise ValueError("find_udm_field_values requires a non-empty query.")
        if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1 or page_size > MAX_FIELD_VALUE_PAGE_SIZE:
            raise ValueError(f"page_size must be an integer between 1 and {MAX_FIELD_VALUE_PAGE_SIZE}.")
        raw = self.adapter.find_udm_field_values(query=text, page_size=page_size, page_token=page_token)
        matches = []
        for m in raw.get("valueMatches", []) or []:
            if not isinstance(m, dict):
                continue
            matches.append(
                UdmFieldValueMatch(
                    field_path=str(m.get("fieldPath", "")),
                    value=str(m.get("value", "")),
                    ingestion_time=_parse_ts(m.get("ingestionTime")),
                    match_start=int(m.get("matchStart", 0) or 0),
                    match_end=int(m.get("matchEnd", 0) or 0),
                )
            )
        return UdmFieldValueMatches(
            query=text,
            matches=matches,
            has_more=bool(raw.get("hasMoreMatches", False)),
            next_page_token=raw.get("nextPageToken") or None,
            field_match_regex=raw.get("fieldMatchRegex"),
            raw=raw,
        )


class TranslateUdmQueryWorkflow:
    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(self, text: str) -> UdmQueryTranslation:
        t = (text or "").strip()
        if not t:
            raise ValueError("translate_udm_query requires non-empty text.")
        if len(t) > MAX_TRANSLATE_TEXT_LENGTH:
            raise ValueError(f"text is longer than {MAX_TRANSLATE_TEXT_LENGTH} characters.")
        raw = self.adapter.translate_udm_query(t)
        query = raw.get("query")
        if not query:
            raise RuntimeError(f"translateUdmQuery returned no query: {raw}")
        tr = raw.get("timeRange") or {}
        return UdmQueryTranslation(
            text=t,
            query=str(query),
            start_time=_parse_ts(tr.get("startTime")) if isinstance(tr, dict) else None,
            end_time=_parse_ts(tr.get("endTime")) if isinstance(tr, dict) else None,
            raw=raw,
        )
