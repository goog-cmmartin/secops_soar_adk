# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Open Knowledge Format (OKF v0.2) core document parser and trust evaluator.

Implements the OKF v0.2 specification:
- Plain Markdown documents with YAML frontmatter delimited by `---`.
- Trust tier derivation: `unverified`, `machine-confirmed`, `human-reviewed`.
- Staleness checking against `stale_after` ISO 8601 timestamps.
- Actor convention validation: `human:<id>`, `process:<id>`, `<producer>/<version>`.
- Preserves raw string timestamps without silent PyYAML timezone mutations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# OKF v0.2 §11: `type` is the only strictly required frontmatter key.
REQUIRED_FRONTMATTER_KEYS = ("type",)

_FRONTMATTER_DELIM = "---"

# OKF v0.2 §7: Actor patterns
_HUMAN_ACTOR_RE = re.compile(r"^human:[A-Za-z0-9_\-@.]+$")
_PROCESS_ACTOR_RE = re.compile(r"^process:[A-Za-z0-9_\-]+$")
_AGENT_ACTOR_RE = re.compile(r"^[A-Za-z0-9_\-]+/[A-Za-z0-9_.\-]+$")


class _Loader(yaml.SafeLoader):
    """SafeLoader that leaves timestamps as the text the author wrote.

    PyYAML's default implicit resolver turns `2026-06-30T14:00:00Z` into a
    datetime object. When serialized back, it mutates into `2026-06-30 14:00:00+00:00`.
    Dropping the timestamp resolver preserves original strings matching YAML 1.2 core.
    """


_Loader.yaml_implicit_resolvers = {
    ch: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


class OKFDocumentError(ValueError):
    """Raised when an OKF document is malformed."""


def is_valid_actor(actor: Any) -> bool:
    """Validate an actor string against OKF v0.2 §7 convention."""
    if not isinstance(actor, str):
        return False
    return bool(
        _HUMAN_ACTOR_RE.match(actor)
        or _PROCESS_ACTOR_RE.match(actor)
        or _AGENT_ACTOR_RE.match(actor)
    )


def normalize_verified(frontmatter: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the `verified` events as a list of mappings (OKF v0.2 §5.2).

    A single verifier MAY be written as one `{ by, at }` mapping without the
    list dash. Consumers MUST treat a bare mapping as a one-element list.
    """
    raw = frontmatter.get("verified")
    if not raw:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def trust_tier(frontmatter: Dict[str, Any]) -> str:
    """Derive the trust tier for an OKF concept (OKF v0.2 §5.3).

    - No `verified` key => 'unverified'
    - `verified` by non-`human:` actors only => 'machine-confirmed'
    - `verified` by at least one `human:<id>` actor => 'human-reviewed'
    """
    events = normalize_verified(frontmatter)
    if not events:
        return "unverified"
    for event in events:
        actor = event.get("by", "")
        if isinstance(actor, str) and actor.startswith("human:"):
            return "human-reviewed"
    return "machine-confirmed"


def parse_iso8601_utc(ts_str: str) -> Optional[datetime]:
    """Parse an ISO 8601 string with UTC indicator into a timezone-aware datetime."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    cleaned = ts_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def is_stale(frontmatter: Dict[str, Any], as_of: Optional[datetime] = None) -> bool:
    """Check if an OKF concept is stale (OKF v0.2 §5.5).

    A concept is stale when now >= stale_after.
    Absent or invalid `stale_after` => False.
    """
    stale_after_str = frontmatter.get("stale_after")
    if not stale_after_str or not isinstance(stale_after_str, str):
        return False
    stale_dt = parse_iso8601_utc(stale_after_str)
    if not stale_dt:
        return False
    now = as_of if as_of is not None else datetime.now(timezone.utc)
    return now >= stale_dt


@dataclass
class OKFDocument:
    """Represents an Open Knowledge Format document (frontmatter + body)."""

    frontmatter: Dict[str, Any] = field(default_factory=dict)
    body: str = ""

    @classmethod
    def parse(cls, text: str) -> "OKFDocument":
        """Parse an OKF document from UTF-8 string content."""
        lines = text.splitlines()
        if not lines or lines[0].strip() != _FRONTMATTER_DELIM:
            return cls(frontmatter={}, body=text)

        end_idx = None
        for i in range(1, len(lines)):
            if lines[i].strip() == _FRONTMATTER_DELIM:
                end_idx = i
                break

        if end_idx is None:
            raise OKFDocumentError("Unterminated YAML frontmatter block (missing closing '---')")

        fm_text = "\n".join(lines[1:end_idx])
        try:
            fm = yaml.load(fm_text, Loader=_Loader) or {}
        except yaml.YAMLError as e:
            raise OKFDocumentError(f"Invalid YAML in frontmatter: {e}") from e

        if not isinstance(fm, dict):
            raise OKFDocumentError("Frontmatter must be a YAML mapping/dictionary")

        body = "\n".join(lines[end_idx + 1:])
        if body.startswith("\n"):
            body = body[1:]
        return cls(frontmatter=fm, body=body)

    @classmethod
    def load(cls, file_path: Path) -> "OKFDocument":
        """Load and parse an OKF document from a file path."""
        text = file_path.read_text(encoding="utf-8")
        return cls.parse(text)

    def serialize(self) -> str:
        """Serialize document back to OKF markdown format."""
        fm_text = yaml.safe_dump(
            self.frontmatter, sort_keys=False, allow_unicode=True
        ).rstrip()
        body = self.body if self.body.endswith("\n") else self.body + "\n"
        return f"{_FRONTMATTER_DELIM}\n{fm_text}\n{_FRONTMATTER_DELIM}\n\n{body}"

    def save(self, file_path: Path) -> None:
        """Write serialized document to disk."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(self.serialize(), encoding="utf-8")

    def validate_okf(self) -> List[str]:
        """Validate OKF v0.2 conformance rules."""
        errors: List[str] = []
        doc_type = self.frontmatter.get("type")
        if not doc_type or not isinstance(doc_type, str):
            errors.append("Missing required frontmatter key: 'type'")

        # Validate actor conventions if generated is present
        gen = self.frontmatter.get("generated")
        if gen is not None:
            if not isinstance(gen, dict):
                errors.append("'generated' must be a mapping {by, at}")
            else:
                actor = gen.get("by")
                if not is_valid_actor(actor):
                    errors.append(f"Invalid actor in generated.by: {repr(actor)}")
                at_val = gen.get("at")
                if at_val and not parse_iso8601_utc(str(at_val)):
                    errors.append(f"Invalid ISO 8601 UTC timestamp in generated.at: {repr(at_val)}")

        # Validate verified entries
        ver_list = normalize_verified(self.frontmatter)
        for idx, ver in enumerate(ver_list):
            actor = ver.get("by")
            if not is_valid_actor(actor):
                errors.append(f"Invalid actor in verified[{idx}].by: {repr(actor)}")
            at_val = ver.get("at")
            if at_val and not parse_iso8601_utc(str(at_val)):
                errors.append(f"Invalid ISO 8601 UTC timestamp in verified[{idx}].at: {repr(at_val)}")

        # Validate status if present
        status = self.frontmatter.get("status")
        if status is not None and status not in ("draft", "stable", "deprecated"):
            errors.append(f"Invalid status: {repr(status)} (must be draft, stable, or deprecated)")

        # Validate stale_after if present
        stale_after = self.frontmatter.get("stale_after")
        if stale_after is not None and not parse_iso8601_utc(str(stale_after)):
            errors.append(f"Invalid ISO 8601 UTC timestamp in stale_after: {repr(stale_after)}")

        # Validate sources list if present
        sources = self.frontmatter.get("sources")
        if sources is not None:
            if not isinstance(sources, list):
                errors.append("'sources' must be a list of source mappings")
            else:
                for idx, src in enumerate(sources):
                    if not isinstance(src, dict):
                        errors.append(f"sources[{idx}] must be a mapping")
                    elif not src.get("resource"):
                        errors.append(f"sources[{idx}] is missing required key: 'resource'")

        return errors
