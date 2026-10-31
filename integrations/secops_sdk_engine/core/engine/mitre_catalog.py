# Copyright 2025 Google LLC
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
from __future__ import annotations

"""MITRE ATT&CK Catalog & Threat Taxonomy Reference.

Provides normalized access to the packaged MITRE Enterprise ATT&CK matrix,
industry threat profiles, and telemetry-to-tactic visibility mappings.
"""

import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent / "data" / "mitre"
TECHNIQUE_REGEX = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


class MitreCatalog:
    """Catalog providing fast in-memory access to MITRE ATT&CK Enterprise Matrix."""

    _instance: Optional[MitreCatalog] = None

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or DATA_DIR
        self._matrix_data: Dict[str, Any] = {}
        self._profiles_data: Dict[str, Any] = {}
        self._visibility_data: Dict[str, Any] = {}
        self._loaded = False
        self._load()

    @classmethod
    def get_instance(cls, data_dir: Optional[Path] = None) -> MitreCatalog:
        if cls._instance is None:
            cls._instance = cls(data_dir=data_dir)
        return cls._instance

    def _load(self) -> None:
        if self._loaded:
            return

        matrix_path = self.data_dir / "enterprise_matrix.json"
        if matrix_path.is_file():
            try:
                with open(matrix_path, "r", encoding="utf-8") as f:
                    self._matrix_data = json.load(f)
            except Exception as e:
                logger.error("Failed to load MITRE enterprise matrix from %s: %s", matrix_path, e)

        profiles_path = self.data_dir / "threat_profiles.json"
        if profiles_path.is_file():
            try:
                with open(profiles_path, "r", encoding="utf-8") as f:
                    self._profiles_data = json.load(f)
            except Exception as e:
                logger.error("Failed to load MITRE threat profiles from %s: %s", profiles_path, e)

        visibility_path = self.data_dir / "log_source_visibility.json"
        if visibility_path.is_file():
            try:
                with open(visibility_path, "r", encoding="utf-8") as f:
                    self._visibility_data = json.load(f)
            except Exception as e:
                logger.error("Failed to load log source visibility from %s: %s", visibility_path, e)

        self._loaded = True

    @property
    def version(self) -> str:
        return self._matrix_data.get("version", "18.1")

    @property
    def total_techniques(self) -> int:
        return self._matrix_data.get("total_techniques", len(self.techniques))

    @property
    def total_tactics(self) -> int:
        return self._matrix_data.get("total_tactics", len(self.tactics))

    @property
    def techniques(self) -> Dict[str, Dict[str, Any]]:
        return self._matrix_data.get("techniques", {})

    @property
    def tactics(self) -> Dict[str, Dict[str, Any]]:
        return self._matrix_data.get("tactics", {})

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        if not technique_id:
            return None
        norm_id = technique_id.strip().upper().replace("_", ".")
        return self.techniques.get(norm_id)

    def get_tactic(self, tactic_key: str) -> Optional[Dict[str, Any]]:
        if not tactic_key:
            return None
        norm_key = tactic_key.strip().lower().replace("_", "-").replace(" ", "-")
        # Try direct match
        if norm_key in self.tactics:
            return self.tactics[norm_key]
        # Try matching by ID or display name
        for k, tac in self.tactics.items():
            if tac.get("id", "").upper() == norm_key.upper() or tac.get("name", "").lower() == norm_key:
                return tac
        return None

    def list_threat_profiles(self) -> List[Dict[str, Any]]:
        results = []
        for key, p in self._profiles_data.items():
            results.append({
                "id": key,
                "profile_id": key,
                "name": p.get("name", key),
                "description": p.get("description", ""),
                "relevant_techniques": p.get("relevant_techniques", 100),
                "high_risk_techniques_count": len(p.get("high_risk_techniques", {})),
                "high_risk_techniques": p.get("high_risk_techniques", {}),
            })
        return results

    def get_threat_profile(self, profile_id: str = "global_baseline") -> Dict[str, Any]:
        key = profile_id.strip().lower() if profile_id else "global_baseline"
        if key in self._profiles_data:
            p = self._profiles_data[key]
            return {
                "profile_id": key,
                "name": p.get("name", key),
                "description": p.get("description", ""),
                "relevant_techniques": p.get("relevant_techniques", 100),
                "high_risk_techniques": p.get("high_risk_techniques", {}),
            }
        # Fallback to global_baseline if unknown
        if "global_baseline" in self._profiles_data:
            return self.get_threat_profile("global_baseline")
        return {
            "profile_id": "custom",
            "name": "Custom Profile",
            "description": "Default generic coverage baseline",
            "relevant_techniques": 150,
            "high_risk_techniques": {},
        }

    def categorize_log_types(self, log_types: List[str]) -> Dict[str, List[str]]:
        """Categorizes a collection of log type strings into telemetry domains."""
        categorized: Dict[str, List[str]] = {cat: [] for cat in self._visibility_data}
        categorized["OTHER"] = []

        # Compile regexes once
        compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for cat, conf in self._visibility_data.items():
            compiled_patterns[cat] = [re.compile(p, re.IGNORECASE) for p in conf.get("patterns", [])]

        for lt in log_types:
            clean_lt = str(lt).strip()
            if not clean_lt:
                continue
            matched = False
            for cat, patterns in compiled_patterns.items():
                if any(p.match(clean_lt) for p in patterns):
                    categorized[cat].append(clean_lt)
                    matched = True
                    break
            if not matched:
                categorized["OTHER"].append(clean_lt)

        return categorized

    def normalize_technique_id(self, technique_id: str) -> str:
        """Normalizes technique ID string into canonical uppercase dot format."""
        if not technique_id:
            return ""
        return technique_id.strip().upper().replace("_", ".")

    def categorize_log_type(self, log_type: str) -> str:
        """Determines the primary telemetry category for a single log type."""
        res = self.categorize_log_types([log_type])
        for cat, items in res.items():
            if cat != "OTHER" and items:
                return cat
        return "OTHER"

    def get_tactical_visibility_for_categories(self, active_categories: List[str]) -> Set[str]:
        """Returns set of MITRE tactic shortnames covered by active log source categories."""
        covered: Set[str] = set()
        for cat in active_categories:
            norm_cat = cat.strip().upper()
            if norm_cat in self._visibility_data:
                for t in self._visibility_data[norm_cat].get("tactics", []):
                    covered.add(t.lower())
        return covered

    def get_tactical_visibility(self, active_categories: List[str]) -> Set[str]:
        """Convenience alias for get_tactical_visibility_for_categories."""
        return self.get_tactical_visibility_for_categories(active_categories)

    def extract_techniques(self, text: str) -> List[str]:
        """Extracts validated MITRE Technique IDs from arbitrary text (meta blocks, rule names, tags)."""
        if not text:
            return []
        found = set()
        for match in TECHNIQUE_REGEX.findall(text):
            norm = match.upper().replace("_", ".")
            if norm in self.techniques:
                found.add(norm)
            else:
                # Also check parent technique if subtechnique (e.g., T1059.001 -> T1059)
                parent = norm.split(".")[0]
                if parent in self.techniques:
                    found.add(norm)
        return sorted(list(found))
