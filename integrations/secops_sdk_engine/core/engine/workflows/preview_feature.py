"""Preview Features Workflows (Milestone 5.12).

Orchestrates discovery and deep inspection of customer preview feature flags.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import PreviewFeatureBatch, PreviewFeatureSummary


def _normalize_feature_summary(raw: Dict[str, Any]) -> PreviewFeatureSummary:
    """Normalizes raw API JSON into typed PreviewFeatureSummary."""
    name = raw.get("name", "")
    fid = name.split("/")[-1] if "/" in name else name
    return PreviewFeatureSummary(
        name=name,
        id=fid,
        display_name=raw.get("displayName", fid),
        description=raw.get("description", ""),
        enabled=bool(raw.get("enabled", False)),
        stage=raw.get("stage", "STAGE_UNSPECIFIED"),
        public_documentation_link=raw.get("publicDocumentationLink", ""),
        expected_retirement_date=raw.get("expectedRetirementDate"),
        update_time=raw.get("updateTime"),
        raw=raw,
    )


class ListPreviewFeaturesWorkflow:
    """Discovers and filters tenant preview features."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        enabled_only: bool = False,
        query: str = "",
        limit: int = 100,
    ) -> PreviewFeatureBatch:
        raw_res = self.adapter.list_preview_features(page_size=1000)
        items = raw_res.get("features", [])

        summaries: List[PreviewFeatureSummary] = []
        for it in items:
            summary = _normalize_feature_summary(it)

            if enabled_only and not summary.enabled:
                continue

            if query:
                q_lower = query.lower()
                if (
                    q_lower not in summary.id.lower()
                    and q_lower not in summary.display_name.lower()
                    and q_lower not in summary.description.lower()
                ):
                    continue

            summaries.append(summary)

        enabled_count = sum(1 for s in summaries if s.enabled)
        total_count = len(summaries)
        limited = summaries[:limit]

        return PreviewFeatureBatch(
            features=limited,
            total_count=total_count,
            enabled_count=enabled_count,
        )


class GetPreviewFeatureWorkflow:
    """Retrieves deep configuration and status for a specific preview feature."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, feature_id: str) -> PreviewFeatureSummary:
        raw = self.adapter.get_preview_feature(feature_id)
        return _normalize_feature_summary(raw)
