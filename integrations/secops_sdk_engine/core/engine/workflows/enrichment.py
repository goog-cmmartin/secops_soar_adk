from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    EnrichmentCombinationBatch,
    EnrichmentCombinationRecord,
    EnrichmentControlBatch,
    EnrichmentControlDetail,
    EnrichmentControlSummary,
)


class ListEnrichmentCombinationsWorkflow:
    """Discovers available enrichment combinations for entity enrichment."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        enrichment_type: str = "ALL",
        target_log_type: str = "",
        limit: int = 100,
    ) -> EnrichmentCombinationBatch:
        raw = self.adapter.get_enrichment_combination()
        raw_name = raw.get("name", "")
        raw_records = raw.get("enrichmentCombinationRecords", [])

        normalized_records: List[EnrichmentCombinationRecord] = []
        for r in raw_records:
            etype = r.get("enrichmentType", "")
            target_raw = r.get("enrichmentTargetLogType", "")
            target_clean = target_raw.split("/")[-1] if target_raw else ""

            source_dict = r.get("enrichmentSource", {})
            src_log_raw = source_dict.get("logType", "")
            src_log_clean = src_log_raw.split("/")[-1] if src_log_raw else None
            ext_src = source_dict.get("externalEnrichmentSource")

            # Apply filters
            if enrichment_type and enrichment_type.upper() != "ALL":
                if etype.upper() != enrichment_type.upper():
                    continue

            if target_log_type:
                q = target_log_type.lower()
                if q not in target_clean.lower() and q not in target_raw.lower():
                    continue

            normalized_records.append(
                EnrichmentCombinationRecord(
                    enrichment_type=etype,
                    target_log_type=target_clean,
                    source_log_type=src_log_clean,
                    external_source=ext_src,
                    raw=r,
                )
            )

        total_count = len(normalized_records)
        if limit > 0:
            normalized_records = normalized_records[:limit]

        return EnrichmentCombinationBatch(
            name=raw_name,
            records=normalized_records,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class SearchEnrichmentControlsWorkflow:
    """Searches deployed enrichment controls that restrict entity enrichment."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        enrichment_type: str = "ALL",
        limit: int = 100,
    ) -> EnrichmentControlBatch:
        raw = self.adapter.list_enrichment_controls(page_size=1000)
        raw_controls = raw.get("enrichmentControls", [])

        controls: List[EnrichmentControlSummary] = []
        for c in raw_controls:
            c_name = c.get("name", "")
            c_id = c_name.split("/")[-1] if c_name else ""
            desc = c.get("description", "")

            opt = c.get("enrichmentControlOption", {})
            etype = opt.get("enrichmentType", "")
            target_raw = opt.get("targetLogType", "")
            target_clean = target_raw.split("/")[-1] if target_raw else ""

            src_dict = opt.get("enrichmentSource", {})
            src_val = src_dict.get("externalEnrichmentSource") or (
                src_dict.get("logType", "").split("/")[-1] if src_dict.get("logType") else "UNKNOWN"
            )

            records_list = c.get("records", [])

            # Filtering
            if enrichment_type and enrichment_type.upper() != "ALL":
                if etype.upper() != enrichment_type.upper():
                    continue

            if query:
                q = query.lower()
                match = (
                    q in c_id.lower()
                    or q in desc.lower()
                    or q in target_clean.lower()
                    or q in etype.lower()
                    or q in str(src_val).lower()
                )
                if not match:
                    continue

            controls.append(
                EnrichmentControlSummary(
                    id=c_id,
                    name=c_name,
                    enrichment_type=etype,
                    target_log_type=target_clean,
                    source=str(src_val),
                    description=desc,
                    records_count=len(records_list),
                    raw=c,
                )
            )

        total_count = len(controls)
        if limit > 0:
            controls = controls[:limit]

        return EnrichmentControlBatch(
            controls=controls,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetEnrichmentControlWorkflow:
    """Deep inspection of a single deployed enrichment control."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, control_id: str) -> EnrichmentControlDetail:
        raw = self.adapter.get_enrichment_control(control_id)
        c_name = raw.get("name", "")
        c_id = c_name.split("/")[-1] if c_name else control_id
        desc = raw.get("description", "")

        opt = raw.get("enrichmentControlOption", {})
        etype = opt.get("enrichmentType", "")
        target_raw = opt.get("targetLogType", "")
        target_clean = target_raw.split("/")[-1] if target_raw else ""

        src_dict = opt.get("enrichmentSource", {})
        src_val = src_dict.get("externalEnrichmentSource") or (
            src_dict.get("logType", "").split("/")[-1] if src_dict.get("logType") else "UNKNOWN"
        )

        records_list = raw.get("records", [])

        summary = EnrichmentControlSummary(
            id=c_id,
            name=c_name,
            enrichment_type=etype,
            target_log_type=target_clean,
            source=str(src_val),
            description=desc,
            records_count=len(records_list),
            raw=raw,
        )

        return EnrichmentControlDetail(
            summary=summary,
            records=records_list,
            raw=raw,
        )
