"""Workflows for Google SecOps Gemini Triage & Investigation Agent (TINA) Investigations."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    TinaConfidence,
    TinaInvestigation,
    TinaInvestigationBatch,
    TinaInvestigationStep,
    TinaNextStep,
    TinaStepSourceMetadata,
    TinaVerdict,
)
from engine.parsing import parse_timestamp


def _clean_id(raw_id: Union[str, int]) -> str:
    """Extracts the terminal identifier from a resource path or string."""
    return str(raw_id).strip().split("/")[-1]


def parse_tina_step(raw: Dict[str, Any]) -> TinaInvestigationStep:
    """Parses a raw investigation step from the SecOps API."""
    name = raw.get("name", "")
    step_id = _clean_id(name) if name else str(raw.get("stepId", ""))

    exec_interval = raw.get("executionInterval") or {}
    start_time = parse_timestamp(exec_interval.get("startTime"))
    end_time = parse_timestamp(exec_interval.get("endTime"))

    raw_meta = raw.get("sourceMetadata") or {}
    source_meta: Optional[TinaStepSourceMetadata] = None
    if raw_meta:
        query_dict = raw_meta.get("query") or {}
        time_range = query_dict.get("timeRange") or {}
        source_meta = TinaStepSourceMetadata(
            source_type=raw_meta.get("sourceType"),
            query_code=query_dict.get("queryCode"),
            time_range_start=parse_timestamp(time_range.get("startTime")),
            time_range_end=parse_timestamp(time_range.get("endTime")),
            unique_results_count=query_dict.get("uniqueResultsCount"),
            total_results_count=query_dict.get("totalResultsCount"),
            operation=query_dict.get("operation"),
            raw=raw_meta,
        )

    return TinaInvestigationStep(
        name=name,
        step_id=step_id,
        analysis_summary=raw.get("analysisSummary", ""),
        description=raw.get("description", ""),
        start_time=start_time,
        end_time=end_time,
        source_metadata=source_meta,
        raw=raw,
    )


def parse_tina_next_step(raw: Dict[str, Any]) -> TinaNextStep:
    """Parses a recommended next step."""
    return TinaNextStep(
        title=raw.get("title", ""),
        step_type=raw.get("type", "MANUAL"),
        raw=raw,
    )


def parse_tina_investigation(raw: Dict[str, Any]) -> TinaInvestigation:
    """Parses a raw TINA investigation dictionary into a strongly typed TinaInvestigation."""
    name = raw.get("name", "")
    inv_id = _clean_id(name) if name else str(raw.get("id", ""))

    time_range = raw.get("timeRange") or {}
    start_time = parse_timestamp(time_range.get("startTime"))
    end_time = parse_timestamp(time_range.get("endTime"))

    raw_steps = raw.get("investigationSteps") or []
    steps = [parse_tina_step(s) for s in raw_steps if isinstance(s, dict)]

    raw_next_steps = raw.get("nextSteps") or []
    next_steps = [parse_tina_next_step(ns) for ns in raw_next_steps if isinstance(ns, dict)]

    alerts_dict = raw.get("alerts") or {}
    alert_ids = alerts_dict.get("ids") or []

    return TinaInvestigation(
        name=name,
        id=inv_id,
        display_name=raw.get("displayName", ""),
        verdict=raw.get("verdict"),
        summary=raw.get("summary", ""),
        status=raw.get("status"),
        confidence=raw.get("confidence"),
        start_time=start_time,
        end_time=end_time,
        notebook=raw.get("notebook"),
        trigger_type=raw.get("triggerType"),
        publish_time=parse_timestamp(raw.get("publishTime")),
        update_time=parse_timestamp(raw.get("updateTime")),
        next_steps=next_steps,
        investigation_steps=steps,
        alert_ids=alert_ids,
        raw=raw,
    )


class ListTinaInvestigationsWorkflow:
    """Workflow to list and paginate Gemini Triage & Investigation Agent (TINA) investigations."""

    def __init__(self, adapter: "GoogleSecOpsAdapter"):
        self.adapter = adapter

    def execute(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = "start_time desc",
    ) -> TinaInvestigationBatch:
        """Fetches investigations and returns a typed batch."""
        res = self.adapter.list_investigations(
            page_size=page_size,
            page_token=page_token,
            filter=filter,
            order_by=order_by,
        )

        raw_list = res.get("investigations", []) if isinstance(res, dict) else []
        investigations = [parse_tina_investigation(item) for item in raw_list if isinstance(item, dict)]
        next_token = res.get("nextPageToken") if isinstance(res, dict) else None

        return TinaInvestigationBatch(
            investigations=investigations,
            total_count=len(investigations),
            next_page_token=next_token,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetTinaInvestigationWorkflow:
    """Workflow to retrieve a specific Gemini TINA investigation by ID."""

    def __init__(self, adapter: "GoogleSecOpsAdapter"):
        self.adapter = adapter

    def execute(self, investigation_id: str) -> TinaInvestigation:
        """Retrieves and parses an individual TINA investigation."""
        if not investigation_id or not str(investigation_id).strip():
            raise ValueError("investigation_id must be a non-empty string.")

        res = self.adapter.get_investigation(investigation_id)
        if not res or not isinstance(res, dict):
            raise RuntimeError(f"Failed to retrieve investigation '{investigation_id}': empty response from SecOps API.")

        return parse_tina_investigation(res)


class GetAlertLatestTinaInvestigationWorkflow:
    """Workflow to retrieve the latest Gemini TINA investigation for an alert."""

    def __init__(self, adapter: "GoogleSecOpsAdapter"):
        self.adapter = adapter

    def execute(self, alert_id: str) -> Optional[TinaInvestigation]:
        """Retrieves and parses the latest investigation for the given alert ID."""
        if not alert_id or not str(alert_id).strip():
            raise ValueError("alert_id must be a non-empty string.")

        res = self.adapter.get_alert_latest_investigation(alert_id)
        if not res or not isinstance(res, dict):
            return None

        return parse_tina_investigation(res)
