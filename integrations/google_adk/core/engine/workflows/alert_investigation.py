from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    AlertInvestigation,
    InvolvedEntitySummary,
)
from engine.parsing import parse_timestamp, parse_timestamp as _parse_timestamp


class InvestigateAlertWorkflow:
    """Orchestrates deep-dive investigation of a SecOps alert and its involved entities."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, alert_name: str) -> AlertInvestigation:
        if not alert_name or not str(alert_name).strip():
            raise ValueError("alert_name must be a non-empty string.")

        clean_name = str(alert_name).strip()

        # Parallel fetch of alert metadata and involved entities
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_alert = executor.submit(self.adapter.get_case_alert, clean_name)
            future_entities = executor.submit(self.adapter.list_alert_entities, clean_name)

            raw_alert = future_alert.result()
            raw_entities = future_entities.result()

        # Parse involved entities
        entities: List[InvolvedEntitySummary] = []
        for e in raw_entities:
            identifier = e.get("identifier") or e.get("name") or ""
            etype = e.get("entityType") or e.get("type")
            entities.append(
                InvolvedEntitySummary(
                    identifier=identifier,
                    display_name=e.get("name") or identifier,
                    entity_type=etype,
                    role=e.get("role"),
                    is_suspicious=bool(e.get("isSuspicious", False)),
                    raw=e,
                )
            )

        # Parse case_id from alert name or payload
        case_id = raw_alert.get("caseId") or ""
        if not case_id and "cases/" in raw_alert.get("name", ""):
            parts = raw_alert["name"].split("/")
            if "cases" in parts:
                idx = parts.index("cases")
                if idx + 1 < len(parts):
                    case_id = parts[idx + 1]

        # Extract risk score if present in additionalProperties or fields
        risk_score = None
        props = raw_alert.get("additionalProperties", {})
        if isinstance(props, dict):
            if "risk_score" in props:
                try:
                    risk_score = int(props["risk_score"])
                except Exception:
                    pass

        provenance = {
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "alert_resource_name": raw_alert.get("name", clean_name),
            "entity_count": len(entities),
        }

        return AlertInvestigation(
            alert_name=raw_alert.get("name", clean_name),
            case_id=str(case_id),
            display_name=raw_alert.get("displayName") or raw_alert.get("ruleGenerator") or "Alert",
            priority=raw_alert.get("priority", "UNKNOWN"),
            status=raw_alert.get("status", "UNKNOWN"),
            rule_name=raw_alert.get("sourceRuleIdentifier") or raw_alert.get("displayName"),
            rule_id=raw_alert.get("ruleGenerator") or raw_alert.get("sourceRuleIdentifier"),
            risk_score=risk_score,
            detection_time=_parse_timestamp(raw_alert.get("startTime")),
            product=raw_alert.get("product"),
            vendor=raw_alert.get("vendor"),
            event_count=int(raw_alert.get("eventCount", 0) or 0),
            entities=entities,
            associated_events=[],
            provenance=provenance,
            raw_alert=raw_alert,
        )
