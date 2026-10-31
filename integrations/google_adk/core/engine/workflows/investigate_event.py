from typing import Any, Dict, Optional, Union

from engine.domain import (
    EventInvestigation,
    EventReference,
    InvestigationProvenance,
    RawLogPayload,
)


class InvestigateEventWorkflow:
    """Orchestrates event investigation and raw log retrieval workflow."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        event_ref: Union[EventReference, Dict[str, Any], str],
        eager_load_raw_log: bool = False,
    ) -> EventInvestigation:
        """Executes event investigation to produce an EventInvestigation domain entity."""
        event_id: str = ""
        log_token: Optional[str] = None
        structured_event: Optional[Dict[str, Any]] = None

        if isinstance(event_ref, EventReference):
            event_id = event_ref.event_id or event_ref.id or ""
            log_token = event_ref.log_token
            structured_event = event_ref.structured_event
        elif isinstance(event_ref, str):
            event_id = event_ref.strip()
        elif hasattr(event_ref, "to_dict") or isinstance(event_ref, dict):
            event_dict = event_ref.to_dict() if hasattr(event_ref, "to_dict") else event_ref
            if "event" in event_dict:
                structured_event = event_dict.get("event", {})
                log_token = event_dict.get("eventLogToken")
                event_id = (
                    (structured_event.get("metadata", {}).get("id") if isinstance(structured_event.get("metadata"), dict) else None)
                    or structured_event.get("id")
                    or event_dict.get("id", "")
                    or event_dict.get("event_id", "")
                )
            elif "udm" in event_dict:
                structured_event = event_dict.get("udm", {})
                event_id = (
                    (structured_event.get("metadata", {}).get("id") if isinstance(structured_event.get("metadata"), dict) else None)
                    or structured_event.get("id")
                    or event_dict.get("id", "")
                    or event_dict.get("event_id", "")
                )
            else:
                structured_event = event_dict
                metadata = structured_event.get("metadata", {})
                if isinstance(metadata, dict):
                    event_id = metadata.get("id", "")
                event_id = event_id or structured_event.get("id", "") or structured_event.get("event_id", "")
        elif hasattr(event_ref, "metadata"):
            meta = getattr(event_ref, "metadata", None)
            if hasattr(meta, "id"):
                event_id = getattr(meta, "id", "")
            elif isinstance(meta, dict):
                event_id = meta.get("id", "")
            event_id = event_id or getattr(event_ref, "id", "") or getattr(event_ref, "event_id", "")

        if isinstance(event_id, str):
            event_id = event_id.strip()
            if event_id.startswith("events/"):
                event_id = event_id.split("/")[-1]

        if not event_id:
            raise ValueError(f"Cannot investigate event: unable to determine event_id from reference: {event_ref}")

        # If no structured event provided in memory, fetch enriched event from provider
        if not structured_event:
            structured_event = self.adapter.fetch_enriched_event(event_id)

        raw_log_payload: Optional[RawLogPayload] = None
        if eager_load_raw_log:
            raw_log_payload = self.adapter.get_raw_log(event_id=event_id, log_token=log_token)

        provenance = InvestigationProvenance(
            provider="google_secops",
            workflow_id="event.investigate",
            event_id=event_id,
        )

        return EventInvestigation(
            event_id=event_id,
            event=structured_event,
            log_token=log_token,
            raw_log=raw_log_payload,
            provenance=provenance,
            adapter=self.adapter,
        )
