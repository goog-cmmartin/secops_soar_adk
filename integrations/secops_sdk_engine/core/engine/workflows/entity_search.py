"""Workflows for UDM Entity Graph Search, Enterprise IoC Intelligence, and Unified Entity Investigation."""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Union

from engine.domain import (
    CaseSearchPrefix,
    CaseSearchQuery,
    EnterpriseIocBatch,
    EnterpriseIocMatch,
    EntityInvestigationReport,
    EntitySummaryResult,
    EntityType,
    SearchBatchResult,
    SearchRequest,
    SearchSession,
)
from engine.entity_detector import detect_entity, DetectedEntity


class SearchEntityGraphWorkflow:
    """Executes streaming UDM searches against the Entity Graph (`graph.entity.*`)."""

    def __init__(self, search_workflow: Any):
        self.search_workflow = search_workflow

    def execute(
        self,
        indicator_or_field: str,
        value: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        receive_limit: int = 10000,
        batch_size: int = 2000,
        hint: Optional[str] = None,
        on_batch: Optional[Callable[[SearchBatchResult, SearchSession], None]] = None,
        on_state_change: Optional[Callable[[SearchSession], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
    ) -> SearchSession:
        """Executes an Entity Graph query.

        If `value` is provided, `indicator_or_field` is treated as the graph field (e.g. 'graph.entity.file.sha256').
        If `value` is omitted, `indicator_or_field` is treated as an untyped indicator and auto-detected.
        """
        if value is not None:
            field_name = indicator_or_field
            val_clean = value.replace("\\", "\\\\").replace('"', '\\"')
            if not field_name.startswith("graph.entity."):
                field_name = f"graph.entity.{field_name}"
            query = f'{field_name} = "{val_clean}"'
        else:
            detected = detect_entity(indicator_or_field, hint=hint)
            query = detected.graph_query

        if not start_time or not end_time:
            now = datetime.now(timezone.utc)
            if not end_time:
                end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            if not start_time:
                start_time = (now - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")

        req = SearchRequest(
            query=query,
            start_time=start_time,
            end_time=end_time,
            receive_limit=receive_limit,
            batch_size=batch_size,
        )
        return self.search_workflow.execute(
            request=req,
            on_batch=on_batch,
            on_state_change=on_state_change,
            cancel_token=cancel_token,
        )


class SearchEnterpriseIocsWorkflow:
    """Searches enterprise-wide IoC matches and Mandiant threat intel."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        value: str,
        value_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        max_matches: int = 10000,
        add_mandiant_attributes: bool = True,
        lookback_days: Optional[int] = None,
    ) -> EnterpriseIocBatch:
        """Executes enterprise IoC search.

        If `value_type` is omitted, auto-detects from the input `value`.
        Without `start_time` the window starts at the epoch (all time), or
        `lookback_days` before now when given.
        """
        val_clean = value.strip()
        if not value_type:
            detected = detect_entity(val_clean)
            if not detected.ioc_value_type:
                raise ValueError(
                    f"Indicator '{val_clean}' of category {detected.category} does not map to an Enterprise IoC valueType."
                )
            value_type = detected.ioc_value_type

        # Time range defaults: all time (epoch start) unless lookback_days or an
        # explicit start_time is given. The previous comment claimed "past 30
        # days" but the code always sent the epoch; that behaviour is kept
        # because it is what callers observed (live 2026-10-10: the same IP had
        # matches all-time and none in the last 30 days).
        now = datetime.now(timezone.utc)
        if start_time:
            st = start_time
        elif lookback_days is not None:
            if lookback_days <= 0:
                raise ValueError("lookback_days must be positive.")
            st = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            st = "1970-01-01T00:00:00Z"
        et = end_time or now.strftime("%Y-%m-%dT%H:%M:%SZ")

        raw_res = self.adapter.search_enterprise_iocs(
            value=val_clean,
            value_type=value_type,
            start_time=st,
            end_time=et,
            max_matches=max_matches,
            add_mandiant_attributes=add_mandiant_attributes,
        )

        matches_raw = raw_res.get("matches", []) if isinstance(raw_res, dict) else []
        parsed_matches: List[EnterpriseIocMatch] = []

        for m in matches_raw:
            if not isinstance(m, dict):
                continue
            parsed_matches.append(
                EnterpriseIocMatch(
                    artifact_indicator=m.get("artifactIndicator", {}),
                    sources=m.get("sources", []),
                    categories=m.get("categories", []),
                    asset_indicators=m.get("assetIndicators", []),
                    ioc_ingest_timestamp=m.get("iocIngestTimestamp"),
                    first_seen=m.get("firstSeen"),
                    last_seen=m.get("lastSeen"),
                    raw=m,
                )
            )

        total_count = int(raw_res.get("totalMatches", len(parsed_matches))) if isinstance(raw_res, dict) else len(parsed_matches)

        return EnterpriseIocBatch(
            matches=parsed_matches,
            total_count=total_count,
            searched_value=val_clean,
            value_type=value_type,
        )


class SummarizeEntityWorkflow:
    """Retrieves entity summary profiles, timeline intervals, and prevalence scores."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        entity_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        return_alerts: bool = False,
        return_prevalence: bool = True,
        include_all_udm_event_types: bool = True,
        field_value: Optional[str] = None,
        value_type: Optional[str] = None,
    ) -> EntitySummaryResult:
        """Executes :summarizeEntity and returns structured EntitySummaryResult.

        Look up by ``entity_id``, or by ``field_value`` (+ optional
        ``value_type``; auto-detected when omitted, e.g. an IP maps to
        ASSET_IP_ADDRESS).
        """
        if not entity_id and not field_value:
            raise ValueError("summarize_entity needs entity_id or field_value.")
        if field_value and not entity_id and not value_type:
            detected = detect_entity(field_value.strip())
            value_type = detected.ioc_value_type
            if not value_type:
                raise ValueError(f"Cannot infer a FieldAndValue valueType for '{field_value}'; pass value_type.")
        kwargs: Dict[str, Any] = {}
        if field_value and not entity_id:
            kwargs = {"field_value": field_value.strip(), "value_type": value_type}
        raw_res = self.adapter.summarize_entity(
            entity_id=entity_id,
            start_time=start_time,
            end_time=end_time,
            return_alerts=return_alerts,
            return_prevalence=return_prevalence,
            include_all_udm_event_types=include_all_udm_event_types,
            **kwargs,
        )

        timeline = raw_res.get("timeline", []) if isinstance(raw_res, dict) else []
        prevalence = raw_res.get("prevalence", {}) if isinstance(raw_res, dict) else {}
        file_meta = raw_res.get("fileMetadata", {}) if isinstance(raw_res, dict) else {}
        entities = raw_res.get("entities", []) if isinstance(raw_res, dict) else []
        entity_type = raw_res.get("entityType", "") if isinstance(raw_res, dict) else ""

        return EntitySummaryResult(
            entity_id=entity_id or (field_value or ""),
            entity_type=entity_type,
            timeline=timeline,
            prevalence=prevalence,
            file_metadata=file_meta,
            entities=entities,
            raw=raw_res if isinstance(raw_res, dict) else {},
        )


class InvestigateEntityWorkflow:
    """Composed workflow correlating Graph Entities, UDM Events, IoC Intel, and SOAR Cases."""

    def __init__(
        self,
        search_graph_wf: SearchEntityGraphWorkflow,
        search_from_entity_wf: Any,
        search_iocs_wf: SearchEnterpriseIocsWorkflow,
        search_cases_wf: Any,
        summarize_entity_wf: SummarizeEntityWorkflow,
    ):
        self.search_graph_wf = search_graph_wf
        self.search_from_entity_wf = search_from_entity_wf
        self.search_iocs_wf = search_iocs_wf
        self.search_cases_wf = search_cases_wf
        self.summarize_entity_wf = summarize_entity_wf

    def execute(
        self,
        indicator: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        max_events: int = 50,
        include_cases: bool = True,
    ) -> EntityInvestigationReport:
        """Executes a full cross-engine investigation of an indicator."""
        detected = detect_entity(indicator)

        now = datetime.now(timezone.utc)
        resolved_end = end_time or now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resolved_start = start_time or (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Search Entity Graph
        graph_events: List[Dict[str, Any]] = []
        try:
            session = self.search_graph_wf.execute(
                indicator_or_field=indicator,
                start_time=start_time,
                end_time=end_time,
                receive_limit=max_events,
                batch_size=max_events,
            )
            graph_events = session.events
        except Exception:
            pass

        # 2. Search Historical UDM Events
        udm_events: List[Dict[str, Any]] = []
        try:
            session_udm = self.search_from_entity_wf.execute(
                entity_type=detected.entity_type,
                entity_value=detected.raw_value,
                start_time=resolved_start,
                end_time=resolved_end,
                receive_limit=max_events,
                batch_size=max_events,
            )
            udm_events = session_udm.events
        except Exception:
            pass

        # 3. Search Enterprise IoCs if applicable
        ioc_matches: List[EnterpriseIocMatch] = []
        if detected.ioc_value_type:
            try:
                batch = self.search_iocs_wf.execute(
                    value=detected.raw_value,
                    value_type=detected.ioc_value_type,
                    start_time=start_time,
                    end_time=end_time,
                )
                ioc_matches = batch.matches
            except Exception:
                pass

        # 4. Search Related SOAR Cases
        related_cases: List[Any] = []
        if include_cases and self.search_cases_wf:
            try:
                case_batch = self.search_cases_wf.execute(
                    CaseSearchQuery(
                        query_text=CaseSearchPrefix.ENTITY.apply(detected.raw_value),
                        page_size=20,
                    )
                )
                related_cases = case_batch.items
            except Exception:
                pass

        # 5. Summarize Entity if a graph entity identifier was discovered
        entity_summary: Optional[EntitySummaryResult] = None
        if self.summarize_entity_wf and graph_events:
            entity_id = None
            for ev in graph_events:
                if not isinstance(ev, dict):
                    continue
                meta = ev.get("metadata") if isinstance(ev.get("metadata"), dict) else {}
                graph_obj = ev.get("graph") if isinstance(ev.get("graph"), dict) else {}
                graph_meta = graph_obj.get("metadata") if isinstance(graph_obj.get("metadata"), dict) else {}
                candidate = (
                    ev.get("entityId")
                    or meta.get("entityId")
                    or graph_meta.get("entityId")
                    or graph_meta.get("id")
                    or meta.get("id")
                    or ev.get("id")
                )
                if candidate:
                    entity_id = str(candidate)
                    break
            if entity_id:
                try:
                    entity_summary = self.summarize_entity_wf.execute(
                        entity_id=entity_id,
                        start_time=resolved_start,
                        end_time=resolved_end,
                    )
                except Exception:
                    pass

        return EntityInvestigationReport(
            indicator=detected.raw_value,
            detected_type=detected.entity_type.value,
            category=detected.category.value,
            entity_graph_events_count=len(graph_events),
            udm_events_count=len(udm_events),
            enterprise_iocs_count=len(ioc_matches),
            related_cases_count=len(related_cases),
            graph_events=graph_events,
            udm_events=udm_events,
            ioc_matches=ioc_matches,
            related_cases=related_cases,
            entity_summary=entity_summary,
        )
