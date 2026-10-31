"""Workflow for discovering active and historical SOAR cases sharing entities with a target case."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Union

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    CasePriority,
    CaseSearchPrefix,
    CaseSearchQuery,
    UniversalDictMixin,
)
from engine.workflows.case_actions import AddCaseCommentWorkflow
from engine.workflows.case_investigation import InvestigateCaseWorkflow
from engine.workflows.case_search import SearchCasesWorkflow
from engine.workflows.correlate_silent_detections import (
    _clean_case_id,
    is_noisy_entity,
)

# Entity types that represent generic metadata or threat intelligence tags rather than concrete observables
NON_OBSERVABLE_ENTITY_TYPES = {
    "GENERIC",
    "THREATSIGNATURE",
    "OUTCOME",
    "UNKNOWN",
}

THREAT_ACTOR_ENTITY_TYPES = {
    "THREATACTOR",
    "THREATCAMPAIGN",
    "MALWARE",
}

PRIORITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "INFORMATIONAL": 1,
    "UNKNOWN": 0,
}


@dataclass
class RelatedCasesByEntityResult(UniversalDictMixin):
    """Structured result for the Related Cases by Entity workflow."""

    case_id: str
    case_title: str = ""
    case_status: str = "UNKNOWN"
    case_priority: str = "UNKNOWN"
    lookback_days: int = 90
    case_status_scope: str = "ALL"
    min_shared_entities: int = 1
    has_related_cases: bool = False
    total_related_cases: int = 0
    active_related_cases_count: int = 0
    closed_related_cases_count: int = 0
    incident_related_cases_count: int = 0
    entities_searched_count: int = 0
    entities_with_hits_count: int = 0
    entities_searched: List[Dict[str, Any]] = field(default_factory=list)
    entity_precedents: List[Dict[str, Any]] = field(default_factory=list)
    related_cases: List[Dict[str, Any]] = field(default_factory=list)
    comment_id: Optional[str] = None
    secops_ui_base_url: str = ""
    provenance: Dict[str, Any] = field(default_factory=dict)


class RelatedCasesByEntityWorkflow:
    """Correlates a SOAR case's involved entities across active and historical SOAR cases."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.investigate_workflow = InvestigateCaseWorkflow(adapter=self.adapter)
        self.search_cases_workflow = SearchCasesWorkflow(adapter=self.adapter)
        self.comment_workflow = AddCaseCommentWorkflow(adapter=self.adapter)

    def execute(
        self,
        case_id: Union[str, int],
        lookback_days: int = 90,
        case_status_scope: str = "ALL",
        min_shared_entities: int = 1,
        max_related_cases: int = 50,
        max_entities_to_search: int = 25,
        include_threat_actors: bool = False,
        entity_filter: Optional[List[str]] = None,
        post_wall_comment: bool = False,
        secops_ui_base_url: str = "",
    ) -> RelatedCasesByEntityResult:
        """Executes cross-case entity correlation across active and historical SOAR cases.

        Args:
            case_id: Target SOAR Case ID or resource name.
            lookback_days: Number of days back to search SOAR case history (default: 90).
            case_status_scope: Filter related cases by status ('ALL', 'ACTIVE_ONLY', 'CLOSED_ONLY').
            min_shared_entities: Minimum number of shared entities required to include a related case (default: 1).
            max_related_cases: Maximum number of related cases to return (default: 50).
            max_entities_to_search: Maximum number of distinct case entities to query (default: 25).
            include_threat_actors: If True, includes THREATACTOR/MALWARE entity types in the search.
            entity_filter: Optional explicit list of entity identifiers to search/filter.
            post_wall_comment: If True, posts a Markdown summary table to the Case Wall.
            secops_ui_base_url: Optional base URL for constructing full SecOps case links.

        Returns:
            RelatedCasesByEntityResult with ranked related cases and per-entity precedent breakdowns.
        """
        clean_case_id = _clean_case_id(case_id)
        lookback_days = max(1, int(lookback_days or 90))
        min_shared_entities = max(1, int(min_shared_entities or 1))
        max_related_cases = max(1, int(max_related_cases or 50))
        max_entities_to_search = max(1, int(max_entities_to_search or 25))
        scope_norm = str(case_status_scope or "ALL").strip().upper().replace(" ", "_")
        base_url_clean = str(secops_ui_base_url or "").strip().rstrip("/")

        # 1. Investigate the source case to extract metadata and involved entities
        investigation = self.investigate_workflow.execute(case_id=clean_case_id)
        case_title = investigation.display_name or f"Case {clean_case_id}"
        case_status = (
            investigation.status.value
            if hasattr(investigation.status, "value")
            else str(investigation.status or "UNKNOWN")
        )
        case_priority = (
            investigation.priority.value
            if hasattr(investigation.priority, "value")
            else str(investigation.priority or "UNKNOWN")
        )

        # 2. Collect and sanitize candidate entities
        filter_set: Optional[Set[str]] = None
        if entity_filter:
            filter_set = {str(x).strip().upper() for x in entity_filter if str(x).strip()}

        candidate_entities: List[Dict[str, Any]] = []
        seen_identifiers: Set[str] = set()

        for ent in investigation.entities:
            ident = str(ent.identifier or "").strip()
            if not ident:
                continue
            ident_upper = ident.upper()
            etype = str(ent.entity_type or "UNKNOWN").strip().upper()

            if filter_set is not None and ident_upper not in filter_set:
                continue

            if etype in NON_OBSERVABLE_ENTITY_TYPES:
                continue
            if not include_threat_actors and etype in THREAT_ACTOR_ENTITY_TYPES:
                continue
            if is_noisy_entity(ident) or ident_upper in ("OUTCOME", "UNKNOWN", "TRUE", "FALSE", "NONE", "NULL"):
                continue

            if ident_upper not in seen_identifiers:
                seen_identifiers.add(ident_upper)
                candidate_entities.append(
                    {
                        "identifier": ident,
                        "entity_type": etype,
                        "display_name": ent.display_name or ident,
                        "role": ent.role,
                        "is_suspicious": bool(ent.is_suspicious),
                    }
                )

        # If explicit entity_filter entries were provided that weren't on the case, include them too
        if entity_filter:
            for raw_ent in entity_filter:
                ident = str(raw_ent or "").strip()
                if not ident:
                    continue
                ident_upper = ident.upper()
                if ident_upper not in seen_identifiers and not is_noisy_entity(ident):
                    seen_identifiers.add(ident_upper)
                    candidate_entities.append(
                        {
                            "identifier": ident,
                            "entity_type": "CUSTOM",
                            "display_name": ident,
                            "role": None,
                            "is_suspicious": False,
                        }
                    )

        # Prioritize suspicious entities and high-signal observable types first
        def _entity_sort_key(e: Dict[str, Any]):
            etype = e.get("entity_type", "")
            type_score = 0
            if etype in ("ADDRESS", "IP", "SOURCEIP", "DESTINATIONIP"):
                type_score = 5
            elif etype in ("USERUNIQNAME", "EMAIL", "USERNAME", "USER"):
                type_score = 5
            elif etype in ("HOSTNAME", "HOST", "ASSET"):
                type_score = 4
            elif etype in ("FILEHASH", "SHA256", "MD5", "SHA1"):
                type_score = 4
            elif etype in ("DESTINATIONURL", "URL", "DOMAIN"):
                type_score = 3
            else:
                type_score = 2
            return (1 if e.get("is_suspicious") else 0, type_score)

        candidate_entities.sort(key=_entity_sort_key, reverse=True)
        searched_entities = candidate_entities[:max_entities_to_search]

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=lookback_days)

        # 3. Search historical & active cases per entity in parallel
        entity_results_map: Dict[str, List[Any]] = {}
        entity_total_counts_map: Dict[str, int] = {}

        def _search_for_entity(ent_meta: Dict[str, Any]):
            ident = ent_meta["identifier"]
            query = CaseSearchQuery(
                query_text=CaseSearchPrefix.ENTITY.apply(ident),
                start_time=start_time,
                end_time=now,
                page_size=50,
                page_number=0,
            )
            batch = self.search_cases_workflow.execute(query)
            return ident, batch.results, int(batch.total_count or len(batch.results))

        if searched_entities:
            with ThreadPoolExecutor(max_workers=min(8, len(searched_entities))) as executor:
                futures = {
                    executor.submit(_search_for_entity, ent): ent
                    for ent in searched_entities
                }
                for fut in as_completed(futures):
                    ent_meta = futures[fut]
                    ident = ent_meta["identifier"]
                    try:
                        _, items, total_cnt = fut.result()
                        entity_results_map[ident] = items
                        entity_total_counts_map[ident] = total_cnt
                    except Exception:
                        entity_results_map[ident] = []
                        entity_total_counts_map[ident] = 0

        # 4. Aggregate by Related Case and by Entity
        related_cases_by_id: Dict[str, Dict[str, Any]] = {}
        entity_precedents: List[Dict[str, Any]] = []

        for ent_meta in searched_entities:
            ident = ent_meta["identifier"]
            etype = ent_meta["entity_type"]
            is_susp = ent_meta["is_suspicious"]
            raw_matches = entity_results_map.get(ident, [])

            matched_case_ids: List[str] = []
            active_cnt = 0
            closed_cnt = 0

            for item in raw_matches:
                rc_id = str(item.case_id or "").strip()
                if not rc_id or rc_id == clean_case_id:
                    continue

                is_closed = bool(item.is_closed)
                if scope_norm in ("ACTIVE_ONLY", "OPEN_ONLY", "OPEN", "ACTIVE") and is_closed:
                    continue
                if scope_norm in ("CLOSED_ONLY", "HISTORICAL_ONLY", "CLOSED", "HISTORICAL") and not is_closed:
                    continue

                if rc_id not in matched_case_ids:
                    matched_case_ids.append(rc_id)
                    if is_closed:
                        closed_cnt += 1
                    else:
                        active_cnt += 1

                if rc_id not in related_cases_by_id:
                    prio_str = (
                        item.priority.value
                        if hasattr(item.priority, "value")
                        else str(item.priority or "UNKNOWN")
                    ).upper()
                    create_iso = (
                        item.create_time.isoformat()
                        if isinstance(item.create_time, datetime)
                        else str(item.create_time or "")
                    )
                    case_url = (
                        f"{base_url_clean}/cases/{rc_id}"
                        if base_url_clean
                        else f"/cases/{rc_id}"
                    )
                    related_cases_by_id[rc_id] = {
                        "case_id": rc_id,
                        "title": item.title or f"Case {rc_id}",
                        "status": "CLOSED" if is_closed else "OPEN",
                        "is_closed": is_closed,
                        "is_incident": bool(item.is_incident),
                        "is_important": bool(item.is_important),
                        "priority": prio_str,
                        "stage": item.stage or "Unknown",
                        "alerts_count": int(item.alerts_count or 0),
                        "create_time": create_iso,
                        "user_assigned": item.user_assigned or "Unassigned",
                        "environment": item.environment or "Default Environment",
                        "products": list(item.products or []),
                        "tags": list(item.tags or []),
                        "ticket_ids": list(item.ticket_ids or []),
                        "shared_entities": [],
                        "shared_entity_identifiers": [],
                        "shared_entities_count": 0,
                        "overlap_ratio": 0.0,
                        "case_url": case_url,
                    }

                rc_entry = related_cases_by_id[rc_id]
                if ident not in rc_entry["shared_entity_identifiers"]:
                    rc_entry["shared_entity_identifiers"].append(ident)
                    rc_entry["shared_entities"].append(
                        {
                            "identifier": ident,
                            "entity_type": etype,
                            "is_suspicious": is_susp,
                        }
                    )
                    rc_entry["shared_entities_count"] = len(rc_entry["shared_entity_identifiers"])
                    rc_entry["overlap_ratio"] = round(
                        rc_entry["shared_entities_count"] / max(1, len(searched_entities)),
                        2,
                    )

            raw_total = entity_total_counts_map.get(ident, len(matched_case_ids))
            has_self_in_raw = any(str(x.case_id or "").strip() == clean_case_id for x in raw_matches)
            adjusted_total = max(len(matched_case_ids), raw_total - (1 if has_self_in_raw else 0))
            if scope_norm != "ALL":
                adjusted_total = len(matched_case_ids)

            entity_precedents.append(
                {
                    "identifier": ident,
                    "entity_type": etype,
                    "is_suspicious": is_susp,
                    "total_related_cases": len(matched_case_ids),
                    "total_historical_matches": adjusted_total,
                    "active_cases_count": active_cnt,
                    "closed_cases_count": closed_cnt,
                    "related_case_ids": matched_case_ids[:25],
                }
            )

        # Sort entity precedents by total_related_cases descending
        entity_precedents.sort(
            key=lambda x: (x["total_related_cases"], x["active_cases_count"]),
            reverse=True,
        )

        # Filter related cases by min_shared_entities and sort
        filtered_cases = [
            rc
            for rc in related_cases_by_id.values()
            if rc["shared_entities_count"] >= min_shared_entities
        ]

        filtered_cases.sort(
            key=lambda rc: (
                rc["shared_entities_count"],
                0 if rc["is_closed"] else 1,
                1 if rc["is_incident"] else 0,
                PRIORITY_RANK.get(rc["priority"], 0),
                rc["create_time"] or "",
            ),
            reverse=True,
        )

        total_related = len(filtered_cases)
        active_related = sum(1 for rc in filtered_cases if not rc["is_closed"])
        closed_related = sum(1 for rc in filtered_cases if rc["is_closed"])
        incident_related = sum(1 for rc in filtered_cases if rc["is_incident"])
        entities_with_hits = sum(1 for ep in entity_precedents if ep["total_related_cases"] > 0)

        ranked_cases = filtered_cases[:max_related_cases]

        result = RelatedCasesByEntityResult(
            case_id=clean_case_id,
            case_title=case_title,
            case_status=case_status,
            case_priority=case_priority,
            lookback_days=lookback_days,
            case_status_scope=scope_norm,
            min_shared_entities=min_shared_entities,
            has_related_cases=total_related > 0,
            total_related_cases=total_related,
            active_related_cases_count=active_related,
            closed_related_cases_count=closed_related,
            incident_related_cases_count=incident_related,
            entities_searched_count=len(searched_entities),
            entities_with_hits_count=entities_with_hits,
            entities_searched=searched_entities,
            entity_precedents=entity_precedents,
            related_cases=ranked_cases,
            comment_id=None,
            secops_ui_base_url=base_url_clean,
            provenance={
                "workflow": "case.related_by_entity",
                "retrieved_at": now.isoformat(),
                "lookback_days": lookback_days,
                "case_status_scope": scope_norm,
                "min_shared_entities": min_shared_entities,
                "entities_searched": len(searched_entities),
                "total_related_cases": total_related,
                "returned_related_cases": len(ranked_cases),
            },
        )

        if post_wall_comment:
            try:
                md = self._build_wall_comment(result)
                comment_rec = self.comment_workflow.execute(case_id=clean_case_id, content=md)
                result.comment_id = getattr(comment_rec, "comment_id", None) or getattr(comment_rec, "name", None)
            except Exception:
                pass

        return result

    @staticmethod
    def _build_wall_comment(res: RelatedCasesByEntityResult) -> str:
        lines = [
            "## [SecOps SDK Engine] Related Cases by Entity",
            f"- **Source Case**: `#{res.case_id}` ({res.case_title})",
            f"- **Lookback Window**: `{res.lookback_days} days` (`{res.case_status_scope}`)",
            f"- **Entities Searched**: `{res.entities_searched_count}` (`{res.entities_with_hits_count}` with historical/active matches)",
            f"- **Related Cases Discovered**: `{res.total_related_cases}` (`{res.active_related_cases_count}` Open, `{res.closed_related_cases_count}` Closed, `{res.incident_related_cases_count}` Incidents)",
        ]
        if res.related_cases:
            lines.append("\n### Top Related Cases")
            lines.append("| Case ID | Status | Priority | Stage | Shared Entities | Title | Created |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for rc in res.related_cases[:15]:
                shared_str = ", ".join(f"`{e}`" for e in rc.get("shared_entity_identifiers", [])[:4])
                if len(rc.get("shared_entity_identifiers", [])) > 4:
                    shared_str += f" (+{len(rc['shared_entity_identifiers']) - 4} more)"
                created_short = (rc.get("create_time") or "")[:19].replace("T", " ")
                lines.append(
                    f"| **[#{rc['case_id']}]({rc['case_url']})** | {rc['status']} | {rc['priority']} | {rc['stage']} | {shared_str} | {rc['title']} | {created_short} |"
                )
        else:
            lines.append("\n_No related open or historical cases found matching the case entities within the lookback window._")
        return "\n".join(lines)
