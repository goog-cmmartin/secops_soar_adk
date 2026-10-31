"""SOAR Case Orchestrate Triage Workflow (`case.orchestrate_triage`)."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.domain import (
    AlertPlaybookStatus,
    CaseInvestigation,
    CasePrecedentSummary,
    CasePriority,
    CaseSearchPrefix,
    CaseSearchQuery,
    CaseSearchResultItem,
    CaseStatus,
    CaseSummary,
    CaseTimeline,
    CaseTimelineEvent,
    CaseTriageAssessment,
    CaseTriageBatch,
    CaseWallRecord,
    EntityPrecedentItem,
    InvolvedEntitySummary,
    TriageVerdict,
)
from engine.workflows.case_actions import GetCaseSummaryWorkflow
from engine.workflows.case_investigation import InvestigateCaseWorkflow
from engine.workflows.case_search import SearchCasesWorkflow


_PRIORITY_WEIGHT = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 30,
    "LOW": 20,
    "INFO": 10,
    "UNKNOWN": 0,
}


def _eval_highest_alert_priority(alerts: List[Any]) -> str:
    """Evaluates the maximum priority string across case alerts."""
    highest = "UNKNOWN"
    max_weight = -1
    for a in alerts:
        p_raw = str(getattr(a, "priority", "UNKNOWN") or "UNKNOWN").upper().replace("PRIORITY_", "")
        weight = _PRIORITY_WEIGHT.get(p_raw, 0)
        if weight > max_weight:
            max_weight = weight
            highest = p_raw
    return highest


def build_case_timeline(
    inv: CaseInvestigation,
    wall_records: Optional[List[CaseWallRecord]] = None,
) -> CaseTimeline:
    """Constructs a unified, chronologically sorted timeline of events and milestones in a case."""
    events: List[CaseTimelineEvent] = []

    # 1. Case creation milestone
    if inv.create_time:
        prio_label = inv.priority.value if hasattr(inv.priority, "value") else str(inv.priority)
        events.append(
            CaseTimelineEvent(
                timestamp=inv.create_time,
                event_type="CASE_CREATED",
                title=f"Case #{inv.case_id} Created",
                description=f"Case opened with priority '{prio_label}' in stage '{inv.stage}'",
                source_id=inv.case_id,
                severity=prio_label,
                metadata={"status": str(inv.status), "assignee": inv.assignee},
            )
        )

    # 2. Alerts & Playbook Milestones
    for alert in inv.alerts:
        ts = alert.start_time or inv.create_time
        events.append(
            CaseTimelineEvent(
                timestamp=ts,
                event_type="ALERT",
                title=f"Alert: {alert.display_name}",
                description=f"Rule: {alert.rule_name or 'N/A'} | Severity: {alert.priority} | Events: {alert.event_count}",
                source_id=alert.alert_id,
                severity=alert.priority,
                metadata={
                    "product": alert.product,
                    "vendor": alert.vendor,
                    "event_count": alert.event_count,
                    "end_time": alert.end_time.isoformat() if alert.end_time else None,
                },
            )
        )
        if alert.has_playbook:
            playbook_status = (alert.playbook_status or "PENDING").upper()
            events.append(
                CaseTimelineEvent(
                    timestamp=alert.start_time or inv.create_time,
                    event_type="PLAYBOOK",
                    title=f"Playbook: {alert.attached_playbook_name}",
                    description=f"Status: {playbook_status} (Runs: {alert.playbook_run_count}) on alert '{alert.display_name}'",
                    source_id=alert.alert_id,
                    severity=alert.priority,
                    metadata={
                        "playbook_name": alert.attached_playbook_name,
                        "playbook_status": playbook_status,
                        "run_count": alert.playbook_run_count,
                    },
                )
            )

    # 3. Case comments & analyst actions
    for c in inv.comments:
        first_line = c.comment.strip().splitlines()[0] if c.comment.strip() else "Empty note"
        if len(first_line) > 100:
            first_line = first_line[:97] + "..."
        events.append(
            CaseTimelineEvent(
                timestamp=c.create_time or inv.create_time,
                event_type="COMMENT",
                title=f"Note by {c.author or 'System'}",
                description=first_line,
                source_id=c.name,
                metadata={"full_comment": c.comment, "author_name": c.author_name},
            )
        )

    # 4. Case Activity Wall records (granular integration actions, tag/stage modifications)
    if wall_records:
        for wr in wall_records:
            # Skip comment activities since they are already covered by inv.comments
            if wr.activity_type == "CASE_COMMENT":
                continue
            ts = wr.create_time or inv.create_time
            ev_type = "ACTION" if wr.activity_type == "CASE_ACTION" else wr.activity_kind
            title_text = f"Activity: {wr.activity_kind.replace('_', ' ').title()}" if wr.activity_kind else "Activity"
            events.append(
                CaseTimelineEvent(
                    timestamp=ts,
                    event_type=ev_type,
                    title=title_text,
                    description=wr.description,
                    source_id=wr.activity_id or wr.name,
                    metadata={"creator": wr.creator_user_id, "details": wr.details},
                )
            )

    def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

    # 5. Case state update
    norm_update = _as_utc(inv.update_time)
    norm_create = _as_utc(inv.create_time)
    if norm_update and (not norm_create or norm_update > norm_create):
        status_label = inv.status.value if hasattr(inv.status, "value") else str(inv.status)
        events.append(
            CaseTimelineEvent(
                timestamp=inv.update_time,
                event_type="CASE_UPDATED",
                title="Case State Updated",
                description=f"Case #{inv.case_id} recorded in stage '{inv.stage}' with status '{status_label}'",
                source_id=inv.case_id,
                metadata={"stage": inv.stage, "assignee": inv.assignee},
            )
        )

    # Sort events chronologically
    min_dt = datetime.min.replace(tzinfo=timezone.utc)
    def _sort_key(ev: CaseTimelineEvent):
        return _as_utc(ev.timestamp) or min_dt

    sorted_events = sorted(events, key=_sort_key)
    valid_times = [_as_utc(ev.timestamp) for ev in sorted_events if ev.timestamp is not None]
    earliest_time = min(valid_times) if valid_times else None
    latest_time = max(valid_times) if valid_times else None

    provenance = {
        "case_id": inv.case_id,
        "event_count": len(sorted_events),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    return CaseTimeline(
        case_id=inv.case_id,
        events=sorted_events,
        earliest_time=earliest_time,
        latest_time=latest_time,
        provenance=provenance,
    )


def _analyze_precedents(
    case_id: str,
    title: str,
    entities: List[InvolvedEntitySummary],
    search_workflow: SearchCasesWorkflow,
) -> CasePrecedentSummary:
    """Analyzes historical case occurrences by title and involved entities."""
    clean_case_id = str(case_id).strip().split("/")[-1]

    # 1. Search prior cases with matching title
    title_prior_case_ids: List[str] = []
    title_closed_count = 0
    title_incident_count = 0

    if title:
        try:
            title_query = CaseSearchQuery(query_text=title, page_size=20)
            title_batch = search_workflow.execute(title_query)
            for c in title_batch.results:
                if str(c.case_id) != clean_case_id:
                    title_prior_case_ids.append(str(c.case_id))
                    if c.is_closed:
                        title_closed_count += 1
                    if c.is_incident:
                        title_incident_count += 1
        except Exception:
            pass

    # 2. Search prior cases by involved entities in parallel
    entity_precedents: List[EntityPrecedentItem] = []
    unique_entities: Dict[str, Optional[str]] = {}
    for e in entities:
        if e.identifier and len(e.identifier) > 2:
            unique_entities[e.identifier] = e.entity_type

    if unique_entities:
        with ThreadPoolExecutor(max_workers=min(6, len(unique_entities))) as executor:
            future_to_entity = {
                executor.submit(
                    search_workflow.execute,
                    CaseSearchQuery(query_text=CaseSearchPrefix.ENTITY.apply(ident), page_size=20),
                ): (ident, etype)
                for ident, etype in unique_entities.items()
            }

            for future in as_completed(future_to_entity):
                ident, etype = future_to_entity[future]
                try:
                    res = future.result()
                    prior_ids: List[str] = []
                    inc_count = 0
                    for c in res.results:
                        if str(c.case_id) != clean_case_id:
                            prior_ids.append(str(c.case_id))
                            if c.is_incident:
                                inc_count += 1

                    entity_precedents.append(
                        EntityPrecedentItem(
                            entity_identifier=ident,
                            entity_type=etype,
                            prior_case_count=len(prior_ids),
                            recent_case_ids=prior_ids[:5],
                            active_incident_count=inc_count,
                            is_frequent=len(prior_ids) >= 3,
                        )
                    )
                except Exception:
                    pass

    total_entity_matches = sum(ep.prior_case_count for ep in entity_precedents)
    all_repeat_ids: Set[str] = set(title_prior_case_ids)
    for ep in entity_precedents:
        all_repeat_ids.update(ep.recent_case_ids)

    # Determine novelty vs repeat status
    is_novel = (len(title_prior_case_ids) == 0 and total_entity_matches == 0)
    is_repeat = (len(title_prior_case_ids) > 0 or total_entity_matches > 0)

    precedent_notes: List[str] = []
    if title and title_prior_case_ids:
        precedent_notes.append(
            f"Observed {len(title_prior_case_ids)} prior case(s) with matching title "
            f"({title_closed_count} closed, {title_incident_count} incidents)."
        )

    for ep in sorted(entity_precedents, key=lambda x: x.prior_case_count, reverse=True):
        if ep.prior_case_count > 0:
            note = f"Entity '{ep.entity_identifier}' ({ep.entity_type or 'ENTITY'}) appeared in {ep.prior_case_count} prior case(s)"
            if ep.active_incident_count > 0:
                note += f" including {ep.active_incident_count} active incident(s)"
            note += "."
            precedent_notes.append(note)

    return CasePrecedentSummary(
        target_case_id=clean_case_id,
        title_query=title,
        title_prior_case_count=len(title_prior_case_ids),
        title_prior_case_ids=title_prior_case_ids[:10],
        title_closed_count=title_closed_count,
        title_incident_count=title_incident_count,
        entity_precedents=entity_precedents,
        total_entity_matches=total_entity_matches,
        is_novel=is_novel,
        is_repeat=is_repeat,
        repeat_case_ids=sorted(list(all_repeat_ids), reverse=True)[:10],
        precedent_notes=precedent_notes,
    )


def _derive_verdict_and_recommendations(
    status: CaseStatus,
    priority: CasePriority,
    highest_alert_priority: str,
    suspicious_entities: List[str],
    is_closed: bool,
    alert_count: int,
    precedent_summary: Optional[CasePrecedentSummary] = None,
    gemini_summary: Optional[CaseSummary] = None,
    alert_playbook_statuses: Optional[List[AlertPlaybookStatus]] = None,
) -> Tuple[TriageVerdict, str, List[str], Optional[str]]:
    """Calculates deterministic triage verdict, summary, recommendations, and suggested stage."""
    if is_closed or status == CaseStatus.CLOSED:
        verdict = TriageVerdict.CLOSED_NO_ACTION
        summary = "Case is closed. No active triage or containment action required."
        recs = ["Case archived; retain for correlation and audit history."]
        return verdict, summary, recs, None

    recs: List[str] = []
    has_suspicious_ents = len(suspicious_entities) > 0
    prio_str = priority.value.upper() if hasattr(priority, "value") else str(priority).upper()

    is_critical = prio_str == "CRITICAL" or highest_alert_priority == "CRITICAL"
    is_high = prio_str == "HIGH" or highest_alert_priority == "HIGH"

    # Precedent checks
    has_active_incident_precedents = False
    is_repeat_benign = False
    is_novel_detection = False

    if precedent_summary:
        if any(ep.active_incident_count > 0 for ep in precedent_summary.entity_precedents):
            has_active_incident_precedents = True
        elif precedent_summary.title_incident_count > 0:
            has_active_incident_precedents = True

        if (
            precedent_summary.title_prior_case_count >= 2
            and precedent_summary.title_closed_count >= (precedent_summary.title_prior_case_count * 0.7)
            and not has_suspicious_ents
            and not is_critical
        ):
            is_repeat_benign = True

        if precedent_summary.is_novel:
            is_novel_detection = True

    # Decision matrix
    if is_critical:
        if has_suspicious_ents or has_active_incident_precedents:
            verdict = TriageVerdict.CRITICAL_ESCALATION
            summary = (
                f"CRITICAL escalation priority: Case has {alert_count} alert(s) with {highest_alert_priority} "
                f"severity and {len(suspicious_entities)} flagged suspicious entity(ies)."
            )
            recs.append(f"Immediate host/identity containment required for: {', '.join(suspicious_entities[:3]) if suspicious_entities else 'Key entities'}")
            recs.append("Escalate case to Tier 2/Tier 3 Incident Response lead.")
            recs.append("Run entity timeline pivot and check lateral movement indicators.")
            suggested_stage = "Incident"
        else:
            verdict = TriageVerdict.HIGH_PRIORITY_INVESTIGATION
            summary = (
                f"Critical alert telemetry detected ({highest_alert_priority} severity) with {alert_count} alert(s)."
            )
            recs.append("Perform deep raw event investigation on trigger detections.")
            recs.append("Verify alert payload against telemetry data tables.")
            suggested_stage = "Investigation"
    elif has_active_incident_precedents:
        verdict = TriageVerdict.REPEAT_ACTIVE_CAMPAIGN
        summary = (
            f"Active campaign correlation: Entities or rule matched active incidents across "
            f"{len(precedent_summary.repeat_case_ids if precedent_summary else [])} related case(s)."
        )
        recs.append("Cross-reference timeline against related active incidents.")
        recs.append("Investigate potential multi-stage lateral movement or credential reuse.")
        suggested_stage = "Investigation"
    elif is_repeat_benign:
        verdict = TriageVerdict.REPEAT_RESOLVED_DUPLICATE
        summary = (
            f"Repeat resolved pattern: {precedent_summary.title_prior_case_count if precedent_summary else 0} "
            f"prior occurrences were closed/resolved."
        )
        recs.append("Review previous case resolutions to confirm expected benign/tuning behavior.")
        recs.append("Consider rule threshold tuning if noise persists.")
        suggested_stage = "Closed"
    elif is_novel_detection:
        verdict = TriageVerdict.NOVEL_DETECTION
        summary = f"Novel detection: Zero prior occurrences found for title or entities across the tenant ({alert_count} alert(s))."
        recs.append("First-time observed threat signal; perform comprehensive alert rule validation.")
        recs.append("Examine raw UDM events and establish baseline entity behavior.")
        suggested_stage = "Investigation"
    elif has_suspicious_ents:
        verdict = TriageVerdict.CONTAINMENT_REQUIRED
        summary = (
            f"Active suspicious entities identified ({len(suspicious_entities)}) in {alert_count} alert(s)."
        )
        recs.append(f"Isolate or reset credentials for suspicious entities: {', '.join(suspicious_entities[:3])}")
        recs.append("Review authentication and network access logs.")
        suggested_stage = "Investigation"
    elif is_high:
        verdict = TriageVerdict.HIGH_PRIORITY_INVESTIGATION
        summary = f"High priority triage queue: {alert_count} alert(s) requiring analyst review."
        recs.append("Review alert rules and attached playbook execution outputs.")
        recs.append("Validate indicator telemetry and determine true/false positive ratio.")
        suggested_stage = "Investigation"
    elif prio_str in ("LOW", "INFO"):
        verdict = TriageVerdict.INFORMATIONAL
        summary = f"Low risk or informational case with {alert_count} alert(s)."
        recs.append("Review for standard tuning or batch closure if benign.")
        suggested_stage = "Triage"
    else:
        verdict = TriageVerdict.STANDARD_TRIAGE
        summary = f"Standard triage queue: {alert_count} alert(s) under observation."
        recs.append("Review case context and assign to active analyst queue.")
        suggested_stage = "Investigation"

    # Incorporate SOAR Playbook status recommendations
    if alert_playbook_statuses:
        for pb in alert_playbook_statuses:
            aname = pb.alert_display_name or pb.alert_id or "Alert"
            if pb.attached_playbook_name:
                pb_stat = str(pb.status or "PENDING").upper()
                if pb_stat in ("SUCCESS", "COMPLETED", "FINISHED"):
                    recs.append(f"[Playbook Success] '{pb.attached_playbook_name}' completed on '{aname}'. Review automated investigation artifacts.")
                elif pb_stat in ("FAILED", "FAILURE", "ERROR"):
                    recs.append(f"[Playbook Failed] '{pb.attached_playbook_name}' failed on '{aname}'. Investigate execution failure or re-trigger playbook.")
                elif pb_stat in ("PENDING", "RUNNING", "IN_PROGRESS", "QUEUED"):
                    recs.append(f"[Playbook In-Progress] '{pb.attached_playbook_name}' is {pb_stat} on '{aname}'. Await completion before manual triage.")
                else:
                    recs.append(f"[Playbook Attached] '{pb.attached_playbook_name}' (Status: {pb_stat}) attached to '{aname}'.")
            else:
                recs.append(f"[Playbook Missing] '{aname}' has no attached SOAR playbook. Perform manual alert triage or attach playbook.")

    # Incorporate Gemini AI next steps if available
    if gemini_summary and gemini_summary.next_steps:
        for ns in gemini_summary.next_steps[:3]:
            if ns not in recs:
                recs.append(f"[Gemini Suggestion] {ns}")

    return verdict, summary, recs, suggested_stage


def _generate_agent_prompt(
    case_id: str,
    title: str,
    priority: str,
    status: str,
    stage: str,
    environment: str,
    assignee: Optional[str],
    highest_alert_priority: str,
    alert_count: int,
    alert_names: List[str],
    suspicious_entities: List[str],
    latest_comment: Optional[str],
    verdict: TriageVerdict,
    precedent_summary: Optional[CasePrecedentSummary] = None,
    gemini_summary: Optional[CaseSummary] = None,
    alert_playbook_statuses: Optional[List[AlertPlaybookStatus]] = None,
) -> str:
    """Constructs a tailored, actionable Antigravity subagent prompt for delegating triage."""
    alert_snippet = ", ".join(alert_names[:3]) if alert_names else "None listed"
    if len(alert_names) > 3:
        alert_snippet += f" (+{len(alert_names) - 3} more)"

    entity_snippet = ", ".join(suspicious_entities[:4]) if suspicious_entities else "None flagged"
    if len(suspicious_entities) > 4:
        entity_snippet += f" (+{len(suspicious_entities) - 4} more)"

    precedent_text = "None analyzed"
    if precedent_summary:
        if precedent_summary.is_novel:
            precedent_text = "NOVEL (0 prior occurrences across tenant)"
        elif precedent_summary.is_repeat:
            precedent_text = f"REPEAT ({precedent_summary.title_prior_case_count} prior title matches, {precedent_summary.total_entity_matches} entity matches)"

    gemini_text = "Not available"
    if gemini_summary and gemini_summary.summary:
        gemini_text = gemini_summary.summary

    playbook_summary_lines = []
    if alert_playbook_statuses:
        for pb in alert_playbook_statuses:
            if pb.attached_playbook_name:
                playbook_summary_lines.append(f"  - '{pb.attached_playbook_name}' ({pb.status or 'PENDING'}) on '{pb.alert_display_name}'")
            else:
                playbook_summary_lines.append(f"  - No playbook attached to '{pb.alert_display_name}'")
    playbook_text = "\n".join(playbook_summary_lines) if playbook_summary_lines else "None listed"

    prompt = (
        f"You are a SecOps Tier-2 SOC Analyst assigned to investigate and triage Case #{case_id}: '{title}'.\n\n"
        f"CASE CONTEXT & METADATA:\n"
        f"- Case ID: {case_id}\n"
        f"- Title: {title}\n"
        f"- Priority: {priority} (Highest Alert Priority: {highest_alert_priority})\n"
        f"- Status: {status} | Stage: {stage}\n"
        f"- Environment: {environment or 'Default'}\n"
        f"- Assigned Analyst: {assignee or 'Unassigned'}\n"
        f"- Triage Initial Verdict: {verdict.value}\n"
        f"- Historical Precedent: {precedent_text}\n\n"
        f"GEMINI AI SUMMARY:\n"
        f"{gemini_text}\n\n"
        f"KEY SIGNALS & EVIDENCE:\n"
        f"- Alerts Count: {alert_count} (Key Alerts: {alert_snippet})\n"
        f"- Attached Playbooks:\n{playbook_text}\n"
        f"- Suspicious Entities: {entity_snippet}\n"
        f"- Latest Note: {latest_comment or 'No existing analyst comments'}\n\n"
        f"MISSION OBJECTIVES:\n"
        f"1. Investigate the triggering detections and raw telemetry for alert(s).\n"
        f"2. Check threat intelligence and UDM timeline for suspicious entities ({entity_snippet}).\n"
        f"3. Verify if automated SOAR playbooks executed properly.\n"
        f"4. Produce an initial triage summary, classify true/false positive, and document recommended next steps."
    )
    return prompt


class GetCaseTimelineWorkflow:
    """Orchestrates comprehensive event timeline extraction for a case, merging alert detections, playbook milestones, comments, updates, and activity wall records."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.investigate_workflow = InvestigateCaseWorkflow(self.adapter)

    def execute(self, case_id: str, include_wall: bool = True) -> CaseTimeline:
        inv = self.investigate_workflow.execute(case_id=case_id)
        wall_records = None
        if include_wall:
            try:
                from engine.workflows.case_wall import GetCaseWallWorkflow
                wall_res = GetCaseWallWorkflow(self.adapter).execute(case_id=case_id, limit=30)
                wall_records = wall_res.records
            except Exception:
                pass
        return build_case_timeline(inv, wall_records=wall_records)


class CaseTriageWorkflow:
    """Executes full analyst triage workflow for a single specific case (`case.triage`)."""

    def __init__(
        self,
        adapter: Optional[Any] = None,
        search_workflow: Optional[SearchCasesWorkflow] = None,
        investigate_workflow: Optional[InvestigateCaseWorkflow] = None,
        case_summary_workflow: Optional[GetCaseSummaryWorkflow] = None,
    ):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.search_workflow = search_workflow or SearchCasesWorkflow(self.adapter)
        self.investigate_workflow = investigate_workflow or InvestigateCaseWorkflow(self.adapter)
        self.case_summary_workflow = case_summary_workflow or GetCaseSummaryWorkflow(self.adapter)

    def execute(
        self,
        case_id: str,
        fetch_summary: bool = True,
        search_precedents: bool = True,
        summary_timeout_sec: float = 15.0,
        apply_stage_update: bool = False,
        post_comment: bool = False,
    ) -> CaseTriageAssessment:
        """Executes full analyst triage workflow for a single specific case."""
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")

        clean_case_id = str(case_id).strip().split("/")[-1]

        # Step 1: Deep case investigation (case, alerts, entities, comments)
        inv = self.investigate_workflow.execute(clean_case_id)

        # Step 2: Gemini AI Case Summary (optional / resilient)
        gemini_summary: Optional[CaseSummary] = None
        if fetch_summary:
            try:
                gemini_summary = self.case_summary_workflow.execute(
                    case_id=clean_case_id,
                    timeout_sec=summary_timeout_sec,
                    poll_interval_sec=2.0,
                )
            except Exception:
                pass

        # Step 3: Historical Precedent Analysis (optional)
        precedent_summary: Optional[CasePrecedentSummary] = None
        if search_precedents:
            try:
                precedent_summary = _analyze_precedents(
                    case_id=clean_case_id,
                    title=inv.display_name,
                    entities=inv.entities,
                    search_workflow=self.search_workflow,
                )
            except Exception:
                pass

        # Extract suspicious entities
        suspicious_ents: List[str] = []
        for e in inv.entities:
            if e.is_suspicious and e.identifier:
                if e.identifier not in suspicious_ents:
                    suspicious_ents.append(e.identifier)

        # Extract latest comment
        comments = inv.comments or []
        latest_comment_text: Optional[str] = None
        if comments:
            def _comment_ts(cm: Any) -> datetime:
                dt = cm.create_time
                if dt is None:
                    return datetime.min.replace(tzinfo=timezone.utc)
                return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

            sorted_comments = sorted(
                [cm for cm in comments if not cm.is_deleted],
                key=_comment_ts,
                reverse=True,
            )
            if sorted_comments:
                latest_comment_text = sorted_comments[0].comment

        alerts = inv.alerts or []
        alert_count = len(alerts)
        highest_alert_prio = _eval_highest_alert_priority(alerts)
        is_closed = inv.status == CaseStatus.CLOSED

        # Extract alert playbook statuses
        alert_playbook_statuses = [
            AlertPlaybookStatus(
                case_id=clean_case_id,
                alert_id=a.alert_id,
                alert_display_name=a.display_name,
                attached_playbook_name=a.attached_playbook_name,
                status=a.playbook_status,
                run_count=a.playbook_run_count,
                alert_group_identifier=a.alert_group_identifier,
            )
            for a in alerts
        ]

        # Synthesize chronological case timeline
        case_timeline = build_case_timeline(inv)

        # Step 4 & 5: Derive verdict, recommendations, suggested stage
        verdict, triage_summary, recommended_actions, suggested_stage = _derive_verdict_and_recommendations(
            status=inv.status,
            priority=inv.priority,
            highest_alert_priority=highest_alert_prio,
            suspicious_entities=suspicious_ents,
            is_closed=is_closed,
            alert_count=alert_count,
            precedent_summary=precedent_summary,
            gemini_summary=gemini_summary,
            alert_playbook_statuses=alert_playbook_statuses,
        )

        alert_names = [a.display_name or a.name for a in alerts]
        prompt = _generate_agent_prompt(
            case_id=clean_case_id,
            title=inv.display_name,
            priority=inv.priority.value if hasattr(inv.priority, "value") else str(inv.priority),
            status=inv.status.value if hasattr(inv.status, "value") else str(inv.status),
            stage=inv.stage,
            environment=inv.environment,
            assignee=inv.assignee,
            highest_alert_priority=highest_alert_prio,
            alert_count=alert_count,
            alert_names=alert_names,
            suspicious_entities=suspicious_ents,
            latest_comment=latest_comment_text,
            verdict=verdict,
            precedent_summary=precedent_summary,
            gemini_summary=gemini_summary,
            alert_playbook_statuses=alert_playbook_statuses,
        )

        # Step 6 & 7: Apply stage update and/or post triage comment if requested
        if apply_stage_update and suggested_stage and not is_closed and suggested_stage != inv.stage:
            try:
                self.adapter.update_case(
                    case_id=clean_case_id,
                    updates={"stage": suggested_stage},
                    update_mask="stage",
                )
                inv.stage = suggested_stage
            except Exception:
                pass

        if post_comment:
            try:
                comment_lines = [
                    f"### [ASOC Automated Case Triage Assessment]",
                    f"**Verdict**: `{verdict.value}`",
                    f"**Summary**: {triage_summary}",
                    "",
                ]
                if precedent_summary and precedent_summary.precedent_notes:
                    comment_lines.append("**Historical Precedents**:")
                    for n in precedent_summary.precedent_notes:
                        comment_lines.append(f"- {n}")
                    comment_lines.append("")

                if gemini_summary and gemini_summary.summary:
                    comment_lines.append(f"**Gemini AI Narrative**: {gemini_summary.summary}")
                    comment_lines.append("")

                if recommended_actions:
                    comment_lines.append("**Recommended Actions**:")
                    for act in recommended_actions:
                        comment_lines.append(f"- {act}")
                    comment_lines.append("")

                comment_lines.append("--- Auto-generated by SecOps Engine SDK ---")
                comment_payload = "\n".join(comment_lines)
                self.adapter.create_case_comment(clean_case_id, comment=comment_payload)
            except Exception:
                pass

        is_novel = precedent_summary.is_novel if precedent_summary else False
        is_repeat = precedent_summary.is_repeat if precedent_summary else False
        prior_case_count = (
            (precedent_summary.title_prior_case_count + precedent_summary.total_entity_matches)
            if precedent_summary
            else 0
        )

        return CaseTriageAssessment(
            case_id=clean_case_id,
            title=inv.display_name,
            priority=inv.priority,
            status=inv.status,
            stage=inv.stage,
            is_closed=is_closed,
            is_incident=inv.is_incident,
            alert_count=alert_count,
            highest_alert_priority=highest_alert_prio,
            suspicious_entity_count=len(suspicious_ents),
            suspicious_entities=suspicious_ents,
            comment_count=len(comments),
            latest_comment=latest_comment_text,
            triage_verdict=verdict,
            triage_summary=triage_summary,
            recommended_actions=recommended_actions,
            suggested_agent_prompt=prompt,
            assigned_user=inv.assignee,
            create_time=inv.create_time,
            update_time=inv.update_time,
            environment=inv.environment,
            tags=[],
            raw_case=inv.raw_case,
            investigation=inv,
            gemini_summary=gemini_summary,
            precedent_summary=precedent_summary,
            is_novel=is_novel,
            is_repeat=is_repeat,
            prior_case_count=prior_case_count,
            suggested_stage_transition=suggested_stage,
            alert_playbook_statuses=alert_playbook_statuses,
            timeline=case_timeline,
        )


class OrchestrateCaseTriageWorkflow:
    """Orchestrates batched case retrieval, parallel multi-resource deep investigation, and triage (`case.orchestrate_triage`)."""

    def __init__(
        self,
        adapter: Optional[Any] = None,
        triage_workflow: Optional[CaseTriageWorkflow] = None,
        search_workflow: Optional[SearchCasesWorkflow] = None,
    ):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.triage_workflow = triage_workflow or CaseTriageWorkflow(self.adapter)
        self.search_workflow = search_workflow or self.triage_workflow.search_workflow
        self.investigate_workflow = self.triage_workflow.investigate_workflow
        self.case_summary_workflow = self.triage_workflow.case_summary_workflow

    def triage_single_case(
        self,
        case_id: str,
        fetch_summary: bool = True,
        search_precedents: bool = True,
        summary_timeout_sec: float = 15.0,
        apply_stage_update: bool = False,
        post_comment: bool = False,
    ) -> CaseTriageAssessment:
        """Delegates single-case triage to CaseTriageWorkflow."""
        return self.triage_workflow.execute(
            case_id=case_id,
            fetch_summary=fetch_summary,
            search_precedents=search_precedents,
            summary_timeout_sec=summary_timeout_sec,
            apply_stage_update=apply_stage_update,
            post_comment=post_comment,
        )

    def execute(
        self,
        case_ids: Optional[List[str]] = None,
        limit: int = 5,
        open_only: bool = True,
        query_text: str = "",
        priorities: Optional[List[str]] = None,
        stages: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        environments: Optional[List[str]] = None,
        assigned_users: Optional[List[str]] = None,
        is_important: Optional[bool] = None,
        page_number: int = 0,
        search_precedents: bool = True,
        fetch_summary: bool = False,
    ) -> CaseTriageBatch:
        """Executes batched case retrieval and parallel triage analysis."""
        if case_ids:
            clean_ids = [str(cid).strip().split("/")[-1] for cid in case_ids if str(cid).strip()]
            assessments: List[CaseTriageAssessment] = []
            batch_errors: Dict[str, str] = {}
            with ThreadPoolExecutor(max_workers=min(8, len(clean_ids))) as executor:
                future_map = {
                    executor.submit(
                        self.triage_workflow.execute,
                        case_id=cid,
                        fetch_summary=fetch_summary,
                        search_precedents=search_precedents,
                    ): cid
                    for cid in clean_ids
                }
                for future in as_completed(future_map):
                    cid = future_map[future]
                    try:
                        assessments.append(future.result())
                    except Exception as exc:
                        batch_errors[cid] = str(exc)

            # Maintain input ordering
            assessment_dict = {a.case_id: a for a in assessments}
            ordered_assessments = [assessment_dict[cid] for cid in clean_ids if cid in assessment_dict]

            open_count = sum(1 for a in ordered_assessments if not a.is_closed)
            closed_count = sum(1 for a in ordered_assessments if a.is_closed)
            critical_high_count = sum(
                1 for a in ordered_assessments
                if a.triage_verdict in (
                    TriageVerdict.CRITICAL_ESCALATION,
                    TriageVerdict.HIGH_PRIORITY_INVESTIGATION,
                    TriageVerdict.REPEAT_ACTIVE_CAMPAIGN,
                )
            )

            provenance: Dict[str, Any] = {
                "workflow": "case.orchestrate_triage",
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "mode": "explicit_case_ids",
                "total_triaged": len(ordered_assessments),
            }
            if batch_errors:
                provenance["errors"] = batch_errors

            return CaseTriageBatch(
                results=ordered_assessments,
                total_cases_analyzed=len(ordered_assessments),
                open_cases_count=open_count,
                closed_cases_count=closed_count,
                critical_high_count=critical_high_count,
                provenance=provenance,
            )

        if limit <= 0:
            raise ValueError("limit must be a positive integer.")

        fetch_size = min(max(limit * 3 if open_only else limit, 15), 100)

        query = CaseSearchQuery(
            query_text=query_text,
            priorities=priorities or [],
            stages=stages or [],
            tags=tags or [],
            environments=environments or [],
            assigned_users=assigned_users or [],
            is_important=is_important,
            page_size=fetch_size,
            page_number=page_number,
        )

        search_batch = self.search_workflow.execute(query)
        candidates: List[CaseSearchResultItem] = []

        for item in search_batch.results:
            if open_only and item.is_closed:
                continue
            candidates.append(item)
            if len(candidates) >= limit:
                break

        assessments_batch: List[CaseTriageAssessment] = []
        search_batch_errors: Dict[str, str] = {}

        if candidates:
            with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as executor:
                future_map = {
                    executor.submit(
                        self.triage_workflow.execute,
                        case_id=c.case_id,
                        fetch_summary=fetch_summary,
                        search_precedents=search_precedents,
                    ): c
                    for c in candidates
                }

                cand_dict: Dict[str, CaseTriageAssessment] = {}
                for future in as_completed(future_map):
                    c = future_map[future]
                    try:
                        cand_dict[c.case_id] = future.result()
                    except Exception as exc:
                        search_batch_errors[c.case_id] = str(exc)

                for c in candidates:
                    if c.case_id in cand_dict:
                        assessments_batch.append(cand_dict[c.case_id])

        open_count = sum(1 for a in assessments_batch if not a.is_closed)
        closed_count = sum(1 for a in assessments_batch if a.is_closed)
        critical_high_count = sum(
            1 for a in assessments_batch
            if a.triage_verdict in (
                TriageVerdict.CRITICAL_ESCALATION,
                TriageVerdict.HIGH_PRIORITY_INVESTIGATION,
                TriageVerdict.REPEAT_ACTIVE_CAMPAIGN,
            )
        )

        provenance = {
            "workflow": "case.orchestrate_triage",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "limit": limit,
            "open_only": open_only,
            "total_candidates_searched": len(search_batch.results),
            "total_triaged": len(assessments_batch),
        }
        if search_batch_errors:
            provenance["errors"] = search_batch_errors

        return CaseTriageBatch(
            results=assessments_batch,
            total_cases_analyzed=len(assessments_batch),
            open_cases_count=open_count,
            closed_cases_count=closed_count,
            critical_high_count=critical_high_count,
            provenance=provenance,
        )
