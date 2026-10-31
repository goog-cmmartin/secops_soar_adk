"""Autonomous AI Case Investigation Workflow (`case.ai_investigate`).

Executes deep multi-stage AI-assisted case investigation:
1. Deep Case Workspace Extraction: Aggregates alerts, entities, and metadata.
2. Gemini AI Narrative Generation & Retrieval: Retrieves and polls Gemini AI case summary.
3. Indicator & Telemetry Parsing: Extracts IPs, user accounts, and hashes.
4. Autonomous Threat Hunting (UDM Search): Hunts across Chronicle event logs.
5. Case Lifecycle Escalation & Audit Logging: Optionally marks incident, updates alert priority,
   and writes a structured investigation report to the case wall.
"""

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from engine.domain import (
    CaseAiInvestigationResult,
    CaseInvestigation,
    CaseSummary,
    SearchRequest,
)
from engine.workflows.case_actions import (
    AddCaseCommentWorkflow,
    GetCaseSummaryWorkflow,
    SetCaseIncidentWorkflow,
    UpdateCaseAlertWorkflow,
)
from engine.workflows.case_investigation import InvestigateCaseWorkflow
from engine.workflows.search_udm import SearchUDMWorkflow


def extract_indicators(text: str) -> Tuple[List[str], List[str], List[str]]:
    """Extracts IPv4/IPv6 addresses, user identities, and file hashes from text."""
    decoded_text = urllib.parse.unquote(text)

    entity_addresses = re.findall(r"\[\[\[([^|]+)\|ADDRESS\|\d+\]\]\]", decoded_text)
    entity_users = re.findall(r"\[\[\[([^|]+)\|USERUNIQNAME\|\d+\]\]\]", decoded_text)
    entity_hashes = re.findall(r"\[\[\[([^|]+)\|HASH\|\d+\]\]\]", decoded_text)

    ipv4_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", decoded_text)
    ipv6_matches = [
        m for m in re.findall(r"(?:::)?(?:[0-9a-fA-F]{1,4}::?){1,7}[0-9a-fA-F]{1,4}", decoded_text)
        if ":" in m
    ]
    user_matches = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", decoded_text)
    hash_matches = re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", decoded_text)

    all_ips = sorted(list(set(ipv4_matches + ipv6_matches + entity_addresses)))
    valid_ips = [
        ip for ip in all_ips
        if not ip.startswith("0.0.0") and not ip.startswith("255.255")
    ]

    all_users = sorted(list(set(user_matches + entity_users)))
    all_hashes = sorted(list(set(hash_matches + entity_hashes)))

    return valid_ips, all_users, all_hashes


class InvestigateCaseWithAIWorkflow:
    """Executes deep AI-driven autonomous case investigation and UDM telemetry scoping."""

    def __init__(
        self,
        adapter: Optional[Any] = None,
        investigate_workflow: Optional[InvestigateCaseWorkflow] = None,
        case_summary_workflow: Optional[GetCaseSummaryWorkflow] = None,
        search_udm_workflow: Optional[SearchUDMWorkflow] = None,
        incident_workflow: Optional[SetCaseIncidentWorkflow] = None,
        update_alert_workflow: Optional[UpdateCaseAlertWorkflow] = None,
        add_comment_workflow: Optional[AddCaseCommentWorkflow] = None,
    ):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.investigate_workflow = investigate_workflow or InvestigateCaseWorkflow(self.adapter)
        self.case_summary_workflow = case_summary_workflow or GetCaseSummaryWorkflow(self.adapter)
        self.search_udm_workflow = search_udm_workflow or SearchUDMWorkflow(self.adapter)
        self.incident_workflow = incident_workflow or SetCaseIncidentWorkflow(self.adapter)
        self.update_alert_workflow = update_alert_workflow or UpdateCaseAlertWorkflow(self.adapter)
        self.add_comment_workflow = add_comment_workflow or AddCaseCommentWorkflow(self.adapter)

    def execute(
        self,
        case_id: str,
        hunt_lookback_days: int = 14,
        hunt_receive_limit: int = 50,
        summary_timeout_sec: float = 90.0,
        escalate_incident: bool = False,
        escalate_alert_priority: Optional[str] = None,
        post_comment: bool = False,
        dry_run: bool = False,
    ) -> CaseAiInvestigationResult:
        """Executes the autonomous AI case investigation.

        Args:
            case_id: Target Google SecOps case identifier.
            hunt_lookback_days: Historical telemetry search window in days.
            hunt_receive_limit: Maximum returned UDM events per indicator hunt.
            summary_timeout_sec: Maximum timeout in seconds to poll for Gemini AI summary.
            escalate_incident: If True and not dry_run, sets case incident flag to True.
            escalate_alert_priority: If provided and not dry_run, updates primary alert priority.
            post_comment: If True and not dry_run, writes an ASOC audit comment to the case wall.
            dry_run: If True, executes read-only analysis without making mutations.
        """
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")

        clean_case_id = str(case_id).strip().split("/")[-1]

        # Stage 1: Deep case investigation (metadata, alerts, entities, comments)
        inv: CaseInvestigation = self.investigate_workflow.execute(clean_case_id)

        # Stage 2: Gemini AI Case Summary retrieval
        summary: CaseSummary = self.case_summary_workflow.execute(
            case_id=clean_case_id,
            timeout_sec=summary_timeout_sec,
        )

        # Stage 3: Indicator extraction (combines entities from investigation and AI narrative)
        text_corpus = " ".join(summary.reasons + summary.next_steps + [summary.summary or ""])
        ips, users, hashes = extract_indicators(text_corpus)

        # Supplement with entities observed directly in the case workspace
        for ent in inv.entities:
            val = getattr(ent, "identifier", None) or getattr(ent, "display_name", "") or ""
            etype = (getattr(ent, "entity_type", "") or "").upper()
            if ("IP" in etype or "ADDRESS" in etype) and val:
                if val not in ips and not val.startswith("0.0.0"):
                    ips.append(val)
            elif "USER" in etype and val:
                if val not in users:
                    users.append(val)
            elif "HASH" in etype and val:
                if val not in hashes:
                    hashes.append(val)

        ips.sort()
        users.sort()
        hashes.sort()

        # Primary alert identification
        primary_alert_id = None
        if inv.alerts:
            primary_alert_id = inv.alerts[0].alert_id

        # Stage 4: Autonomous UDM threat hunt across historical event telemetry
        hunt_results: Dict[str, int] = {}
        now = datetime.now(timezone.utc)
        start_time = (now - timedelta(days=hunt_lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        def _escape_udm(val: str) -> str:
            return val.replace("\\", "\\\\").replace('"', '\\"')

        for ip in ips:
            esc_ip = _escape_udm(ip)
            query = f'principal.ip = "{esc_ip}" or target.ip = "{esc_ip}"'
            req = SearchRequest(
                query=query,
                start_time=start_time,
                end_time=end_time,
                receive_limit=hunt_receive_limit,
            )
            try:
                session = self.search_udm_workflow.execute(req)
                hunt_results[ip] = session.received_count
            except Exception:
                hunt_results[ip] = -1

        for user in users:
            esc_user = _escape_udm(user)
            query = f'principal.user.userid = "{esc_user}" or target.user.userid = "{esc_user}"'
            req = SearchRequest(
                query=query,
                start_time=start_time,
                end_time=end_time,
                receive_limit=hunt_receive_limit,
            )
            try:
                session = self.search_udm_workflow.execute(req)
                hunt_results[user] = session.received_count
            except Exception:
                hunt_results[user] = -1

        for file_hash in hashes:
            esc_hash = _escape_udm(file_hash.lower())
            if len(file_hash) == 32:
                query = f'target.process.file.md5 = "{esc_hash}" or target.file.md5 = "{esc_hash}"'
            elif len(file_hash) == 40:
                query = f'target.process.file.sha1 = "{esc_hash}" or target.file.sha1 = "{esc_hash}"'
            else:
                query = f'target.process.file.sha256 = "{esc_hash}" or target.file.sha256 = "{esc_hash}"'
            req = SearchRequest(
                query=query,
                start_time=start_time,
                end_time=end_time,
                receive_limit=hunt_receive_limit,
            )
            try:
                session = self.search_udm_workflow.execute(req)
                hunt_results[file_hash] = session.received_count
            except Exception:
                hunt_results[file_hash] = -1

        # Stage 5: Escalations & Audit Logging
        incident_marked = False
        alert_escalated = False
        comment_posted = False

        if escalate_incident and not dry_run:
            res = self.incident_workflow.execute(case_id=clean_case_id, incident=True)
            incident_marked = bool(res.incident)

        if primary_alert_id and escalate_alert_priority and not dry_run:
            self.update_alert_workflow.execute(
                case_id=clean_case_id,
                alert_id=primary_alert_id,
                priority=escalate_alert_priority,
            )
            alert_escalated = True

        hunt_summary_lines = "\n".join(
            [f"- `{ioc}`: {count if count >= 0 else 'Error/No Access'} events found" for ioc, count in hunt_results.items()]
        )
        reasons_text = "\n".join([f"- {r}" for r in summary.reasons])
        next_steps_text = "\n".join([f"- {s}" for s in summary.next_steps])

        audit_comment = f"""### [Autonomous AI Investigation Report]
**Threat Context**: {summary.summary or 'N/A'}

**Underlying Evidence & MITRE ATT&CK**:
{reasons_text or 'None recorded'}

**Automated UDM Threat Hunt Telemetry**:
{hunt_summary_lines or 'No indicators queried'}

**Actions Taken**:
- Case Incident Status: {'Marked as Incident' if incident_marked else 'Unchanged'}
- Primary Alert Priority: {escalate_alert_priority if alert_escalated else 'Unchanged'}

**Recommended Follow-up Actions**:
{next_steps_text or 'None'}
"""

        if post_comment and not dry_run:
            self.add_comment_workflow.execute(case_id=clean_case_id, comment=audit_comment)
            comment_posted = True

        provenance = {
            "workflow": "case.ai_investigate",
            "executed_at": now.isoformat(),
            "case_id": clean_case_id,
            "lookback_days": hunt_lookback_days,
            "indicators_hunted": len(hunt_results),
            "dry_run": dry_run,
        }

        return CaseAiInvestigationResult(
            case_id=clean_case_id,
            summary_state=summary.state,
            summary_text=summary.summary,
            extracted_ips=ips,
            extracted_users=users,
            extracted_hashes=hashes,
            hunt_results=hunt_results,
            primary_alert_id=primary_alert_id,
            incident_marked=incident_marked,
            alert_escalated=alert_escalated,
            comment_posted=comment_posted,
            audit_comment=audit_comment,
            dry_run=dry_run,
            investigation=inv,
            provenance=provenance,
        )
