"""SOAR Playbook Inventory, Resilience Scoring & Decay Audit Workflow.

Performs deep static topology and runtime telemetry analysis across Google SecOps
SOAR playbooks and modular nested blocks:
1. Ingestion: Fetches menu cards, categories, and full step execution DAGs.
2. Static Resilience: Evaluates 15 deterministic scoring rules (100-point baseline).
3. Runtime Telemetry: Pulls 30-day execution metrics from Chronicle dashboard queries.
4. Visualization & GenAI: Generates Mermaid.js DAG flowchart and Gemini 4-part architectural narrative.
5. Persistence: Stores audit report in Firestore collection `soar_playbooks` with 1MB limit safeguards.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, NamedTuple, Optional, Tuple, Union

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class PlaybookRuleFinding:
    """Represents a single resilience scoring finding or deduction."""
    rule_id: str
    category: str
    title: str
    description: str
    deduction: int
    severity: str
    remediation: str
    affected_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


@dataclass
class PlaybookTelemetry:
    """30-Day execution telemetry metrics from Chronicle dashboard queries."""
    total_runs: int = 0
    failed_runs: int = 0
    completed_runs: int = 0
    failure_rate_pct: float = 0.0
    avg_duration_seconds: float = 0.0
    lookback_days: int = 30
    statuses: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookDecayReport:
    """Complete comprehensive audit report for a single SOAR playbook."""
    workflow_identifier: str
    numeric_id: Optional[int]
    name: str
    category: str
    is_enabled: bool
    is_debug_mode: bool
    priority: int
    resilience_score: int
    resilience_grade: str
    findings: List[PlaybookRuleFinding]
    telemetry: PlaybookTelemetry
    mermaid_dag: str
    executive_brief: Optional[str] = None
    created_at_iso: Optional[str] = None
    modified_at_iso: Optional[str] = None
    step_count: int = 0
    relation_count: int = 0
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        d["telemetry"] = self.telemetry.to_dict()
        return d


# ---------------------------------------------------------------------------
# 100-Point Resilience Scoring Engine
# ---------------------------------------------------------------------------

class PlaybookEvaluationResult:
    """Evaluation result supporting both tuple unpacking and dict/attribute access."""
    __slots__ = ("resilience_score", "resilience_grade", "findings")

    def __init__(self, resilience_score: int, resilience_grade: str, findings: List[PlaybookRuleFinding]):
        self.resilience_score = resilience_score
        self.resilience_grade = resilience_grade
        self.findings = findings

    def __iter__(self):
        yield self.resilience_score
        yield self.resilience_grade
        yield self.findings

    def __len__(self) -> int:
        return 3

    def __getitem__(self, item: Any) -> Any:
        if isinstance(item, int):
            return (self.resilience_score, self.resilience_grade, self.findings)[item]
        if item == "score":
            return self.resilience_score
        return getattr(self, item)

    def __repr__(self) -> str:
        return f"PlaybookEvaluationResult(score={self.resilience_score}, grade={self.resilience_grade!r}, findings={len(self.findings)})"


class PlaybookScoringEngine:
    """Evaluates 100-point resilience baseline across static DAG and execution telemetry."""

    @classmethod
    def evaluate(
        cls,
        playbook_raw: Dict[str, Any],
        telemetry: Optional[Union[PlaybookTelemetry, Dict[str, Any]]] = None,
    ) -> PlaybookEvaluationResult:
        """Evaluates all 15 resilience rules and computes score and grade."""
        findings: List[PlaybookRuleFinding] = []
        score = 100

        if telemetry is None:
            telemetry = PlaybookTelemetry()
        elif isinstance(telemetry, dict):
            telemetry = PlaybookTelemetry(
                total_runs=int(telemetry.get("total_runs", 0)),
                completed_runs=int(telemetry.get("completed_runs", 0)),
                failed_runs=int(telemetry.get("failed_runs", 0)),
                failure_rate_pct=float(telemetry.get("failure_rate_pct", 0.0)),
                avg_duration_seconds=float(telemetry.get("avg_duration_seconds", 0.0)),
                lookback_days=int(telemetry.get("lookback_days", 30)),
                statuses=telemetry.get("statuses", {}),
            )

        is_enabled = bool(playbook_raw.get("isEnabled", False))
        is_debug = bool(playbook_raw.get("isDebugMode", False))
        priority = int(playbook_raw.get("priority", 2))
        environments = playbook_raw.get("environments", []) or []
        steps = playbook_raw.get("steps", []) or []
        relations = playbook_raw.get("stepsRelations", []) or playbook_raw.get("relations", []) or []
        trigger = playbook_raw.get("trigger", {}) or {}

        # Precompute relation maps
        faulted_sources = set()
        all_targets = set()
        for rel in relations:
            if isinstance(rel, dict):
                from_step = rel.get("fromStep") or rel.get("fromStepIdentifier")
                to_step = rel.get("toStep") or rel.get("toStepIdentifier")
                status = str(rel.get("destinationActionStatus") or rel.get("condition", "")).upper()
                if to_step:
                    all_targets.add(to_step)
                if status == "FAULTED" and from_step:
                    faulted_sources.add(from_step)

        # -------------------------------------------------------------------
        # Rule HYG-01: Production Hygiene (-15 pts)
        # -------------------------------------------------------------------
        if is_enabled and is_debug:
            deduction = 15
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="HYG-01",
                category="Production Hygiene",
                title="Active Playbook Running with Debug Mode Enabled",
                description="Playbook is enabled in production while debugMode is active, risking unwanted test traces and payload leaks.",
                deduction=deduction,
                severity="CRITICAL",
                remediation="Disable debug mode on production playbooks before enabling automatic trigger execution.",
            ))

        # -------------------------------------------------------------------
        # Step-Level Static Inspections (ERR-01, ERR-02, ERR-03, ERR-04, HITL-01, HITL-OBS)
        # -------------------------------------------------------------------
        missing_retries_count = 0
        missing_retries_steps = []
        enrichment_hard_stops = []
        silent_containment_fails = []
        spof_critical_steps = []
        sla_bottleneck_steps = []
        hitl_steps = []

        enrich_keywords = ("enrich", "lookup", "virustotal", "whois", "reputation", "dns", "ipinfo")
        contain_keywords = ("isolate", "block", "disable user", "quarantine", "revoke", "reset password", "firewall", "kill")

        for step in steps:
            if not isinstance(step, dict):
                continue
            step_id = step.get("identifier") or step.get("id") or "unknown"
            step_name = step.get("name") or step.get("instanceName") or ""
            step_name_lower = step_name.lower()
            step_type = str(step.get("type", "")).upper()
            action_name = str(step.get("actionName", "")).lower()
            combined_desc = f"{step_name_lower} {action_name}"

            auto_skip = bool(step.get("autoSkipOnFailure", False))

            # Inspect Retry Configuration
            retry_cfg = step.get("retryConfiguration") or step.get("RetryConfiguration") or {}
            retry_enabled = False
            if isinstance(retry_cfg, dict):
                retry_enabled = bool(retry_cfg.get("enabled") or retry_cfg.get("Enabled", False))
            if not retry_enabled and isinstance(step.get("retries"), int):
                retry_enabled = step["retries"] > 0

            is_action_step = step_type in ("ACTION", "STEP", "AUTOMATIC", "") or bool(step.get("actionProvider"))

            # ERR-01: Missing retries
            if is_action_step and not retry_enabled:
                missing_retries_count += 1
                missing_retries_steps.append(step_name or step_id)

            # ERR-02: Enrichment Hard-Stop
            is_enrichment = any(kw in combined_desc for kw in enrich_keywords)
            has_faulted_fallback = step_id in faulted_sources
            if is_enrichment and not auto_skip and not has_faulted_fallback:
                enrichment_hard_stops.append(step_name or step_id)

            # ERR-03: Silent Containment Fail
            is_containment = any(kw in combined_desc for kw in contain_keywords)
            if is_containment and auto_skip:
                silent_containment_fails.append(step_name or step_id)

            # ERR-04: Single Point of Failure (Action step with no retries, no skip, no FAULTED path)
            if is_action_step and not retry_enabled and not auto_skip and not has_faulted_fallback:
                spof_critical_steps.append(step_name or step_id)

            # HITL-01 / HITL-OBS
            is_hitl = (
                step_type in ("MANUAL", "APPROVAL", "QUESTION")
                or "approval" in combined_desc
                or "question" in combined_desc
                or bool(step.get("isManual"))
                or bool(step.get("hasApprovalLink"))
            )
            if is_hitl:
                hitl_steps.append(step_name or step_id)
                # Check for timeout
                has_timeout = bool(
                    step.get("pendingActionTimeout")
                    or step.get("PendingActionTimeout")
                    or step.get("timeoutInMinutes")
                )
                if not has_timeout:
                    sla_bottleneck_steps.append(step_name or step_id)

        # ERR-01 deduction (-2 per step, max -10)
        if missing_retries_count > 0:
            deduction = min(missing_retries_count * 2, 10)
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="ERR-01",
                category="Step Resilience",
                title=f"Missing Action Retries ({missing_retries_count} steps)",
                description=f"{missing_retries_count} action step(s) execute without automated retry configurations enabled, risking premature failure on transient network blips.",
                deduction=deduction,
                severity="MEDIUM" if deduction < 6 else "HIGH",
                remediation="Enable retryConfiguration with exponential backoff on all network connector steps.",
                affected_steps=missing_retries_steps[:5],
            ))

        # ERR-02 deduction (-5)
        if enrichment_hard_stops:
            deduction = 5
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="ERR-02",
                category="Resilience",
                title="Enrichment Connector Hard-Stop Risk",
                description="Enrichment steps (VirusTotal, IP/Domain lookup) will halt the entire workflow on third-party API outage without an error boundary or auto-skip.",
                deduction=deduction,
                severity="HIGH",
                remediation="Configure autoSkipOnFailure=True or attach a FAULTED destination edge to provide graceful enrichment fallback.",
                affected_steps=enrichment_hard_stops[:5],
            ))

        # ERR-03 deduction (-3)
        if silent_containment_fails:
            deduction = 3
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="ERR-03",
                category="Containment Integrity",
                title="Silent Containment Failure Risk",
                description="Critical containment steps (isolate, block, quarantine) have autoSkipOnFailure=True without downstream verification, allowing threats to persist unnoticed.",
                deduction=deduction,
                severity="HIGH",
                remediation="Disable autoSkipOnFailure on containment actions and implement an explicit FAULTED incident escalation step.",
                affected_steps=silent_containment_fails[:5],
            ))

        # ERR-04 deduction (-8)
        if spof_critical_steps:
            deduction = 8
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="ERR-04",
                category="Resilience",
                title=f"Single Point of Failure ({len(spof_critical_steps)} steps)",
                description="Critical action step has zero retries, no auto-skip, and no FAULTED relation path. Any API error will terminate the playbook run.",
                deduction=deduction,
                severity="HIGH",
                remediation="Add a FAULTED branch relation or enable retry policy.",
                affected_steps=spof_critical_steps[:5],
            ))

        # HITL-01 deduction (-5)
        if sla_bottleneck_steps:
            deduction = 5
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="HITL-01",
                category="SLA Bottleneck",
                title="Interactive Human-in-the-Loop Step Lacks Timeout",
                description="Analyst approval or multi-choice prompt lacks a configured pendingActionTimeout, allowing investigations to stall indefinitely in queue.",
                deduction=deduction,
                severity="MEDIUM",
                remediation="Configure an SLA timeout (e.g. 15-30 minutes) on manual approval steps to auto-escalate or bypass.",
                affected_steps=sla_bottleneck_steps[:5],
            ))

        # HITL-OBS (+0)
        if hitl_steps:
            findings.append(PlaybookRuleFinding(
                rule_id="HITL-OBS",
                category="Governance",
                title="Human-in-the-Loop Safeguard Present",
                description=f"Playbook incorporates {len(hitl_steps)} human analyst interaction step(s) providing governance review before consequential actions.",
                deduction=0,
                severity="INFO",
                remediation="Ensure analyst decision queues have active notification integrations (Slack/Email/Chat).",
                affected_steps=hitl_steps[:5],
            ))

        # -------------------------------------------------------------------
        # Priority & Trigger Scope (PRIO-01, PRIO-02, PRIO-03)
        # -------------------------------------------------------------------
        trigger_conditions = trigger.get("conditions", []) if isinstance(trigger, dict) else []
        is_broad_trigger = len(trigger_conditions) <= 1

        if priority == 3 and is_broad_trigger:
            deduction = 5
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="PRIO-01",
                category="Execution Priority",
                title="Shadowing Risk: Low Priority with Broad Trigger",
                description="Configured with priority 3 (lowest) and broad or empty trigger conditions, causing higher-priority workflows to shadow or preempt execution.",
                deduction=deduction,
                severity="LOW",
                remediation="Increase priority or narrow trigger conditions to specific alert types or rules.",
            ))

        is_global_env = ("*" in environments) or (len(environments) == 0)
        if priority == 1 and is_global_env and is_broad_trigger:
            deduction = 5
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="PRIO-02",
                category="Execution Scope",
                title="Global Interception Risk: Priority 1 with Wildcard Environment",
                description="Playbook is bound to environment '*' at priority 1 with broad trigger conditions, intercepting cases across all tenants and SOC environments.",
                deduction=deduction,
                severity="HIGH",
                remediation="Scope playbook execution to designated environments or refine trigger filters.",
            ))

        # PRIO-03: Master Orchestrator pattern
        has_nested = any(
            str(s.get("type", "")).upper() in ("BLOCK", "NESTED", "NESTEDACTION")
            or "sub-playbook" in (s.get("name") or "").lower()
            for s in steps
        )
        if priority == 1 and has_nested:
            findings.append(PlaybookRuleFinding(
                rule_id="PRIO-03",
                category="Best Practice",
                title="Master Orchestrator Architectural Pattern",
                description="Playbook operates at priority 1 and delegates specialized containment or investigation tasks to modular nested sub-playbooks.",
                deduction=0,
                severity="INFO",
                remediation="Maintain modular sub-playbooks with discrete version control.",
            ))

        # -------------------------------------------------------------------
        # Lifecycle & Maintenance Decay (MAINT-01, MAINT-02)
        # -------------------------------------------------------------------
        now_ts = datetime.now(timezone.utc).timestamp()

        def _to_ms(val: Any) -> int:
            if isinstance(val, (int, float)):
                return int(val)
            if isinstance(val, str) and val:
                try:
                    dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                    return int(dt.timestamp() * 1000)
                except Exception:
                    pass
            return 0

        created_ms = _to_ms(playbook_raw.get("creationTimeUnixTimeInMs") or playbook_raw.get("creationTime") or playbook_raw.get("created_at"))
        modified_ms = _to_ms(playbook_raw.get("modificationTimeUnixTimeInMs") or playbook_raw.get("modificationTime") or playbook_raw.get("updated_at")) or created_ms

        created_days_ago = (now_ts - (created_ms / 1000.0)) / 86400.0 if created_ms > 0 else 0
        unmodified_days = (now_ts - (modified_ms / 1000.0)) / 86400.0 if modified_ms > 0 else 0

        if is_enabled and created_days_ago > 365:
            if unmodified_days > 365:
                ded = 10
            elif unmodified_days > 180:
                ded = 6
            elif unmodified_days > 90:
                ded = 3
            else:
                ded = 0
            if ded > 0:
                score -= ded
                findings.append(PlaybookRuleFinding(
                    rule_id="MAINT-01",
                    category="Lifecycle Decay",
                    title=f"Stale Active Playbook (Unmodified for {int(unmodified_days)}d)",
                    description=f"Playbook was created {int(created_days_ago)} days ago and has not been tuned or reviewed in {int(unmodified_days)} days.",
                    deduction=ded,
                    severity="MEDIUM",
                    remediation="Conduct periodic review to verify integrated connector actions, authentication, and logic validity.",
                ))

        if created_days_ago > 90 and abs(modified_ms - created_ms) < 1000:
            deduction = 3
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="MAINT-02",
                category="Tuning Governance",
                title="Un-Tuned Playbook Never Modified Post-Creation",
                description=f"Playbook was deployed {int(created_days_ago)} days ago and has never been updated or tuned since initial creation.",
                deduction=deduction,
                severity="LOW",
                remediation="Audit initial parameters and adjust thresholds based on actual production alert volume.",
            ))

        # -------------------------------------------------------------------
        # Telemetry-Driven Deductions (EXEC-01, EXEC-02, EXEC-03)
        # -------------------------------------------------------------------
        if is_enabled and telemetry.total_runs == 0 and telemetry.lookback_days >= 30:
            deduction = 5
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="EXEC-01",
                category="Runtime Telemetry",
                title="Silent Playbook: 0 Executions Over 30 Days",
                description="Playbook is enabled in production but registered zero execution runs in the last 30 days. Triggers may be obsolete or disconnected.",
                deduction=deduction,
                severity="MEDIUM",
                remediation="Audit trigger conditions or disable playbook to prevent cluttering automation catalog.",
            ))

        if telemetry.total_runs >= 5 and telemetry.failure_rate_pct > 20.0:
            deduction = 10
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="EXEC-02",
                category="Runtime Telemetry",
                title=f"High Failure Rate ({telemetry.failure_rate_pct:.1f}% over 30d)",
                description=f"Playbook failed in {telemetry.failed_runs} of {telemetry.total_runs} runs ({telemetry.failure_rate_pct:.1f}%), exceeding the 20% reliability threshold.",
                deduction=deduction,
                severity="CRITICAL",
                remediation="Inspect Chronicle faulted action logs and verify API credentials for failing integrations.",
            ))

        if telemetry.total_runs > 1000:
            deduction = 3
            score -= deduction
            findings.append(PlaybookRuleFinding(
                rule_id="EXEC-03",
                category="Runtime Telemetry",
                title=f"High Execution Frequency ({telemetry.total_runs} runs/30d)",
                description=f"Playbook executed {telemetry.total_runs} times in 30 days, creating potential connector rate-limiting and quota exhaustion risks.",
                deduction=deduction,
                severity="LOW",
                remediation="Review upstream alert clustering or increase trigger specificity to avoid redundant executions.",
            ))

        # Clamp score between 0 and 100
        score = max(0, min(100, score))

        # Determine letter grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return PlaybookEvaluationResult(score, grade, findings)


# ---------------------------------------------------------------------------
# Zero-Dependency Mermaid.js DAG Generator
# ---------------------------------------------------------------------------

class PlaybookMermaidGenerator:
    """Generates clean, interactive Mermaid.js flowchart DAGs for SOAR playbooks."""

    @classmethod
    def generate(cls, playbook_raw: Dict[str, Any]) -> str:
        """Constructs Mermaid flowchart with specialized node shapes and labeled edges."""
        steps = playbook_raw.get("steps", []) or []
        relations = playbook_raw.get("stepsRelations", []) or playbook_raw.get("relations", []) or []

        lines = [
            "flowchart TD",
            "    classDef trigger fill:#4285f4,stroke:#1a73e8,stroke-width:2px,color:#fff;",
            "    classDef action fill:#1e293b,stroke:#475569,stroke-width:1.5px,color:#f8fafc;",
            "    classDef condition fill:#d97706,stroke:#b45309,stroke-width:1.5px,color:#fff;",
            "    classDef block fill:#7c3aed,stroke:#6d28d9,stroke-width:1.5px,color:#fff;",
            "    classDef hitl fill:#059669,stroke:#047857,stroke-width:1.5px,color:#fff;",
        ]

        # Node ID mapping (sanitizing UUIDs into clean alphanumeric tokens)
        node_ids = {}
        for idx, step in enumerate(steps):
            raw_id = step.get("identifier") or step.get("id") or f"step_{idx}"
            clean_id = f"step_{re.sub(r'[^a-zA-Z0-9_]', '_', str(raw_id))[:16]}"
            node_ids[raw_id] = clean_id

        # Trigger node
        lines.append("    TRIGGER([\"⚡ Trigger: Incident Ingestion Scope\"]):::trigger")

        # Destination tracking to identify root steps
        target_ids = set()
        for rel in relations:
            if isinstance(rel, dict):
                to_step = rel.get("toStep") or rel.get("toStepIdentifier")
                if to_step:
                    target_ids.add(to_step)

        # Render Nodes
        for idx, step in enumerate(steps):
            raw_id = step.get("identifier") or step.get("id") or f"step_{idx}"
            nid = node_ids.get(raw_id, f"step_{idx}")
            name = (step.get("name") or step.get("instanceName") or f"Step {idx + 1}").replace('"', "'")
            stype = str(step.get("type", "")).upper()
            name_lower = name.lower()

            if stype in ("CONDITION", "condition") or "condition" in name_lower:
                label = f"{name}"
                lines.append(f"    {nid}{{{{\"❓ {label}\"}}}}:::condition")
            elif stype in ("BLOCK", "NESTED", "NESTEDACTION") or "sub-playbook" in name_lower:
                label = f"{name}"
                lines.append(f"    {nid}[[\"📦 {label}\"]]:::block")
            elif (
                stype in ("MANUAL", "APPROVAL", "QUESTION")
                or "approval" in name_lower
                or "question" in name_lower
                or bool(step.get("isManual"))
            ):
                label = f"{name}"
                lines.append(f"    {nid}[\"👤 {label}\"]:::hitl")
            else:
                provider = step.get("actionProvider") or step.get("integration") or ""
                provider_str = f" ({provider})" if provider else ""
                label = f"{name}{provider_str}"
                lines.append(f"    {nid}[\"⚙️ {label}\"]:::action")

        # Connect Trigger to Root Steps
        for step in steps:
            raw_id = step.get("identifier") or step.get("id")
            if raw_id not in target_ids and raw_id in node_ids:
                lines.append(f"    TRIGGER --> {node_ids[raw_id]}")

        # Render Edges
        for rel in relations:
            if not isinstance(rel, dict):
                continue
            from_step = rel.get("fromStep") or rel.get("fromStepIdentifier")
            to_step = rel.get("toStep") or rel.get("toStepIdentifier")
            if from_step in node_ids and to_step in node_ids:
                from_nid = node_ids[from_step]
                to_nid = node_ids[to_step]
                status = str(rel.get("destinationActionStatus") or rel.get("condition", "")).upper()
                cond = str(rel.get("condition", "")).upper()

                if status == "FAULTED" or cond == "FAULTED":
                    lines.append(f"    {from_nid} -- \"⚠️ FAULTED\" --> {to_nid}")
                elif cond in ("1", "TRUE") or status in ("1", "TRUE", "SUCCESS"):
                    lines.append(f"    {from_nid} -- \"TRUE\" --> {to_nid}")
                elif cond in ("2", "FALSE") or status in ("2", "FALSE"):
                    lines.append(f"    {from_nid} -- \"FALSE\" --> {to_nid}")
                else:
                    lines.append(f"    {from_nid} --> {to_nid}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 30-Day Execution Telemetry Aggregator
# ---------------------------------------------------------------------------

class PlaybookTelemetryAggregator:
    """Executes native Chronicle dashboard queries to compute 30-day runtime telemetry."""

    CHRONICLE_PLAYBOOK_QUERY = (
        "events:\n"
        "playbook.display_name != \"\"\n"
        "match:\n"
        "playbook.display_name, playbook.metadata.name, playbook.status, "
        "playbook.name, playbook.case_response_platform_info.case_id, "
        "playbook.metadata.environments, playbook.start_time.seconds, "
        "playbook.end_time.seconds\n"
        "order:\n"
        "playbook.start_time.seconds"
    )

    @classmethod
    def pull_telemetry_batch(
        cls,
        engine: SecOpsEngine,
        lookback_days: int = 30,
        clear_cache: bool = True,
    ) -> Dict[str, PlaybookTelemetry]:
        """Pulls 30-day telemetry for all playbooks and returns map keyed by workflow UUID and name."""
        telemetry_map: Dict[str, PlaybookTelemetry] = {}

        try:
            res = engine.adapter.execute_dashboard_query(
                query_text=cls.CHRONICLE_PLAYBOOK_QUERY,
                time_unit="DAY",
                time_value=str(lookback_days),
                clear_cache=clear_cache,
            )
            rows = res.rows or []
        except Exception as ex:
            logger.warning("Failed to pull 30-day playbook telemetry from Chronicle: %s", ex)
            return telemetry_map

        # Aggregate raw rows per playbook
        aggregates: Dict[str, Dict[str, Any]] = {}

        for row in rows:
            wf_uuid = str(row.get("metadata.name") or "").strip()
            display_name = str(row.get("display_name") or "").strip()
            status = str(row.get("status") or "").upper()
            start_s = float(row.get("start_time.seconds") or 0)
            end_s = float(row.get("end_time.seconds") or 0)

            keys_to_index = []
            if wf_uuid:
                keys_to_index.append(wf_uuid)
            if display_name:
                keys_to_index.append(display_name)

            for k in keys_to_index:
                if k not in aggregates:
                    aggregates[k] = {
                        "total": 0,
                        "failed": 0,
                        "completed": 0,
                        "duration_sum": 0.0,
                        "duration_count": 0,
                        "statuses": {},
                    }
                agg = aggregates[k]
                agg["total"] += 1
                agg["statuses"][status] = agg["statuses"].get(status, 0) + 1

                if status in ("FAILED", "FAULTED"):
                    agg["failed"] += 1
                elif status in ("COMPLETED", "SUCCESS"):
                    agg["completed"] += 1

                if end_s >= start_s > 0:
                    agg["duration_sum"] += (end_s - start_s)
                    agg["duration_count"] += 1

        for k, agg in aggregates.items():
            tot = agg["total"]
            failed = agg["failed"]
            comp = agg["completed"]
            fail_rate = (failed / tot * 100.0) if tot > 0 else 0.0
            avg_dur = (agg["duration_sum"] / agg["duration_count"]) if agg["duration_count"] > 0 else 0.0

            telemetry_map[k] = PlaybookTelemetry(
                total_runs=tot,
                failed_runs=failed,
                completed_runs=comp,
                failure_rate_pct=round(fail_rate, 2),
                avg_duration_seconds=round(avg_dur, 1),
                lookback_days=lookback_days,
                statuses=agg["statuses"],
            )

        return telemetry_map


# ---------------------------------------------------------------------------
# GenAI Executive Brief Synthesizer
# ---------------------------------------------------------------------------

class PlaybookBriefSynthesizer:
    """Generates structured 4-part architectural executive briefs using Gemini."""

    @classmethod
    def synthesize(
        cls,
        report: PlaybookDecayReport,
        steps: List[Dict[str, Any]],
        project_id: Optional[str] = None,
    ) -> Optional[str]:
        """Synthesizes structured narrative brief via Google GenAI SDK with ADC."""
        step_summaries = []
        for s in steps[:15]:
            step_summaries.append(f"- {s.get('name') or s.get('instanceName')}: type={s.get('type')}, autoSkip={s.get('autoSkipOnFailure')}")

        findings_summary = [f"- [{f.rule_id}] {f.title} ({f.deduction} pts): {f.description}" for f in report.findings]

        prompt = (
            f"You are the Lead SecOps SOAR Automation Architect. Synthesize a concise, authoritative "
            f"4-part architectural executive brief for the following Google SecOps SOAR Playbook:\n\n"
            f"Playbook Name: {report.name}\n"
            f"Category: {report.category}\n"
            f"Active: {report.is_enabled} | Priority: {report.priority}\n"
            f"Resilience Score: {report.resilience_score}/100 (Grade: {report.resilience_grade})\n"
            f"30-Day Telemetry: {report.telemetry.total_runs} runs, {report.telemetry.failed_runs} failures "
            f"({report.telemetry.failure_rate_pct}%), avg duration {report.telemetry.avg_duration_seconds}s.\n\n"
            f"Workflow Steps ({report.step_count} total):\n" + "\n".join(step_summaries) + "\n\n"
            f"Audit Findings:\n" + ("\n".join(findings_summary) if findings_summary else "None (Clean Topology)") + "\n\n"
            f"Format the output strictly under these 4 markdown headings with actionable, technical commentary:\n"
            f"#### 🎯 1. Strategic Intent & Trigger Scope\n"
            f"#### 🔄 2. Investigation & Data Pipeline\n"
            f"#### 🔀 3. Decision Branches & Human-in-the-Loop Governance\n"
            f"#### 🏁 4. Automated Containment & Case Resolution\n"
        )

        try:
            from google import genai
            client = genai.Client(vertexai=True, project=project_id, location="global")
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            return response.text
        except Exception as ex:
            logger.debug("Vertex AI global executive brief synthesis failed, falling back to local synthesis: %s", ex)
            return cls._deterministic_brief_fallback(report)

    @classmethod
    def _deterministic_brief_fallback(cls, report: PlaybookDecayReport) -> str:
        """Deterministic architectural summary when GenAI endpoint is unreachable."""
        return (
            f"#### 🎯 1. Strategic Intent & Trigger Scope\n"
            f"Orchestrates automated security operations for `{report.name}` within category `{report.category}`. "
            f"Configured with execution priority {report.priority} and active status `{report.is_enabled}`.\n\n"
            f"#### 🔄 2. Investigation & Data Pipeline\n"
            f"Traverses {report.step_count} step(s) with {report.relation_count} execution relation(s). "
            f"Recorded {report.telemetry.total_runs} live executions over the last {report.telemetry.lookback_days} days "
            f"with an average duration of {report.telemetry.avg_duration_seconds}s.\n\n"
            f"#### 🔀 3. Decision Branches & Human-in-the-Loop Governance\n"
            f"Resilience health score evaluated at **{report.resilience_score}/100 (Grade {report.resilience_grade})** "
            f"with {len(report.findings)} identified governance or error handling finding(s).\n\n"
            f"#### 🏁 4. Automated Containment & Case Resolution\n"
            f"Operational reliability is {'healthy' if report.telemetry.failure_rate_pct <= 20 else 'degraded'} "
            f"with a failure rate of {report.telemetry.failure_rate_pct}%."
        )


# ---------------------------------------------------------------------------
# AuditPlaybookDecayWorkflow
# ---------------------------------------------------------------------------

class AuditPlaybookDecayWorkflow:
    """Orchestrates comprehensive SOAR playbook inventory and resilience decay audits."""

    def __init__(self, engine: SecOpsEngine):
        self.engine = engine

    def execute(
        self,
        workflow_identifier: Optional[str] = None,
        category: Optional[str] = None,
        lookback_days: int = 30,
        generate_brief: bool = True,
        persist: bool = True,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Executes the 5-stage SOAR playbook inventory, resilience scoring, and decay audit.

        Args:
            workflow_identifier: Optional specific playbook UUID to audit.
            category: Optional category filter (e.g. "GSA", "Demoverse", "Blocks").
            lookback_days: Chronicle telemetry evaluation window in days (default: 30).
            generate_brief: Whether to synthesize the GenAI 4-part architectural narrative.
            persist: Whether to persist reports to Evidence Fabric Firestore `soar_playbooks`.
            limit: Maximum playbooks to audit when scanning catalog (default: 20).

        Returns:
            Dictionary containing audit summary, inventory counts, and detailed reports.
        """
        # 1. Pull Telemetry Batch across tenant
        telemetry_map = PlaybookTelemetryAggregator.pull_telemetry_batch(
            engine=self.engine,
            lookback_days=lookback_days,
            clear_cache=True,
        )

        # 2. Ingest Playbook Menu Cards
        menu_cards = self.engine.adapter.get_playbook_menu_cards(
            playbook_types=["REGULAR", "NESTED"]
        )

        # Apply Filters
        filtered_cards = []
        for card in menu_cards:
            card_id = str(card.get("identifier") or card.get("id"))
            card_name = card.get("name") or ""
            card_cat = card.get("categoryName") or ""

            if workflow_identifier and workflow_identifier not in (card_id, card_name):
                continue
            if category and category.lower() not in card_cat.lower():
                continue
            filtered_cards.append(card)

        selected_cards = filtered_cards[:limit]
        reports: List[PlaybookDecayReport] = []

        from agents.core.evidence_store import get_evidence_store
        evidence_store = get_evidence_store() if persist else None

        for card in selected_cards:
            wf_id = card.get("identifier")
            if not wf_id:
                continue

            try:
                # Fetch full DAG definition
                full_info = self.engine.adapter.get_playbook_full_info(wf_id)
            except Exception as ex:
                logger.warning("Could not fetch full info for playbook %s: %s", wf_id, ex)
                continue

            # Correlate telemetry
            name = full_info.get("name") or card.get("name") or wf_id
            tel = telemetry_map.get(wf_id) or telemetry_map.get(name) or PlaybookTelemetry(lookback_days=lookback_days)

            # Evaluate Resilience Scoring Engine
            score, grade, findings = PlaybookScoringEngine.evaluate(
                playbook_raw=full_info,
                telemetry=tel,
            )

            # Generate Mermaid DAG
            mermaid_dag = PlaybookMermaidGenerator.generate(full_info)

            # Build Report
            created_ms = full_info.get("creationTimeUnixTimeInMs")
            modified_ms = full_info.get("modificationTimeUnixTimeInMs")
            try:
                created_ts = float(created_ms) / 1000.0 if created_ms is not None else None
            except (ValueError, TypeError):
                created_ts = None
            try:
                modified_ts = float(modified_ms) / 1000.0 if modified_ms is not None else None
            except (ValueError, TypeError):
                modified_ts = None

            rep = PlaybookDecayReport(
                workflow_identifier=wf_id,
                numeric_id=full_info.get("id"),
                name=name,
                category=full_info.get("categoryName") or card.get("categoryName") or "Default",
                is_enabled=bool(full_info.get("isEnabled", False)),
                is_debug_mode=bool(full_info.get("isDebugMode", False)),
                priority=int(full_info.get("priority", 2)),
                resilience_score=score,
                resilience_grade=grade,
                findings=findings,
                telemetry=tel,
                mermaid_dag=mermaid_dag,
                created_at_iso=datetime.fromtimestamp(created_ts, tz=timezone.utc).isoformat() if created_ts else None,
                modified_at_iso=datetime.fromtimestamp(modified_ts, tz=timezone.utc).isoformat() if modified_ts else None,
                step_count=len(full_info.get("steps", [])),
                relation_count=len(full_info.get("stepsRelations", [])),
            )

            # GenAI Executive Narrative Synthesis
            if generate_brief:
                rep.executive_brief = PlaybookBriefSynthesizer.synthesize(
                    report=rep,
                    steps=full_info.get("steps", []),
                    project_id=getattr(evidence_store, "project_id", None) if evidence_store else None,
                )

            # Persist to Evidence Fabric Firestore (collection soar_playbooks)
            if evidence_store:
                try:
                    evidence_store.save_playbook_analysis(wf_id, rep.to_dict())
                except Exception as ex:
                    logger.warning("Failed to persist playbook analysis for %s: %s", wf_id, ex)

            reports.append(rep)

        # Aggregate Executive Summary
        total_audited = len(reports)
        avg_score = (sum(r.resilience_score for r in reports) / total_audited) if total_audited > 0 else 100.0
        degraded_count = sum(1 for r in reports if r.resilience_score < 70 or r.telemetry.failure_rate_pct > 20.0)

        return {
            "summary": {
                "total_playbooks_catalog": len(menu_cards),
                "total_audited": total_audited,
                "average_resilience_score": round(avg_score, 1),
                "degraded_playbooks_count": degraded_count,
                "lookback_days": lookback_days,
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
            },
            "playbooks": [r.to_dict() for r in reports],
        }
