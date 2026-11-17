"""SecOps Platform Health Check Agent & Native Dashboard Sync Workflow.

Executes a multi-pillar operational health check across Google SecOps (Chronicle SIEM & SOAR):
1. Pillar 1 — SOAR Playbook Failures & Latency (`PLAYBOOK`)
2. Pillar 2 — YARA-L & Curated Detection Rule Errors (`RULE`)
3. Pillar 3 — CBN Parser Failures, Drop Anomalies & Version Drift (`PARSER`)
4. Pillar 4 — Data Feed & Collector Pipeline Health (`FEED`)
5. Pillar 5 — SOAR Scheduled Jobs & Remote Agents (`SOAR_JOB`)
6. Pillar 6 — Ingestion Timestamp Integrity & Clock Skew (`TIMESTAMP`)
7. Pillar 7 — Google Cloud Logging Operational Errors (`CLOUD_LOGGING`)

Reconciles all findings against a stateful Chronicle Data Table (`secops_platform_health_ledger`)
to track `NEW`, `RECURRING`, and `RESOLVED` issues over time, and publishes the live
telemetry + historical delta ledger onto the 'SecOps Platform Health & Operations Center'
Chronicle Native Dashboard.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from engine.domain import (
    DashboardSearchQuery,
    FeedHealthStatus,
    ParserHealthStatus,
    RuleHealthStatus,
)
from engine.workflows.dashboards import (
    AddDashboardChartWorkflow,
    CreateDashboardWorkflow,
    GetDashboardDetailWorkflow,
    SearchDashboardsWorkflow,
    UpdateDashboardChartWorkflow,
    UpdateDashboardWorkflow,
)
from engine.workflows.homepage_dashboard import (
    _build_kpi_text_visualization,
    _needs_visualization_update,
)

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine

logger = logging.getLogger(__name__)

DEFAULT_HEALTH_DATA_TABLE_ID = "secops_platform_health_ledger"
DEFAULT_HEALTH_DASHBOARD_TITLE = "SecOps Platform Health & Operations Center"

HEALTH_LEDGER_COLUMNS: List[Dict[str, Any]] = [
    {"columnIndex": 0, "originalColumn": "fingerprint_id", "columnType": "STRING"},
    {"columnIndex": 1, "originalColumn": "pillar", "columnType": "STRING"},
    {"columnIndex": 2, "originalColumn": "resource_name", "columnType": "STRING"},
    {"columnIndex": 3, "originalColumn": "issue_code", "columnType": "STRING"},
    {"columnIndex": 4, "originalColumn": "lifecycle_status", "columnType": "STRING"},
    {"columnIndex": 5, "originalColumn": "severity", "columnType": "STRING"},
    {"columnIndex": 6, "originalColumn": "first_seen_utc", "columnType": "STRING"},
    {"columnIndex": 7, "originalColumn": "last_seen_utc", "columnType": "STRING"},
    {"columnIndex": 8, "originalColumn": "occurrence_count", "columnType": "STRING"},
    {"columnIndex": 9, "originalColumn": "error_summary", "columnType": "STRING"},
    {"columnIndex": 10, "originalColumn": "remediation", "columnType": "STRING"},
]


def _sanitize_cell(val: Any, max_len: int = 380) -> str:
    """Normalizes string for Data Table storage and Markdown table safety."""
    if val is None:
        return ""
    text = re.sub(r"\s+", " ", str(val)).strip()
    text = text.replace("|", "/")
    if len(text) > max_len:
        text = text[: max_len - 3].rsplit(" ", 1)[0] + "..."
    return text


def _make_fingerprint(pillar: str, resource_id: str, issue_code: str) -> str:
    """Constructs a deterministic issue fingerprint key."""
    clean_p = re.sub(r"[^A-Za-z0-9_.-]", "_", str(pillar).strip().upper())
    clean_r = re.sub(r"[^A-Za-z0-9_.-]", "_", str(resource_id).strip())[:80]
    clean_c = re.sub(r"[^A-Za-z0-9_.-]", "_", str(issue_code).strip().upper())
    return f"{clean_p}:{clean_r}:{clean_c}"


@dataclass
class PlatformHealthIssue:
    """Normalized health issue tracked in the Data Table ledger and Native Dashboard."""

    fingerprint_id: str
    pillar: str
    resource_name: str
    issue_code: str
    lifecycle_status: str  # NEW, RECURRING, RESOLVED
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    first_seen_utc: str
    last_seen_utc: str
    occurrence_count: int
    error_summary: str
    remediation: str

    def to_row_values(self) -> List[str]:
        return [
            _sanitize_cell(self.fingerprint_id, 160),
            _sanitize_cell(self.pillar, 40),
            _sanitize_cell(self.resource_name, 120),
            _sanitize_cell(self.issue_code, 80),
            _sanitize_cell(self.lifecycle_status, 30),
            _sanitize_cell(self.severity, 30),
            _sanitize_cell(self.first_seen_utc, 40),
            _sanitize_cell(self.last_seen_utc, 40),
            str(max(1, int(self.occurrence_count))),
            _sanitize_cell(self.error_summary, 380),
            _sanitize_cell(self.remediation, 380),
        ]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PlatformHealthCheckWorkflow:
    """Executes multi-pillar platform health checks, reconciles the Data Table ledger, and updates the Native Dashboard."""

    def __init__(self, engine: SecOpsEngine):
        self.engine = engine
        self.adapter = engine.adapter
        self._search_dash_wf = SearchDashboardsWorkflow(self.adapter)
        self._get_dash_wf = GetDashboardDetailWorkflow(self.adapter)
        self._create_dash_wf = CreateDashboardWorkflow(self.adapter)
        self._update_dash_wf = UpdateDashboardWorkflow(self.adapter)
        self._add_chart_wf = AddDashboardChartWorkflow(self.adapter)
        self._update_chart_wf = UpdateDashboardChartWorkflow(self.adapter)

    def execute(
        self,
        lookback_days: int = 7,
        sync_data_table: bool = True,
        data_table_id: str = DEFAULT_HEALTH_DATA_TABLE_ID,
        sync_dashboard: bool = True,
        dashboard_title: str = DEFAULT_HEALTH_DASHBOARD_TITLE,
        dashboard_id: Optional[str] = None,
        include_additional_pillars: bool = True,
        ai_executive_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Runs the complete platform health check, Data Table state reconciliation, and Native Dashboard sync."""
        started_dt = datetime.now(timezone.utc)
        now_iso = started_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        now_display = started_dt.strftime("%Y-%m-%d %H:%M UTC")

        audited_pillars: Set[str] = set()
        pillar_summaries: Dict[str, Dict[str, Any]] = {}
        live_issues: List[PlatformHealthIssue] = []
        collection_errors: List[str] = []

        # ------------------------------------------------------------------
        # Pillar 1: SOAR Playbook Failures & Latency
        # ------------------------------------------------------------------
        try:
            pb_rep = self.engine.audit_soar_playbook_health(days=lookback_days, scan_deep=True)
            audited_pillars.add("PLAYBOOK")
            pb_sum = pb_rep.get("summary", {})
            pillar_summaries["PLAYBOOK"] = pb_sum
            for pf in pb_rep.get("prioritized_findings", []):
                p_name = str(pf.get("playbook_name") or "Unknown Playbook")
                i_code = str(pf.get("issue_code") or "PLAYBOOK_FAULT")
                fp = _make_fingerprint("PLAYBOOK", p_name, i_code)
                live_issues.append(
                    PlatformHealthIssue(
                        fingerprint_id=fp,
                        pillar="PLAYBOOK",
                        resource_name=p_name,
                        issue_code=i_code,
                        lifecycle_status="NEW",
                        severity=str(pf.get("severity") or "HIGH"),
                        first_seen_utc=now_iso,
                        last_seen_utc=now_iso,
                        occurrence_count=1,
                        error_summary=str(pf.get("summary") or ""),
                        remediation=str(pf.get("remediation") or ""),
                    )
                )
        except Exception as exc:
            logger.warning("Pillar 1 (Playbook Health) check failed: %s", exc)
            collection_errors.append(f"PLAYBOOK: {exc}")

        # ------------------------------------------------------------------
        # Pillar 2: YARA-L & Curated Detection Rule Errors
        # ------------------------------------------------------------------
        try:
            rule_rep = self.engine.audit_rule_health(
                include_curated=True,
                latency_threshold_min=30.0,
                error_lookback_days=lookback_days,
            )
            audited_pillars.add("RULE")
            pillar_summaries["RULE"] = {
                "total_rules_audited": rule_rep.total_rules_audited,
                "custom_rules_audited": rule_rep.custom_rules_audited,
                "curated_rulesets_audited": rule_rep.curated_rulesets_audited,
                "healthy_count": rule_rep.healthy_count,
                "failing_count": rule_rep.failing_count,
                "latency_alert_count": rule_rep.latency_alert_count,
                "decay_count": rule_rep.decay_count,
                "misconfigured_count": rule_rep.misconfigured_count,
                "total_detections_24h": rule_rep.total_detections_24h,
                "rules_firing_24h": rule_rep.rules_firing_24h,
                "execution_errors_considered": rule_rep.execution_errors_considered,
            }

            # Track individual EXECUTION_ERROR, COMPILATION_ERROR, and HIGH_LATENCY rules
            for rf in rule_rep.findings:
                st_val = rf.status.value if hasattr(rf.status, "value") else str(rf.status)
                if st_val in ("EXECUTION_ERROR", "COMPILATION_ERROR", "HIGH_LATENCY"):
                    sev = "CRITICAL" if st_val in ("EXECUTION_ERROR", "COMPILATION_ERROR") else "HIGH"
                    r_label = f"{rf.display_name} ({rf.rule_id})" if rf.display_name and rf.display_name != rf.rule_id else rf.rule_id
                    err_msg = rf.last_error_message or rf.details or f"Rule status: {st_val}"
                    rem_msg = "; ".join(rf.remediation_steps) if rf.remediation_steps else "Inspect YARA-L rule logic and execution error telemetry."
                    fp = _make_fingerprint("RULE", rf.rule_id, st_val)
                    live_issues.append(
                        PlatformHealthIssue(
                            fingerprint_id=fp,
                            pillar="RULE",
                            resource_name=r_label,
                            issue_code=st_val,
                            lifecycle_status="NEW",
                            severity=sev,
                            first_seen_utc=now_iso,
                            last_seen_utc=now_iso,
                            occurrence_count=1,
                            error_summary=f"[{rf.rule_owner}] {err_msg}",
                            remediation=rem_msg,
                        )
                    )

            # Also pull raw ruleExecutionErrors in case Curated Rule errors are not in custom rule list
            raw_errors_res = self.engine.list_rule_errors(page_size=100)
            seen_rule_fps = {i.fingerprint_id for i in live_issues}
            grouped_raw_errs: Dict[str, List[Any]] = {}
            for err in raw_errors_res.errors:
                r_ref = (err.rule_resource_name or err.curated_rule or "unknown_rule").split("/")[-1]
                grouped_raw_errs.setdefault(r_ref, []).append(err)

            for r_ref, err_list in grouped_raw_errs.items():
                fp = _make_fingerprint("RULE", r_ref, "EXECUTION_ERROR")
                if fp in seen_rule_fps:
                    continue
                latest_err = err_list[0]
                is_curated = bool(latest_err.curated_rule) or r_ref.startswith("ur_")
                owner_tag = "CURATED_RULE" if is_curated else "CUSTOM_RULE"
                live_issues.append(
                    PlatformHealthIssue(
                        fingerprint_id=fp,
                        pillar="RULE",
                        resource_name=r_ref,
                        issue_code="EXECUTION_ERROR",
                        lifecycle_status="NEW",
                        severity="HIGH" if is_curated else "CRITICAL",
                        first_seen_utc=now_iso,
                        last_seen_utc=now_iso,
                        occurrence_count=1,
                        error_summary=(
                            f"[{owner_tag}] {len(err_list)} execution error(s); latest code={latest_err.error_code}: "
                            f"{latest_err.error_message or 'Rule evaluation error'} "
                            f"(window end: {getattr(latest_err, 'end_time', None) or getattr(latest_err, 'window_end_time', None) or 'N/A'})"
                        ),
                        remediation="Inspect rule execution window complexity, joins, or open a Google SecOps support case for curated rule ID.",
                    )
                )
                seen_rule_fps.add(fp)

            # Aggregate misconfigured alerting rules into a single governance ledger item if > 0
            if rule_rep.misconfigured_count > 0:
                sample_mis = [
                    f.display_name or f.rule_id
                    for f in rule_rep.findings
                    if (f.status.value if hasattr(f.status, "value") else str(f.status)) == "MISCONFIGURED_ALERTING"
                ][:5]
                fp = _make_fingerprint("RULE", "TENANT_RULESET", "MISCONFIGURED_ALERTING")
                live_issues.append(
                    PlatformHealthIssue(
                        fingerprint_id=fp,
                        pillar="RULE",
                        resource_name=f"{rule_rep.misconfigured_count} Rules (Enabled / Alerting Disabled)",
                        issue_code="MISCONFIGURED_ALERTING",
                        lifecycle_status="NEW",
                        severity="MEDIUM",
                        first_seen_utc=now_iso,
                        last_seen_utc=now_iso,
                        occurrence_count=1,
                        error_summary=(
                            f"{rule_rep.misconfigured_count} high/critical detection rules are enabled and firing "
                            f"with alerting disabled (samples: {', '.join(sample_mis)})."
                        ),
                        remediation="Review silent high-severity rules and enable alerting or convert them to intentional composite signal rules.",
                    )
                )
        except Exception as exc:
            logger.warning("Pillar 2 (Rule Health) check failed: %s", exc)
            collection_errors.append(f"RULE: {exc}")

        # ------------------------------------------------------------------
        # Pillar 3: CBN Parser Failures & Drop Anomalies
        # ------------------------------------------------------------------
        try:
            parser_rep = self.engine.audit_parser_health(lookback_days=lookback_days)
            audited_pillars.add("PARSER")
            pillar_summaries["PARSER"] = {
                "total_parsers_audited": parser_rep.total_parsers_audited,
                "healthy_count": parser_rep.healthy_count,
                "failed_count": parser_rep.failed_count,
                "irregular_count": parser_rep.irregular_count,
                "version_drift_count": parser_rep.version_drift_count,
                "extension_conflict_count": parser_rep.extension_conflict_count,
                "quota_rejections_detected": parser_rep.quota_rejections_detected,
                "health_hub_available": parser_rep.health_hub_available,
                "deep_dive_available": parser_rep.deep_dive_available,
            }
            for pf in parser_rep.findings:
                st_val = pf.status.value if hasattr(pf.status, "value") else str(pf.status)
                if st_val in ("HEALTHY", "UNKNOWN"):
                    continue
                sev = "CRITICAL" if st_val in ("FAILED", "INACTIVE_NO_PARSER") else ("HIGH" if st_val in ("IRREGULAR", "EXTENSION_CONFLICT") else "MEDIUM")
                fp = _make_fingerprint("PARSER", pf.log_type, st_val)
                rem_msg = "; ".join(pf.remediation_steps) if pf.remediation_steps else f"Run diagnose_unparsed_logs(log_type='{pf.log_type}') to inspect raw log drop failures."
                drop_info = f" (drop_code={pf.drop_reason_code})" if pf.drop_reason_code else ""
                live_issues.append(
                    PlatformHealthIssue(
                        fingerprint_id=fp,
                        pillar="PARSER",
                        resource_name=pf.log_type,
                        issue_code=f"PARSER_{st_val}",
                        lifecycle_status="NEW",
                        severity=sev,
                        first_seen_utc=now_iso,
                        last_seen_utc=now_iso,
                        occurrence_count=1,
                        error_summary=f"Log type '{pf.log_type}' parser status={st_val}{drop_info}: {pf.anomaly_description or 'Normalization errors detected.'}",
                        remediation=rem_msg,
                    )
                )
        except Exception as exc:
            logger.warning("Pillar 3 (Parser Health) check failed: %s", exc)
            collection_errors.append(f"PARSER: {exc}")

        # ------------------------------------------------------------------
        # Additional Pillars (4: Feeds, 5: SOAR Jobs & Agents, 6: Timestamp Skew, 7: Cloud Logging)
        # ------------------------------------------------------------------
        if include_additional_pillars:
            # Pillar 4: Data Feed & Collector Pipeline Health
            try:
                feed_rep = self.engine.audit_feed_health(lookback_days=lookback_days)
                audited_pillars.add("FEED")
                pillar_summaries["FEED"] = {
                    "total_feeds_audited": feed_rep.total_feeds_audited,
                    "healthy_count": feed_rep.healthy_count,
                    "failed_count": feed_rep.failed_count,
                    "irregular_count": feed_rep.irregular_count,
                    "high_latency_count": feed_rep.high_latency_count,
                    "inactive_count": feed_rep.inactive_count,
                }
                for ff in feed_rep.findings:
                    st_val = ff.status.value if hasattr(ff.status, "value") else str(ff.status)
                    if st_val in ("FAILED", "SILENT_PUSH_STOP", "IRREGULAR", "HIGH_LATENCY"):
                        sev = "CRITICAL" if st_val in ("FAILED", "SILENT_PUSH_STOP") else "HIGH"
                        f_label = f"{ff.feed_name} ({ff.log_type})" if ff.feed_name else f"{ff.feed_id} ({ff.log_type})"
                        fp = _make_fingerprint("FEED", ff.feed_id or ff.feed_name, st_val)
                        rem_msg = "; ".join(ff.remediation_steps) if ff.remediation_steps else "Verify feed API credentials, IAM permissions, and collector connectivity."
                        live_issues.append(
                            PlatformHealthIssue(
                                fingerprint_id=fp,
                                pillar="FEED",
                                resource_name=f_label,
                                issue_code=f"FEED_{st_val}",
                                lifecycle_status="NEW",
                                severity=sev,
                                first_seen_utc=now_iso,
                                last_seen_utc=now_iso,
                                occurrence_count=1,
                                error_summary=ff.anomaly_description or f"Feed '{f_label}' reported status {st_val} (state={ff.state}).",
                                remediation=rem_msg,
                            )
                        )
            except Exception as exc:
                logger.warning("Pillar 4 (Feed Health) check failed: %s", exc)
                collection_errors.append(f"FEED: {exc}")

            # Pillar 5: SOAR Scheduled Jobs & Remote Agents
            try:
                job_instances = self.engine.list_job_instances()
                remote_agents = self.engine.list_remote_agents()
                audited_pillars.add("SOAR_JOB")

                failed_jobs_count = 0
                for ji in job_instances:
                    last_st = str(ji.last_run_status or "").upper()
                    inst_st = str(ji.status or "").upper()
                    if last_st in ("FAILED", "ERROR", "FAULTED") or inst_st in ("FAILED", "ERROR"):
                        failed_jobs_count += 1
                        j_label = f"{ji.display_name or ji.job_name} ({ji.integration})"
                        fp = _make_fingerprint("SOAR_JOB", ji.id or j_label, "JOB_RUN_FAILED")
                        live_issues.append(
                            PlatformHealthIssue(
                                fingerprint_id=fp,
                                pillar="SOAR_JOB",
                                resource_name=j_label,
                                issue_code="JOB_RUN_FAILED",
                                lifecycle_status="NEW",
                                severity="HIGH",
                                first_seen_utc=now_iso,
                                last_seen_utc=now_iso,
                                occurrence_count=1,
                                error_summary=f"SOAR Scheduled Job '{j_label}' last_run_status={last_st} at {ji.last_run_time or 'N/A'}.",
                                remediation=f"Inspect job execution logs via get_job_instance_logs(job_instance_id='{ji.id}').",
                            )
                        )

                inactive_agents = [a for a in remote_agents if not a.is_active]
                for ra in inactive_agents:
                    fp = _make_fingerprint("SOAR_JOB", ra.identifier or ra.display_name, "REMOTE_AGENT_INACTIVE")
                    live_issues.append(
                        PlatformHealthIssue(
                            fingerprint_id=fp,
                            pillar="SOAR_JOB",
                            resource_name=ra.display_name or ra.identifier,
                            issue_code="REMOTE_AGENT_INACTIVE",
                            lifecycle_status="NEW",
                            severity="HIGH",
                            first_seen_utc=now_iso,
                            last_seen_utc=now_iso,
                            occurrence_count=1,
                            error_summary=f"SOAR Remote Agent '{ra.display_name}' is in state '{ra.agent_state}' (environments: {', '.join(ra.environments) or 'Default'}).",
                            remediation="Verify Remote Agent container/VM service health and network connectivity to SecOps SOAR.",
                        )
                    )

                pillar_summaries["SOAR_JOB"] = {
                    "total_job_instances": len(job_instances),
                    "failed_job_instances": failed_jobs_count,
                    "total_remote_agents": len(remote_agents),
                    "inactive_remote_agents": len(inactive_agents),
                }
            except Exception as exc:
                logger.warning("Pillar 5 (SOAR Jobs & Remote Agents) check failed: %s", exc)
                collection_errors.append(f"SOAR_JOB: {exc}")

            # Pillar 6: Ingestion Timestamp Integrity / Clock Skew
            try:
                ts_rep = self.engine.audit_timestamp_integrity(days=lookback_days, persist=False)
                audited_pillars.add("TIMESTAMP")
                log_type_rows = getattr(ts_rep, "log_types", None) or []
                anomalous_rows = [m for m in log_type_rows if getattr(m, "is_anomaly", False)]
                pillar_summaries["TIMESTAMP"] = {
                    "total_log_types_audited": ts_rep.total_log_types_audited,
                    "healthy_count": ts_rep.healthy_count,
                    "anomalous_log_types_count": len(anomalous_rows),
                }
                for m in anomalous_rows[:8]:
                    issue_code = "CLOCK_SKEW_FUTURE" if m.cnt_lt_0_hours > 0 and m.average_difference_minutes < 0 else "INGESTION_LAG_HIGH"
                    sev = "HIGH" if abs(m.average_difference_minutes) >= 120.0 else "MEDIUM"
                    fp = _make_fingerprint("TIMESTAMP", m.log_type, issue_code)
                    live_issues.append(
                        PlatformHealthIssue(
                            fingerprint_id=fp,
                            pillar="TIMESTAMP",
                            resource_name=m.log_type,
                            issue_code=issue_code,
                            lifecycle_status="NEW",
                            severity=sev,
                            first_seen_utc=now_iso,
                            last_seen_utc=now_iso,
                            occurrence_count=1,
                            error_summary=(
                                f"Log type '{m.log_type}' has avg ingestion delta {m.average_difference_minutes} min "
                                f"across {m.total} events (>2h delayed: {m.cnt_gt_2_hours}, future-dated <0h: {m.cnt_lt_0_hours})."
                            ),
                            remediation="Verify NTP synchronization and timezone config on source collectors/forwarders, or widen YARA-L rule lookback windows.",
                        )
                    )
            except Exception as exc:
                logger.warning("Pillar 6 (Timestamp Integrity) check failed: %s", exc)
                collection_errors.append(f"TIMESTAMP: {exc}")

            # Pillar 7: Google Cloud Logging Operational Errors
            try:
                gcp_err_rep = self.engine.query_secops_errors(hours=min(lookback_days * 24, 168), page_size=25)
                audited_pillars.add("CLOUD_LOGGING")
                pillar_summaries["CLOUD_LOGGING"] = {
                    "error_entries_found": len(gcp_err_rep.entries),
                    "lookback_hours": min(lookback_days * 24, 168),
                }
                if gcp_err_rep.entries:
                    top_entry = gcp_err_rep.entries[0]
                    top_msg = (
                        getattr(top_entry, "text_payload", "")
                        or (top_entry.json_payload.get("message") if isinstance(top_entry.json_payload, dict) else "")
                        or (top_entry.proto_payload.get("status", {}).get("message") if isinstance(top_entry.proto_payload, dict) else "")
                        or str(top_entry.json_payload or top_entry.proto_payload or "Cloud Logging error entry")
                    )
                    fp = _make_fingerprint("CLOUD_LOGGING", "chronicle.googleapis.com", "GCP_LOGGING_ERRORS")
                    live_issues.append(
                        PlatformHealthIssue(
                            fingerprint_id=fp,
                            pillar="CLOUD_LOGGING",
                            resource_name="chronicle.googleapis.com",
                            issue_code="GCP_LOGGING_ERRORS",
                            lifecycle_status="NEW",
                            severity="HIGH",
                            first_seen_utc=now_iso,
                            last_seen_utc=now_iso,
                            occurrence_count=1,
                            error_summary=(
                                f"{len(gcp_err_rep.entries)} Cloud Logging >=ERROR entries found; latest ({top_entry.timestamp}): "
                                f"{str(top_msg)[:220]}"
                            ),
                            remediation="Review Cloud Logging filter 'chronicle.googleapis.com' for forwarder, parser, or API export faults.",
                        )
                    )
            except Exception as exc:
                logger.warning("Pillar 7 (Cloud Logging) check failed: %s", exc)
                collection_errors.append(f"CLOUD_LOGGING: {exc}")

        # ------------------------------------------------------------------
        # Reconcile with Chronicle Data Table (`secops_platform_health_ledger`)
        # ------------------------------------------------------------------
        ledger_result = self._reconcile_health_ledger(
            table_id=data_table_id,
            live_issues=live_issues,
            audited_pillars=audited_pillars,
            now_iso=now_iso,
            sync_data_table=sync_data_table,
        )

        all_reconciled: List[PlatformHealthIssue] = ledger_result["reconciled_issues"]
        new_issues = [i for i in all_reconciled if i.lifecycle_status == "NEW"]
        recurring_issues = [i for i in all_reconciled if i.lifecycle_status == "RECURRING"]
        resolved_issues = [i for i in all_reconciled if i.lifecycle_status == "RESOLVED"]

        # Compute Overall Platform Health Score (0 - 100)
        health_score, health_grade = self._compute_overall_score(new_issues + recurring_issues)

        # ------------------------------------------------------------------
        # Sync Chronicle Native Dashboard (`SecOps Platform Health & Operations Center`)
        # ------------------------------------------------------------------
        dashboard_result: Optional[Dict[str, Any]] = None
        if sync_dashboard:
            try:
                dashboard_result = self.sync_dashboard(
                    dashboard_title=dashboard_title,
                    dashboard_id=dashboard_id,
                    health_score=health_score,
                    health_grade=health_grade,
                    pillar_summaries=pillar_summaries,
                    new_issues=new_issues,
                    recurring_issues=recurring_issues,
                    resolved_issues=resolved_issues,
                    data_table_id=data_table_id,
                    lookback_days=lookback_days,
                    refreshed_at_str=now_display,
                    ai_executive_summary=ai_executive_summary,
                )
            except Exception as exc:
                logger.warning("Failed to sync Platform Health Native Dashboard: %s", exc)
                collection_errors.append(f"DASHBOARD_SYNC: {exc}")

        return {
            "status": "SUCCESS",
            "evaluated_at_utc": now_iso,
            "lookback_days": lookback_days,
            "overall_health_score": health_score,
            "overall_health_grade": health_grade,
            "audited_pillars": sorted(list(audited_pillars)),
            "pillar_summaries": pillar_summaries,
            "ledger_summary": {
                "data_table_id": data_table_id,
                "synced": ledger_result["synced"],
                "table_created": ledger_result["table_created"],
                "rows_added": ledger_result["rows_added"],
                "rows_deleted": ledger_result["rows_deleted"],
                "new_issues_count": len(new_issues),
                "recurring_issues_count": len(recurring_issues),
                "resolved_issues_count": len(resolved_issues),
                "total_tracked_issues": len(all_reconciled),
            },
            "new_issues": [i.to_dict() for i in new_issues],
            "recurring_issues": [i.to_dict() for i in recurring_issues],
            "resolved_issues": [i.to_dict() for i in resolved_issues],
            "dashboard_sync": dashboard_result,
            "collection_errors": collection_errors,
        }

    # ----------------------------------------------------------------------
    # Data Table State Machine Reconciliation
    # ----------------------------------------------------------------------

    def _reconcile_health_ledger(
        self,
        table_id: str,
        live_issues: List[PlatformHealthIssue],
        audited_pillars: Set[str],
        now_iso: str,
        sync_data_table: bool = True,
    ) -> Dict[str, Any]:
        """Reads prior state from Data Table, transitions NEW/RECURRING/RESOLVED, and persists updates."""
        table_created = False
        existing_rows_by_fp: Dict[str, Tuple[str, PlatformHealthIssue]] = {}

        if sync_data_table:
            # 1. Ensure Data Table exists
            try:
                self.engine.get_data_table(table_id)
            except Exception:
                try:
                    self.engine.create_data_table(
                        table_id=table_id,
                        display_name=table_id,
                        description=(
                            "Stateful long-term issue ledger for the SecOps Platform Health Check Agent "
                            "(tracks NEW, RECURRING, and RESOLVED issues across Playbooks, Rules, Parsers, Feeds, and Jobs)."
                        ),
                        column_info=HEALTH_LEDGER_COLUMNS,
                    )
                    table_created = True
                except Exception as create_exc:
                    logger.warning("Could not create Data Table %s: %s", table_id, create_exc)

            # 2. Read existing rows (paginate up to 500 rows)
            try:
                page_token: Optional[str] = None
                for _ in range(5):
                    row_batch = self.engine.list_data_table_rows(
                        table_name_or_id=table_id,
                        page_size=200,
                        page_token=page_token,
                    )
                    for r in row_batch.rows:
                        vals = r.values or []
                        if len(vals) >= 11:
                            fp_val = vals[0].strip()
                            try:
                                occ = int(vals[8])
                            except (ValueError, TypeError):
                                occ = 1
                            parsed_issue = PlatformHealthIssue(
                                fingerprint_id=fp_val,
                                pillar=vals[1],
                                resource_name=vals[2],
                                issue_code=vals[3],
                                lifecycle_status=vals[4],
                                severity=vals[5],
                                first_seen_utc=vals[6],
                                last_seen_utc=vals[7],
                                occurrence_count=occ,
                                error_summary=vals[9],
                                remediation=vals[10],
                            )
                            existing_rows_by_fp[fp_val] = (r.id, parsed_issue)
                    page_token = row_batch.next_page_token
                    if not page_token:
                        break
            except Exception as read_exc:
                logger.warning("Failed to list rows from Data Table %s: %s", table_id, read_exc)

        # 3. Compute state transitions
        reconciled: List[PlatformHealthIssue] = []
        rows_to_delete: List[str] = []
        rows_to_insert: List[Dict[str, Any]] = []
        seen_live_fps: Set[str] = set()

        for item in live_issues:
            fp = item.fingerprint_id
            if fp in seen_live_fps:
                continue
            seen_live_fps.add(fp)

            prior_tuple = existing_rows_by_fp.get(fp)
            if prior_tuple is None:
                # Brand new issue
                item.lifecycle_status = "NEW"
                item.occurrence_count = 1
                item.first_seen_utc = now_iso
                item.last_seen_utc = now_iso
                reconciled.append(item)
                rows_to_insert.append({"values": item.to_row_values()})
            else:
                row_id, prior_issue = prior_tuple
                if prior_issue.lifecycle_status.upper() == "RESOLVED":
                    # Regression / re-opened issue -> classify as NEW
                    item.lifecycle_status = "NEW"
                    item.occurrence_count = prior_issue.occurrence_count + 1
                    item.first_seen_utc = now_iso
                    item.last_seen_utc = now_iso
                else:
                    # Active in prior run and still active -> RECURRING
                    item.lifecycle_status = "RECURRING"
                    item.occurrence_count = prior_issue.occurrence_count + 1
                    item.first_seen_utc = prior_issue.first_seen_utc or now_iso
                    item.last_seen_utc = now_iso
                reconciled.append(item)
                rows_to_delete.append(row_id)
                rows_to_insert.append({"values": item.to_row_values()})

        # 4. Identify RESOLVED issues (were NEW or RECURRING in an audited pillar, but absent in live_issues)
        for fp, (row_id, prior_issue) in existing_rows_by_fp.items():
            if fp in seen_live_fps:
                continue
            if prior_issue.pillar in audited_pillars and prior_issue.lifecycle_status.upper() in ("NEW", "RECURRING"):
                prior_issue.lifecycle_status = "RESOLVED"
                prior_issue.last_seen_utc = now_iso
                if not prior_issue.error_summary.startswith("[RESOLVED"):
                    prior_issue.error_summary = f"[RESOLVED at {now_iso}] {prior_issue.error_summary}"
                reconciled.append(prior_issue)
                rows_to_delete.append(row_id)
                rows_to_insert.append({"values": prior_issue.to_row_values()})
            elif prior_issue.lifecycle_status.upper() == "RESOLVED":
                reconciled.append(prior_issue)

        # 5. Apply Data Table mutations
        deleted_count = 0
        added_count = 0
        if sync_data_table:
            for idx_del, r_id in enumerate(rows_to_delete):
                if idx_del >= 45:
                    time.sleep(1.05)
                try:
                    self.engine.delete_data_table_row(table_name_or_id=table_id, row_id=r_id)
                    deleted_count += 1
                except Exception as del_exc:
                    logger.debug("Could not delete superseded row %s in %s: %s", r_id, table_id, del_exc)

            if rows_to_insert:
                try:
                    self.engine.add_data_table_rows(table_name_or_id=table_id, rows=rows_to_insert)
                    added_count = len(rows_to_insert)
                except Exception as add_exc:
                    logger.warning("Failed to bulk insert rows into %s: %s", table_id, add_exc)

        # Sort reconciled issues by severity then occurrence count
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        reconciled.sort(key=lambda x: (sev_rank.get(x.severity.upper(), 4), -x.occurrence_count, x.pillar))

        return {
            "synced": sync_data_table,
            "table_created": table_created,
            "rows_deleted": deleted_count,
            "rows_added": added_count,
            "reconciled_issues": reconciled,
        }

    @staticmethod
    def _compute_overall_score(active_issues: List[PlatformHealthIssue]) -> Tuple[int, str]:
        """Computes a 0-100 platform health score and letter grade from active issues."""
        deductions = 0
        for iss in active_issues:
            sev = iss.severity.upper()
            if sev == "CRITICAL":
                deductions += 8
            elif sev == "HIGH":
                deductions += 4
            elif sev == "MEDIUM":
                deductions += 2
            else:
                deductions += 1
        score = max(15, min(100, 100 - deductions))
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
        return score, grade

    # ----------------------------------------------------------------------
    # Native Dashboard Rendering & Upsert
    # ----------------------------------------------------------------------

    def sync_dashboard(
        self,
        dashboard_title: str,
        dashboard_id: Optional[str],
        health_score: int,
        health_grade: str,
        pillar_summaries: Dict[str, Dict[str, Any]],
        new_issues: List[PlatformHealthIssue],
        recurring_issues: List[PlatformHealthIssue],
        resolved_issues: List[PlatformHealthIssue],
        data_table_id: str,
        lookback_days: int,
        refreshed_at_str: str,
        ai_executive_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates or updates the 'SecOps Platform Health & Operations Center' Native Dashboard."""
        active_issues = new_issues + recurring_issues

        banner_md = self._format_banner_markdown(
            dashboard_title=dashboard_title,
            health_score=health_score,
            health_grade=health_grade,
            new_count=len(new_issues),
            recurring_count=len(recurring_issues),
            resolved_count=len(resolved_issues),
            pillar_summaries=pillar_summaries,
            data_table_id=data_table_id,
            refreshed_at_str=refreshed_at_str,
        )
        ledger_md = self._format_ledger_markdown(
            new_issues=new_issues,
            recurring_issues=recurring_issues,
            resolved_issues=resolved_issues,
            data_table_id=data_table_id,
            refreshed_at_str=refreshed_at_str,
        )
        remediation_md = self._format_remediation_markdown(
            active_issues=active_issues,
            resolved_issues=resolved_issues,
            pillar_summaries=pillar_summaries,
            refreshed_at_str=refreshed_at_str,
            custom_ai_summary=ai_executive_summary,
        )
        playbook_md = self._format_playbook_pillar_markdown(
            pillar_summaries=pillar_summaries,
            active_issues=active_issues,
            lookback_days=lookback_days,
        )
        rule_md = self._format_rule_pillar_markdown(
            pillar_summaries=pillar_summaries,
            active_issues=active_issues,
        )
        parser_md = self._format_parser_feed_pillar_markdown(
            pillar_summaries=pillar_summaries,
            active_issues=active_issues,
        )

        desired_tiles: List[Dict[str, Any]] = [
            {
                "display_name": "Platform Health Operations Banner",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 0,
                "span_x": 96,
                "span_y": 7,
                "visualization": {
                    "markdown": {
                        "content": banner_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "7d Rule Detections Volume (Live)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 0,
                "start_y": 7,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["RULE_DETECTIONS"],
                "time_unit": "DAY",
                "time_value": "7",
                "query": 'detection.detection.rule_id != ""\noutcome:\n  $detection_count = count(detection.id)',
                "visualization": _build_kpi_text_visualization(
                    label="7d Rule Detections",
                    field="detection_count",
                ),
            },
            {
                "display_name": "24h Active UDM Log Sources (Live)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 32,
                "start_y": 7,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["UDM"],
                "time_unit": "DAY",
                "time_value": "1",
                "query": 'metadata.event_type != "EVENTTYPE_UNSPECIFIED"\noutcome:\n  $log_types = count_distinct(metadata.log_type)',
                "visualization": _build_kpi_text_visualization(
                    label="Active Log Types (24h)",
                    field="log_types",
                ),
            },
            {
                "display_name": "24h UDM Events Ingested (Live)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 64,
                "start_y": 7,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["UDM"],
                "time_unit": "DAY",
                "time_value": "1",
                "query": 'metadata.event_type != "EVENTTYPE_UNSPECIFIED"\noutcome:\n  $event_count = count(metadata.id)',
                "visualization": _build_kpi_text_visualization(
                    label="24h UDM Events",
                    field="event_count",
                ),
            },
            {
                "display_name": "Active & Historical Issue Delta Ledger (Data Table)",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 18,
                "span_x": 58,
                "span_y": 28,
                "visualization": {
                    "markdown": {
                        "content": ledger_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "AI SRE Executive Root-Cause & Remediation Plan",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 58,
                "start_y": 18,
                "span_x": 38,
                "span_y": 28,
                "visualization": {
                    "markdown": {
                        "content": remediation_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Pillar 1: SOAR Playbooks & Scheduled Jobs Health",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 46,
                "span_x": 32,
                "span_y": 30,
                "visualization": {
                    "markdown": {
                        "content": playbook_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Pillar 2: YARA-L & Curated Detection Rule Health",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 32,
                "start_y": 46,
                "span_x": 32,
                "span_y": 30,
                "visualization": {
                    "markdown": {
                        "content": rule_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Pillar 3: CBN Parsers, Data Feeds & Timestamp Skew",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 64,
                "start_y": 46,
                "span_x": 32,
                "span_y": 30,
                "visualization": {
                    "markdown": {
                        "content": parser_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
        ]

        # Resolve or create the Native Dashboard
        target_dash_id = dashboard_id
        existing_detail = None
        action_taken = "UPDATED"

        if target_dash_id:
            try:
                existing_detail = self._get_dash_wf.execute(target_dash_id, include_queries=False)
                target_dash_id = existing_detail.summary.id
            except Exception:
                existing_detail = None

        if existing_detail is None:
            batch = self._search_dash_wf.execute(DashboardSearchQuery(query=dashboard_title, limit=50))
            for s in batch.dashboards:
                if s.display_name.strip().lower() == dashboard_title.strip().lower() and s.type.upper() == "CUSTOM":
                    target_dash_id = s.id
                    existing_detail = self._get_dash_wf.execute(target_dash_id, include_queries=False)
                    break

        description_text = (
            f"SecOps Platform Health & Operations Center — Stateful issue tracking via Data Table "
            f"'{data_table_id}' (Playbooks, Rules, Parsers, Feeds, SOAR Jobs, Timestamp Skew). Last synced: {refreshed_at_str}."
        )

        if existing_detail is None:
            created_summary = self._create_dash_wf.execute(
                display_name=dashboard_title,
                description=description_text,
                dashboard_type="CUSTOM",
            )
            target_dash_id = created_summary.id
            action_taken = "CREATED"
            existing_charts_by_name: Dict[str, Any] = {}
        else:
            existing_charts_by_name = {c.display_name: c for c in existing_detail.charts}

        synced_tiles: List[Dict[str, Any]] = []
        chart_layout_entries: List[Dict[str, Any]] = []

        for spec in desired_tiles:
            t_name = spec["display_name"]
            existing_chart = existing_charts_by_name.get(t_name)
            layout_obj = {
                "startX": int(spec["start_x"]),
                "startY": int(spec["start_y"]),
                "spanX": int(spec["span_x"]),
                "spanY": int(spec["span_y"]),
            }
            if existing_chart is not None:
                chart_id_val = existing_chart.id
                full_chart_res_name = existing_chart.name
                if _needs_visualization_update(
                    existing_chart.visualization,
                    spec["visualization"],
                    spec["tile_type"],
                ):
                    self._update_chart_wf.execute(
                        chart_id=chart_id_val,
                        display_name=t_name,
                        visualization=spec["visualization"],
                    )
                    op_label = "UPDATED"
                else:
                    op_label = "UNCHANGED"
                synced_tiles.append(
                    {
                        "display_name": t_name,
                        "chart_id": chart_id_val,
                        "tile_type": spec["tile_type"],
                        "operation": op_label,
                        "layout": layout_obj,
                    }
                )
            else:
                add_res = self._add_chart_wf.execute(
                    dashboard_id=target_dash_id,
                    display_name=t_name,
                    tile_type=spec["tile_type"],
                    visualization=spec["visualization"],
                    data_sources=spec.get("data_sources"),
                    query=spec.get("query"),
                    time_unit=spec.get("time_unit", "DAY"),
                    time_value=spec.get("time_value", "1"),
                    start_x=spec["start_x"],
                    start_y=spec["start_y"],
                    span_x=spec["span_x"],
                    span_y=spec["span_y"],
                )
                new_chart_id = ""
                full_chart_res_name = ""
                if isinstance(add_res, dict):
                    dc = add_res.get("dashboardChart", {})
                    if isinstance(dc, dict) and dc.get("name"):
                        full_chart_res_name = dc["name"]
                        new_chart_id = full_chart_res_name.split("/")[-1]
                synced_tiles.append(
                    {
                        "display_name": t_name,
                        "chart_id": new_chart_id,
                        "tile_type": spec["tile_type"],
                        "operation": "ADDED",
                        "layout": layout_obj,
                    }
                )

            if full_chart_res_name:
                chart_layout_entries.append(
                    {
                        "dashboardChart": full_chart_res_name,
                        "chartLayout": layout_obj,
                    }
                )

        try:
            self._update_dash_wf.execute(
                dashboard_id=target_dash_id,
                display_name=dashboard_title,
                description=description_text,
                charts=chart_layout_entries if chart_layout_entries else None,
            )
        except Exception as layout_exc:
            logger.warning("Failed to patch dashboard chart layouts: %s", layout_exc)

        return {
            "action": action_taken,
            "dashboard_id": target_dash_id,
            "dashboard_title": dashboard_title,
            "last_synced_utc": refreshed_at_str,
            "tiles": synced_tiles,
        }

    # ----------------------------------------------------------------------
    # Markdown Builders for Dashboard Tiles
    # ----------------------------------------------------------------------

    @staticmethod
    def _format_banner_markdown(
        dashboard_title: str,
        health_score: int,
        health_grade: str,
        new_count: int,
        recurring_count: int,
        resolved_count: int,
        pillar_summaries: Dict[str, Dict[str, Any]],
        data_table_id: str,
        refreshed_at_str: str,
    ) -> str:
        pb_fail = pillar_summaries.get("PLAYBOOK", {}).get("failing_playbooks_count", 0)
        rl_fail = pillar_summaries.get("RULE", {}).get("failing_count", 0)
        pr_fail = pillar_summaries.get("PARSER", {}).get("failed_count", 0) + pillar_summaries.get("PARSER", {}).get("irregular_count", 0)
        fd_fail = pillar_summaries.get("FEED", {}).get("failed_count", 0) + pillar_summaries.get("FEED", {}).get("irregular_count", 0)

        pb_badge = f"🔴 {pb_fail} Degraded" if pb_fail > 0 else "🟢 Healthy"
        rl_badge = f"🔴 {rl_fail} Rule Errors" if rl_fail > 0 else "🟢 Healthy"
        pr_badge = f"🔴 {pr_fail} Parser Faults" if pr_fail > 0 else "🟢 Healthy"
        fd_badge = f"🟡 {fd_fail} Feed Alerts" if fd_fail > 0 else "🟢 Healthy"

        return (
            f"# 🛡️ {dashboard_title}\n"
            f"**Platform Reliability Score:** `{health_score}/100 (Grade {health_grade})` &nbsp;|&nbsp; "
            f"**State Ledger (`%{data_table_id}`):** `🆕 {new_count} NEW` · `🔁 {recurring_count} RECURRING` · `✅ {resolved_count} RESOLVED` &nbsp;|&nbsp; "
            f"**Last Audit:** `{refreshed_at_str}`\n\n"
            f"**Pillar Status:** &nbsp; **SOAR Playbooks:** {pb_badge} &nbsp;|&nbsp; "
            f"**YARA-L & Curated Rules:** {rl_badge} &nbsp;|&nbsp; "
            f"**CBN Parsers:** {pr_badge} &nbsp;|&nbsp; "
            f"**Data Feeds:** {fd_badge}"
        )

    @staticmethod
    def _format_ledger_markdown(
        new_issues: List[PlatformHealthIssue],
        recurring_issues: List[PlatformHealthIssue],
        resolved_issues: List[PlatformHealthIssue],
        data_table_id: str,
        refreshed_at_str: str,
    ) -> str:
        lines = [
            f"### 📋 Stateful Issue Delta Ledger (`%{data_table_id}`)",
            f"*Tracks whether operational faults are brand-new (`NEW`), persisting across checks (`RECURRING`), or fixed (`RESOLVED`). Updated `{refreshed_at_str}`.*",
            "",
            "| State | Severity | Pillar | Asset / Resource | Runs Seen | First Seen (UTC) | Fault & Telemetry Summary |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        combined = new_issues + recurring_issues
        if not combined:
            lines.append("| ✅ **CLEAN** | `INFO` | `ALL` | All Audited Subsystems | `0` | — | Zero active Playbook, Rule, or Parser issues detected. |")
        else:
            for iss in combined[:16]:
                state_badge = "🆕 **NEW**" if iss.lifecycle_status == "NEW" else "🔁 **RECURRING**"
                sev_icon = "🔴" if iss.severity == "CRITICAL" else ("🟠" if iss.severity == "HIGH" else "🟡")
                first_short = iss.first_seen_utc[:16].replace("T", " ") if iss.first_seen_utc else "—"
                summary_short = _sanitize_cell(iss.error_summary, 145)
                res_short = _sanitize_cell(iss.resource_name, 42)
                lines.append(
                    f"| {state_badge} | {sev_icon} `{iss.severity}` | `{iss.pillar}` | **{res_short}** | `{iss.occurrence_count}x` | `{first_short}` | {summary_short} |"
                )

        if resolved_issues:
            lines.extend([
                "",
                "#### ✅ Recently Resolved Issues",
            ])
            for r_iss in resolved_issues[:5]:
                lines.append(
                    f"- **`[{r_iss.pillar}]` {r_iss.resource_name}** (`{r_iss.issue_code}`) — {r_iss.error_summary}"
                )

        return "\n".join(lines)

    @staticmethod
    def _format_remediation_markdown(
        active_issues: List[PlatformHealthIssue],
        resolved_issues: List[PlatformHealthIssue],
        pillar_summaries: Dict[str, Dict[str, Any]],
        refreshed_at_str: str,
        custom_ai_summary: Optional[str] = None,
    ) -> str:
        lines = [
            "### 🤖 AI SRE Root-Cause & Action Plan",
            f"*Synthesized by SecOps Platform Health Check Agent (`{refreshed_at_str}`)*",
            "",
        ]
        if custom_ai_summary and custom_ai_summary.strip():
            lines.append(custom_ai_summary.strip())
            lines.append("")

        crit_count = sum(1 for i in active_issues if i.severity == "CRITICAL")
        high_count = sum(1 for i in active_issues if i.severity == "HIGH")

        lines.append(
            f"**Executive Posture:** Currently tracking **{len(active_issues)} active platform findings** "
            f"(`{crit_count}` Critical, `{high_count}` High) and **{len(resolved_issues)} resolved issues**."
        )
        lines.append("")
        lines.append("#### 🛠️ Top Prioritized Remediations")

        for idx, iss in enumerate(active_issues[:7], start=1):
            tag = "🆕" if iss.lifecycle_status == "NEW" else f"🔁 {iss.occurrence_count}x"
            lines.append(
                f"{idx}. **{iss.pillar} — `{iss.resource_name}`** ({tag}, `{iss.severity}`)\n"
                f"   - *Root Cause:* {_sanitize_cell(iss.error_summary, 170)}\n"
                f"   - *Action:* {_sanitize_cell(iss.remediation, 170)}"
            )

        return "\n".join(lines)

    @staticmethod
    def _format_playbook_pillar_markdown(
        pillar_summaries: Dict[str, Dict[str, Any]],
        active_issues: List[PlatformHealthIssue],
        lookback_days: int,
    ) -> str:
        pb = pillar_summaries.get("PLAYBOOK", {})
        jb = pillar_summaries.get("SOAR_JOB", {})
        pb_issues = [i for i in active_issues if i.pillar in ("PLAYBOOK", "SOAR_JOB")]

        lines = [
            f"### ⚡ Pillar 1: SOAR Playbooks & Jobs ({lookback_days}d)",
            f"- **Catalog Playbooks:** `{pb.get('total_catalog_playbooks', 0)}` (`{pb.get('active_executing_playbooks', 0)}` active in {lookback_days}d)",
            f"- **Total Playbook Runs:** `{pb.get('total_runs', 0)}` (`{pb.get('completed_runs', 0)}` Completed, **`{pb.get('failed_runs', 0)}` Failed**, **`{pb.get('terminated_runs', 0)}` Terminated**)",
            f"- **Overall Failure Rate:** `{pb.get('overall_failure_rate_pct', 0.0)}%` (`{pb.get('failing_playbooks_count', 0)}` failing, `{pb.get('slow_playbooks_count', 0)}` slow >3m)",
            f"- **SOAR Scheduled Jobs:** `{jb.get('total_job_instances', 0)}` instances (`{jb.get('failed_job_instances', 0)}` failing) | **Remote Agents:** `{jb.get('total_remote_agents', 0)}` (`{jb.get('inactive_remote_agents', 0)}` inactive)",
            "",
            "#### 🚨 Active Playbook & Job Faults",
        ]
        if not pb_issues:
            lines.append("- ✅ All executing SOAR playbooks and scheduled jobs completed without faults.")
        else:
            for iss in pb_issues[:6]:
                lines.append(
                    f"- **[{iss.severity}] `{iss.resource_name}`** (`{iss.lifecycle_status}` · `{iss.occurrence_count}x`)\n"
                    f"  {_sanitize_cell(iss.error_summary, 200)}"
                )
        return "\n".join(lines)

    @staticmethod
    def _format_rule_pillar_markdown(
        pillar_summaries: Dict[str, Dict[str, Any]],
        active_issues: List[PlatformHealthIssue],
    ) -> str:
        rl = pillar_summaries.get("RULE", {})
        rl_issues = [i for i in active_issues if i.pillar == "RULE"]

        lines = [
            "### 🎯 Pillar 2: YARA-L & Curated Rules",
            f"- **Total Audited:** `{rl.get('total_rules_audited', 0)}` (`{rl.get('custom_rules_audited', 0)}` Custom YARA-L + `{rl.get('curated_rulesets_audited', 0)}` Curated Rulesets)",
            f"- **24h Detection Velocity:** `{rl.get('total_detections_24h', 0):,}` detections across `{rl.get('rules_firing_24h', 0)}` firing rules",
            f"- **Execution / Compilation Errors:** **`{rl.get('failing_count', 0)}` rules** (`{rl.get('execution_errors_considered', 0)}` raw API errors)",
            f"- **High Latency (>30m):** **`{rl.get('latency_alert_count', 0)}` rules** | **Misconfigured Alerting:** `{rl.get('misconfigured_count', 0)}` rules",
            "",
            "#### 🚨 Active Rule Execution & Latency Faults",
        ]
        if not rl_issues:
            lines.append("- ✅ Zero YARA-L or Curated Detection rule execution errors detected.")
        else:
            for iss in rl_issues[:7]:
                lines.append(
                    f"- **[{iss.severity}] `{iss.resource_name}`** (`{iss.lifecycle_status}` · `{iss.occurrence_count}x`)\n"
                    f"  {_sanitize_cell(iss.error_summary, 190)}"
                )
        return "\n".join(lines)

    @staticmethod
    def _format_parser_feed_pillar_markdown(
        pillar_summaries: Dict[str, Dict[str, Any]],
        active_issues: List[PlatformHealthIssue],
    ) -> str:
        pr = pillar_summaries.get("PARSER", {})
        fd = pillar_summaries.get("FEED", {})
        ts = pillar_summaries.get("TIMESTAMP", {})
        cl = pillar_summaries.get("CLOUD_LOGGING", {})
        pf_issues = [i for i in active_issues if i.pillar in ("PARSER", "FEED", "TIMESTAMP", "CLOUD_LOGGING")]

        lines = [
            "### 🧩 Pillar 3: Parsers, Feeds & Skew",
            f"- **CBN Parsers Audited:** `{pr.get('total_parsers_audited', 0)}` (`{pr.get('healthy_count', 0)}` Healthy, **`{pr.get('failed_count', 0)}` Failed**, **`{pr.get('irregular_count', 0)}` Irregular**)",
            f"- **Ingestion Feeds Audited:** `{fd.get('total_feeds_audited', 0)}` (`{fd.get('healthy_count', 0)}` Healthy, `{fd.get('failed_count', 0)}` Failed, `{fd.get('irregular_count', 0)}` Irregular)",
            f"- **Timestamp Integrity:** `{ts.get('total_log_types_audited', 0)}` log types (`{ts.get('anomalous_log_types_count', 0)}` with severe lag/skew)",
            f"- **Cloud Logging (`>=ERROR`):** `{cl.get('error_entries_found', 0)}` entries",
            "",
            "#### 🚨 Active Parser, Feed & Pipeline Faults",
        ]
        if not pf_issues:
            lines.append("- ✅ All CBN parsers, feeds, and ingestion timestamps are operating nominally.")
        else:
            for iss in pf_issues[:8]:
                lines.append(
                    f"- **[{iss.pillar}] `{iss.resource_name}`** (`{iss.lifecycle_status}` · `{iss.occurrence_count}x`)\n"
                    f"  {_sanitize_cell(iss.error_summary, 180)}"
                )
        return "\n".join(lines)
