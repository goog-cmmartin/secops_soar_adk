"""SOAR Playbook Health Check and Governance Workflow.

Audits SOAR playbooks and modular blocks across Google SecOps by fusing
structural configuration governance with live operational telemetry from the
native 'Playbook Dashboard (SOAR)'.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from engine.workflows.playbook_decay import (
    PlaybookScoringEngine,
    PlaybookTelemetry,
    PlaybookTelemetryAggregator,
)

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine

logger = logging.getLogger(__name__)


class AuditPlaybookHealthWorkflow:
    """Orchestrates comprehensive health and operational auditing across SOAR playbooks."""

    def __init__(self, engine: SecOpsEngine):
        self.engine = engine

    def execute(
        self,
        days: int = 7,
        scan_deep: bool = True,
        fail_threshold_pct: float = 15.0,
        slow_threshold_minutes: float = 3.0,
    ) -> Dict[str, Any]:
        """Audits SOAR playbooks for configuration anomalies, failure spikes, faulted actions, and queue latency.

        Args:
            days: Lookback evaluation window in days (default: 7).
            scan_deep: Whether to execute deep query analytics from native Playbook Dashboard.
            fail_threshold_pct: Failure rate % threshold to flag playbooks as high risk.
            slow_threshold_minutes: Runtime duration in minutes to flag slow workflows.

        Returns:
            Dictionary containing executive summary, operational metrics, and prioritized findings.
        """
        slow_threshold_seconds = float(slow_threshold_minutes) * 60.0
        raw_rows: List[Dict[str, Any]] = []

        if scan_deep:
            try:
                res = self.engine.adapter.execute_dashboard_query(
                    query_text=PlaybookTelemetryAggregator.CHRONICLE_PLAYBOOK_QUERY,
                    time_unit="DAY",
                    time_value=str(max(1, int(days))),
                    clear_cache=True,
                )
                raw_rows = res.rows or []
            except Exception as exc:
                logger.warning("Failed to pull playbook runtime telemetry: %s", exc)

        # Group runtime stats by display_name and workflow UUID
        by_name: Dict[str, Dict[str, Any]] = {}
        uuid_to_name: Dict[str, str] = {}

        for row in raw_rows:
            wf_uuid = str(row.get("metadata.name") or "").strip()
            display_name = str(row.get("display_name") or wf_uuid or "Unknown Playbook").strip()
            status = str(row.get("status") or "UNKNOWN").upper()
            case_id = str(row.get("case_response_platform_info.case_id") or "").strip()
            start_s = float(row.get("start_time.seconds") or 0)
            end_s = float(row.get("end_time.seconds") or 0)

            if wf_uuid and display_name:
                uuid_to_name[wf_uuid] = display_name

            entry = by_name.setdefault(
                display_name,
                {
                    "playbook_name": display_name,
                    "workflow_uuid": wf_uuid,
                    "total_runs": 0,
                    "completed_runs": 0,
                    "failed_runs": 0,
                    "terminated_runs": 0,
                    "in_progress_runs": 0,
                    "duration_sum": 0.0,
                    "duration_count": 0,
                    "max_duration_seconds": 0.0,
                    "statuses": {},
                    "failed_case_ids": [],
                    "recent_case_ids": [],
                },
            )
            if wf_uuid and not entry.get("workflow_uuid"):
                entry["workflow_uuid"] = wf_uuid

            entry["total_runs"] += 1
            entry["statuses"][status] = entry["statuses"].get(status, 0) + 1

            if case_id and case_id not in entry["recent_case_ids"] and len(entry["recent_case_ids"]) < 10:
                entry["recent_case_ids"].append(case_id)

            if status in ("FAILED", "FAULTED", "ERROR"):
                entry["failed_runs"] += 1
                if case_id and case_id not in entry["failed_case_ids"] and len(entry["failed_case_ids"]) < 10:
                    entry["failed_case_ids"].append(case_id)
            elif status in ("TERMINATED", "CANCELLED", "ABORTED"):
                entry["terminated_runs"] += 1
                if case_id and case_id not in entry["failed_case_ids"] and len(entry["failed_case_ids"]) < 10:
                    entry["failed_case_ids"].append(case_id)
            elif status in ("COMPLETED", "SUCCESS", "FINISHED"):
                entry["completed_runs"] += 1
            elif status in ("IN_PROGRESS", "PENDING", "QUEUED", "RUNNING"):
                entry["in_progress_runs"] += 1

            if end_s >= start_s > 0:
                dur = end_s - start_s
                entry["duration_sum"] += dur
                entry["duration_count"] += 1
                if dur > entry["max_duration_seconds"]:
                    entry["max_duration_seconds"] = dur

        # Pull static catalog cards to enrich failing/active playbooks with step diagnostics
        menu_cards: List[Dict[str, Any]] = []
        try:
            menu_cards = self.engine.adapter.get_playbook_menu_cards(
                playbook_types=["REGULAR", "NESTED"]
            )
        except Exception as exc:
            logger.warning("Failed to list playbook menu cards: %s", exc)

        cards_by_name: Dict[str, Dict[str, Any]] = {}
        cards_by_id: Dict[str, Dict[str, Any]] = {}
        for c in menu_cards:
            c_name = str(c.get("name") or "").strip()
            c_id = str(c.get("identifier") or c.get("id") or "").strip()
            if c_name:
                cards_by_name[c_name] = c
            if c_id:
                cards_by_id[c_id] = c

        playbook_metrics: List[Dict[str, Any]] = []
        failing_playbooks: List[Dict[str, Any]] = []
        slow_playbooks: List[Dict[str, Any]] = []
        prioritized_findings: List[Dict[str, Any]] = []

        total_runs_all = 0
        total_failed_all = 0
        total_terminated_all = 0
        total_completed_all = 0

        for name, agg in sorted(by_name.items(), key=lambda kv: (kv[1]["failed_runs"], kv[1]["total_runs"]), reverse=True):
            tot = agg["total_runs"]
            failed = agg["failed_runs"]
            terminated = agg["terminated_runs"]
            completed = agg["completed_runs"]
            in_prog = agg["in_progress_runs"]
            fail_pct = round((failed / tot * 100.0), 2) if tot > 0 else 0.0
            unhealthy_pct = round(((failed + terminated) / tot * 100.0), 2) if tot > 0 else 0.0
            avg_dur = round((agg["duration_sum"] / agg["duration_count"]), 1) if agg["duration_count"] > 0 else 0.0
            max_dur = round(agg["max_duration_seconds"], 1)

            total_runs_all += tot
            total_failed_all += failed
            total_terminated_all += terminated
            total_completed_all += completed

            wf_uuid = agg.get("workflow_uuid") or ""
            card = cards_by_name.get(name) or cards_by_id.get(wf_uuid) or {}
            card_id = str(card.get("identifier") or wf_uuid or "").strip()

            fragile_steps: List[str] = []
            resilience_score: Optional[int] = None
            resilience_grade: Optional[str] = None
            static_findings: List[Dict[str, Any]] = []

            # Inspect full DAG for any failing, terminated, or slow playbook
            if card_id and (failed > 0 or terminated > 0 or avg_dur >= slow_threshold_seconds):
                try:
                    full_info = self.engine.adapter.get_playbook_full_info(card_id)
                    steps = full_info.get("steps", []) or []
                    for s in steps:
                        s_name = str(s.get("name") or s.get("instanceName") or s.get("actionName") or "Unnamed Step")
                        s_type = int(s.get("type", 0))
                        auto_skip = bool(s.get("autoSkipOnFailure", False))
                        if s_type == 0 and not auto_skip:
                            fragile_steps.append(s_name)
                    tel_obj = PlaybookTelemetry(
                        total_runs=tot,
                        failed_runs=failed,
                        completed_runs=completed,
                        failure_rate_pct=fail_pct,
                        avg_duration_seconds=avg_dur,
                        lookback_days=days,
                        statuses=agg["statuses"],
                    )
                    eval_res = PlaybookScoringEngine.evaluate(full_info, tel_obj)
                    resilience_score = eval_res.score
                    resilience_grade = eval_res.grade
                    static_findings = [f.to_dict() for f in eval_res.findings]
                except Exception as exc:
                    logger.debug("Could not inspect full DAG for %s: %s", name, exc)

            item = {
                "playbook_name": name,
                "workflow_identifier": card_id or wf_uuid,
                "category": card.get("categoryName") or "Default",
                "total_runs": tot,
                "completed_runs": completed,
                "failed_runs": failed,
                "terminated_runs": terminated,
                "in_progress_runs": in_prog,
                "failure_rate_pct": fail_pct,
                "unhealthy_rate_pct": unhealthy_pct,
                "avg_duration_seconds": avg_dur,
                "max_duration_seconds": max_dur,
                "statuses": agg["statuses"],
                "failed_case_ids": agg["failed_case_ids"],
                "fragile_steps": fragile_steps[:8],
                "resilience_score": resilience_score,
                "resilience_grade": resilience_grade,
                "static_findings": static_findings,
            }
            playbook_metrics.append(item)

            if failed > 0 or terminated > 0 or fail_pct >= fail_threshold_pct:
                failing_playbooks.append(item)
                sev = "CRITICAL" if (fail_pct >= 50.0 or failed >= 10) else ("HIGH" if fail_pct >= fail_threshold_pct or failed >= 3 else "MEDIUM")
                step_hint = (
                    f" Unguarded actions without autoSkipOnFailure: {', '.join(fragile_steps[:4])}."
                    if fragile_steps
                    else ""
                )
                case_hint = (
                    f" Sample affected Case IDs: {', '.join(agg['failed_case_ids'][:5])}."
                    if agg["failed_case_ids"]
                    else ""
                )
                prioritized_findings.append(
                    {
                        "issue_code": "PLAYBOOK_EXEC_FAILURE" if failed > 0 else "PLAYBOOK_TERMINATED",
                        "severity": sev,
                        "playbook_name": name,
                        "workflow_identifier": card_id or wf_uuid,
                        "summary": (
                            f"Playbook '{name}' recorded {failed} FAILED and {terminated} TERMINATED runs "
                            f"out of {tot} executions ({fail_pct}% failure rate, avg {avg_dur}s) over {days}d."
                            f"{step_hint}{case_hint}"
                        ),
                        "remediation": (
                            f"Inspect failed playbook runs in Cases {', '.join(agg['failed_case_ids'][:3]) or 'N/A'}, "
                            f"enable error handling / autoSkipOnFailure on fragile steps ({', '.join(fragile_steps[:3]) or 'action nodes'}), "
                            f"and verify connector timeouts."
                        ),
                    }
                )

            if avg_dur >= slow_threshold_seconds:
                slow_playbooks.append(item)
                prioritized_findings.append(
                    {
                        "issue_code": "PLAYBOOK_HIGH_LATENCY",
                        "severity": "HIGH" if avg_dur >= 300.0 else "MEDIUM",
                        "playbook_name": name,
                        "workflow_identifier": card_id or wf_uuid,
                        "summary": (
                            f"Playbook '{name}' averages {avg_dur}s ({round(avg_dur / 60.0, 1)} min) across {tot} runs "
                            f"(threshold: {slow_threshold_minutes} min)."
                        ),
                        "remediation": "Review synchronous waiting actions or polling loops and convert long-running steps to async execution.",
                    }
                )

        overall_fail_pct = round((total_failed_all / total_runs_all * 100.0), 2) if total_runs_all > 0 else 0.0

        return {
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "lookback_days": days,
            "summary": {
                "total_catalog_playbooks": len(menu_cards),
                "active_executing_playbooks": len(playbook_metrics),
                "total_runs": total_runs_all,
                "completed_runs": total_completed_all,
                "failed_runs": total_failed_all,
                "terminated_runs": total_terminated_all,
                "overall_failure_rate_pct": overall_fail_pct,
                "failing_playbooks_count": len(failing_playbooks),
                "slow_playbooks_count": len(slow_playbooks),
            },
            "failing_playbooks": failing_playbooks,
            "slow_playbooks": slow_playbooks,
            "playbook_metrics": playbook_metrics,
            "prioritized_findings": prioritized_findings,
        }
