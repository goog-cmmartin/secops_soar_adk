"""Timestamp Integrity and Ingestion Delay Auditing Workflow.

Measures the delta Δt = metadata.ingested_timestamp - metadata.event_timestamp across
all ingested log types in Google SecOps via Chronicle dashboardQueries:execute:
1. Ingestion Bottlenecks (Δt >> 0): Identifies log forwarder queues stalled or network throttling.
2. Clock Skews / NTP Errors (Δt < 0): Identifies future timestamps corrupting forensic timelines.
3. State-Aware Progression Engine: Classifies feeds as NEW, PREVIOUSLY KNOWN, RESOLVED, or HEALTHY.
4. GenAI Advisory Synthesis: Produces actionable infrastructure runbook guidance.
5. Evidence Fabric Dual-Document Persistence: Stores latest snapshot and immutable historical trend records.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
    from agents.core.evidence_store import EvidenceFabricStore
from engine.domain import (
    TimestampIntegrityReport,
    TimestampMetricRow,
    TimestampProgressionState,
)

logger = logging.getLogger(__name__)

TIMESTAMP_INTEGRITY_QUERY = """$log_type = strings.to_upper(metadata.log_type)

match:
    $log_type

outcome:
    $total = count(metadata.id)
    $average_difference_minutes = math.round(cast.as_int(avg(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds)) / 60, 2)
    $cnt_lt_0_hours = sum(
        if(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds < 0, 1, 0)
    )
    $cnt_0_1_hours = sum(
        if(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds >= 0 AND metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds <= 3600, 1, 0)
    )
    $cnt_1_2_hours = sum(
        if(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds > 3600 AND metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds <= 7200, 1, 0)
    )
    $cnt_gt_2_hours = sum(
        if(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds > 7200, 1, 0)
    )

order:
    $average_difference_minutes desc"""


class TimestampIntegrityWorkflow:
    """Orchestrates ingestion timestamp delta auditing and clock drift tracking."""

    def __init__(
        self,
        adapter: GoogleSecOpsAdapter,
        evidence_store: Optional[EvidenceFabricStore] = None,
    ):
        self.adapter = adapter
        self.evidence_store = evidence_store

    @staticmethod
    def classify_progression(is_anomaly: bool, had_issue: bool) -> TimestampProgressionState:
        if is_anomaly:
            return (
                TimestampProgressionState.PREVIOUSLY_KNOWN
                if had_issue
                else TimestampProgressionState.NEW
            )
        else:
            return (
                TimestampProgressionState.RESOLVED
                if had_issue
                else TimestampProgressionState.HEALTHY
            )

    def execute(
        self,
        days: int = 7,
        clear_cache: bool = True,
        project_id: Optional[str] = None,
        persist: bool = True,
    ) -> TimestampIntegrityReport:
        """Executes full timestamp integrity audit across all tenant log sources.

        Args:
            days: Lookback relative time window in days (default: 7).
            clear_cache: Whether to bypass cache for live telemetry freshness.
            project_id: Optional GCP project ID for GenAI brief synthesis.
            persist: Whether to write the report to the Evidence Fabric store
                (latest + history documents). Default True preserves the
                original behaviour; it only has an effect when an evidence
                store is wired. With ``persist=False`` the run performs no
                writes (the baseline is still read for progression states).

        Returns:
            TimestampIntegrityReport with metrics, progression classifications, and narrative.
            ``persisted`` / ``persistence_error`` / ``baseline_available`` /
            ``baseline_error`` describe the Evidence Fabric interaction.
        """
        # 1. Execute Statistical YARA-L 2 Query
        query_result = self.adapter.execute_dashboard_query(
            query_text=TIMESTAMP_INTEGRITY_QUERY,
            time_unit="DAY",
            time_value=str(days),
            clear_cache=clear_cache,
            dialect="YL2",
        )

        rows = query_result.rows if query_result and hasattr(query_result, "rows") else []

        # 2. Retrieve Historical Baseline from Evidence Fabric (read-only)
        prev_data = {}
        baseline_available = False
        baseline_error: Optional[str] = None
        if self.evidence_store:
            try:
                prev_report = self.evidence_store.get_latest_timestamp_integrity()
                if prev_report and isinstance(prev_report, dict):
                    prev_data = prev_report.get("metrics", {})
                    baseline_available = True
            except Exception as e:
                baseline_error = f"{type(e).__name__}: {e}"
                logger.warning("Failed to retrieve previous timestamp integrity baseline: %s", e)

        # 3. Classify State Progression and Compute Metrics
        metric_rows: List[TimestampMetricRow] = []
        metrics_dict: Dict[str, Dict[str, Any]] = {}
        comparative_findings: Dict[str, str] = {}

        healthy_count = 0
        new_anomalies_count = 0
        previously_known_count = 0
        resolved_count = 0
        total_skewed = 0
        total_delayed = 0

        for r in rows:
            def _get_val(key: str, default: Any = None) -> Any:
                if key in r:
                    return r[key]
                if f"${key}" in r:
                    return r[f"${key}"]
                return default

            lt = str(_get_val("log_type", "UNKNOWN") or "UNKNOWN")
            total = int(_get_val("total", 0) or 0)
            avg_diff = float(_get_val("average_difference_minutes", 0.0) or 0.0)
            cnt_lt_0 = int(_get_val("cnt_lt_0_hours", 0) or 0)
            cnt_0_1 = int(_get_val("cnt_0_1_hours", 0) or 0)
            cnt_1_2 = int(_get_val("cnt_1_2_hours", 0) or 0)
            cnt_gt_2 = int(_get_val("cnt_gt_2_hours", 0) or 0)

            is_anomaly = (avg_diff > 60.0) or (cnt_lt_0 > 0)
            had_issue = False
            if lt in prev_data:
                p_entry = prev_data[lt]
                p_avg = float(p_entry.get("average_difference_minutes", 0.0) or 0.0)
                p_skew = int(p_entry.get("cnt_lt_0_hours", 0) or 0)
                had_issue = (p_avg > 60.0) or (p_skew > 0)

            progression = self.classify_progression(is_anomaly=is_anomaly, had_issue=had_issue)
            state = progression.value
            if is_anomaly:
                if had_issue:
                    previously_known_count += 1
                else:
                    new_anomalies_count += 1
            else:
                if had_issue:
                    resolved_count += 1
                else:
                    healthy_count += 1

            total_skewed += cnt_lt_0
            total_delayed += cnt_gt_2

            row_obj = TimestampMetricRow(
                log_type=lt,
                total=total,
                average_difference_minutes=avg_diff,
                cnt_lt_0_hours=cnt_lt_0,
                cnt_0_1_hours=cnt_0_1,
                cnt_1_2_hours=cnt_1_2,
                cnt_gt_2_hours=cnt_gt_2,
                progression_state=state,
                is_anomaly=is_anomaly,
                raw=r,
            )
            metric_rows.append(row_obj)
            metrics_dict[lt] = row_obj.to_dict()
            comparative_findings[lt] = state

        # Also detect feeds that disappeared or fully recovered
        for prev_lt, prev_m in prev_data.items():
            if prev_lt not in metrics_dict:
                p_avg = float(prev_m.get("average_difference_minutes", 0.0) or 0.0)
                p_skew = int(prev_m.get("cnt_lt_0_hours", 0) or 0)
                if (p_avg > 60.0) or (p_skew > 0):
                    comparative_findings[prev_lt] = TimestampProgressionState.RESOLVED.value
                    resolved_count += 1

        top_delayed = sorted(
            [m for m in metric_rows if m.average_difference_minutes > 60.0],
            key=lambda x: x.average_difference_minutes,
            reverse=True,
        )
        top_skewed = sorted(
            [m for m in metric_rows if m.cnt_lt_0_hours > 0],
            key=lambda x: x.cnt_lt_0_hours,
            reverse=True,
        )

        now_str = datetime.now(timezone.utc).isoformat()
        report = TimestampIntegrityReport(
            timestamp=now_str,
            days=days,
            total_log_types_audited=len(metric_rows),
            healthy_count=healthy_count,
            new_anomalies_count=new_anomalies_count,
            previously_known_count=previously_known_count,
            resolved_count=resolved_count,
            total_skewed_events=total_skewed,
            total_delayed_events=total_delayed,
            metrics=metrics_dict,
            comparative_findings=comparative_findings,
            log_types=metric_rows,
            top_delayed_log_types=top_delayed,
            top_skewed_log_types=top_skewed,
            persist_requested=bool(persist),
            baseline_available=baseline_available,
            baseline_error=baseline_error,
        )

        # 4. Synthesize GenAI Operational Brief
        report.narrative = self._synthesize_brief(report, project_id=project_id)

        # 5. Dual-Document Persistence to Evidence Fabric (skipped when persist=False)
        if persist and self.evidence_store:
            try:
                snapshot_id = self.evidence_store.save_timestamp_integrity_report(
                    report.to_dict(include_run_metadata=False)
                )
                report.persisted = True
                report.persisted_snapshot_id = str(snapshot_id) if snapshot_id else None
            except Exception as e:
                report.persistence_error = f"{type(e).__name__}: {e}"
                logger.error("Failed to persist timestamp integrity report to Evidence Fabric: %s", e)
        elif persist:
            report.persistence_error = "No evidence store configured; report was not persisted."

        return report

    run = execute

    def _synthesize_brief(
        self,
        report: TimestampIntegrityReport,
        project_id: Optional[str] = None,
    ) -> str:
        """Synthesizes GenAI operational narrative via Vertex AI Gemini with deterministic fallback."""
        pid = (
            project_id
            or getattr(self.adapter, "project_id", None)
            or os.getenv("GOOGLE_CLOUD_PROJECT")
            or os.getenv("GCP_PROJECT")
        )

        delayed_summary = [
            f"- `{r.log_type}`: avg delay {r.average_difference_minutes}m, {r.cnt_gt_2_hours:,} events delayed >2h [{r.progression_state}]"
            for r in report.top_delayed_log_types[:5]
        ]
        skewed_summary = [
            f"- `{r.log_type}`: {r.cnt_lt_0_hours:,} future events (NTP clock drift) [{r.progression_state}]"
            for r in report.top_skewed_log_types[:5]
        ]

        prompt = (
            f"You are the SecOps Timestamp Integrity Agent for Google SecOps.\n"
            f"Synthesize an authoritative technical executive brief evaluating telemetry data hygiene "
            f"and ingestion latency across {report.total_log_types_audited} log sources over {report.days} days.\n\n"
            f"Key Audit Metrics:\n"
            f"- Total Log Types: {report.total_log_types_audited} ({report.healthy_count} Healthy, "
            f"{report.new_anomalies_count} New Anomalies, {report.previously_known_count} Previously Known, "
            f"{report.resolved_count} Resolved)\n"
            f"- Future Events (NTP Clock Skew): {report.total_skewed_events:,} events with Δt < 0\n"
            f"- Severe Delayed Events (>2h): {report.total_delayed_events:,} events\n\n"
            f"Top Ingestion Delays (Δt >> 0):\n"
            + ("\n".join(delayed_summary) if delayed_summary else "None (Real-Time Ingestion)")
            + "\n\n"
            f"Top Clock Skews (Δt < 0):\n"
            + ("\n".join(skewed_summary) if skewed_summary else "None (Zero NTP Skew)")
            + "\n\n"
            f"Format the output strictly under these 4 markdown sections:\n"
            f"#### ⏱️ 1. Ingestion Pipeline Hygiene & Real-Time Flow\n"
            f"#### 🔴 2. High-Latency Bottlenecks & Forwarder Delays (Δt ≫ 0)\n"
            f"#### ⚠️ 3. Clock Drift & NTP Desynchronization Risks (Δt < 0)\n"
            f"#### 🛠️ 4. Recommended Infrastructure & Collector Remediation\n"
        )

        try:
            from google import genai
            client = genai.Client(vertexai=True, project=pid, location="global")
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            return response.text
        except Exception as ex:
            logger.debug("Vertex AI executive brief generation unavailable, using deterministic brief: %s", ex)
            return self._deterministic_brief_fallback(report)

    def _deterministic_brief_fallback(self, report: TimestampIntegrityReport) -> str:
        """Deterministic architectural summary when GenAI endpoint is unreachable."""
        delayed_lines = [
            f"- `{r.log_type}`: average delta **{r.average_difference_minutes} minutes**, "
            f"{r.cnt_gt_2_hours:,} logs delayed >2h ({r.progression_state})"
            for r in report.top_delayed_log_types[:4]
        ]
        skew_lines = [
            f"- `{r.log_type}`: **{r.cnt_lt_0_hours:,} future events** detected ({r.progression_state})"
            for r in report.top_skewed_log_types[:4]
        ]

        delayed_txt = "\n".join(delayed_lines) if delayed_lines else "- All active log streams exhibit real-time flow (<60m average delay)."
        skew_txt = "\n".join(skew_lines) if skew_lines else "- Zero NTP clock skew detected across all evaluated telemetry sources."

        return (
            f"#### ⏱️ 1. Ingestion Pipeline Hygiene & Real-Time Flow\n"
            f"Evaluated telemetry delta \(\Delta t = \\text{{ingested}} - \\text{{event}}\) across **{report.total_log_types_audited} log sources** "
            f"over the past {report.days} days. **{report.healthy_count}** feeds exhibit nominal real-time flow, with **{report.new_anomalies_count} new anomalies**, "
            f"**{report.previously_known_count} previously known issues**, and **{report.resolved_count} resolved streams**.\n\n"
            f"#### 🔴 2. High-Latency Bottlenecks & Forwarder Delays (Δt ≫ 0)\n"
            f"{delayed_txt}\n\n"
            f"#### ⚠️ 3. Clock Drift & NTP Desynchronization Risks (Δt < 0)\n"
            f"{skew_txt}\n\n"
            f"#### 🛠️ 4. Recommended Infrastructure & Collector Remediation\n"
            f"- For feeds with \(\Delta t \\gg 0\): Inspect local forwarder queue sizes, batching intervals, and egress bandwidth limits.\n"
            f"- For feeds with \(\Delta t < 0\): Resynchronize host NTP daemons (e.g. `chronyd` or `w32time`) and verify timezone offsets in ingestion parsers."
        )


def run_timestamp_integrity_audit(
    adapter: GoogleSecOpsAdapter,
    evidence_store: Optional[EvidenceFabricStore] = None,
    days: int = 7,
    clear_cache: bool = True,
    persist: bool = True,
) -> TimestampIntegrityReport:
    """Convenience functional runner for timestamp integrity audit."""
    workflow = TimestampIntegrityWorkflow(adapter=adapter, evidence_store=evidence_store)
    return workflow.execute(days=days, clear_cache=clear_cache, persist=persist)
