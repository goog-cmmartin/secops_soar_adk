"""Proactive Feed Health Audit Workflow.

Correlates feed configuration, Google SecOps Health Hub telemetry,
and ingestion velocity to detect feed decay, silent push stops, and transport latency.

Feed state handling follows the documented Chronicle ``Feed.State`` enum
(v1alpha ``projects.locations.instances.feeds``): ``STATE_UNSPECIFIED``,
``ACTIVE``, ``INACTIVE``, ``RUNNING``, ``SUCCEEDED``, ``FAILED``.
See ``discovery/observations/05_ingestion_health_observations.md``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    FeedBatch,
    FeedHealthFinding,
    FeedHealthReport,
    FeedHealthStatus,
    FeedSummary,
)
from engine.workflows.feed import SearchFeedsWorkflow
from engine.workflows.health_utils import (
    HEALTH_HUB_DASHBOARD_ID,
    DeepDiveTelemetry,
    collect_dashboard_chart_rows,
    fetch_deep_dive_telemetry,
    resolve_collector_name,
)

logger = logging.getLogger(__name__)

# Documented Feed.State values in which the feed is configured to collect.
OPERATIONAL_FEED_STATES = frozenset({"ACTIVE", "RUNNING", "SUCCEEDED"})
# FAILED is documented; ERROR is a legacy/defensive alias (not in the enum).
FAILED_FEED_STATES = frozenset({"FAILED", "ERROR"})
# INACTIVE is documented (Health Hub reports it as "Disabled_feed"); DISABLED is
# a legacy/defensive alias (not in the enum).
INACTIVE_FEED_STATES = frozenset({"INACTIVE", "DISABLED"})

# Health Hub charts carrying per-feed rows (keyed by feed_id). The KPI tiles
# "Failed Sources" / "Irregular Data Sources" only return a scalar count and
# cannot be mapped to feeds, so they are not queried.
HH_SOURCE_STATUS_CHART = "health status by data source"
HH_SOURCE_LATENCY_CHART = "latency status by source"
HEALTH_HUB_FEED_CHART_KEYS = [HH_SOURCE_STATUS_CHART, HH_SOURCE_LATENCY_CHART]

# Health Hub latency cells that carry no measurement.
_NO_LATENCY_VALUES = frozenset({"", "-", "n/a", "no data recorded"})


class AuditFeedHealthWorkflow:
    """Orchestrates comprehensive health assessment across all configured feeds."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter
        # Set by _collect_health_hub_telemetry on each run.
        self.health_hub_available = False

    def execute(self, lookback_days: int = 7) -> FeedHealthReport:
        """Executes feed health assessment against live SecOps tenant.
        
        1. Discovers all configured push and pull feeds.
        2. Queries Health Hub dashboard telemetry for source status and latency.
        3. Queries Data Health Deep Dive for collector routing, volume funnels, and quota drops.
        4. Analyzes feed states, last initiation times, and telemetry.
        5. Generates structured FeedHealthReport with actionable remediation steps.

        Telemetry failures never abort the audit; they are listed in
        ``telemetry_errors`` and reflected in ``health_hub_available`` /
        ``deep_dive_available``.
        """
        # Step 1: Discover all feeds
        feed_search_wf = SearchFeedsWorkflow(self.adapter)
        feed_batch: FeedBatch = feed_search_wf.execute(limit=1000)
        feeds: List[FeedSummary] = feed_batch.feeds

        # Step 2: Query Health Hub and Deep Dive telemetry
        telemetry_errors: List[str] = []
        source_telemetry = self._collect_health_hub_telemetry(telemetry_errors)
        health_hub_available = self.health_hub_available
        deep_dive_telemetry: DeepDiveTelemetry = fetch_deep_dive_telemetry(self.adapter)
        telemetry_errors.extend(deep_dive_telemetry.errors)

        # Step 3: Evaluate each feed
        findings: List[FeedHealthFinding] = []
        healthy_count = 0
        irregular_count = 0
        failed_count = 0
        high_latency_count = 0
        inactive_count = 0
        unknown_count = 0
        quota_rejections = 0

        for f in feeds:
            finding = self._evaluate_feed(
                f, source_telemetry, deep_dive_telemetry, health_hub_available=health_hub_available
            )
            findings.append(finding)

            if finding.status == FeedHealthStatus.HEALTHY:
                healthy_count += 1
            elif finding.status in (FeedHealthStatus.FAILED, FeedHealthStatus.SILENT_PUSH_STOP):
                failed_count += 1
            elif finding.status == FeedHealthStatus.IRREGULAR:
                irregular_count += 1
            elif finding.status == FeedHealthStatus.HIGH_LATENCY:
                high_latency_count += 1
            elif finding.status == FeedHealthStatus.INACTIVE:
                inactive_count += 1
            elif finding.status == FeedHealthStatus.UNKNOWN:
                unknown_count += 1

            if finding.quota_rejected_volume_mb > 0.0:
                quota_rejections += 1

        return FeedHealthReport(
            findings=findings,
            healthy_count=healthy_count,
            irregular_count=irregular_count,
            failed_count=failed_count,
            high_latency_count=high_latency_count,
            inactive_count=inactive_count,
            unknown_count=unknown_count,
            quota_rejections_detected=quota_rejections,
            total_feeds_audited=len(feeds),
            health_hub_available=health_hub_available,
            deep_dive_available=deep_dive_telemetry.available,
            telemetry_errors=telemetry_errors,
            generated_at=datetime.now(timezone.utc),
        )

    def _collect_health_hub_telemetry(
        self, errors: Optional[List[str]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Extracts per-feed telemetry (keyed by feed_id) from Health Hub charts.

        Dashboard/chart failures are appended to ``errors`` (and logged) instead
        of being swallowed; ``self.health_hub_available`` records whether any
        target chart executed.
        """
        telemetry_map: Dict[str, Dict[str, Any]] = {}
        charts = collect_dashboard_chart_rows(
            self.adapter, HEALTH_HUB_DASHBOARD_ID, "Health Hub", HEALTH_HUB_FEED_CHART_KEYS
        )
        self.health_hub_available = charts.available
        if errors is not None:
            errors.extend(charts.errors)

        def _entry(key: str) -> Dict[str, Any]:
            return telemetry_map.setdefault(key, {
                "chart_signals": [],
                "latency": None,
                "health_status": None,
                "issue": None,
                "error_code": None,
                "raw_rows": [],
            })

        # Per-source status: Healthy / Warning / Critical
        for row in charts.rows_by_key.get(HH_SOURCE_STATUS_CHART, []):
            key = str(row.get("feed_id") or "").strip()
            if not key:
                continue  # collector/forwarder rows are not feeds
            entry = _entry(key)
            entry["raw_rows"].append(row)
            status = str(row.get("status") or row.get("original_status") or "").strip()
            if status:
                entry["health_status"] = status
            if status.lower() == "critical":
                entry["chart_signals"].append("FAILED")
            elif status.lower() == "warning":
                entry["chart_signals"].append("IRREGULAR")
            issue = row.get("latest_issue_desc") or row.get("issue")
            if issue and str(issue).upper() != "OK":
                entry["issue"] = str(issue)
            if row.get("latest_error_code") and str(row["latest_error_code"]).upper() != "OK":
                entry["error_code"] = str(row["latest_error_code"])

        # Per-source latency (p95 event -> ingestion)
        for row in charts.rows_by_key.get(HH_SOURCE_LATENCY_CHART, []):
            key = str(row.get("feed_id") or "").strip()
            if not key:
                continue
            entry = _entry(key)
            entry["raw_rows"].append(row)
            for col in ("event_ingestion_latency_p95", "event_ingestion_latency", "latency"):
                val = row.get(col)
                if val is not None and str(val).strip().lower() not in _NO_LATENCY_VALUES:
                    entry["latency"] = str(val)
                    break

        return telemetry_map

    def _evaluate_feed(
        self,
        feed: FeedSummary,
        telemetry_map: Dict[str, Dict[str, Any]],
        deep_dive_telemetry: DeepDiveTelemetry,
        health_hub_available: bool = True,
    ) -> FeedHealthFinding:
        """Evaluates a single feed and classifies health."""
        raw = feed.raw or {}
        state = feed.state.upper()
        source_type = feed.feed_source_type.upper()
        log_type = feed.log_type
        last_initiation = raw.get("lastFeedInitiationTime")

        # Telemetry lookup by feed ID, reference ID, or log type
        telem = (
            telemetry_map.get(feed.id)
            or telemetry_map.get(feed.reference_id)
            or telemetry_map.get(log_type)
            or {}
        )
        chart_signals = telem.get("chart_signals", [])
        latency = telem.get("latency")
        hh_status = telem.get("health_status")
        hh_issue = telem.get("issue")
        observed = bool(telem)

        # Deep dive correlation
        collector_name = (
            deep_dive_telemetry.collector_by_log_type.get(feed.log_type)
            or resolve_collector_name(feed.feed_source_type, feed.log_type)
        )
        funnel = deep_dive_telemetry.volume_funnel_by_log_type.get(feed.log_type, {})
        quota_rejected = deep_dive_telemetry.quota_rejected_volume_mb.get(feed.log_type, 0.0)
        quota_limit = deep_dive_telemetry.quota_limit_mb_per_sec.get(feed.log_type, 0.0)

        def _finding(status: FeedHealthStatus, description: str, remediation: List[str],
                     last_event: Optional[str] = last_initiation) -> FeedHealthFinding:
            return FeedHealthFinding(
                feed_id=feed.id,
                feed_name=feed.display_name,
                source_type=source_type,
                log_type=log_type,
                status=status,
                state=state,
                collector_name=collector_name,
                latency_p95=latency,
                volume_funnel=funnel,
                quota_rejected_volume_mb=quota_rejected,
                quota_limit_mb_per_sec=quota_limit,
                last_event_time=last_event,
                anomaly_description=description,
                remediation_steps=remediation,
                health_hub_status=hh_status,
                telemetry_observed=observed,
                raw=raw,
            )

        if hh_issue:
            hh_issue = hh_issue.strip().rstrip(".")
        hh_suffix = f" Health Hub: {hh_status or 'n/a'} - {hh_issue}." if hh_issue else ""

        # 1. State-based failures
        if state in FAILED_FEED_STATES:
            remediation = [
                "Check source credentials (IAM role, S3 key, API token).",
                "Verify source endpoint network connectivity and firewall rules.",
                "Review feed error logs in SecOps SIEM Settings -> Feeds.",
            ]
            if quota_rejected > 0.0:
                remediation.append(f"Quota burst limit exceeded: {quota_rejected:.2f} MB dropped. Increase tenant quota allocation.")
            failure = raw.get("failureMsg") or (raw.get("failureDetails") or {}).get("errorCause")
            desc = f"Feed '{feed.display_name}' is in {state} state."
            if failure:
                desc += f" Failure: {failure}."
            action = (raw.get("failureDetails") or {}).get("errorAction")
            if action:
                remediation.insert(0, str(action))
            return _finding(FeedHealthStatus.FAILED, desc + hh_suffix, remediation)

        # 2. Inactive / disabled feeds: intentionally not collecting.
        if state in INACTIVE_FEED_STATES:
            return _finding(
                FeedHealthStatus.INACTIVE,
                f"Feed '{feed.display_name}' is {state} (disabled; not collecting).{hh_suffix}",
                [
                    "Enable the feed (SIEM Settings -> Feeds, or feeds.enable) if log collection for this source is expected.",
                    "If the source is retired, delete the feed to keep the ingestion inventory accurate.",
                ],
            )

        # 3. Undocumented / unspecified state: cannot be classified.
        if state not in OPERATIONAL_FEED_STATES:
            return _finding(
                FeedHealthStatus.UNKNOWN,
                f"Feed '{feed.display_name}' reports state '{state}', which is not an operational "
                f"Feed.State value (ACTIVE/RUNNING/SUCCEEDED); health cannot be determined.{hh_suffix}",
                ["Inspect the feed in SIEM Settings -> Feeds and confirm its configuration state."],
            )

        # 4. Health Hub Failed Signal ("Health Status by Data Source" = Critical)
        if "FAILED" in chart_signals:
            remediation = [
                "Inspect Data Health Hub dashboard for detailed collector errors.",
                "Verify data source payload schema and pipeline health.",
            ]
            if quota_rejected > 0.0:
                remediation.append(f"Quota burst limit exceeded: {quota_rejected:.2f} MB dropped. Increase tenant quota allocation.")
            desc = "Health Hub flagged source as FAILED."
            if hh_issue:
                desc += f" Issue: {hh_issue}."
            return _finding(FeedHealthStatus.FAILED, desc, remediation)

        # 5. Health Hub Irregular Signal ("Health Status by Data Source" = Warning)
        if "IRREGULAR" in chart_signals:
            remediation = [
                "Check network stability and rate limits on source publisher.",
                "Verify if source generation is naturally intermittent or experiencing transport drops.",
            ]
            if quota_rejected > 0.0:
                remediation.append(f"Quota burst limit exceeded: {quota_rejected:.2f} MB dropped. Increase tenant quota allocation.")
            desc = "Health Hub flagged source as IRREGULAR (intermittent ingestion gaps)."
            if hh_issue:
                desc += f" Issue: {hh_issue}."
            return _finding(FeedHealthStatus.IRREGULAR, desc, remediation)

        # 6. Latency Check
        if latency and any(unit in latency.lower() for unit in ["hr", "hour", "day"]):
            return _finding(
                FeedHealthStatus.HIGH_LATENCY,
                f"High ingestion latency detected: {latency}.",
                [
                    "Check forwarder/collector queue depth and buffer size.",
                    "Verify if source timestamps are delayed upstream before arrival.",
                ],
            )

        # Healthy by state. Make explicit whether Health Hub corroborated it.
        if observed:
            evidence = f" Health Hub status: {hh_status or 'n/a'}."
        elif health_hub_available:
            evidence = " No Health Hub row matched this feed; classification is state-only."
        else:
            evidence = " Health Hub telemetry unavailable; classification is state-only."

        # 7. Push Feed Observation
        if "PUSH" in source_type and not last_initiation and not telem:
            return _finding(
                FeedHealthStatus.HEALTHY,
                f"Push feed is {state} (monitoring continuous inbound streams).{evidence}",
                [],
                last_event=None,
            )

        # 8. Default Healthy
        return _finding(FeedHealthStatus.HEALTHY, f"Feed is operating normally.{evidence}", [])
