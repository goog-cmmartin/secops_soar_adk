"""Proactive SIEM Parser Health Audit Workflow.

Correlates parser configuration, CBN versioning, Parser Extensions,
and Google SecOps Health Hub telemetry to detect normalization failures,
syntax errors, extension conflicts, and version drift.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    ParserBatch,
    ParserExtensionBatch,
    ParserExtensionSummary,
    ParserHealthFinding,
    ParserHealthReport,
    ParserHealthStatus,
    ParserSummary,
)
from engine.workflows.health_utils import (
    HEALTH_HUB_DASHBOARD_ID,
    DeepDiveTelemetry,
    collect_dashboard_chart_rows,
    fetch_deep_dive_telemetry,
    resolve_collector_name,
)
from engine.workflows.parser import (
    SearchParserExtensionsWorkflow,
    SearchParsersWorkflow,
)

# Health Hub charts with per-log-type rows used by the parser audit.
HEALTH_HUB_PARSER_CHART_KEYS = ["health status by parser", "latency status by log type"]


class AuditParserHealthWorkflow:
    """Orchestrates comprehensive health assessment across all SIEM parsers and normalizers."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter
        # Set by _collect_health_hub_parser_telemetry on each run.
        self.health_hub_available = False

    def execute(self, lookback_days: int = 7) -> ParserHealthReport:
        """Executes parser health assessment against live SecOps tenant.
        
        1. Discovers all configured SIEM parsers across log types.
        2. Discovers all parser extensions and dynamic parsing configurations.
        3. Queries Health Hub and Data Health Deep Dive telemetry for parser health status, drops, funnels, and latency.
        4. Cross-references version drift, extension conflicts, collector sources, and drop reasons.
        5. Generates structured ParserHealthReport with actionable remediation guidance.
        """
        # Step 1: Discover all parsers
        parser_search_wf = SearchParsersWorkflow(self.adapter)
        parser_batch: ParserBatch = parser_search_wf.execute(log_type="-", limit=1000)
        parsers: List[ParserSummary] = parser_batch.parsers

        # Group parsers by log type (select active parser first, or latest created)
        parsers_by_lt: Dict[str, List[ParserSummary]] = {}
        for p in parsers:
            parsers_by_lt.setdefault(p.log_type, []).append(p)

        # Step 2: Discover all parser extensions
        ext_search_wf = SearchParserExtensionsWorkflow(self.adapter)
        ext_batch: ParserExtensionBatch = ext_search_wf.execute(log_type="-", limit=1000)
        extensions_by_lt: Dict[str, ParserExtensionSummary] = {
            e.log_type: e for e in ext_batch.parser_extensions
        }

        # Step 3: Query Health Hub and Deep Dive parser telemetry
        telemetry_errors: List[str] = []
        parser_telemetry = self._collect_health_hub_parser_telemetry(telemetry_errors)
        health_hub_available = self.health_hub_available
        deep_dive_telemetry: DeepDiveTelemetry = fetch_deep_dive_telemetry(self.adapter)
        telemetry_errors.extend(deep_dive_telemetry.errors)

        # Step 4: Evaluate each log type
        findings: List[ParserHealthFinding] = []
        healthy_count = 0
        irregular_count = 0
        failed_count = 0
        version_drift_count = 0
        extension_conflict_count = 0
        quota_rejections = 0

        # Unique log types across inventory and telemetry
        all_log_types = sorted(
            set(
                list(parsers_by_lt.keys())
                + list(parser_telemetry.keys())
                + list(deep_dive_telemetry.volume_funnel_by_log_type.keys())
                + list(deep_dive_telemetry.parser_errors_by_log_type.keys())
            )
        )

        for lt in all_log_types:
            lt_parsers = parsers_by_lt.get(lt, [])
            active_p = next((p for p in lt_parsers if p.state.upper() == "ACTIVE"), None)
            target_p = active_p or (lt_parsers[0] if lt_parsers else None)
            ext = extensions_by_lt.get(lt)
            telem = parser_telemetry.get(lt, {})

            finding = self._evaluate_parser(lt, target_p, ext, telem, deep_dive_telemetry)
            findings.append(finding)

            if finding.status == ParserHealthStatus.HEALTHY:
                healthy_count += 1
            elif finding.status == ParserHealthStatus.FAILED:
                failed_count += 1
            elif finding.status == ParserHealthStatus.IRREGULAR:
                irregular_count += 1
            elif finding.status == ParserHealthStatus.VERSION_DRIFT:
                version_drift_count += 1
            elif finding.status == ParserHealthStatus.EXTENSION_CONFLICT:
                extension_conflict_count += 1
            elif finding.status == ParserHealthStatus.INACTIVE_NO_PARSER:
                failed_count += 1

            if finding.quota_rejected_volume_mb > 0.0:
                quota_rejections += 1

        return ParserHealthReport(
            findings=findings,
            healthy_count=healthy_count,
            irregular_count=irregular_count,
            failed_count=failed_count,
            version_drift_count=version_drift_count,
            extension_conflict_count=extension_conflict_count,
            quota_rejections_detected=quota_rejections,
            total_parsers_audited=len(findings),
            health_hub_available=health_hub_available,
            deep_dive_available=deep_dive_telemetry.available,
            telemetry_errors=telemetry_errors,
            generated_at=datetime.now(timezone.utc),
        )

    def _collect_health_hub_parser_telemetry(
        self, errors: Optional[List[str]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Extracts telemetry per log type from Health Hub parser charts.

        Chart/dashboard failures are appended to ``errors`` and logged rather
        than swallowed; ``self.health_hub_available`` records whether any target
        chart executed. The KPI tiles "Failed Parsers" / "Irregular Parsers"
        only return a scalar count (no log_type column), so they are not queried.
        """
        telemetry_map: Dict[str, Dict[str, Any]] = {}
        charts = collect_dashboard_chart_rows(
            self.adapter, HEALTH_HUB_DASHBOARD_ID, "Health Hub", HEALTH_HUB_PARSER_CHART_KEYS
        )
        self.health_hub_available = charts.available
        if errors is not None:
            errors.extend(charts.errors)

        for rows in charts.rows_by_key.values():
            for row in rows:
                lt = row.get("log_type") or row.get("logType") or ""
                if not lt:
                    continue
                lt = str(lt).strip()

                if lt not in telemetry_map:
                    telemetry_map[lt] = {
                        "status": None,
                        "latest_drop_reason_code": None,
                        "anomalous_since": None,
                        "last_normalization_time": None,
                        "event_latency": None,
                    }

                if "status" in row and row["status"]:
                    telemetry_map[lt]["status"] = str(row["status"])
                if "latest_drop_reason_code" in row and row["latest_drop_reason_code"]:
                    telemetry_map[lt]["latest_drop_reason_code"] = str(row["latest_drop_reason_code"])
                if "anomalous_since" in row and row["anomalous_since"]:
                    telemetry_map[lt]["anomalous_since"] = str(row["anomalous_since"])
                if "last_normalization_time" in row and row["last_normalization_time"]:
                    telemetry_map[lt]["last_normalization_time"] = str(row["last_normalization_time"])
                if "event_ingestion_latency" in row and row["event_ingestion_latency"]:
                    telemetry_map[lt]["event_latency"] = str(row["event_ingestion_latency"])

        return telemetry_map

    def _evaluate_parser(
        self,
        log_type: str,
        parser: Optional[ParserSummary],
        extension: Optional[ParserExtensionSummary],
        telemetry: Dict[str, Any],
        deep_dive_telemetry: DeepDiveTelemetry,
    ) -> ParserHealthFinding:
        """Evaluates parser posture, health hub signals, version drift, and extensions."""
        p_id = parser.id if parser else "NONE"
        state = parser.state if parser else "NONE"
        creator = parser.creator_source if parser else "UNKNOWN"
        version = parser.version if parser else ""
        latest_ver = parser.latest_version if parser else ""
        rollback = parser.rollback_available if parser else False
        raw = parser.raw if parser else {}

        has_ext = extension is not None
        ext_id = extension.id if extension else None
        ext_state = extension.state if extension else None
        dyn_parsing = extension.has_dynamic_parsing if extension else False
        opted_count = extension.opted_fields_count if extension else 0

        telem_status = (telemetry.get("status") or "").lower()
        drop_reason = telemetry.get("latest_drop_reason_code")
        anom_since = telemetry.get("anomalous_since")
        last_norm = telemetry.get("last_normalization_time")
        latency = telemetry.get("event_latency")

        # Deep dive telemetry extraction
        collector_name = deep_dive_telemetry.collector_by_log_type.get(log_type)
        funnel = deep_dive_telemetry.volume_funnel_by_log_type.get(log_type, {})
        errors = deep_dive_telemetry.parser_errors_by_log_type.get(log_type, [])
        zscore_detail = errors[0].get("issue") if errors else None
        quota_rejected = deep_dive_telemetry.quota_rejected_volume_mb.get(log_type, 0.0)
        quota_limit = deep_dive_telemetry.quota_limit_mb_per_sec.get(log_type, 0.0)

        # 1. No Active Parser
        if not parser or state.upper() not in ("ACTIVE", "LIVE"):
            return ParserHealthFinding(
                log_type=log_type,
                parser_id=p_id,
                status=ParserHealthStatus.INACTIVE_NO_PARSER,
                state=state,
                creator_source=creator,
                collector_name=collector_name,
                version=version,
                latest_version=latest_ver,
                rollback_available=rollback,
                has_extension=has_ext,
                extension_id=ext_id,
                extension_state=ext_state,
                dynamic_parsing_enabled=dyn_parsing,
                opted_fields_count=opted_count,
                drop_reason_code=drop_reason,
                zscore_anomaly_detail=zscore_detail,
                anomalous_since=anom_since,
                last_normalization_time=last_norm,
                event_latency=latency,
                volume_funnel=funnel,
                quota_rejected_volume_mb=quota_rejected,
                quota_limit_mb_per_sec=quota_limit,
                anomaly_description=f"Log type '{log_type}' has no active parser configured in SecOps.",
                remediation_steps=[
                    f"Activate default parser or submit custom CBN parser for log type '{log_type}'.",
                    "Verify if raw ingestion feeds for this log type are producing data.",
                ],
                raw=raw,
            )

        # 2. Critical Health Hub Signal
        if telem_status in ("critical", "failed"):
            remediation = [
                f"Inspect parser CBN Logstash definition for syntax errors on '{log_type}'.",
                "Review recent raw ingestion logs to see if upstream log format changed.",
                "If custom parser, run parser validation with test logs.",
            ]
            if quota_rejected > 0.0:
                remediation.append(f"Quota burst limit exceeded: {quota_rejected:.2f} MB dropped. Increase tenant quota allocation.")

            desc = f"Health Hub flagged parser as CRITICAL: {drop_reason or 'Normalization error'}."
            if zscore_detail:
                desc += f" Anomaly Detail: {zscore_detail}."

            return ParserHealthFinding(
                log_type=log_type,
                parser_id=p_id,
                status=ParserHealthStatus.FAILED,
                state=state,
                creator_source=creator,
                collector_name=collector_name,
                version=version,
                latest_version=latest_ver,
                rollback_available=rollback,
                has_extension=has_ext,
                extension_id=ext_id,
                extension_state=ext_state,
                dynamic_parsing_enabled=dyn_parsing,
                opted_fields_count=opted_count,
                drop_reason_code=drop_reason,
                zscore_anomaly_detail=zscore_detail,
                anomalous_since=anom_since,
                last_normalization_time=last_norm,
                event_latency=latency,
                volume_funnel=funnel,
                quota_rejected_volume_mb=quota_rejected,
                quota_limit_mb_per_sec=quota_limit,
                anomaly_description=desc,
                remediation_steps=remediation,
                raw=raw,
            )

        # 3. Warning / Irregular Health Hub Signal
        if telem_status in ("warning", "irregular"):
            remediation = [
                "Check for unmapped fields or partial regex match failures in CBN code.",
                "Review parser extension snippet to ensure JSON/grok fields are captured.",
            ]
            if quota_rejected > 0.0:
                remediation.append(f"Quota burst limit exceeded: {quota_rejected:.2f} MB dropped. Increase tenant quota allocation.")

            desc = f"Health Hub flagged parser as IRREGULAR: {drop_reason or 'Intermittent parsing drops'}."
            if zscore_detail:
                desc += f" Anomaly Detail: {zscore_detail}."

            return ParserHealthFinding(
                log_type=log_type,
                parser_id=p_id,
                status=ParserHealthStatus.IRREGULAR,
                state=state,
                creator_source=creator,
                collector_name=collector_name,
                version=version,
                latest_version=latest_ver,
                rollback_available=rollback,
                has_extension=has_ext,
                extension_id=ext_id,
                extension_state=ext_state,
                dynamic_parsing_enabled=dyn_parsing,
                opted_fields_count=opted_count,
                drop_reason_code=drop_reason,
                zscore_anomaly_detail=zscore_detail,
                anomalous_since=anom_since,
                last_normalization_time=last_norm,
                event_latency=latency,
                volume_funnel=funnel,
                quota_rejected_volume_mb=quota_rejected,
                quota_limit_mb_per_sec=quota_limit,
                anomaly_description=desc,
                remediation_steps=remediation,
                raw=raw,
            )

        # 4. Extension Conflict / Disabled State
        if has_ext and ext_state and ext_state.upper() in ("ERROR", "FAILED"):
            return ParserHealthFinding(
                log_type=log_type,
                parser_id=p_id,
                status=ParserHealthStatus.EXTENSION_CONFLICT,
                state=state,
                creator_source=creator,
                collector_name=collector_name,
                version=version,
                latest_version=latest_ver,
                rollback_available=rollback,
                has_extension=has_ext,
                extension_id=ext_id,
                extension_state=ext_state,
                dynamic_parsing_enabled=dyn_parsing,
                opted_fields_count=opted_count,
                drop_reason_code=drop_reason,
                zscore_anomaly_detail=zscore_detail,
                anomalous_since=anom_since,
                last_normalization_time=last_norm,
                event_latency=latency,
                volume_funnel=funnel,
                quota_rejected_volume_mb=quota_rejected,
                quota_limit_mb_per_sec=quota_limit,
                anomaly_description=f"Parser Extension '{ext_id}' is in ERROR state.",
                remediation_steps=[
                    "Validate extension CBN snippet against sample logs.",
                    "Check dynamic parsing opted fields for invalid JSON paths.",
                ],
                raw=raw,
            )

        # 5. Version Drift Check
        if version and latest_ver and version != latest_ver and creator.upper() == "GOOGLE":
            return ParserHealthFinding(
                log_type=log_type,
                parser_id=p_id,
                status=ParserHealthStatus.VERSION_DRIFT,
                state=state,
                creator_source=creator,
                collector_name=collector_name,
                version=version,
                latest_version=latest_ver,
                rollback_available=rollback,
                has_extension=has_ext,
                extension_id=ext_id,
                extension_state=ext_state,
                dynamic_parsing_enabled=dyn_parsing,
                opted_fields_count=opted_count,
                drop_reason_code=drop_reason,
                zscore_anomaly_detail=zscore_detail,
                anomalous_since=anom_since,
                last_normalization_time=last_norm,
                event_latency=latency,
                volume_funnel=funnel,
                quota_rejected_volume_mb=quota_rejected,
                quota_limit_mb_per_sec=quota_limit,
                anomaly_description=f"Parser version drift: active version is v{version}, but v{latest_ver} is available.",
                remediation_steps=[
                    f"Upgrade parser for '{log_type}' from v{version} to latest Google default v{latest_ver}.",
                    "Test parser changes in SIEM Settings before deploying to production.",
                ],
                raw=raw,
            )

        # 6. Default Healthy
        desc = "Parser is healthy and normalizing events."
        if has_ext:
            desc += f" (Active Extension with {opted_count} dynamic fields)."

        return ParserHealthFinding(
            log_type=log_type,
            parser_id=p_id,
            status=ParserHealthStatus.HEALTHY,
            state=state,
            creator_source=creator,
            collector_name=collector_name,
            version=version,
            latest_version=latest_ver,
            rollback_available=rollback,
            has_extension=has_ext,
            extension_id=ext_id,
            extension_state=ext_state,
            dynamic_parsing_enabled=dyn_parsing,
            opted_fields_count=opted_count,
            drop_reason_code=drop_reason,
            zscore_anomaly_detail=zscore_detail,
            anomalous_since=anom_since,
            last_normalization_time=last_norm,
            event_latency=latency,
            volume_funnel=funnel,
            quota_rejected_volume_mb=quota_rejected,
            quota_limit_mb_per_sec=quota_limit,
            anomaly_description=desc,
            remediation_steps=[],
            raw=raw,
        )
