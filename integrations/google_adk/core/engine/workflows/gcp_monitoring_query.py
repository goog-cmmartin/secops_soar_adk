"""Workflow implementation for querying Google Cloud Monitoring for Chronicle and SecOps telemetry."""

from datetime import datetime, timedelta, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from engine.domain import (
    ChronicleIngestionMetricsResult,
    GcpMonitoringQueryResult,
    IngestionMetricPoint,
    LogTypeIngestionSeries,
    MetricPoint,
    TimeSeriesData,
)

logger = logging.getLogger(__name__)


def _extract_point_value(val_dict: Any) -> Any:
    """Extracts typed value from a Google Cloud Monitoring TimeSeries point value dict."""
    if not isinstance(val_dict, dict):
        return val_dict
    if "int64Value" in val_dict:
        try:
            return int(val_dict["int64Value"])
        except (ValueError, TypeError):
            return val_dict["int64Value"]
    if "doubleValue" in val_dict:
        try:
            return float(val_dict["doubleValue"])
        except (ValueError, TypeError):
            return val_dict["doubleValue"]
    if "boolValue" in val_dict:
        return bool(val_dict["boolValue"])
    if "stringValue" in val_dict:
        return str(val_dict["stringValue"])
    if "distributionValue" in val_dict:
        return val_dict["distributionValue"]
    return val_dict


def _normalize_time_series(raw: Dict[str, Any]) -> TimeSeriesData:
    """Transforms a raw Google Cloud Monitoring JSON TimeSeries into a typed TimeSeriesData."""
    metric = raw.get("metric", {}) if isinstance(raw.get("metric"), dict) else {}
    resource = raw.get("resource", {}) if isinstance(raw.get("resource"), dict) else {}

    raw_points = raw.get("points", []) or []
    points: List[MetricPoint] = []
    for p in raw_points:
        if isinstance(p, dict):
            interval = p.get("interval", {}) if isinstance(p.get("interval"), dict) else {}
            val = _extract_point_value(p.get("value", {}))
            points.append(
                MetricPoint(
                    start_time=interval.get("startTime", ""),
                    end_time=interval.get("endTime", ""),
                    value=val,
                )
            )

    return TimeSeriesData(
        metric_type=metric.get("type", ""),
        metric_labels=metric.get("labels", {}) if isinstance(metric.get("labels"), dict) else {},
        resource_type=resource.get("type", ""),
        resource_labels=resource.get("labels", {}) if isinstance(resource.get("labels"), dict) else {},
        metric_kind=raw.get("metricKind", "GAUGE"),
        value_type=raw.get("valueType", "INT64"),
        points=points,
        raw=raw,
    )


# Chronicle ingestion metrics verified on a live tenant (2026-10-09). All are
# DELTA/INT64 on resource type chronicle.googleapis.com/Collector, whose
# resource labels include log_type, collector_id, project_id, location.
CHRONICLE_METRIC_PREFIX = "chronicle.googleapis.com/"
CHRONICLE_COLLECTOR_RESOURCE_TYPE = "chronicle.googleapis.com/Collector"
CHRONICLE_INGESTION_METRICS = (
    "ingestion/log/record_count",
    "ingestion/log/bytes_count",
    "normalizer/log/record_count",
)
LOG_TYPE_GROUP_FIELD = "resource.label.log_type"
ALL_LOG_TYPES_KEY = "ALL"
_MAX_MONITORING_PAGES = 100
_LOG_TYPE_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


def resolve_chronicle_ingestion_metric(metric: str) -> str:
    """Validates ``metric`` against the allowed set and returns the full metric type."""
    short = (metric or "").strip()
    if short.startswith(CHRONICLE_METRIC_PREFIX):
        short = short[len(CHRONICLE_METRIC_PREFIX):]
    if short not in CHRONICLE_INGESTION_METRICS:
        raise ValueError(
            f"Unsupported Chronicle ingestion metric '{metric}'. "
            f"Allowed: {', '.join(CHRONICLE_INGESTION_METRICS)}."
        )
    return CHRONICLE_METRIC_PREFIX + short


def build_chronicle_ingestion_filter(metric: str, log_types: Optional[List[str]] = None) -> str:
    """Builds a Cloud Monitoring filter selecting exactly one Chronicle metric type.

    ``log_types`` filters on the *resource* label ``log_type`` (the metric has no
    ``log_type`` metric label).
    """
    parts = [
        f'metric.type = "{resolve_chronicle_ingestion_metric(metric)}"',
        f'resource.type = "{CHRONICLE_COLLECTOR_RESOURCE_TYPE}"',
    ]
    clean: List[str] = []
    for lt in log_types or []:
        lt = (lt or "").strip()
        if not lt or not set(lt) <= _LOG_TYPE_CHARS:
            raise ValueError(f"Invalid log type '{lt}': expected letters, digits and underscores only.")
        clean.append(lt)
    if len(clean) == 1:
        parts.append(f'{LOG_TYPE_GROUP_FIELD} = "{clean[0]}"')
    elif clean:
        joined = ", ".join(f'"{lt}"' for lt in clean)
        parts.append(f"{LOG_TYPE_GROUP_FIELD} = one_of({joined})")
    return " AND ".join(parts)


def parse_ingestion_series(
    series: List[TimeSeriesData], group_by_log_type: bool
) -> List[LogTypeIngestionSeries]:
    """Collapses normalized streams into per-log-type point lists sorted by start time.

    Streams with the same log type (e.g. split across pages) are merged; duplicate
    intervals keep the first value seen. Result is ordered by total, descending.
    """
    merged: Dict[str, Dict[Tuple[str, str], Any]] = {}
    for ts in series:
        key = (ts.resource_labels.get("log_type") or "UNKNOWN") if group_by_log_type else ALL_LOG_TYPES_KEY
        bucket = merged.setdefault(key, {})
        for p in ts.points:
            bucket.setdefault((p.start_time, p.end_time), p.value)
    out = [
        LogTypeIngestionSeries(
            log_type=key,
            points=[IngestionMetricPoint(start=s, end=e, value=v) for (s, e), v in sorted(bucket.items())],
        )
        for key, bucket in merged.items()
    ]
    out.sort(key=lambda s: (-s.total, s.log_type))
    return out


class GcpMonitoringQueryWorkflow:
    """Executes time series queries against Google Cloud Monitoring API (v3) for SecOps telemetry."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        filter_str: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        hours: int = 24,
        project_id: Optional[str] = None,
        alignment_period: Optional[str] = None,
        per_series_aligner: Optional[str] = None,
        cross_series_reducer: Optional[str] = None,
        group_by_fields: Optional[List[str]] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Executes a Cloud Monitoring time series query with interval calculation, alignment, and normalization."""
        if not filter_str:
            raise ValueError("Cloud Monitoring query requires a non-empty filter_str expression.")

        now = datetime.now(timezone.utc)
        if not end_time:
            end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        if not start_time:
            start_dt = now - timedelta(hours=hours)
            start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        raw_resp = self.adapter.query_cloud_monitoring_time_series(
            filter_str=filter_str,
            start_time=start_time,
            end_time=end_time,
            project_id=project_id,
            alignment_period=alignment_period,
            per_series_aligner=per_series_aligner,
            cross_series_reducer=cross_series_reducer,
            group_by_fields=group_by_fields,
            page_size=page_size,
            page_token=page_token,
        )

        raw_series = raw_resp.get("timeSeries", []) or []
        series = [_normalize_time_series(s) for s in raw_series]
        next_token = raw_resp.get("nextPageToken")
        queried_projects = [project_id] if project_id else [getattr(self.adapter, "project_id", "")]

        return GcpMonitoringQueryResult(
            time_series=series,
            next_page_token=next_token,
            total_series=len(series),
            filter_applied=filter_str,
            time_interval=f"{start_time} - {end_time}",
            projects_queried=queried_projects,
        )

    def query_chronicle_ingestion_metrics(
        self,
        hours: int = 24,
        log_type: Optional[str] = None,
        alignment_period: str = "3600s",
        per_series_aligner: str = "ALIGN_SUM",
        project_id: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Queries Chronicle log ingestion count and volume metrics (legacy filter).

        Legacy: the ``starts_with`` filter matches several metric types, which the
        live Cloud Monitoring API rejects with HTTP 400, and ``log_type`` is a
        resource label, not a metric label. Use ``query_chronicle_ingestion_series``
        (what ``SecOpsEngine.get_chronicle_ingestion_metrics`` calls).
        """
        filter_parts = ['metric.type = starts_with("chronicle.googleapis.com/")']
        if log_type:
            filter_parts.append(f'metric.label.log_type = "{log_type}"')

        combined_filter = " AND ".join(filter_parts)
        return self.execute(
            filter_str=combined_filter,
            hours=hours,
            project_id=project_id,
            alignment_period=alignment_period,
            per_series_aligner=per_series_aligner,
        )

    def query_chronicle_ingestion_series(
        self,
        metric: str = "ingestion/log/record_count",
        lookback_hours: int = 24,
        log_types: Optional[List[str]] = None,
        group_by_log_type: bool = True,
        alignment_period_s: int = 3600,
        project_id: Optional[str] = None,
    ) -> ChronicleIngestionMetricsResult:
        """Queries one Chronicle ingestion metric, aligned with ALIGN_SUM, per log type.

        - Exactly one metric type per call (Cloud Monitoring rejects filters that
          match several metrics with HTTP 400).
        - log_type filtering/grouping uses ``resource.label.log_type``.
        - ``group_by_log_type=True`` reduces with REDUCE_SUM grouped by log type;
          False reduces everything into a single ``"ALL"`` series.
        - Follows ``nextPageToken`` until exhausted; API errors propagate.
        """
        filter_str = build_chronicle_ingestion_filter(metric, log_types)
        if int(lookback_hours) <= 0:
            raise ValueError("lookback_hours must be a positive integer.")
        if int(alignment_period_s) < 60:
            raise ValueError("alignment_period_s must be at least 60 seconds.")
        alignment = f"{int(alignment_period_s)}s"
        group_fields = [LOG_TYPE_GROUP_FIELD] if group_by_log_type else []
        proj = project_id or getattr(self.adapter, "project_id", "")

        now = datetime.now(timezone.utc)
        end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        start_time = (now - timedelta(hours=int(lookback_hours))).strftime("%Y-%m-%dT%H:%M:%SZ")

        raw_series: List[TimeSeriesData] = []
        page_token: Optional[str] = None
        pages = 0
        started = time.monotonic()
        while True:
            if pages >= _MAX_MONITORING_PAGES:
                raise RuntimeError(
                    f"Cloud Monitoring pagination exceeded {_MAX_MONITORING_PAGES} pages for filter: {filter_str}"
                )
            resp = self.adapter.query_cloud_monitoring_time_series(
                filter_str=filter_str,
                start_time=start_time,
                end_time=end_time,
                project_id=proj or None,
                alignment_period=alignment,
                per_series_aligner="ALIGN_SUM",
                cross_series_reducer="REDUCE_SUM",
                group_by_fields=group_fields or None,
                page_size=1000,
                page_token=page_token,
            )
            pages += 1
            raw_series.extend(_normalize_time_series(s) for s in (resp.get("timeSeries") or []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        duration = round(time.monotonic() - started, 3)

        return ChronicleIngestionMetricsResult(
            metric_type=resolve_chronicle_ingestion_metric(metric),
            filter_applied=filter_str,
            project_id=proj,
            start_time=start_time,
            end_time=end_time,
            alignment_period=alignment,
            per_series_aligner="ALIGN_SUM",
            cross_series_reducer="REDUCE_SUM",
            group_by_fields=group_fields,
            called_at=now.isoformat(),
            call_duration_s=duration,
            pages_fetched=pages,
            series=parse_ingestion_series(raw_series, group_by_log_type),
            time_series=raw_series,
        )

    def query_chronicle_normalizer_metrics(
        self,
        hours: int = 24,
        log_type: Optional[str] = None,
        alignment_period: str = "3600s",
        per_series_aligner: str = "ALIGN_SUM",
        project_id: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Queries Chronicle normalizer and parser throughput metrics."""
        filter_parts = ['metric.type = starts_with("chronicle.googleapis.com/normalizer")']
        if log_type:
            filter_parts.append(f'metric.label.log_type = "{log_type}"')

        combined_filter = " AND ".join(filter_parts)
        return self.execute(
            filter_str=combined_filter,
            hours=hours,
            project_id=project_id,
            alignment_period=alignment_period,
            per_series_aligner=per_series_aligner,
        )

    def query_chronicle_api_metrics(
        self,
        hours: int = 24,
        alignment_period: str = "3600s",
        per_series_aligner: str = "ALIGN_RATE",
        cross_series_reducer: str = "REDUCE_SUM",
        project_id: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Queries Chronicle API consumption and request rate metrics (serviceruntime)."""
        combined_filter = (
            'metric.type = "serviceruntime.googleapis.com/api/request_count" '
            'AND resource.type = "consumed_api" '
            'AND resource.label.service = "chronicle.googleapis.com"'
        )
        return self.execute(
            filter_str=combined_filter,
            hours=hours,
            project_id=project_id,
            alignment_period=alignment_period,
            per_series_aligner=per_series_aligner,
            cross_series_reducer=cross_series_reducer,
        )

    def query_chronicle_agent_metrics(
        self,
        hours: int = 24,
        alignment_period: str = "300s",
        per_series_aligner: str = "ALIGN_MEAN",
        project_id: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Queries Chronicle forwarder agent queue size, capacity, and CPU consumption."""
        combined_filter = 'metric.type = starts_with("chronicle.googleapis.com/agent/")'
        return self.execute(
            filter_str=combined_filter,
            hours=hours,
            project_id=project_id,
            alignment_period=alignment_period,
            per_series_aligner=per_series_aligner,
        )
