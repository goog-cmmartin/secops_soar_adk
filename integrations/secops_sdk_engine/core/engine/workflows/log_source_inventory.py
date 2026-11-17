"""SecOps Log Source Inventory & Collector Health Workflow.

Bridges Google SecOps (Chronicle) ingestion telemetry, UDM multi-host event autodetection,
Chronicle Feeds API, and downstream Bindplane OTel Agent & Configuration APIs into:
1. A stateful Chronicle Data Table (`asoc_log_source_inventory`) that tracks:
   - Registered Bindplane OTel Agents, their assigned OTel pipeline configurations,
     configured source log types, active filter/drop processors, and per-log-type
     health (`HEALTHY`, `PARTIAL_DROP`, `SILENT_AGENT`).
   - Configured Chronicle Feeds (`v1alpha/feeds`) and their operational health
     (`HEALTHY`, `FEED_SILENT`, `FEED_FAILED`, `INACTIVE`).
   - Auto-discovered individual child hosts/devices sitting behind shared multi-host
     feeds, forwarders, and cloud sinks (QRadar "Log Source Identifier" parity),
     persisting them across runs so hosts that stop sending logs are flagged as
     `SILENT_HOST` instead of disappearing.
   - Log Source Grouping (`log_source_group`) populated automatically from
     `metadata.ingestion_labels` (`log_source_group`, `environment`, `sourceUsecase`,
     `sourceFolder`, `ingestion_source`) or Bindplane configs, while preserving custom
     analyst group overrides in the Data Table.
2. A Chronicle Native Dashboard (`Log Source Inventory & Collector Health`) combining
   live GoogleSQL Pipe Syntax (`|>`) visualizations with rich Markdown inventory tables.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from engine.domain import DashboardSearchQuery
from engine.workflows.dashboards import (
    AddDashboardChartWorkflow,
    CreateDashboardWorkflow,
    GetDashboardDetailWorkflow,
    SearchDashboardsWorkflow,
    UpdateDashboardChartWorkflow,
    UpdateDashboardWorkflow,
)
from engine.workflows.feed import SearchFeedsWorkflow
from engine.workflows.homepage_dashboard import _build_kpi_text_visualization

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine

logger = logging.getLogger(__name__)

DEFAULT_INVENTORY_DATA_TABLE_ID = "asoc_log_source_inventory"
DEFAULT_INVENTORY_DASHBOARD_TITLE = "Log Source Inventory & Collector Health"
DEFAULT_BINDPLANE_API_URL = "https://app.bindplane.com/v1"

INVENTORY_COLUMNS: List[Dict[str, Any]] = [
    {"columnIndex": 0, "originalColumn": "inventory_key", "columnType": "STRING"},
    {"columnIndex": 1, "originalColumn": "source_category", "columnType": "STRING"},
    {"columnIndex": 2, "originalColumn": "ingestion_mechanism", "columnType": "STRING"},
    {"columnIndex": 3, "originalColumn": "log_type", "columnType": "STRING"},
    {"columnIndex": 4, "originalColumn": "log_source_identifier", "columnType": "STRING"},
    {"columnIndex": 5, "originalColumn": "log_source_group", "columnType": "STRING"},
    {"columnIndex": 6, "originalColumn": "otel_or_feed_config", "columnType": "STRING"},
    {"columnIndex": 7, "originalColumn": "health_status", "columnType": "STRING"},
    {"columnIndex": 8, "originalColumn": "events_24h", "columnType": "STRING"},
    {"columnIndex": 9, "originalColumn": "volume_mb_24h", "columnType": "STRING"},
    {"columnIndex": 10, "originalColumn": "last_seen_utc", "columnType": "STRING"},
]

# User's canonical GoogleSQL Pipe Syntax query for Ingestion Mechanism Volume & Diversity
INGESTION_MECHANISM_SQL_QUERY = """FROM ingestion
|> WHERE component = 'Ingestion API'
    AND NULLIF(log_type, '') IS NOT NULL
|> EXTEND
    CASE collector_id
      WHEN 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' THEN 'Out-of-Band Feeds (S3 / GCS / API)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1111' THEN 'Bindplane Agent (Google Edition)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1112' THEN 'Bindplane Enterprise (Google Edition)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1113' THEN 'Bindplane Enterprise'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1114' THEN 'Headless Collector (OTel)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1115' THEN 'Chronicle REST API'
      WHEN 'aaaa2222-aaaa-2222-aaaa-2222aaaa2222' THEN 'HTTPS Push (Webhook / PubSub / Firehose)'
      WHEN 'aaaa3333-aaaa-3333-aaaa-3333aaaa3333' THEN 'Native GCP / Cloud Storage / ETD'
      WHEN 'aaaa4444-aaaa-4444-aaaa-4444aaaa4444' THEN 'Azure Event Hub'
      WHEN 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' THEN 'Legacy Unstructured Log Entries API'
      WHEN 'cccccccc-cccc-cccc-cccc-cccccccccccc' THEN 'Legacy UDM Events API'
      WHEN 'dddddddd-dddd-dddd-dddd-dddddddddddd' THEN 'Native Google Workspace'
      WHEN 'ffffffff-ffff-ffff-ffff-ffffffffffff' THEN 'SOAR Alerts'
      ELSE IF(NULLIF(collector_id, '') IS NOT NULL, 'SecOps Forwarder', 'Unspecified')
    END AS ingestion_mechanism
|> AGGREGATE
    ROUND(SUM(log_volume) / POW(1000, 3), 4) AS total_gb,
    COUNT(DISTINCT log_type) AS distinct_log_types
  GROUP BY ingestion_mechanism
|> EXTEND
    ROUND(total_gb * 100.0 / NULLIF(SUM(total_gb) OVER (), 0), 2) AS pct_of_total
|> ORDER BY total_gb DESC"""

# Detailed collector + ingestion_source breakdown from `ingestion` table
INGESTION_SOURCE_BREAKDOWN_SQL_QUERY = """FROM ingestion
|> WHERE component = 'Ingestion API'
    AND NULLIF(log_type, '') IS NOT NULL
|> EXTEND
    CASE collector_id
      WHEN 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' THEN 'Out-of-Band Feeds (S3 / GCS / API)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1111' THEN 'Bindplane Agent (Google Edition)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1112' THEN 'Bindplane Enterprise (Google Edition)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1113' THEN 'Bindplane Enterprise'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1114' THEN 'Headless Collector (OTel)'
      WHEN 'aaaa1111-aaaa-1111-aaaa-1111aaaa1115' THEN 'Chronicle REST API'
      WHEN 'aaaa2222-aaaa-2222-aaaa-2222aaaa2222' THEN 'HTTPS Push (Webhook / PubSub / Firehose)'
      WHEN 'aaaa3333-aaaa-3333-aaaa-3333aaaa3333' THEN 'Native GCP / Cloud Storage / ETD'
      WHEN 'aaaa4444-aaaa-4444-aaaa-4444aaaa4444' THEN 'Azure Event Hub'
      WHEN 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' THEN 'Legacy Unstructured Log Entries API'
      WHEN 'cccccccc-cccc-cccc-cccc-cccccccccccc' THEN 'Legacy UDM Events API'
      WHEN 'dddddddd-dddd-dddd-dddd-dddddddddddd' THEN 'Native Google Workspace'
      WHEN 'ffffffff-ffff-ffff-ffff-ffffffffffff' THEN 'SOAR Alerts'
      ELSE IF(NULLIF(collector_id, '') IS NOT NULL, 'SecOps Forwarder', 'Unspecified')
    END AS ingestion_mechanism,
    COALESCE(NULLIF(ingestion_source, ''), '(Collector / API Direct)') AS source_host
|> AGGREGATE
    SUM(log_count) AS total_logs,
    ROUND(SUM(log_volume) / POW(1000, 2), 2) AS total_mb,
    MAX(TIMESTAMP_SECONDS(end_time)) AS last_seen_ts
  GROUP BY ingestion_mechanism, collector_id, source_host, log_type
|> ORDER BY total_mb DESC"""

# Multi-Host Feed & Agent Device Autodetection + Ingestion Label Grouping from `events`
MULTI_HOST_UDM_SQL_QUERY = """FROM events
|> WHERE NULLIF(metadata.log_type, '') IS NOT NULL
|> EXTEND
    COALESCE(
      NULLIF((SELECT l.value FROM UNNEST(metadata.ingestion_labels) AS l WHERE l.key = 'ingestion_source' LIMIT 1), ''),
      NULLIF(observer.hostname, ''),
      NULLIF(principal.hostname, ''),
      NULLIF(src.hostname, ''),
      NULLIF(target.hostname, ''),
      NULLIF(principal.asset.hostname, ''),
      NULLIF(target.asset.hostname, ''),
      NULLIF(observer.asset.hostname, ''),
      NULLIF(metadata.product_name, ''),
      metadata.log_type
    ) AS log_source_identifier,
    COALESCE(
      NULLIF((SELECT l.value FROM UNNEST(metadata.ingestion_labels) AS l WHERE l.key IN ('log_source_group', 'environment', 'sourceUsecase', 'sourceFolder') LIMIT 1), ''),
      NULLIF((SELECT l.value FROM UNNEST(metadata.ingestion_labels) AS l WHERE l.key = 'ingestion_source' LIMIT 1), ''),
      NULLIF(metadata.vendor_name, ''),
      'UNGROUPED'
    ) AS log_source_group
|> AGGREGATE
    COUNT(1) AS event_count,
    MAX(TIMESTAMP_SECONDS(metadata.event_timestamp.seconds)) AS last_event_ts
  GROUP BY metadata.log_type AS log_type, log_source_identifier, log_source_group
|> ORDER BY event_count DESC
|> LIMIT 250"""


def _sanitize_cell(val: Any, max_len: int = 380) -> str:
    """Normalizes string for Data Table storage and Markdown table safety."""
    if val is None:
        return ""
    text = re.sub(r"\s+", " ", str(val)).strip()
    text = text.replace("|", "/")
    if len(text) > max_len:
        text = text[: max_len - 3].rsplit(" ", 1)[0] + "..."
    return text


def _make_inventory_key(source_category: str, log_type: str, identifier: str) -> str:
    """Constructs a deterministic primary key for a log source inventory row."""
    clean_cat = re.sub(r"[^A-Za-z0-9_.-]", "_", str(source_category).strip().upper())
    clean_lt = re.sub(r"[^A-Za-z0-9_.-]", "_", str(log_type).strip().upper())
    clean_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(identifier).strip())[:90]
    return f"{clean_cat}:{clean_lt}:{clean_id}"


def _build_sql_table_visualization(columns: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Builds a Chronicle Native Dashboard Table visualization config for SQL queries."""
    return {
        "xAxes": [{"axisType": "VALUE"}],
        "yAxes": [{"axisType": "VALUE"}],
        "legends": [{"legendOrient": "HORIZONTAL"}],
        "columnDefs": [{"field": field, "header": header} for field, header in columns],
        "groupingType": "Off",
        "tableConfig": {},
    }


@dataclass
class LogSourceInventoryItem:
    """Normalized Log Source Inventory record persisted in `asoc_log_source_inventory`."""

    inventory_key: str
    source_category: str          # OTEL_AGENT, CLOUD_FEED, MULTI_HOST_FEED_DEVICE, FORWARDER, NATIVE_GCP, API_PUSH
    ingestion_mechanism: str      # Human-readable collector mechanism
    log_type: str                 # Chronicle log_type (e.g. BRO_JSON, WINEVTLOG, CS_EDR)
    log_source_identifier: str    # Hostname, device identifier, or feed display name
    log_source_group: str         # Group from ingestion_labels, Bindplane config, or analyst override
    otel_or_feed_config: str      # Downstream Bindplane OTel pipeline config/processors or Feed details
    health_status: str            # HEALTHY, PARTIAL_DROP, SILENT_AGENT, SILENT_HOST, FEED_SILENT, FEED_FAILED, INACTIVE
    events_24h: int
    volume_mb_24h: float
    last_seen_utc: str

    def to_row_values(self) -> List[str]:
        return [
            _sanitize_cell(self.inventory_key, 180),
            _sanitize_cell(self.source_category, 40),
            _sanitize_cell(self.ingestion_mechanism, 80),
            _sanitize_cell(self.log_type, 60),
            _sanitize_cell(self.log_source_identifier, 120),
            _sanitize_cell(self.log_source_group, 100),
            _sanitize_cell(self.otel_or_feed_config, 360),
            _sanitize_cell(self.health_status, 40),
            str(max(0, int(self.events_24h))),
            f"{max(0.0, float(self.volume_mb_24h)):.2f}",
            _sanitize_cell(self.last_seen_utc, 40),
        ]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _resolve_bindplane_credentials(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    account_id: Optional[str] = None,
) -> Tuple[str, str, str]:
    """Resolves Bindplane REST API URL, API key, and Account/Project ID from parameters, environment, or local .env files."""
    resolved_url = (api_url or os.environ.get("BINDPLANE_API_URL") or "").strip()
    resolved_key = (api_key or os.environ.get("BINDPLANE_API_KEY") or "").strip()
    resolved_account = (
        account_id
        or os.environ.get("BINDPLANE_PROJECT_ID")
        or os.environ.get("BINDPLANE_ACCOUNT_ID")
        or ""
    ).strip()

    if not resolved_key or not resolved_account:
        candidate_envs = [
            os.path.join(os.getcwd(), ".env"),
            os.path.expanduser("~/Documents/Project/secops-agent-skills/.env"),
            os.path.expanduser("~/Documents/Project/secops_soar_dev_env/.env"),
        ]
        for env_file in candidate_envs:
            if os.path.isfile(env_file):
                try:
                    with open(env_file, "r", encoding="utf-8") as fh:
                        for raw_line in fh:
                            line = raw_line.strip()
                            if not line or line.startswith("#") or "=" not in line:
                                continue
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'").strip('"')
                            if k == "BINDPLANE_API_KEY" and not resolved_key:
                                resolved_key = v
                            elif k in ("BINDPLANE_PROJECT_ID", "BINDPLANE_ACCOUNT_ID") and not resolved_account:
                                resolved_account = v
                            elif k == "BINDPLANE_API_URL" and not resolved_url:
                                resolved_url = v
                except Exception:
                    pass

    if not resolved_url:
        resolved_url = DEFAULT_BINDPLANE_API_URL
    return resolved_url.rstrip("/"), resolved_key, resolved_account


def fetch_bindplane_inventory(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    account_id: Optional[str] = None,
    timeout_seconds: int = 20,
) -> Dict[str, Any]:
    """Queries the Bindplane REST API (/v1/agents and /v1/configs) to discover downstream OTel agents and pipelines."""
    base_url, key, acct_id = _resolve_bindplane_credentials(
        api_url=api_url, api_key=api_key, account_id=account_id
    )
    if not key:
        return {
            "available": False,
            "agents": [],
            "configs_by_key": {},
            "error": "Bindplane API Key not provided or found in environment.",
        }

    headers = {
        "X-Bindplane-Api-Key": key,
        "Accept": "application/json",
        "User-Agent": "Google-SecOps-SDK-Engine/6.3",
    }
    if acct_id:
        headers["X-Bindplane-Account-ID"] = acct_id

    try:
        req_agents = urllib.request.Request(f"{base_url}/agents", headers=headers, method="GET")
        with urllib.request.urlopen(req_agents, timeout=timeout_seconds) as resp:
            agents_payload = json.loads(resp.read().decode("utf-8"))
        agents_list = agents_payload.get("agents", []) if isinstance(agents_payload, dict) else []

        try:
            req_configs = urllib.request.Request(f"{base_url}/configurations", headers=headers, method="GET")
            with urllib.request.urlopen(req_configs, timeout=timeout_seconds) as resp:
                configs_payload = json.loads(resp.read().decode("utf-8"))
        except Exception:
            req_configs = urllib.request.Request(f"{base_url}/configs", headers=headers, method="GET")
            with urllib.request.urlopen(req_configs, timeout=timeout_seconds) as resp:
                configs_payload = json.loads(resp.read().decode("utf-8"))
        configs_list = (
            configs_payload
            if isinstance(configs_payload, list)
            else configs_payload.get("configurations", configs_payload.get("configs", []))
        )

        # Optional lookup of reusable /v1/processors and /v1/sources for v2 Configurations
        reusable_procs: Dict[str, Dict[str, Any]] = {}
        try:
            req_procs = urllib.request.Request(f"{base_url}/processors", headers=headers, method="GET")
            with urllib.request.urlopen(req_procs, timeout=timeout_seconds) as resp:
                procs_payload = json.loads(resp.read().decode("utf-8"))
            procs_list = (
                procs_payload
                if isinstance(procs_payload, list)
                else procs_payload.get("processors", [])
            )
            for p_item in procs_list:
                if not isinstance(p_item, dict):
                    continue
                p_meta = p_item.get("metadata", {})
                p_name_base = str(p_meta.get("name") or "").strip()
                p_ver = str(p_meta.get("version") or "").strip()
                p_spec = p_item.get("spec", {})
                p_type = str(p_spec.get("type") or "").strip()
                p_params = p_spec.get("parameters") or []
                mapped_lts: List[str] = []
                for prm in p_params:
                    if isinstance(prm, dict) and prm.get("name") == "secops_field":
                        for sf in prm.get("value") or []:
                            if isinstance(sf, dict) and sf.get("logType"):
                                mapped_lts.append(str(sf["logType"]).strip().upper())
                info_obj = {"type": p_type, "log_types": mapped_lts}
                if p_name_base:
                    reusable_procs[p_name_base] = info_obj
                    if p_ver:
                        reusable_procs[f"{p_name_base}:{p_ver}"] = info_obj
        except Exception:
            pass

        reusable_sources: Dict[str, str] = {}
        try:
            req_srcs = urllib.request.Request(f"{base_url}/sources", headers=headers, method="GET")
            with urllib.request.urlopen(req_srcs, timeout=timeout_seconds) as resp:
                srcs_payload = json.loads(resp.read().decode("utf-8"))
            srcs_list = (
                srcs_payload
                if isinstance(srcs_payload, list)
                else srcs_payload.get("sources", [])
            )
            for s_item in srcs_list:
                if not isinstance(s_item, dict):
                    continue
                s_meta = s_item.get("metadata", {})
                s_name_base = str(s_meta.get("name") or "").strip()
                s_ver = str(s_meta.get("version") or "").strip()
                s_type = str(s_item.get("spec", {}).get("type") or "").strip()
                if s_name_base:
                    reusable_sources[s_name_base] = s_type
                    if s_ver:
                        reusable_sources[f"{s_name_base}:{s_ver}"] = s_type
        except Exception:
            pass

        configs_by_name: Dict[str, Dict[str, Any]] = {}
        for cfg in configs_list:
            meta = cfg.get("metadata", {})
            c_name = meta.get("name", "")
            c_ver = meta.get("version", "")
            spec = cfg.get("spec", {})
            platform = (
                spec.get("platform")
                or meta.get("labels", {}).get("platform")
                or "any"
            )
            raw_res = cfg.get("resources", [])
            spec_sources = spec.get("sources", [])

            sources_info: List[Dict[str, Any]] = []
            processors_info: List[Dict[str, str]] = []
            expected_log_types: List[str] = []

            # 1. Parse v1 'resources' array if present
            for r in raw_res:
                kind = r.get("kind", "")
                r_meta = r.get("metadata", {})
                r_name = f"{r_meta.get('name', '')}:{r_meta.get('version', '')}".rstrip(":")
                r_spec = r.get("spec", {})
                r_type = r_spec.get("type", "")
                params = r_spec.get("parameters", [])

                if kind == "Source":
                    found_lt: List[str] = []
                    for p in params:
                        p_name = p.get("name", "")
                        p_val = p.get("value")
                        if p_name == "chronicle_log_type" and p_val:
                            found_lt.append(str(p_val).strip().upper())
                        elif p_name == "file_type_groups" and isinstance(p_val, list):
                            for grp in p_val:
                                if isinstance(grp, dict) and grp.get("chronicle_log_type"):
                                    found_lt.append(str(grp["chronicle_log_type"]).strip().upper())
                    if not found_lt:
                        base_r_name = r_meta.get("name", "").upper()
                        if base_r_name in ("WINEVTLOG", "BRO_JSON", "NIX_SYSTEM", "SYSLOG", "WINDOWS_SYSMON", "POWERSHELL"):
                            found_lt.append(base_r_name)
                    for lt in found_lt:
                        if lt and lt not in expected_log_types:
                            expected_log_types.append(lt)
                    sources_info.append(
                        {
                            "resource": r_name,
                            "source_type": r_type,
                            "log_types": found_lt,
                        }
                    )
                elif kind == "Processor":
                    processors_info.append({"resource": r_name, "processor_type": r_type})

            # 2. Parse v2 'spec.sources' array if present
            for s_obj in spec_sources:
                if not isinstance(s_obj, dict):
                    continue
                s_ref_name = str(
                    s_obj.get("name")
                    or s_obj.get("displayName")
                    or s_obj.get("type")
                    or s_obj.get("id")
                    or "inline-source"
                ).strip()
                s_base_name = s_ref_name.split(":")[0].strip()
                s_type = (
                    str(s_obj.get("type") or "").strip()
                    or reusable_sources.get(s_ref_name)
                    or reusable_sources.get(s_base_name)
                    or "otel_source"
                )
                found_lt_v2: List[str] = []

                for p_obj in s_obj.get("processors") or []:
                    if not isinstance(p_obj, dict):
                        continue
                    p_ref_name = str(
                        p_obj.get("name")
                        or p_obj.get("displayName")
                        or p_obj.get("id")
                        or "processor"
                    ).strip()
                    p_base_name = p_ref_name.split(":")[0].strip()
                    reusable_info = (
                        reusable_procs.get(p_ref_name)
                        or reusable_procs.get(p_base_name)
                        or {}
                    )
                    p_type = (
                        str(p_obj.get("type") or "").strip()
                        or reusable_info.get("type")
                        or "processor"
                    )
                    processors_info.append(
                        {"resource": p_ref_name, "processor_type": p_type}
                    )

                    # Extract Chronicle logType from reusable standardization processor or inline parameters
                    for m_lt in reusable_info.get("log_types") or []:
                        if m_lt and m_lt not in found_lt_v2:
                            found_lt_v2.append(m_lt)
                    for prm in p_obj.get("parameters") or []:
                        if isinstance(prm, dict) and prm.get("name") == "secops_field":
                            for sf in prm.get("value") or []:
                                if isinstance(sf, dict) and sf.get("logType"):
                                    lt_val = str(sf["logType"]).strip().upper()
                                    if lt_val and lt_val not in found_lt_v2:
                                        found_lt_v2.append(lt_val)

                # Fallback inference from source or processor base name
                if not found_lt_v2:
                    upper_base = s_base_name.upper()
                    if upper_base in (
                        "WINEVTLOG",
                        "BRO_JSON",
                        "NIX_SYSTEM",
                        "SYSLOG",
                        "WINDOWS_SYSMON",
                        "POWERSHELL",
                        "JOURNALD",
                    ):
                        found_lt_v2.append(upper_base)
                    elif "JOURNALD" in upper_base:
                        found_lt_v2.append("JOURNALD")

                for lt in found_lt_v2:
                    if lt and lt not in expected_log_types:
                        expected_log_types.append(lt)

                sources_info.append(
                    {
                        "resource": s_ref_name,
                        "source_type": s_type,
                        "log_types": found_lt_v2,
                    }
                )

            filter_procs = [
                p
                for p in processors_info
                if "filter" in p["processor_type"].lower()
                or "drop" in p["processor_type"].lower()
                or "drop" in p["resource"].lower()
            ]
            label_procs = [
                p
                for p in processors_info
                if "ingestion_label" in p["resource"].lower()
                or "copy_field" in p["processor_type"].lower()
            ]

            parsed_cfg = {
                "name": c_name,
                "version": c_ver,
                "platform": platform,
                "expected_log_types": expected_log_types,
                "sources": sources_info,
                "processors": processors_info,
                "filter_processors": filter_procs,
                "label_processors": label_procs,
            }
            if c_name:
                configs_by_name[c_name] = parsed_cfg
                configs_by_name[f"{c_name}:{c_ver}"] = parsed_cfg

        normalized_agents: List[Dict[str, Any]] = []
        for ag in agents_list:
            hostname = str(ag.get("hostname") or ag.get("name") or ag.get("id") or "unknown-agent").strip()
            cfg_ref = ag.get("configuration") if isinstance(ag.get("configuration"), dict) else {}
            cfg_status = ag.get("configurationStatus") if isinstance(ag.get("configurationStatus"), dict) else {}
            ag_labels = ag.get("labels") if isinstance(ag.get("labels"), dict) else {}

            current_cfg_str = str(cfg_status.get("current") or "").strip()
            assigned_cfg_str = str(cfg_status.get("assigned") or ag_labels.get("configuration") or "").strip()

            cfg_name = str(
                cfg_ref.get("name")
                or assigned_cfg_str
                or (current_cfg_str.split(":")[0] if current_cfg_str else "")
            ).strip()
            cfg_ver = (
                cfg_ref.get("version")
                or (current_cfg_str.split(":", 1)[1] if ":" in current_cfg_str else "")
            )
            rollout_status = (
                cfg_ref.get("status", {}).get("rollout")
                if isinstance(cfg_ref.get("status"), dict)
                else ("Valid" if cfg_status.get("currentStage", {}).get("Valid") else "Active")
            )
            matched_cfg = (
                configs_by_name.get(f"{cfg_name}:{cfg_ver}")
                or configs_by_name.get(current_cfg_str)
                or configs_by_name.get(cfg_name)
                or {}
            )
            if not cfg_ver and matched_cfg.get("version"):
                cfg_ver = matched_cfg.get("version")

            os_display = str(
                ag.get("os")
                or ag.get("operatingSystem")
                or ag.get("platform")
                or ag_labels.get("bindplane/agent-os")
                or "Unknown OS"
            ).strip()

            normalized_agents.append(
                {
                    "id": ag.get("id", ""),
                    "hostname": hostname,
                    "connected": bool(ag.get("connected", False)),
                    "status": ag.get("status", "Unknown"),
                    "os": os_display,
                    "agent_version": ag.get("version", ""),
                    "type": ag.get("type", "bindplane-otel-collector"),
                    "config_name": cfg_name,
                    "config_version": cfg_ver,
                    "rollout_status": rollout_status,
                    "expected_log_types": matched_cfg.get("expected_log_types", []),
                    "sources": matched_cfg.get("sources", []),
                    "filter_processors": matched_cfg.get("filter_processors", []),
                    "label_processors": matched_cfg.get("label_processors", []),
                }
            )

        return {
            "available": True,
            "api_url": base_url,
            "agents": normalized_agents,
            "configs_by_name": configs_by_name,
            "error": None,
        }
    except Exception as exc:
        logger.warning("Bindplane API discovery failed: %s", exc)
        return {
            "available": False,
            "api_url": base_url,
            "agents": [],
            "configs_by_name": {},
            "error": str(exc),
        }


class LogSourceInventoryWorkflow:
    """Discovers, correlates, and persists the unified Log Source Inventory Data Table and Native Dashboard."""

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
        data_table_id: str = DEFAULT_INVENTORY_DATA_TABLE_ID,
        sync_dashboard: bool = True,
        dashboard_title: str = DEFAULT_INVENTORY_DASHBOARD_TITLE,
        dashboard_id: Optional[str] = None,
        bindplane_api_url: Optional[str] = None,
        bindplane_api_key: Optional[str] = None,
        include_multi_host_discovery: bool = True,
        max_multi_host_rows: int = 120,
    ) -> Dict[str, Any]:
        """Executes end-to-end Log Source Inventory discovery, Data Table reconciliation, and Dashboard sync."""
        started_dt = datetime.now(timezone.utc)
        now_iso = started_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        now_display = started_dt.strftime("%Y-%m-%d %H:%M UTC")
        collection_errors: List[str] = []

        # ------------------------------------------------------------------
        # 1. Fetch Downstream Bindplane OTel Agents & Pipeline Configurations
        # ------------------------------------------------------------------
        bp_data = fetch_bindplane_inventory(
            api_url=bindplane_api_url,
            api_key=bindplane_api_key,
        )
        if not bp_data.get("available") and bp_data.get("error"):
            collection_errors.append(f"BINDPLANE_API: {bp_data['error']}")

        # ------------------------------------------------------------------
        # 2. Fetch Chronicle Ingestion Telemetry (24h and lookback_days)
        # ------------------------------------------------------------------
        mechanism_rows_24h: List[Dict[str, Any]] = []
        source_breakdown_24h: List[Dict[str, Any]] = []
        try:
            mech_res = self.adapter.execute_dashboard_query(
                query_text=INGESTION_MECHANISM_SQL_QUERY,
                time_unit="DAY",
                time_value="1",
                dialect="SQL",
            )
            mechanism_rows_24h = list(mech_res.rows or [])
        except Exception as exc:
            logger.warning("Failed to execute 24h ingestion mechanism SQL query: %s", exc)
            collection_errors.append(f"INGESTION_MECHANISM_SQL: {exc}")

        try:
            src_res = self.adapter.execute_dashboard_query(
                query_text=INGESTION_SOURCE_BREAKDOWN_SQL_QUERY,
                time_unit="DAY",
                time_value="1",
                dialect="SQL",
            )
            source_breakdown_24h = list(src_res.rows or [])
        except Exception as exc:
            logger.warning("Failed to execute 24h ingestion source breakdown SQL query: %s", exc)
            collection_errors.append(f"INGESTION_SOURCE_SQL: {exc}")

        # Build lookup maps from 24h `ingestion` telemetry
        # Map: (source_host_lower, log_type_upper) -> {total_logs, total_mb, last_seen_ts, ingestion_mechanism}
        ing_by_host_and_lt: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # Map: log_type_upper -> {total_logs, total_mb, last_seen_ts, mechanisms: set}
        ing_by_lt: Dict[str, Dict[str, Any]] = {}

        for row in source_breakdown_24h:
            lt = str(row.get("log_type") or "").strip().upper()
            host = str(row.get("source_host") or "").strip()
            mech = str(row.get("ingestion_mechanism") or "Unspecified").strip()
            logs_cnt = int(float(row.get("total_logs") or 0))
            vol_mb = float(row.get("total_mb") or 0.0)
            last_ts = str(row.get("last_seen_ts") or now_iso)

            if not lt:
                continue

            key_hl = (host.lower(), lt)
            cur_hl = ing_by_host_and_lt.setdefault(
                key_hl,
                {"total_logs": 0, "total_mb": 0.0, "last_seen_ts": last_ts, "ingestion_mechanism": mech},
            )
            cur_hl["total_logs"] += logs_cnt
            cur_hl["total_mb"] += vol_mb
            if last_ts > cur_hl["last_seen_ts"]:
                cur_hl["last_seen_ts"] = last_ts

            cur_lt = ing_by_lt.setdefault(
                lt,
                {"total_logs": 0, "total_mb": 0.0, "last_seen_ts": last_ts, "mechanisms": set()},
            )
            cur_lt["total_logs"] += logs_cnt
            cur_lt["total_mb"] += vol_mb
            cur_lt["mechanisms"].add(mech)
            if last_ts > cur_lt["last_seen_ts"]:
                cur_lt["last_seen_ts"] = last_ts

        # ------------------------------------------------------------------
        # 3. Fetch Multi-Host UDM Event Autodetection (24h vs lookback_days)
        # ------------------------------------------------------------------
        udm_hosts_24h: List[Dict[str, Any]] = []
        udm_hosts_lookback: List[Dict[str, Any]] = []
        if include_multi_host_discovery:
            try:
                res_24h = self.adapter.execute_dashboard_query(
                    query_text=MULTI_HOST_UDM_SQL_QUERY,
                    time_unit="DAY",
                    time_value="1",
                    dialect="SQL",
                )
                udm_hosts_24h = list(res_24h.rows or [])
            except Exception as exc:
                logger.warning("Failed to execute 24h multi-host UDM SQL query: %s", exc)
                collection_errors.append(f"UDM_MULTI_HOST_24H_SQL: {exc}")

            if lookback_days > 1:
                try:
                    res_lb = self.adapter.execute_dashboard_query(
                        query_text=MULTI_HOST_UDM_SQL_QUERY,
                        time_unit="DAY",
                        time_value=str(max(2, int(lookback_days))),
                        dialect="SQL",
                    )
                    udm_hosts_lookback = list(res_lb.rows or [])
                except Exception as exc:
                    logger.warning("Failed to execute %dd multi-host UDM SQL query: %s", lookback_days, exc)
                    collection_errors.append(f"UDM_MULTI_HOST_LOOKBACK_SQL: {exc}")

        # Map UDM 24h activity by (identifier_lower, log_type_upper)
        udm_24h_by_id_lt: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for r in udm_hosts_24h:
            lt = str(r.get("log_type") or "").strip().upper()
            ident = str(r.get("log_source_identifier") or "").strip()
            grp = str(r.get("log_source_group") or "UNGROUPED").strip()
            cnt = int(float(r.get("event_count") or 0))
            last_ts = str(r.get("last_event_ts") or now_iso)
            if lt and ident:
                udm_24h_by_id_lt[(ident.lower(), lt)] = {
                    "event_count": cnt,
                    "last_event_ts": last_ts,
                    "log_source_group": grp,
                    "identifier": ident,
                }

        # ------------------------------------------------------------------
        # 4. Fetch Configured Chronicle Feeds (`v1alpha/feeds`)
        # ------------------------------------------------------------------
        configured_feeds: List[Any] = []
        try:
            feed_batch = SearchFeedsWorkflow(self.adapter).execute(limit=500)
            configured_feeds = list(feed_batch.feeds or [])
        except Exception as exc:
            logger.warning("Failed to list Chronicle Feeds: %s", exc)
            collection_errors.append(f"CHRONICLE_FEEDS_API: {exc}")

        # ------------------------------------------------------------------
        # 5. Assemble Live Inventory Items Across All 3 Layers
        # ------------------------------------------------------------------
        live_items: List[LogSourceInventoryItem] = []
        seen_keys: Set[str] = set()
        bp_agent_hostnames_lower: Set[str] = set()
        bp_agent_summaries: List[Dict[str, Any]] = []

        # Layer A: Registered Bindplane OTel Agents & Pipeline Configurations
        for ag in bp_data.get("agents", []):
            hostname = ag["hostname"]
            bp_agent_hostnames_lower.add(hostname.lower())
            cfg_name = ag["config_name"] or "Unassigned"
            cfg_ver = ag["config_version"]
            cfg_badge = f"{cfg_name}:{cfg_ver}" if cfg_ver != "" else cfg_name
            expected_lts: List[str] = ag["expected_log_types"] or ["UNSPECIFIED_OTEL"]
            filter_procs = ag.get("filter_processors", [])
            filter_names = ", ".join(p["processor_type"].split(":")[0] for p in filter_procs) if filter_procs else "None"
            conn_str = "Connected" if ag["connected"] else f"Disconnected ({ag['status']})"

            # Check each expected log_type for this agent in Chronicle 24h telemetry
            agent_lt_stats: Dict[str, Dict[str, Any]] = {}
            active_lts: List[str] = []
            missing_lts: List[str] = []
            total_agent_events_24h = 0
            total_agent_mb_24h = 0.0

            for lt in expected_lts:
                lt_up = lt.upper()
                ing_stat = ing_by_host_and_lt.get((hostname.lower(), lt_up))
                udm_stat = udm_24h_by_id_lt.get((hostname.lower(), lt_up))
                ev_cnt = 0
                vol_mb = 0.0
                last_seen = "NEVER"
                grp_val = cfg_name or hostname

                if ing_stat:
                    ev_cnt = max(ev_cnt, int(ing_stat["total_logs"]))
                    vol_mb = max(vol_mb, float(ing_stat["total_mb"]))
                    last_seen = ing_stat["last_seen_ts"]
                if udm_stat:
                    ev_cnt = max(ev_cnt, int(udm_stat["event_count"]))
                    if last_seen == "NEVER" or udm_stat["last_event_ts"] > last_seen:
                        last_seen = udm_stat["last_event_ts"]
                    if udm_stat.get("log_source_group") and udm_stat["log_source_group"] != "UNGROUPED":
                        grp_val = udm_stat["log_source_group"]

                agent_lt_stats[lt_up] = {
                    "events_24h": ev_cnt,
                    "volume_mb_24h": vol_mb,
                    "last_seen_utc": last_seen,
                    "group": grp_val,
                }
                total_agent_events_24h += ev_cnt
                total_agent_mb_24h += vol_mb
                if ev_cnt > 0:
                    active_lts.append(lt_up)
                else:
                    missing_lts.append(lt_up)

            # Determine per-log-type health status for this Bindplane agent
            for lt_up, st in agent_lt_stats.items():
                if st["events_24h"] > 0:
                    h_status = "HEALTHY"
                elif active_lts:
                    # Agent is shipping other log types in its config, but this log type dropped to 0!
                    h_status = "PARTIAL_DROP"
                else:
                    h_status = "SILENT_AGENT"

                otel_desc = (
                    f"Config: {cfg_badge} | Expected: {', '.join(expected_lts)} | "
                    f"Filters: {len(filter_procs)} ({filter_names}) | Agent: {conn_str} ({ag['os']})"
                )
                inv_key = _make_inventory_key("OTEL_AGENT", lt_up, hostname)
                seen_keys.add(inv_key)
                live_items.append(
                    LogSourceInventoryItem(
                        inventory_key=inv_key,
                        source_category="OTEL_AGENT",
                        ingestion_mechanism="Bindplane Agent (Google Edition)",
                        log_type=lt_up,
                        log_source_identifier=hostname,
                        log_source_group=st["group"],
                        otel_or_feed_config=otel_desc,
                        health_status=h_status,
                        events_24h=st["events_24h"],
                        volume_mb_24h=st["volume_mb_24h"],
                        last_seen_utc=st["last_seen_utc"],
                    )
                )

            overall_agent_health = (
                "HEALTHY"
                if (active_lts and not missing_lts)
                else ("PARTIAL_DROP" if active_lts and missing_lts else "SILENT_AGENT")
            )
            bp_agent_summaries.append(
                {
                    "hostname": hostname,
                    "os": ag["os"],
                    "connected": ag["connected"],
                    "config_badge": cfg_badge,
                    "expected_log_types": expected_lts,
                    "active_log_types": active_lts,
                    "missing_log_types": missing_lts,
                    "filter_count": len(filter_procs),
                    "filter_names": filter_names,
                    "events_24h": total_agent_events_24h,
                    "volume_mb_24h": round(total_agent_mb_24h, 2),
                    "health_status": overall_agent_health,
                }
            )

        # Layer B: Configured Chronicle Feeds (`v1alpha/feeds`)
        for fd in configured_feeds:
            lt_up = str(fd.log_type or "UNKNOWN").strip().upper()
            f_name = str(fd.display_name or fd.id or lt_up).strip()
            f_state = str(fd.state or "UNKNOWN").strip().upper()
            f_src_type = str(fd.feed_source_type or "UNKNOWN").strip()

            lt_stat = ing_by_lt.get(lt_up, {})
            ev_24h = int(lt_stat.get("total_logs", 0))
            mb_24h = float(lt_stat.get("total_mb", 0.0))
            last_ts = str(lt_stat.get("last_seen_ts", "NEVER"))
            mechs = sorted(list(lt_stat.get("mechanisms", [])))
            mech_label = mechs[0] if mechs else "Out-of-Band Feeds (S3 / GCS / API)"

            if f_state in ("INACTIVE", "DISABLED"):
                f_health = "INACTIVE"
            elif f_state in ("FAILED", "ERROR"):
                f_health = "FEED_FAILED"
            elif ev_24h > 0:
                f_health = "HEALTHY"
            else:
                f_health = "FEED_SILENT"

            feed_cfg_desc = f"Feed ID: {fd.id[:12]} | Source Type: {f_src_type} | State: {f_state}"
            inv_key = _make_inventory_key("CLOUD_FEED", lt_up, f_name)
            if inv_key not in seen_keys:
                seen_keys.add(inv_key)
                live_items.append(
                    LogSourceInventoryItem(
                        inventory_key=inv_key,
                        source_category="CLOUD_FEED",
                        ingestion_mechanism=mech_label,
                        log_type=lt_up,
                        log_source_identifier=f_name,
                        log_source_group=f_src_type,
                        otel_or_feed_config=feed_cfg_desc,
                        health_status=f_health,
                        events_24h=ev_24h,
                        volume_mb_24h=mb_24h,
                        last_seen_utc=last_ts,
                    )
                )

        # Layer C: Multi-Host Feed & Forwarder Child Devices (UDM Autodetection)
        # First add active 24h child hosts/sources
        added_multi_host = 0
        for r in udm_hosts_24h:
            if added_multi_host >= max_multi_host_rows:
                break
            lt_up = str(r.get("log_type") or "").strip().upper()
            ident = str(r.get("log_source_identifier") or "").strip()
            grp = str(r.get("log_source_group") or "UNGROUPED").strip()
            ev_cnt = int(float(r.get("event_count") or 0))
            last_ts = str(r.get("last_event_ts") or now_iso)

            if not lt_up or not ident:
                continue
            # Skip if already tracked as a Bindplane OTel Agent for this log_type
            if ident.lower() in bp_agent_hostnames_lower:
                continue

            lt_stat = ing_by_lt.get(lt_up, {})
            mechs = sorted(list(lt_stat.get("mechanisms", [])))
            mech_label = mechs[0] if mechs else "Shared Feed / Forwarder"
            total_lt_logs = max(1, int(lt_stat.get("total_logs", ev_cnt)))
            total_lt_mb = float(lt_stat.get("total_mb", 0.0))
            # Estimate proportional volume for this child host within the log_type
            est_mb = round(total_lt_mb * min(1.0, float(ev_cnt) / float(total_lt_logs)), 2)

            cat = "NATIVE_GCP" if lt_up.startswith("GCP_") else "MULTI_HOST_FEED_DEVICE"
            inv_key = _make_inventory_key(cat, lt_up, ident)
            if inv_key in seen_keys:
                continue
            seen_keys.add(inv_key)
            added_multi_host += 1

            live_items.append(
                LogSourceInventoryItem(
                    inventory_key=inv_key,
                    source_category=cat,
                    ingestion_mechanism=mech_label,
                    log_type=lt_up,
                    log_source_identifier=ident,
                    log_source_group=grp,
                    otel_or_feed_config=f"Auto-Discovered Host/Service via {mech_label}",
                    health_status="HEALTHY",
                    events_24h=ev_cnt,
                    volume_mb_24h=est_mb,
                    last_seen_utc=last_ts,
                )
            )

        # Next check 7d lookback UDM hosts that dropped to 0 events in the last 24h (`SILENT_HOST`)
        for r in udm_hosts_lookback:
            lt_up = str(r.get("log_type") or "").strip().upper()
            ident = str(r.get("log_source_identifier") or "").strip()
            grp = str(r.get("log_source_group") or "UNGROUPED").strip()
            last_ts = str(r.get("last_event_ts") or "UNKNOWN")
            if not lt_up or not ident:
                continue
            if ident.lower() in bp_agent_hostnames_lower:
                continue
            if (ident.lower(), lt_up) in udm_24h_by_id_lt:
                continue

            cat = "NATIVE_GCP" if lt_up.startswith("GCP_") else "MULTI_HOST_FEED_DEVICE"
            inv_key = _make_inventory_key(cat, lt_up, ident)
            if inv_key in seen_keys:
                continue
            seen_keys.add(inv_key)

            lt_stat = ing_by_lt.get(lt_up, {})
            mechs = sorted(list(lt_stat.get("mechanisms", [])))
            mech_label = mechs[0] if mechs else "Shared Feed / Forwarder"

            live_items.append(
                LogSourceInventoryItem(
                    inventory_key=inv_key,
                    source_category=cat,
                    ingestion_mechanism=mech_label,
                    log_type=lt_up,
                    log_source_identifier=ident,
                    log_source_group=grp,
                    otel_or_feed_config=f"Historical Child Host (Active in {lookback_days}d window, 0 events in 24h)",
                    health_status="SILENT_HOST",
                    events_24h=0,
                    volume_mb_24h=0.0,
                    last_seen_utc=last_ts,
                )
            )

        # ------------------------------------------------------------------
        # 6. Reconcile Stateful Inventory in Data Table (`asoc_log_source_inventory`)
        # ------------------------------------------------------------------
        reconcile_res = self._reconcile_inventory_table(
            table_id=data_table_id,
            live_items=live_items,
            now_iso=now_iso,
            sync_data_table=sync_data_table,
        )
        all_inventory: List[LogSourceInventoryItem] = reconcile_res["reconciled_items"]

        # Compute summary counts
        healthy_items = [i for i in all_inventory if i.health_status == "HEALTHY"]
        partial_drop_items = [i for i in all_inventory if i.health_status == "PARTIAL_DROP"]
        silent_agent_items = [i for i in all_inventory if i.health_status == "SILENT_AGENT"]
        silent_host_items = [i for i in all_inventory if i.health_status == "SILENT_HOST"]
        feed_alert_items = [i for i in all_inventory if i.health_status in ("FEED_FAILED", "FEED_SILENT")]

        # ------------------------------------------------------------------
        # 7. Sync Associated Chronicle Native Dashboard
        # ------------------------------------------------------------------
        dashboard_result: Optional[Dict[str, Any]] = None
        if sync_dashboard:
            try:
                dashboard_result = self.sync_dashboard(
                    dashboard_title=dashboard_title,
                    dashboard_id=dashboard_id,
                    data_table_id=data_table_id,
                    all_inventory=all_inventory,
                    bp_agent_summaries=bp_agent_summaries,
                    mechanism_rows_24h=mechanism_rows_24h,
                    lookback_days=lookback_days,
                    refreshed_at_str=now_display,
                )
            except Exception as exc:
                logger.warning("Failed to sync Log Source Inventory Native Dashboard: %s", exc)
                collection_errors.append(f"DASHBOARD_SYNC: {exc}")

        return {
            "status": "SUCCESS",
            "evaluated_at_utc": now_iso,
            "lookback_days": lookback_days,
            "bindplane_connected": bp_data.get("available", False),
            "bindplane_agents_count": len(bp_agent_summaries),
            "summary": {
                "total_inventory_rows": len(all_inventory),
                "healthy_count": len(healthy_items),
                "partial_drop_count": len(partial_drop_items),
                "silent_agent_count": len(silent_agent_items),
                "silent_host_count": len(silent_host_items),
                "feed_alert_count": len(feed_alert_items),
                "configured_feeds_count": len(configured_feeds),
            },
            "data_table_sync": {
                "data_table_id": data_table_id,
                "synced": reconcile_res["synced"],
                "table_created": reconcile_res["table_created"],
                "rows_added": reconcile_res["rows_added"],
                "rows_deleted": reconcile_res["rows_deleted"],
            },
            "bindplane_agents": bp_agent_summaries,
            "anomalies": [
                i.to_dict()
                for i in all_inventory
                if i.health_status in ("PARTIAL_DROP", "SILENT_AGENT", "SILENT_HOST", "FEED_FAILED", "FEED_SILENT")
            ],
            "dashboard_sync": dashboard_result,
            "collection_errors": collection_errors,
        }

    # ----------------------------------------------------------------------
    # Stateful Data Table Reconciliation (`asoc_log_source_inventory`)
    # ----------------------------------------------------------------------

    def _reconcile_inventory_table(
        self,
        table_id: str,
        live_items: List[LogSourceInventoryItem],
        now_iso: str,
        sync_data_table: bool = True,
    ) -> Dict[str, Any]:
        """Reconciles live inventory items with existing rows in `asoc_log_source_inventory`."""
        table_created = False
        existing_by_key: Dict[str, Tuple[str, LogSourceInventoryItem]] = {}

        if sync_data_table:
            try:
                self.engine.get_data_table(table_id)
            except Exception:
                try:
                    self.engine.create_data_table(
                        table_id=table_id,
                        display_name=table_id,
                        description=(
                            "Unified Log Source Inventory & Collector Health table bridging Chronicle ingestion "
                            "telemetry, Bindplane OTel Agent/Pipeline configurations, Chronicle Feeds, and "
                            "multi-host UDM device autodetection."
                        ),
                        column_info=INVENTORY_COLUMNS,
                    )
                    table_created = True
                except Exception as create_exc:
                    logger.warning("Could not create Data Table %s: %s", table_id, create_exc)

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
                            k_val = vals[0].strip()
                            try:
                                ev_cnt = int(float(vals[8] or 0))
                            except (ValueError, TypeError):
                                ev_cnt = 0
                            try:
                                vol_mb = float(vals[9] or 0.0)
                            except (ValueError, TypeError):
                                vol_mb = 0.0
                            parsed = LogSourceInventoryItem(
                                inventory_key=k_val,
                                source_category=vals[1],
                                ingestion_mechanism=vals[2],
                                log_type=vals[3],
                                log_source_identifier=vals[4],
                                log_source_group=vals[5],
                                otel_or_feed_config=vals[6],
                                health_status=vals[7],
                                events_24h=ev_cnt,
                                volume_mb_24h=vol_mb,
                                last_seen_utc=vals[10],
                            )
                            existing_by_key[k_val] = (r.id, parsed)
                    page_token = row_batch.next_page_token
                    if not page_token:
                        break
            except Exception as read_exc:
                logger.warning("Failed to list rows from Data Table %s: %s", table_id, read_exc)

        reconciled: List[LogSourceInventoryItem] = []
        rows_to_delete: List[str] = []
        rows_to_insert: List[Dict[str, Any]] = []
        seen_live_keys: Set[str] = set()

        for item in live_items:
            k = item.inventory_key
            if k in seen_live_keys:
                continue
            seen_live_keys.add(k)

            prior_tuple = existing_by_key.get(k)
            if prior_tuple is not None:
                row_id, prior_item = prior_tuple
                # Preserve custom analyst-assigned log_source_group if it was customized in the Data Table
                default_groups = {"", "UNGROUPED", item.log_source_identifier, item.log_type}
                if (
                    prior_item.log_source_group
                    and prior_item.log_source_group not in default_groups
                ):
                    item.log_source_group = prior_item.log_source_group

                # Preserve historical last_seen_utc if the source currently has 0 events
                if item.events_24h == 0 and prior_item.last_seen_utc and prior_item.last_seen_utc != "NEVER":
                    item.last_seen_utc = prior_item.last_seen_utc

                rows_to_delete.append(row_id)

            reconciled.append(item)
            rows_to_insert.append({"values": item.to_row_values()})

        # Retain previously discovered hosts/agents that aged out of the live query window as SILENT_HOST
        for k, (row_id, prior_item) in existing_by_key.items():
            if k in seen_live_keys:
                continue
            already_silent = (
                prior_item.events_24h == 0
                and prior_item.volume_mb_24h == 0.0
                and prior_item.health_status in ("SILENT_AGENT", "FEED_SILENT", "SILENT_HOST")
            )
            prior_item.events_24h = 0
            prior_item.volume_mb_24h = 0.0
            if prior_item.source_category == "OTEL_AGENT":
                prior_item.health_status = "SILENT_AGENT"
            elif prior_item.source_category == "CLOUD_FEED":
                prior_item.health_status = "FEED_SILENT"
            else:
                prior_item.health_status = "SILENT_HOST"
            reconciled.append(prior_item)
            if not already_silent:
                rows_to_delete.append(row_id)
                rows_to_insert.append({"values": prior_item.to_row_values()})

        deleted_count = 0
        added_count = 0
        if sync_data_table:
            # Respect Chronicle DataTableRowDeletesPerMinutePerProjectPerUser quota (60/min):
            # run the first 45 deletes immediately, then pace any remaining deletes at 1.05s.
            for idx_del, r_id in enumerate(rows_to_delete):
                if idx_del >= 45:
                    time.sleep(1.05)
                try:
                    self.engine.delete_data_table_row(table_name_or_id=table_id, row_id=r_id)
                    deleted_count += 1
                except Exception as del_exc:
                    logger.debug("Could not delete superseded row %s in %s: %s", r_id, table_id, del_exc)

            if rows_to_insert:
                # Batch insert in chunks of 100
                for idx in range(0, len(rows_to_insert), 100):
                    chunk = rows_to_insert[idx : idx + 100]
                    try:
                        self.engine.add_data_table_rows(table_name_or_id=table_id, rows=chunk)
                        added_count += len(chunk)
                    except Exception as add_exc:
                        logger.warning("Failed to bulk insert rows into %s: %s", table_id, add_exc)

        # Sort reconciled items: anomalies first, then OTel agents, then by 24h events descending
        status_rank = {
            "PARTIAL_DROP": 0,
            "SILENT_AGENT": 1,
            "FEED_FAILED": 2,
            "SILENT_HOST": 3,
            "FEED_SILENT": 4,
            "HEALTHY": 5,
            "INACTIVE": 6,
        }
        cat_rank = {
            "OTEL_AGENT": 0,
            "CLOUD_FEED": 1,
            "MULTI_HOST_FEED_DEVICE": 2,
            "NATIVE_GCP": 3,
        }
        reconciled.sort(
            key=lambda x: (
                status_rank.get(x.health_status, 9),
                cat_rank.get(x.source_category, 9),
                -x.events_24h,
                x.log_source_identifier,
            )
        )

        return {
            "synced": sync_data_table,
            "table_created": table_created,
            "rows_deleted": deleted_count,
            "rows_added": added_count,
            "reconciled_items": reconciled,
        }

    # ----------------------------------------------------------------------
    # Native Dashboard Creation & Sync (`Log Source Inventory & Collector Health`)
    # ----------------------------------------------------------------------

    def sync_dashboard(
        self,
        dashboard_title: str,
        dashboard_id: Optional[str],
        data_table_id: str,
        all_inventory: List[LogSourceInventoryItem],
        bp_agent_summaries: List[Dict[str, Any]],
        mechanism_rows_24h: List[Dict[str, Any]],
        lookback_days: int,
        refreshed_at_str: str,
    ) -> Dict[str, Any]:
        """Creates or updates the 'Log Source Inventory & Collector Health' Chronicle Native Dashboard."""
        banner_md = self._format_banner_markdown(
            dashboard_title=dashboard_title,
            data_table_id=data_table_id,
            all_inventory=all_inventory,
            bp_agent_summaries=bp_agent_summaries,
            refreshed_at_str=refreshed_at_str,
        )
        bp_table_md = self._format_bindplane_markdown(
            bp_agent_summaries=bp_agent_summaries,
            refreshed_at_str=refreshed_at_str,
        )
        anomalies_md = self._format_anomalies_markdown(
            all_inventory=all_inventory,
            data_table_id=data_table_id,
            refreshed_at_str=refreshed_at_str,
        )
        ledger_md = self._format_inventory_ledger_markdown(
            all_inventory=all_inventory,
            data_table_id=data_table_id,
            refreshed_at_str=refreshed_at_str,
        )

        desired_tiles: List[Dict[str, Any]] = [
            {
                "display_name": "Log Source Inventory & Collector Health Banner",
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
                "display_name": "24h Active Log Types (Live SQL)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 0,
                "start_y": 7,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["INGESTION_METRICS"],
                "time_unit": "DAY",
                "time_value": "1",
                "dialect": "SQL",
                "query": (
                    "FROM ingestion\n"
                    "|> WHERE component = 'Ingestion API' AND NULLIF(log_type, '') IS NOT NULL\n"
                    "|> AGGREGATE COUNT(DISTINCT log_type) AS distinct_log_types"
                ),
                "visualization": _build_kpi_text_visualization(
                    label="Active Log Types (24h)",
                    field="distinct_log_types",
                ),
            },
            {
                "display_name": "24h Active Collectors & Pipelines (Live SQL)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 32,
                "start_y": 7,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["INGESTION_METRICS"],
                "time_unit": "DAY",
                "time_value": "1",
                "dialect": "SQL",
                "query": (
                    "FROM ingestion\n"
                    "|> WHERE component = 'Ingestion API' AND NULLIF(collector_id, '') IS NOT NULL\n"
                    "|> AGGREGATE COUNT(DISTINCT collector_id) AS active_collectors"
                ),
                "visualization": _build_kpi_text_visualization(
                    label="Active Collectors (24h)",
                    field="active_collectors",
                ),
            },
            {
                "display_name": "24h Ingestion Volume GB (Live SQL)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 64,
                "start_y": 7,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["INGESTION_METRICS"],
                "time_unit": "DAY",
                "time_value": "1",
                "dialect": "SQL",
                "query": (
                    "FROM ingestion\n"
                    "|> WHERE component = 'Ingestion API'\n"
                    "|> AGGREGATE ROUND(SUM(log_volume) / POW(1000, 3), 2) AS total_gb"
                ),
                "visualization": _build_kpi_text_visualization(
                    label="24h Volume (GB)",
                    field="total_gb",
                ),
            },
            {
                "display_name": "Bindplane OTel Agent & Downstream Pipeline Inventory",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 18,
                "span_x": 54,
                "span_y": 28,
                "visualization": {
                    "markdown": {
                        "content": bp_table_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Log Source Drop Anomalies & Grouping Guide",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 54,
                "start_y": 18,
                "span_x": 42,
                "span_y": 28,
                "visualization": {
                    "markdown": {
                        "content": anomalies_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Log Volume by Ingestion Mechanism (Live SQL)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 0,
                "start_y": 46,
                "span_x": 48,
                "span_y": 26,
                "data_sources": ["INGESTION_METRICS"],
                "time_unit": "DAY",
                "time_value": str(max(1, int(lookback_days))),
                "dialect": "SQL",
                "query": INGESTION_MECHANISM_SQL_QUERY,
                "visualization": _build_sql_table_visualization(
                    [
                        ("ingestion_mechanism", "Ingestion Mechanism"),
                        ("total_gb", "Total Volume (GB)"),
                        ("distinct_log_types", "Distinct Log Types"),
                        ("pct_of_total", "% of Total Volume"),
                    ]
                ),
            },
            {
                "display_name": "Multi-Host Feed & Agent Device Autodetection by Group (Live SQL)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 48,
                "start_y": 46,
                "span_x": 48,
                "span_y": 26,
                "data_sources": ["INGESTION_METRICS", "UDM"],
                "time_unit": "DAY",
                "time_value": "1",
                "dialect": "SQL",
                "query": MULTI_HOST_UDM_SQL_QUERY,
                "visualization": _build_sql_table_visualization(
                    [
                        ("log_type", "Log Type"),
                        ("log_source_identifier", "Log Source Identifier (Host / Service)"),
                        ("log_source_group", "Log Source Group (Ingestion Label)"),
                        ("event_count", "Events (24h)"),
                        ("last_event_ts", "Last Event (UTC)"),
                    ]
                ),
            },
            {
                "display_name": "Unified Log Source Inventory Ledger (Data Table)",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 72,
                "span_x": 96,
                "span_y": 32,
                "visualization": {
                    "markdown": {
                        "content": ledger_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
        ]

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
            f"Unified Log Source Inventory, Bindplane OTel Pipeline Configuration & Multi-Host Feed Autodetection "
            f"— Backed by Data Table '{data_table_id}'. Last synced: {refreshed_at_str}."
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
                if spec["tile_type"] == "TILE_TYPE_MARKDOWN":
                    old_md = existing_chart.visualization.get("markdown", {}).get("content")
                    new_md = spec["visualization"].get("markdown", {}).get("content")
                    if old_md != new_md:
                        self._update_chart_wf.execute(
                            chart_id=chart_id_val,
                            display_name=t_name,
                            visualization=spec["visualization"],
                        )
                        op_label = "UPDATED"
                    else:
                        op_label = "UNCHANGED"
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
                    dialect=spec.get("dialect"),
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
        data_table_id: str,
        all_inventory: List[LogSourceInventoryItem],
        bp_agent_summaries: List[Dict[str, Any]],
        refreshed_at_str: str,
    ) -> str:
        healthy_cnt = sum(1 for i in all_inventory if i.health_status == "HEALTHY")
        partial_cnt = sum(1 for i in all_inventory if i.health_status == "PARTIAL_DROP")
        silent_ag_cnt = sum(1 for i in all_inventory if i.health_status == "SILENT_AGENT")
        silent_host_cnt = sum(1 for i in all_inventory if i.health_status == "SILENT_HOST")
        feed_err_cnt = sum(1 for i in all_inventory if i.health_status in ("FEED_FAILED", "FEED_SILENT"))

        bp_total = len(bp_agent_summaries)
        bp_connected = sum(1 for a in bp_agent_summaries if a.get("connected"))

        partial_badge = f"🟠 {partial_cnt} Partial Drop" if partial_cnt > 0 else "🟢 0 Partial Drops"
        silent_ag_badge = f"🔴 {silent_ag_cnt} Silent Agent Sources" if silent_ag_cnt > 0 else "🟢 0 Silent Agents"
        silent_host_badge = f"🔴 {silent_host_cnt} Silent Hosts" if silent_host_cnt > 0 else "🟢 0 Silent Hosts"
        feed_badge = f"🟡 {feed_err_cnt} Feed Alerts" if feed_err_cnt > 0 else "🟢 All Feeds Nominal"

        return (
            f"# 📡 {dashboard_title}\n"
            f"**Stateful Inventory Data Table (`%{data_table_id}`):** `{len(all_inventory)} Tracked Sources` "
            f"(`🟢 {healthy_cnt} Healthy` · `{partial_badge}` · `{silent_ag_badge}` · `{silent_host_badge}`) &nbsp;|&nbsp; "
            f"**Last Sync:** `{refreshed_at_str}`\n\n"
            f"**Downstream Bindplane OTel Fleet:** `{bp_connected}/{bp_total} Agents Connected` &nbsp;|&nbsp; "
            f"**Cloud & API Feeds:** {feed_badge} &nbsp;|&nbsp; "
            f"**Log Source Grouping:** `metadata.ingestion_labels` + `%{data_table_id}`"
        )

    @staticmethod
    def _format_bindplane_markdown(
        bp_agent_summaries: List[Dict[str, Any]],
        refreshed_at_str: str,
    ) -> str:
        lines = [
            "### 🔌 Bindplane OTel Agent & Downstream Pipeline Configuration Inventory",
            f"*Correlates live Bindplane REST API (`/v1/agents` & `/v1/configs`) with Google SecOps `ingestion` & `events` telemetry (`{refreshed_at_str}`)*",
            "",
            "| Agent Hostname | OS & State | Assigned OTel Config | Expected Log Types | Active Filters | 24h Events (MB) | SecOps Ingestion Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        if not bp_agent_summaries:
            lines.append("| *(No Bindplane agents fetched)* | — | — | — | — | — | Configure `BINDPLANE_API_KEY` to index OTel pipelines. |")
            return "\n".join(lines)

        for ag in bp_agent_summaries:
            conn_icon = "🟢 Online" if ag["connected"] else "⚪ Offline"
            os_short = _sanitize_cell(ag["os"], 26)
            expected_str = ", ".join(f"`{lt}`" for lt in ag["expected_log_types"]) or "`None`"
            filt_str = f"`{ag['filter_count']}` ({_sanitize_cell(ag['filter_names'], 38)})" if ag["filter_count"] > 0 else "`0`"
            vol_str = f"`{ag['events_24h']:,}` (`{ag['volume_mb_24h']} MB`)"

            st = ag["health_status"]
            if st == "HEALTHY":
                st_badge = "🟢 **HEALTHY** (All Sources Active)"
            elif st == "PARTIAL_DROP":
                missing_str = ", ".join(ag["missing_log_types"])
                active_str = ", ".join(ag["active_log_types"])
                st_badge = f"🟠 **PARTIAL_DROP** (Missing `{missing_str}`; Receiving `{active_str}`)"
            else:
                st_badge = "🔴 **SILENT_AGENT** (0 Events in SecOps 24h)"

            lines.append(
                f"| **`{ag['hostname']}`** | {conn_icon} · {os_short} | `{ag['config_badge']}` | {expected_str} | {filt_str} | {vol_str} | {st_badge} |"
            )

        return "\n".join(lines)

    @staticmethod
    def _format_anomalies_markdown(
        all_inventory: List[LogSourceInventoryItem],
        data_table_id: str,
        refreshed_at_str: str,
    ) -> str:
        anomalies = [
            i
            for i in all_inventory
            if i.health_status in ("PARTIAL_DROP", "SILENT_AGENT", "SILENT_HOST", "FEED_FAILED", "FEED_SILENT")
        ]
        lines = [
            "### 🚨 Detected Log Source Drops & Silent Collectors",
            f"*Proactive comparison of Bindplane OTel configs, Feeds, and historical UDM hosts against 24h ingestion (`{refreshed_at_str}`)*",
            "",
        ]
        if not anomalies:
            lines.append("- ✅ **All registered Bindplane OTel agents, Feeds, and multi-host devices are actively shipping logs.**")
        else:
            for item in anomalies[:8]:
                if item.health_status == "PARTIAL_DROP":
                    icon = "🟠 **PARTIAL_DROP**"
                    detail = f"Agent `{item.log_source_identifier}` is online in Bindplane and shipping other log types, but **`{item.log_type}`** has `0` events in 24h ({item.otel_or_feed_config})."
                elif item.health_status == "SILENT_AGENT":
                    icon = "🔴 **SILENT_AGENT**"
                    detail = f"Bindplane agent `{item.log_source_identifier}` (`{item.log_type}`) sent `0` events in 24h ({item.otel_or_feed_config})."
                elif item.health_status == "SILENT_HOST":
                    icon = "🔴 **SILENT_HOST**"
                    detail = f"Child host `{item.log_source_identifier}` (`{item.log_type}`, Group: `{item.log_source_group}`) stopped sending logs (Last seen: `{item.last_seen_utc}`)."
                else:
                    icon = f"🟡 **{item.health_status}**"
                    detail = f"Cloud Feed `{item.log_source_identifier}` (`{item.log_type}`) has `0` events in 24h ({item.otel_or_feed_config})."
                lines.append(f"- {icon} — **`{item.log_source_identifier}` (`{item.log_type}`)**\n  {detail}")

        lines.extend(
            [
                "",
                "---",
                "### 🏷️ Log Source Grouping & QRadar Parity Guide",
                f"- **Tagging at Ingestion (OTel / Feeds):** Bindplane processor `SECOPS_METRIC_INGESTION_LABEL` automatically stamps `metadata.ingestion_labels` (`ingestion_source`, `log_source_group`, `environment`, `sourceUsecase`).",
                f"- **Data Table Group Overrides (`%{data_table_id}`):** Edit the `log_source_group` column in Data Table **`{data_table_id}`** to assign custom KRI or Critical Asset groups — custom group tags are automatically preserved across scheduled sync runs.",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _format_inventory_ledger_markdown(
        all_inventory: List[LogSourceInventoryItem],
        data_table_id: str,
        refreshed_at_str: str,
    ) -> str:
        lines = [
            f"### 📋 Unified Log Source Inventory Ledger (`%{data_table_id}`)",
            f"*Showing top {min(35, len(all_inventory))} of **{len(all_inventory)}** tracked log sources across OTel Agents, Cloud Feeds, and Auto-Discovered Child Hosts (`{refreshed_at_str}`)*",
            "",
            "| Status | Category | Log Type | Log Source Identifier (Host / Feed) | Log Source Group | Downstream OTel / Feed Config | 24h Events | 24h MB | Last Seen (UTC) |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        status_badges = {
            "HEALTHY": "🟢 `HEALTHY`",
            "PARTIAL_DROP": "🟠 `PARTIAL_DROP`",
            "SILENT_AGENT": "🔴 `SILENT_AGENT`",
            "SILENT_HOST": "🔴 `SILENT_HOST`",
            "FEED_FAILED": "🔴 `FEED_FAILED`",
            "FEED_SILENT": "🟡 `FEED_SILENT`",
            "INACTIVE": "⚪ `INACTIVE`",
        }
        for item in all_inventory[:35]:
            badge = status_badges.get(item.health_status, f"`{item.health_status}`")
            last_short = item.last_seen_utc[:16].replace("T", " ") if item.last_seen_utc and item.last_seen_utc != "NEVER" else "NEVER"
            cfg_short = _sanitize_cell(item.otel_or_feed_config, 95)
            ident_short = _sanitize_cell(item.log_source_identifier, 38)
            grp_short = _sanitize_cell(item.log_source_group, 32)
            lines.append(
                f"| {badge} | `{item.source_category}` | **`{item.log_type}`** | **`{ident_short}`** | `{grp_short}` | {cfg_short} | `{item.events_24h:,}` | `{item.volume_mb_24h:.2f}` | `{last_short}` |"
            )

        return "\n".join(lines)
