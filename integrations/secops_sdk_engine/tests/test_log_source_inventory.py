"""
Unit Tests for Unified Log Source Inventory & Collector Health Workflow.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import json

from engine.workflows.log_source_inventory import (
    INGESTION_MECHANISM_SQL_QUERY,
    MULTI_HOST_UDM_SQL_QUERY,
    LogSourceInventoryItem,
    LogSourceInventoryWorkflow,
    _build_sql_table_visualization,
    _make_inventory_key,
    fetch_bindplane_inventory,
)


def test_make_inventory_key_and_row_values():
    key = _make_inventory_key("OTEL_AGENT", "BRO_JSON", "lin-zeek-04-a")
    assert key == "OTEL_AGENT:BRO_JSON:lin-zeek-04-a"

    item = LogSourceInventoryItem(
        inventory_key=key,
        source_category="OTEL_AGENT",
        ingestion_mechanism="Bindplane Enterprise (Google Edition)",
        log_type="BRO_JSON",
        log_source_identifier="lin-zeek-04-a",
        log_source_group="ZEEK",
        otel_or_feed_config="Bindplane v1.105.1 | Config: ZEEK:5 | PARTIAL DROP",
        health_status="PARTIAL_DROP",
        events_24h=0,
        volume_mb_24h=0.0,
        last_seen_utc="2026-11-04T20:00:00Z",
    )
    vals = item.to_row_values()
    assert len(vals) == 11
    assert vals[0] == "OTEL_AGENT:BRO_JSON:lin-zeek-04-a"
    assert vals[7] == "PARTIAL_DROP"
    assert "|" not in vals[6]


def test_build_sql_table_visualization():
    vis = _build_sql_table_visualization([("ingestion_mechanism", "Ingestion Mechanism"), ("total_gb", "Total GB")])
    assert vis["groupingType"] == "Off"
    assert len(vis["columnDefs"]) == 2
    assert vis["columnDefs"][0]["field"] == "ingestion_mechanism"


def test_fetch_bindplane_inventory_v2_schema():
    mock_agents = {
        "agents": [
            {
                "id": "ag-1",
                "hostname": "lin-zeek-04-a",
                "connected": True,
                "status": 1,
                "operatingSystem": "Ubuntu 26.04",
                "version": "v1.105.1",
                "type": "observiq-otel-collector",
                "configurationStatus": {"assigned": "ZEEK", "current": "ZEEK:5"},
            }
        ]
    }
    mock_configs = [
        {
            "metadata": {"name": "ZEEK", "version": 5, "labels": {"platform": "linux"}},
            "spec": {
                "sources": [
                    {
                        "name": "BRO_JSON:8",
                        "processors": [
                            {"displayName": "Drop DNS Noise", "type": "filter-by-condition:3"},
                            {"name": "BRO_JSON:5"},
                        ],
                    },
                    {
                        "name": "NIX_SYSTEM:13",
                        "processors": [{"name": "NIX_SYSTEM:5"}],
                    },
                ]
            },
        }
    ]
    mock_procs = [
        {
            "metadata": {"name": "BRO_JSON", "version": 5},
            "spec": {
                "type": "google_secops_standardization:5",
                "parameters": [{"name": "secops_field", "value": [{"logType": "BRO_JSON"}]}],
            },
        },
        {
            "metadata": {"name": "NIX_SYSTEM", "version": 5},
            "spec": {
                "type": "google_secops_standardization:5",
                "parameters": [{"name": "secops_field", "value": [{"logType": "NIX_SYSTEM"}]}],
            },
        },
    ]
    mock_sources = [
        {"metadata": {"name": "BRO_JSON", "version": 8}, "spec": {"type": "file_v2:10"}},
        {"metadata": {"name": "NIX_SYSTEM", "version": 13}, "spec": {"type": "file_v2:10"}},
    ]

    def _fake_urlopen(req, timeout=20):
        url = req.full_url
        if url.endswith("/agents"):
            payload = mock_agents
        elif url.endswith("/configurations"):
            payload = mock_configs
        elif url.endswith("/processors"):
            payload = mock_procs
        elif url.endswith("/sources"):
            payload = mock_sources
        else:
            payload = {}
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode("utf-8")
        resp.__enter__.return_value = resp
        return resp

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        res = fetch_bindplane_inventory(
            api_url="https://app.bindplane.com/v1",
            api_key="bp_test_key",
            account_id="acct_test",
        )

    assert res["available"] is True
    assert len(res["agents"]) == 1
    ag = res["agents"][0]
    assert ag["hostname"] == "lin-zeek-04-a"
    assert ag["config_name"] == "ZEEK"
    assert ag["expected_log_types"] == ["BRO_JSON", "NIX_SYSTEM"]
    assert len(ag["filter_processors"]) == 1


def test_log_source_inventory_workflow_reconciliation_and_anomalies():
    adapter = MagicMock()
    engine = MagicMock()
    engine.adapter = adapter

    # 1. Mock Dashboard Queries (Mechanism, Breakdown, UDM Multi-Host)
    def _mock_exec_query(query_text, time_unit="DAY", time_value="1", dialect=None):
        assert dialect == "SQL"
        if query_text == INGESTION_MECHANISM_SQL_QUERY:
            return SimpleNamespace(
                rows=[
                    {
                        "ingestion_mechanism": "Bindplane Enterprise (Google Edition)",
                        "total_gb": 1.25,
                        "distinct_log_types": 3,
                        "pct_of_total": 80.0,
                    }
                ]
            )
        elif query_text == MULTI_HOST_UDM_SQL_QUERY:
            if time_value == "1":
                return SimpleNamespace(
                    rows=[
                        {
                            "log_type": "CS_EDR",
                            "log_source_identifier": "workstation-01",
                            "log_source_group": "Crowdstrike_VIP",
                            "event_count": 450,
                            "last_event_ts": "2026-11-04T19:30:00Z",
                        }
                    ]
                )
            else:
                return SimpleNamespace(
                    rows=[
                        {
                            "log_type": "CS_EDR",
                            "log_source_identifier": "workstation-01",
                            "log_source_group": "Crowdstrike_VIP",
                            "event_count": 2100,
                            "last_event_ts": "2026-11-04T19:30:00Z",
                        },
                        {
                            "log_type": "CS_EDR",
                            "log_source_identifier": "silent-laptop-99",
                            "log_source_group": "Crowdstrike",
                            "event_count": 120,
                            "last_event_ts": "2026-11-02T10:00:00Z",
                        },
                    ]
                )
        else:
            # Breakdown query: lin-zeek-04-a ships NIX_SYSTEM but NOT BRO_JSON; lab-02 ships nothing
            return SimpleNamespace(
                rows=[
                    {
                        "ingestion_mechanism": "Bindplane Enterprise (Google Edition)",
                        "collector_id": "aaaa1111-aaaa-1111-aaaa-1111aaaa1112",
                        "source_host": "lin-zeek-04-a",
                        "log_type": "NIX_SYSTEM",
                        "total_logs": 5000,
                        "total_mb": 4.2,
                        "last_seen_ts": "2026-11-04T19:55:00Z",
                    }
                ]
            )

    adapter.execute_dashboard_query.side_effect = _mock_exec_query
    adapter.list_feeds.return_value = {
        "feeds": [
            {
                "name": "projects/p/locations/us/instances/c/feeds/feed-1",
                "feedState": "ACTIVE",
                "details": {
                    "feedSourceType": "API",
                    "logType": "projects/p/locations/us/instances/c/logTypes/OKTA",
                    "displayName": "Okta System Log",
                },
            }
        ]
    }

    # Mock existing Data Table row with custom analyst group tag and a previously active host
    prior_row_custom_group = SimpleNamespace(
        id="row-1",
        values=[
            "OTEL_AGENT:BRO_JSON:lin-zeek-04-a",
            "OTEL_AGENT",
            "Bindplane Enterprise (Google Edition)",
            "BRO_JSON",
            "lin-zeek-04-a",
            "Critical_DMZ_Sensors",  # Custom group set by analyst
            "Bindplane config",
            "HEALTHY",
            "1000",
            "2.50",
            "2026-11-03T12:00:00Z",
        ],
    )
    engine.list_data_table_rows.return_value = SimpleNamespace(
        rows=[prior_row_custom_group],
        next_page_token=None,
    )

    mock_bp = {
        "available": True,
        "api_url": "https://app.bindplane.com/v1",
        "agents": [
            {
                "id": "ag-1",
                "hostname": "lin-zeek-04-a",
                "connected": True,
                "status": 1,
                "os": "Ubuntu 26.04",
                "agent_version": "v1.105.1",
                "type": "observiq-otel-collector",
                "config_name": "ZEEK",
                "config_version": 5,
                "rollout_status": "Valid",
                "expected_log_types": ["BRO_JSON", "NIX_SYSTEM"],
                "sources": [],
                "filter_processors": [{"resource": "Drop DNS Noise", "processor_type": "filter-by-condition:3"}],
                "label_processors": [],
            },
            {
                "id": "ag-2",
                "hostname": "lab-02",
                "connected": True,
                "status": 1,
                "os": "Windows Server 2025",
                "agent_version": "v1.110.1",
                "type": "observiq-otel-collector",
                "config_name": "WINEVTLOG_BASE",
                "config_version": 6,
                "rollout_status": "Valid",
                "expected_log_types": ["WINEVTLOG"],
                "sources": [],
                "filter_processors": [],
                "label_processors": [],
            },
        ],
        "configs_by_name": {},
        "error": None,
    }

    with patch("engine.workflows.log_source_inventory.fetch_bindplane_inventory", return_value=mock_bp):
        wf = LogSourceInventoryWorkflow(engine=engine)
        res = wf.execute(
            lookback_days=7,
            sync_data_table=True,
            data_table_id="asoc_log_source_inventory",
            sync_dashboard=False,
            include_multi_host_discovery=True,
        )

    assert res["status"] == "SUCCESS"
    assert res["bindplane_connected"] is True
    assert res["summary"]["partial_drop_count"] == 1
    assert res["summary"]["silent_agent_count"] == 1
    assert res["summary"]["silent_host_count"] >= 1

    # Verify custom analyst group tag "Critical_DMZ_Sensors" was preserved on lin-zeek-04-a BRO_JSON
    anomalies_by_key = {a["inventory_key"]: a for a in res["anomalies"]}
    zeek_bro = anomalies_by_key["OTEL_AGENT:BRO_JSON:lin-zeek-04-a"]
    assert zeek_bro["health_status"] == "PARTIAL_DROP"
    assert zeek_bro["log_source_group"] == "Critical_DMZ_Sensors"
    assert zeek_bro["last_seen_utc"] == "2026-11-03T12:00:00Z"

    # Verify lab-02 was flagged as SILENT_AGENT
    lab02_win = anomalies_by_key["OTEL_AGENT:WINEVTLOG:lab-02"]
    assert lab02_win["health_status"] == "SILENT_AGENT"

    # Verify silent-laptop-99 from 7d UDM lookback was flagged as SILENT_HOST
    silent_edr = anomalies_by_key["MULTI_HOST_FEED_DEVICE:CS_EDR:silent-laptop-99"]
    assert silent_edr["health_status"] == "SILENT_HOST"
