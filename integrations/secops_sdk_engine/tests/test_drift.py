"""
Unit Tests for Log Source Drift Profiling and Evaluation Engine.
"""

import pytest
from engine.drift import (
    extract_raw_keys,
    extract_json_keys,
    extract_udm_paths,
    build_profile_from_events,
    evaluate_stream_drift,
)


class MockEvent:
    def __init__(self, d):
        self._d = d

    def to_dict(self):
        return self._d


def test_extract_raw_keys_json_and_kv():
    # JSON payload
    json_log = '{"agent": {"id": "123", "version": "1.0"}, "user": "admin", "tags": ["prod", "us"]}'
    keys = extract_raw_keys(json_log)
    assert "agent.id" in keys
    assert "agent.version" in keys
    assert "user" in keys

    # CEF / Key-Value fallback
    cef_log = "CEF:0|Vendor|Product|1.0|100|Event|5|src=10.0.0.1 dst=10.0.0.2 spt=12345 dpt=443"
    cef_keys = extract_raw_keys(cef_log)
    assert {"src", "dst", "spt", "dpt"}.issubset(cef_keys)


def test_extract_udm_paths_excludes_volatile():
    udm_dict = {
        "metadata": {
            "id": "volatile-event-id-12345",
            "eventTimestamp": "2026-11-04T10:00:00Z",
            "eventType": "PROCESS_LAUNCH",
            "productName": "Falcon",
        },
        "principal": {
            "user": {"userid": "chris"},
            "process": {"file": {"md5": "abc12345"}},
        },
    }
    paths = extract_udm_paths(udm_dict)
    assert "metadata.eventType" in paths
    assert "metadata.productName" in paths
    assert "principal.user.userid" in paths
    assert "principal.process.file.md5" in paths
    # Verify volatile IDs and timestamps are excluded
    assert "metadata.id" not in paths
    assert "metadata.eventTimestamp" not in paths


def test_build_profile_and_drift_evaluation():
    # 1. Build profile from mock events
    events = [
        MockEvent({
            "event": {
                "metadata": {"eventType": "PROCESS_LAUNCH"},
                "principal": {"process": {"file": {"md5": "123", "sha256": "456"}}},
            }
        })
        for _ in range(20)
    ]
    raw_logs = ['{"aid": "host1", "pid": 1234, "cmd": "curl", "rare_key": "val"}'] * 15
    # Add one rare key in only 1 log (< 20% prevalence)
    raw_logs.append('{"aid": "host2", "pid": 5678, "cmd": "ls", "ephemeral_guid": "xxx"}')

    profile = build_profile_from_events(
        log_type="CS_EDR",
        event_type="PROCESS_LAUNCH",
        events=events,
        raw_log_payloads=raw_logs,
        min_key_prevalence=0.20,
    )

    assert profile["partition_key"] == "CS_EDR:PROCESS_LAUNCH"
    assert "aid" in profile["qualified_raw_keys"]
    assert "pid" in profile["qualified_raw_keys"]
    # ephemeral_guid appeared in only 1/16 logs (~6%), should be filtered out
    assert "ephemeral_guid" not in profile["qualified_raw_keys"]
    assert "principal.process.file.sha256" in profile["critical_udm_fields"]

    # 2. Test Control Stream (STABLE)
    stable_eval = evaluate_stream_drift(profile, events, raw_logs)
    assert stable_eval["status"] == "STABLE"
    assert stable_eval["syntactic_drift"] == 0.0

    # 3. Test Syntactic Drift (keys vanished)
    mutated_raw_logs = ['{"new_aid_key": "host1", "pid": 1234}'] * 15
    drift_eval = evaluate_stream_drift(profile, events, mutated_raw_logs, drift_tolerance=0.15)
    assert drift_eval["status"] == "ALERT"
    assert any("SYNTACTIC_DRIFT" in a for a in drift_eval["alerts"])
    assert "aid" in drift_eval["vanished_keys"]

    # 4. Test Semantic UDM Collapse
    broken_events = [MockEvent({"event": {"metadata": {"eventType": "PROCESS_LAUNCH"}}})] * 20
    collapse_eval = evaluate_stream_drift(profile, broken_events, raw_logs)
    assert collapse_eval["status"] == "ALERT"
    assert any("SEMANTIC_UDM_COLLAPSE" in a for a in collapse_eval["alerts"])

    # 5. Test Insufficient Volume
    low_vol_eval = evaluate_stream_drift(profile, events[:3], raw_logs[:3], min_events_required=10)
    assert low_vol_eval["status"] == "INSUFFICIENT_VOLUME"


def test_data_table_row_serialization_and_parsing():
    import json

    profile = {
        "partition_key": "OKTA:USER_LOGIN",
        "log_type": "OKTA",
        "event_type": "USER_LOGIN",
        "qualified_raw_keys": ["actor.alternateId", "client.ipAddress"],
        "critical_udm_fields": ["principal.user.userid", "principal.ip"],
    }

    # Simulate profile_log_source row creation
    row_values = [
        profile["partition_key"],
        profile["log_type"],
        profile.get("event_type") or "*",
        "ACTIVE",
        len(profile["qualified_raw_keys"]),
        len(profile["critical_udm_fields"]),
        json.dumps(profile),
        "2026-11-04T12:00:00Z",
        "",
        "STABLE",
    ]

    assert row_values[0] == "OKTA:USER_LOGIN"
    assert row_values[3] == "ACTIVE"

    # Simulate detect_log_source_drift_job row ingestion
    deserialized_profile = json.loads(row_values[6])
    assert deserialized_profile["partition_key"] == "OKTA:USER_LOGIN"
    assert deserialized_profile["qualified_raw_keys"] == ["actor.alternateId", "client.ipAddress"]

    # Simulate row update after drift evaluation
    updated_row = list(row_values)
    updated_row[8] = "2026-11-04T12:15:00Z"
    updated_row[9] = "ALERT"

    assert updated_row[8] == "2026-11-04T12:15:00Z"
    assert updated_row[9] == "ALERT"

