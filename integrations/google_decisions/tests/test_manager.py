import json
from unittest.mock import MagicMock, patch
import pytest

from integrations.google_decisions.core.GoogleDecisionsManager import (
    GoogleDecisionsManager,
    SafeLogger,
    safe_ascii,
)


def test_safe_logger_handles_missing_warning():
    class LegacySiemplifyLogger:
        def __init__(self):
            self.messages = []

        def info(self, msg):
            self.messages.append(("info", msg))

        def error(self, msg):
            self.messages.append(("error", msg))

    raw = LegacySiemplifyLogger()
    logger = SafeLogger(raw)
    logger.warning("Test warning fallback")
    logger.info("Test info")
    logger.error("Test error")

    assert ("info", "[WARNING] Test warning fallback") in raw.messages
    assert ("info", "Test info") in raw.messages
    assert ("error", "Test error") in raw.messages


def test_presets_catalog_loads_all_five_secops_packs():
    mgr = GoogleDecisionsManager(api_key="test-key")
    presets = mgr.load_presets()
    expected = {
        "Tier-1 Alert Triage & Routing",
        "Phishing & Email Security Gate",
        "Command-Line & Script Risk Assessment",
        "DLP & Data Exfiltration Policy Gate",
        "Case Closure & False Positive Gate",
    }
    assert expected.issubset(set(presets.keys()))
    for name in expected:
        canonical, q_map = mgr.get_preset_questions(name)
        assert canonical == name
        assert len(q_map) >= 4
        normalized = mgr.normalize_questions(q_map)
        assert len(normalized) == len(q_map)


def test_normalize_questions_supports_native_and_openai_formats():
    # 1. Native map format
    native = {
        "is_malicious": {"type": "noul", "instructions": "Is it malicious?"},
        "route": {
            "type": "choice",
            "instructions": "Pick queue",
            "criteria": {"t1": "Tier 1", "t2": "Tier 2"},
        },
        "sev": {
            "type": "score",
            "instructions": "Rate severity",
            "criteria": ["Low", "High"],
        },
    }
    norm = GoogleDecisionsManager.normalize_questions(native)
    assert norm["is_malicious"]["type"] == "noul"
    assert norm["route"]["type"] == "choice"
    assert norm["sev"]["type"] == "score"

    # 2. OpenAI Decisions array format (predicate -> noul, choices list -> criteria dict)
    openai_list = [
        {"name": "damaged", "type": "predicate", "instructions": "Is item damaged?"},
        {
            "name": "action",
            "type": "choice",
            "instructions": "Select action",
            "choices": [
                {"value": "replace", "description": "Replace item"},
                {"value": "keep", "description": "Keep item"},
            ],
        },
        {
            "name": "severity",
            "type": "score",
            "instructions": "Rate damage",
            "levels": [{"label": "None"}, {"label": "Severe"}],
        },
    ]
    norm2 = GoogleDecisionsManager.normalize_questions(openai_list)
    assert norm2["damaged"]["type"] == "noul"
    assert norm2["action"]["criteria"] == {"replace": "Replace item", "keep": "Keep item"}
    assert norm2["severity"]["criteria"] == ["None", "Severe"]


def test_build_input_payload_text_and_multimodal():
    # Plain text + alert context
    payload_str = GoogleDecisionsManager.build_input_payload(
        input_text="PowerShell encoded command",
        alert_context='{"alert": {"name": "Suspicious PowerShell"}}',
    )
    assert isinstance(payload_str, str)
    assert "PowerShell encoded command" in payload_str
    assert "Suspicious PowerShell" in payload_str

    # Multimodal with inline base64 data URL
    payload_mm = GoogleDecisionsManager.build_input_payload(
        input_text="Inspect phishing screenshot",
        media_data_or_uri="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
        media_mime_type="image/png",
    )
    assert isinstance(payload_mm, list)
    assert payload_mm[0] == {"type": "text", "text": "Inspect phishing screenshot"}
    assert payload_mm[1] == {
        "type": "image",
        "mime_type": "image/png",
        "data": "iVBORw0KGgoAAAANSUhEUg==",
    }


@patch("integrations.google_decisions.core.GoogleDecisionsManager.requests.get")
def test_wif_auto_discovers_api_key_from_gcp(mock_get):
    # Mock list keys + get keyString
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json.return_value = {
        "keys": [
            {
                "name": "projects/123/locations/global/keys/k1",
                "displayName": "Generative Language API Key",
                "restrictions": {
                    "apiTargets": [{"service": "generativelanguage.googleapis.com"}]
                },
            }
        ]
    }
    ks_resp = MagicMock()
    ks_resp.status_code = 200
    ks_resp.json.return_value = {"keyString": "AIzaSyMockedAutoDiscoveredKey"}
    mock_get.side_effect = [list_resp, ks_resp]

    mgr = GoogleDecisionsManager(
        workload_identity_email="sa-vertex-ai@example-gcp-project.iam.gserviceaccount.com",
        project_id="example-gcp-project",
    )
    fake_creds = MagicMock()
    fake_creds.token = "ya29.mock_wif_oauth_token"
    mgr._credentials = fake_creds

    headers = mgr.get_auth_headers()
    assert headers["x-goog-api-key"] == "AIzaSyMockedAutoDiscoveredKey"
    assert mgr._auth_method == "wif_apikeys_auto"


@patch("integrations.google_decisions.core.GoogleDecisionsManager.requests.post")
def test_evaluate_decisions_confidence_gating_and_summary(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "answers": {
            "is_tp": {"type": "noul", "noul": 0.96, "confidence": 0.96},
            "queue": {
                "type": "choice",
                "choice": "tier2_ir",
                "confidence": 0.72,
                "probabilities": {"tier2_ir": 0.72, "tier1": 0.28},
            },
            "sev": {
                "type": "score",
                "score": 2.85,
                "confidence": 0.91,
                "probabilities": {"0": 0.0, "1": 0.05, "2": 0.04, "3": 0.91},
                "legend": {"0": "Info", "1": "Low", "2": "Med", "3": "High"},
            },
        },
        "usage": {
            "total_input_tokens": 310,
            "total_output_tokens": 0,
            "total_tokens": 310,
        },
    }
    mock_post.return_value = mock_resp

    mgr = GoogleDecisionsManager(api_key="AIzaTestKey")
    result = mgr.evaluate_decisions(
        input_payload="Suspicious activity",
        questions={
            "is_tp": {"type": "noul", "instructions": "Is TP?"},
            "queue": {
                "type": "choice",
                "instructions": "Queue?",
                "criteria": {"tier2_ir": "IR", "tier1": "T1"},
            },
            "sev": {
                "type": "score",
                "instructions": "Sev?",
                "criteria": ["Info", "Low", "Med", "High"],
            },
        },
        confidence_threshold=0.80,
    )

    # Queue has confidence 0.72 < 0.80, so escalation_required should be True
    assert result["all_confident"] is False
    assert result["escalation_required"] is True
    assert result["low_confidence_questions"] == ["queue"]
    assert result["summary"]["is_tp"] is True
    assert result["summary"]["is_tp_probability"] == 0.96
    assert result["summary"]["queue"] == "tier2_ir"
    assert result["summary"]["sev"] == 2.85
    assert result["summary"]["sev_level"] == 3
    assert result["summary"]["sev_label"] == "High"
    assert result["usage"]["total_output_tokens"] == 0


def test_enforce_input_budget_compacts_bulky_json_and_truncates():
    bulky_payload = {
        "total_detections": 420,
        "silent_detections_count": 418,
        "rules_triggered": ["ru_1", "ru_2"],
        "udm_events": [{"event_id": f"ev_{i}", "raw_log": "A" * 1200} for i in range(250)],
    }
    raw_text = f"Case #109430 Telemetry:\n{json.dumps(bulky_payload)}"
    assert len(raw_text) > 250000

    bounded_text, meta = GoogleDecisionsManager.enforce_input_budget(
        input_payload=raw_text,
        question_count=6,
        max_input_chars=60000,
    )
    assert meta["json_compacted"] is True
    assert len(bounded_text) <= 60000
    assert "total_detections" in bounded_text
    assert "_udm_events_total_count" in bounded_text

    # Test hard head+tail truncation when non-JSON string exceeds limit
    plain_oversized = "HEAD_MARKER_" + ("X" * 80000) + "_TAIL_MARKER"
    trunc_text, trunc_meta = GoogleDecisionsManager.enforce_input_budget(
        input_payload=plain_oversized,
        question_count=6,
        max_input_chars=10000,
    )
    assert trunc_meta["input_truncated"] is True
    assert len(trunc_text) <= 10000
    assert trunc_text.startswith("HEAD_MARKER_")
    assert trunc_text.endswith("_TAIL_MARKER")
    assert "TRUNCATED" in trunc_text
