import json
import sys
from unittest.mock import MagicMock, patch


def _setup_soar_sdk_mocks():
    """Provides lightweight mocks for Chronicle SOAR runtime modules during unit testing."""
    script_result = MagicMock()
    script_result.EXECUTION_STATE_COMPLETED = 0
    script_result.EXECUTION_STATE_FAILED = 2

    siemplify_utils = MagicMock()
    siemplify_utils.output_handler = lambda fn: fn

    sys.modules.setdefault("ScriptResult", script_result)
    sys.modules.setdefault("SiemplifyUtils", siemplify_utils)
    sys.modules.setdefault("SiemplifyAction", MagicMock())


_setup_soar_sdk_mocks()

from integrations.google_decisions.actions import (  # noqa: E402
    evaluate_decisions,
    ping,
    run_soc_decision_preset,
)


@patch("integrations.google_decisions.actions.ping.GoogleDecisionsManager")
@patch("integrations.google_decisions.actions.ping.SiemplifyAction")
def test_ping_action_success(mock_siemplify_cls, mock_mgr_cls):
    mock_siemplify = MagicMock()
    mock_siemplify.extract_configuration_param.return_value = "test-val"
    mock_siemplify.extract_action_param.return_value = "gemini-decision-1"
    mock_siemplify_cls.return_value = mock_siemplify

    mock_mgr = MagicMock()
    mock_mgr.test_connection.return_value = True
    mock_mgr_cls.return_value = mock_mgr

    ping.main()
    mock_mgr.test_connection.assert_called_once()
    args, _ = mock_siemplify.end.call_args
    assert args[1] is True


@patch("integrations.google_decisions.actions.run_soc_decision_preset.GoogleDecisionsManager")
@patch("integrations.google_decisions.actions.run_soc_decision_preset.SiemplifyAction")
def test_run_soc_decision_preset_action(mock_siemplify_cls, mock_mgr_cls):
    mock_siemplify = MagicMock()
    mock_siemplify.case_id = "42"
    mock_siemplify.extract_configuration_param.return_value = ""
    mock_siemplify.extract_action_param.side_effect = lambda name, **kwargs: {
        "Decision Preset": "Tier-1 Alert Triage & Routing",
        "Additional Context or Telemetry": "Encoded powershell command detected",
        "Include Alert Context": "true",
        "Additional Custom Questions JSON": "",
        "Media Input (Base64 or HTTPS URI)": "",
        "Media MIME Type": "",
        "Confidence Threshold": "0.80",
    }.get(name, kwargs.get("default_value", ""))
    mock_siemplify_cls.return_value = mock_siemplify

    mock_mgr = MagicMock()
    mock_mgr.serialize_soar_context.return_value = '{"alert": {"name": "PS Alert"}}'
    mock_mgr.build_input_payload.return_value = "Combined input"
    mock_mgr.run_preset.return_value = {
        "status": "success",
        "preset_name": "Tier-1 Alert Triage & Routing",
        "question_count": 5,
        "all_confident": True,
        "latency_ms": 350,
        "summary": {"is_true_positive": True, "recommended_queue": "tier2_incident_response"},
        "answers": {},
        "usage": {"total_input_tokens": 412, "total_output_tokens": 0},
    }
    mock_mgr_cls.return_value = mock_mgr

    run_soc_decision_preset.main()
    mock_siemplify.result.add_result_json.assert_called_once()
    args, _ = mock_siemplify.end.call_args
    assert "Tier-1 Alert Triage & Routing" in args[0]
    assert json.loads(args[1])["is_true_positive"] is True
