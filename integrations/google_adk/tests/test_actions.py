import unittest
import sys
from pathlib import Path

workspace_dir = Path(__file__).parent.parent.parent.parent
mock_sdk_dir = workspace_dir / 'mock_sdk'
integration_dir = Path(__file__).parent.parent

sys.path.insert(0, str(mock_sdk_dir))
sys.path.insert(0, str(integration_dir))
sys.path.insert(0, str(integration_dir / 'core'))
sys.path.insert(0, str(integration_dir / 'actions'))

from SiemplifyAction import SiemplifyAction


class TestGoogleADKActions(unittest.TestCase):
    def setUp(self):
        SiemplifyAction.reset_mocks()
        SiemplifyAction.set_mock_configuration({
            'Gemini API Key': 'test-gemini-key',
            'Service Account JSON': '{}',
            'Workload Identity Email': 'adk-runner@sdl-preview-americas.iam.gserviceaccount.com',
            'Model Name': 'gemini-3.7-flash',
            'GCP Project ID': 'sdl-preview-americas',
            'SecOps Project ID': 'sdl-preview-americas',
            'SecOps Region': 'us',
            'SecOps Customer ID': 'a556547c-1cff-43ef-a2e4-cf5b12a865df',
        })

    def test_ping(self):
        SiemplifyAction.set_mock_action_params({'Model Name': 'gemini-3.7-flash'})
        from actions import ping
        try:
            ping.main()
        except SystemExit:
            pass

    def test_run_google_search_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'Analyze threat actor APT29 techniques',
            'Thinking Budget': 0,
            'Enable Memory': False,
        })
        from actions import run_google_search_agent
        try:
            run_google_search_agent.main()
        except SystemExit:
            pass

    def test_run_adk_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'Review suspicious process launch',
            'Agent Name': 'SecOps_Triage',
            'Enable Google Search': True,
            'Enable Memory': False,
        })
        from actions import run_adk_agent
        try:
            run_adk_agent.main()
        except SystemExit:
            pass

    def test_run_adk_skill_registry_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'List available triage skills',
        })
        from actions import run_adk_skill_registry_agent
        try:
            run_adk_skill_registry_agent.main()
        except SystemExit:
            pass

    def test_run_adk_gcs_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'List security artifact buckets',
            'Allow GCS Write': False,
            'Allow GCS Admin': False,
        })
        from actions import run_adk_gcs_agent
        try:
            run_adk_gcs_agent.main()
        except SystemExit:
            pass

    def test_run_code_execution_agent_sandbox(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'Calculate hash counts',
        })
        from actions import run_code_execution_agent_sandbox
        try:
            run_code_execution_agent_sandbox.main()
        except SystemExit:
            pass

    def test_run_code_execution_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'Calculate entropy of sample payload',
        })
        from actions import run_code_execution_agent
        try:
            run_code_execution_agent.main()
        except SystemExit:
            pass

    def test_run_hosted_mcp_adk_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'Query SecOps logs via MCP',
        })
        from actions import run_hosted_mcp_adk_agent
        try:
            run_hosted_mcp_adk_agent.main()
        except SystemExit:
            pass

    def test_run_adk_memory_bank_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Prompt': 'Recall previous incident notes',
            'Session ID': 'session_12345',
        })
        from actions import run_adk_memory_bank_agent
        try:
            run_adk_memory_bank_agent.main()
        except SystemExit:
            pass

    def test_run_adk_agent_registry_agent(self):
        SiemplifyAction.set_mock_action_params({
            'User Query': 'Ask registry reasoning engine for triage recommendation',
            'Agent Registry Project ID': 'my-gcp-project',
        })
        from actions import run_adk_agent_registry_agent
        try:
            run_adk_agent_registry_agent.main()
        except SystemExit:
            pass

    def test_recover_adk_report_from_case_comments(self):
        from actions import run_adk_agent

        class DummyEngine:
            def list_case_comments(self, case_id):
                return [
                    {
                        "name": "cases/109362/caseComments/20526",
                        "comment": (
                            "### 🛡️ Tier 1 Autonomous Triage Report (T+10m Scheduled Sweep)\n"
                            "> **Verdict:** `True Positive (Malicious)` | **Disposition:** `Malicious — Active Compromise / Intrusion` | **Confidence:** `HIGH`\n\n"
                            "### 1. Executive Summary (BLUF)\nConfirmed CVE-2024-4577 exploitation."
                        ),
                    },
                    {
                        "name": "cases/109362/caseComments/20524",
                        "comment": "### [Automated Correlation] Silent Detections & Evidence\n- **Lookback Window**: 48 hours",
                    },
                ]

        self.assertFalse(
            run_adk_agent._is_valid_adk_report(
                "Case '109362' already carries 'Tier1:Triaged' tag; reusing cached ADK Agent result to preserve Case Overview widget."
            )
        )
        recovered = run_adk_agent._recover_adk_report_from_case_comments(
            secops_engine=DummyEngine(),
            case_id="109362",
            agent_name="SecOps_Triage_109362",
            model_name="gemini-3.8-flash",
            session_id="case_109362",
        )
        self.assertIsNotNone(recovered)
        self.assertTrue(recovered.get("recovered_from_case_wall"))
        self.assertIn("**Verdict:** `True Positive (Malicious)`", recovered.get("final_response", ""))


if __name__ == '__main__':
    unittest.main()
