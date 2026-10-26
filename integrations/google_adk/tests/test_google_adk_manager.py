import unittest
import sys
from pathlib import Path

root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir / "core"))

from GoogleADKManager import GoogleADKManager, google_search


class TestGoogleADKManager(unittest.TestCase):
    def setUp(self):
        self.manager = GoogleADKManager(
            api_key="test-api-key",
            project_id="test-project",
            location="us-central1",
            model_name="gemini-3.7-flash",
        )

    def test_workload_identity_init(self):
        wif_mgr = GoogleADKManager(
            workload_identity_email='secops-runner@project.iam.gserviceaccount.com',
            project_id='test-project',
        )
        self.assertEqual(wif_mgr.workload_identity_email, 'secops-runner@project.iam.gserviceaccount.com')

    def test_init_and_test_connection(self):
        self.assertEqual(self.manager.project_id, "test-project")
        self.assertEqual(self.manager.model_name, "gemini-3.7-flash")
        self.assertTrue(self.manager.test_connection())

    def test_resolve_memory_configuration_disabled(self):
        session_id, mem_service, tools = self.manager.resolve_memory_configuration(
            enable_memory=False, session_id=None
        )
        self.assertIsNone(session_id)
        self.assertIsNone(mem_service)
        self.assertEqual(len(tools), 0)

    def test_resolve_memory_configuration_enabled(self):
        session_id, mem_service, tools = self.manager.resolve_memory_configuration(
            enable_memory=True, session_id="my-custom-session"
        )
        self.assertEqual(session_id, "my-custom-session")
        self.assertIsNotNone(mem_service)
        self.assertEqual(len(tools), 1)
        tool_result = tools[0]("what was the hash?")
        self.assertEqual(tool_result["status"], "success")

    def test_init_mcp_toolset(self):
        mcp = self.manager.init_mcp_toolset("https://mcp.example.com", "my-project", ["tool1"])
        self.assertTrue(callable(mcp))
        res = mcp("tool1", {"arg": "val"})
        self.assertEqual(res["tool_called"], "tool1")
        self.assertEqual(res["mcp_url"], "https://mcp.example.com")

    def test_init_gcs_toolsets(self):
        ro_tools = self.manager.init_gcs_toolsets(enable_admin=False, enable_write=False)
        self.assertEqual(len(ro_tools), 2)

        full_tools = self.manager.init_gcs_toolsets(enable_admin=True, enable_write=True)
        self.assertEqual(len(full_tools), 4)

    def test_init_skill_registry_toolset(self):
        search_skills = self.manager.init_skill_registry_toolset()
        skills = search_skills("triage")
        self.assertTrue(len(skills) > 0)
        reg_res = self.manager.register_gcp_skill(
            skill_id="WF-001",
            display_name="Test Skill",
            description="A test runbook",
            markdown_instructions="# Instructions",
        )
        self.assertEqual(reg_res["status"], "success")

    def test_google_search_tool(self):
        res = google_search("Cobalt Strike C2")
        self.assertEqual(res["status"], "success")
        self.assertTrue(len(res["results"]) > 0)

    def test_run_agent_simulation_fallback(self):
        res = self.manager.run_agent(
            agent_name="Analyst",
            instructions="Analyze the event",
            input_text="IP: 198.51.100.1",
            thinking_budget=1024,
            enable_code_execution=True,
        )
        self.assertEqual(res["agent_name"], "Analyst")
        self.assertIn("Code Execution", res["final_response"])
        self.assertTrue(len(res["thoughts"]) > 0)


if __name__ == "__main__":
    unittest.main()
