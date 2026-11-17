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

    def test_init_secops_engine_toolset_includes_homepage_dashboard(self):
        from unittest.mock import patch
        tools = self.manager.init_secops_engine_toolset(
            customer_id="a556547c-1cff-43ef-a2e4-cf5b12a865df",
            project_id="sdl-preview-americas",
            region="us",
        )
        tool_map = {t.__name__: t for t in tools}
        self.assertIn("sync_secops_homepage_dashboard", tool_map)
        self.assertGreaterEqual(len(tools), 30)

        with patch("engine.facade.SecOpsEngine.sync_secops_homepage_dashboard") as mock_sync:
            mock_sync.return_value = {"status": "SUCCESS", "dashboard_id": "dash-123"}
            res1 = tool_map["sync_secops_homepage_dashboard"](
                dashboard_name="Google SecOps Homepage",
                dashboard_id="dash-123",
                community_categories="community-blog-42,news-announcements-9",
            )
            self.assertEqual(res1["status"], "SUCCESS")
            mock_sync.assert_called_with(
                dashboard_name="Google SecOps Homepage",
                dashboard_id="dash-123",
                status_lookback_days=30,
                max_release_notes=4,
                max_community_posts=6,
                community_categories=["community-blog-42", "news-announcements-9"],
                include_tenant_health=True,
                ai_executive_summary=None,
            )

            res2 = tool_map["sync_secops_homepage_dashboard"](
                dashboard_title="Custom Title",
                dashboard_id="dash-123",
                community_categories=["community-blog-42"],
            )
            self.assertEqual(res2["status"], "SUCCESS")
            mock_sync.assert_called_with(
                dashboard_name="Custom Title",
                dashboard_id="dash-123",
                status_lookback_days=30,
                max_release_notes=4,
                max_community_posts=6,
                community_categories=["community-blog-42"],
                include_tenant_health=True,
                ai_executive_summary=None,
            )

    def test_tier1_triage_tools_exposed_and_wired(self):
        from unittest.mock import MagicMock, patch
        tools = self.manager.init_secops_engine_toolset(
            customer_id="a556547c-1cff-43ef-a2e4-cf5b12a865df",
            project_id="sdl-preview-americas",
            region="us",
        )
        tool_map = {t.__name__: t for t in tools}
        for expected_tool in [
            "validate_udm_sql",
            "query_udm_sql",
            "update_case_alert",
            "add_soar_case_tag",
            "remove_soar_case_tag",
        ]:
            self.assertIn(expected_tool, tool_map)

        with patch("adapters.google_secops.GoogleSecOpsAdapter.validate_query") as mock_val, \
             patch("adapters.google_secops.GoogleSecOpsAdapter.execute_dashboard_query") as mock_exec:
            mock_val.return_value = MagicMock(
                valid=True,
                dialect="DIALECT_SQL",
                raw_query_type="QUERY_TYPE_STRUCTURAL_CONVERSION",
                error_text=None,
                error_type=None,
            )
            v_res = tool_map["validate_udm_sql"]("FROM events |> LIMIT 5")
            self.assertTrue(v_res["valid"])
            mock_val.assert_called_with("FROM events |> LIMIT 5", dialect="DIALECT_SQL")

            mock_exec.return_value = MagicMock(
                columns=["event_type", "cnt"],
                rows=[{"event_type": "PROCESS_LAUNCH", "cnt": "10"}],
                total_rows=1,
                time_window={"relativeTime": {"timeUnit": "DAY", "startTimeVal": "1"}},
            )
            q_res = tool_map["query_udm_sql"](
                "FROM events |> AGGREGATE COUNT(*) AS cnt GROUP BY metadata.event_type AS event_type",
                lookback_hours=24,
            )
            self.assertTrue(q_res["valid"])
            self.assertEqual(q_res["total_rows"], 1)

        with patch("engine.facade.SecOpsEngine.update_case_alert") as mock_alert:
            mock_alert.return_value = MagicMock(
                to_dict=lambda: {"status": "CLOSE", "alert_id": "de_123", "priority": "LOW"}
            )
            a_res = tool_map["update_case_alert"](case_id="108671", alert_id="de_123", status="CLOSE", priority="LOW")
            self.assertEqual(a_res["status"], "CLOSE")
            mock_alert.assert_called_with(
                case_id="108671",
                alert_id="de_123",
                priority="LOW",
                status="CLOSE",
            )

        with patch("engine.facade.SecOpsEngine.add_case_tag") as mock_tag:
            mock_tag.return_value = {"status": "SUCCESS", "case_id": "108671", "tags_added": ["Tier1:Triaged", "Verdict:BTP"]}
            t_res = tool_map["add_soar_case_tag"](case_id="108671", tags="Tier1:Triaged, Verdict:BTP")
            self.assertEqual(t_res["status"], "SUCCESS")
            mock_tag.assert_called_with(case_id="108671", tags=["Tier1:Triaged", "Verdict:BTP"])

    def test_gemini_4_hydrogen_uses_global_and_thinking_level(self):
        from unittest.mock import MagicMock, patch
        mgr = GoogleADKManager(
            api_key="test-api-key",
            project_id="test-project",
            location="us-central1",
            model_name="gemini-4-hydrogen",
        )
        self.assertEqual(mgr.location, "global")

        mock_resp = MagicMock()
        mock_resp.text = "# Incident Investigation Report\n> **Verdict:** `True Positive (Malicious)` | **Disposition:** `Malicious — Active Compromise / Intrusion` | **Confidence:** `HIGH`"
        mock_resp.candidates = []
        mock_resp.automatic_function_calling_history = []

        with patch("google.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.models.generate_content.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            res = mgr.run_agent(
                agent_name="Logic_Analyst_Agent",
                instructions="Analyze the case",
                input_text="Case 109588",
                thinking_budget=8192,
            )
            self.assertIn("True Positive (Malicious)", res["final_response"])
            call_kwargs = mock_client.models.generate_content.call_args.kwargs
            cfg = call_kwargs["config"]
            self.assertEqual(str(cfg.thinking_config.thinking_level).split(".")[-1], "HIGH")
            self.assertIsNone(cfg.thinking_config.thinking_budget)


if __name__ == "__main__":
    unittest.main()
