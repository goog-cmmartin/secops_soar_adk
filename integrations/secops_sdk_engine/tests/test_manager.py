import unittest
from unittest.mock import MagicMock
from core.SecOpsSDKEngineManager import SafeLogger, SecOpsSDKCredentialProvider, SecOpsSDKEngineManager


class MockLoggerWithoutWarning:
    def __init__(self):
        self.logs = []

    def info(self, msg, *args, **kwargs):
        self.logs.append(("INFO", msg))

    def error(self, msg, *args, **kwargs):
        self.logs.append(("ERROR", msg))


class TestSecOpsSDKEngineManager(unittest.TestCase):
    def test_safe_logger_defensive_warning(self):
        """Ensures SafeLogger intercepts warning on loggers lacking .warning()."""
        raw_logger = MockLoggerWithoutWarning()
        safe = SafeLogger(raw_logger)
        # Should NOT raise AttributeError:
        safe.warning("This is a warning message")
        self.assertTrue(any("WARNING" in l[1] or l[0] == "WARNING" for l in raw_logger.logs))

    def test_manager_initialization_with_sa_json(self):
        """Validates manager initialization with Service Account JSON."""
        sa_mock = '{"type": "service_account", "project_id": "mock-proj", "private_key": "fake", "client_email": "test@mock-proj.iam.gserviceaccount.com"}'
        mgr = SecOpsSDKEngineManager(
            customer_id="cust-12345",
            project_id="mock-proj",
            region="us",
            service_account_json=sa_mock,
        )
        self.assertEqual(mgr.customer_id, "cust-12345")
        self.assertEqual(mgr.project_id, "mock-proj")
        self.assertEqual(mgr.region, "us")
        self.assertIn("us-chronicle.googleapis.com", mgr.api_base)

    def test_manager_initialization_with_wif(self):
        """Validates manager initialization with Workload Identity email."""
        wif_email = "sa-chronicle@my-project.iam.gserviceaccount.com"
        mgr = SecOpsSDKEngineManager(
            customer_id="cust-99999",
            region="europe",
            workload_identity_email=wif_email,
        )
        self.assertEqual(mgr.customer_id, "cust-99999")
        self.assertEqual(mgr.project_id, "my-project")
        self.assertEqual(mgr.region, "europe")
        self.assertIn("europe-chronicle.googleapis.com", mgr.api_base)

    def test_parsed_entity_filter_types_and_identifiers(self):
        """Validates ParsedEntityFilter for Filter Out (Exclude), Filter In (Include), and inline prefixes."""
        from engine.workflows.correlate_silent_detections import ParsedEntityFilter

        # 1. Exclude DESTINATIONURL, FILENAME, PROCESS (default SOAR mode 'Filter Out (Exclude)')
        f_excl = ParsedEntityFilter(
            entity_filter=["DESTINATIONURL", "FILENAME", "PROCESS"],
            entity_filter_mode="Filter Out (Exclude)",
        )
        self.assertFalse(f_excl.matches("https://evil.example/login", "DESTINATIONURL"))
        self.assertFalse(f_excl.matches("https://evil.example/login", "URL"))
        self.assertFalse(f_excl.matches("payload.exe", "FILENAME"))
        self.assertFalse(f_excl.matches("/usr/bin/php-fpm", "PROCESS"))
        self.assertTrue(f_excl.matches("185.220.101.42", "ADDRESS"))
        self.assertTrue(f_excl.matches("rhel-web01", "HOSTNAME"))
        self.assertTrue(f_excl.matches("marcus.vance@apexfinancial.com", "USERUNIQNAME"))
        self.assertEqual(f_excl.explicit_include_id_values, [])

        # 2. AUTO mode with bare entity types also excludes those types automatically
        f_auto_types = ParsedEntityFilter(
            entity_filter=["DESTINATIONURL", "FILENAME", "PROCESS"],
            entity_filter_mode="AUTO",
        )
        self.assertFalse(f_auto_types.matches("https://evil.example/login", "DESTINATIONURL"))
        self.assertFalse(f_auto_types.matches("payload.exe", "FILENAME"))
        self.assertFalse(f_auto_types.matches("/usr/bin/php-fpm", "PROCESS"))
        self.assertTrue(f_auto_types.matches("185.220.101.42", "ADDRESS"))

        # 3. Filter In (Include) mode with specific entity types
        f_incl_types = ParsedEntityFilter(
            entity_filter=["ADDRESS", "HOSTNAME"],
            entity_filter_mode="Filter In (Include)",
        )
        self.assertTrue(f_incl_types.matches("185.220.101.42", "ADDRESS"))
        self.assertTrue(f_incl_types.matches("rhel-web01", "HOSTNAME"))
        self.assertFalse(f_incl_types.matches("https://evil.example/login", "DESTINATIONURL"))

        # 4. Inline '-' / '!' and '+' prefixes
        f_inline = ParsedEntityFilter(
            entity_filter=["-DESTINATIONURL", "!PROCESS", "+185.220.101.42"],
            entity_filter_mode="Filter In (Include)",
        )
        self.assertTrue(f_inline.matches("185.220.101.42", "ADDRESS"))
        self.assertFalse(f_inline.matches("10.0.0.5", "ADDRESS"))
        self.assertFalse(f_inline.matches("https://evil.example", "DESTINATIONURL"))
        self.assertEqual(f_inline.explicit_include_id_values, ["185.220.101.42"])

    def test_prewarm_case_summaries(self):
        """Validates prewarm_case_summaries workflow filtering, deduplication, and summary triggering."""
        from datetime import datetime, timedelta, timezone

        mgr = SecOpsSDKEngineManager(
            customer_id="cust-12345",
            project_id="mock-proj",
            region="us",
        )
        now = datetime.now(timezone.utc)
        c1 = MagicMock(
            case_id="108552",
            display_name="New Case 1",
            priority="HIGH",
            create_time=now - timedelta(minutes=5),
            update_time=now - timedelta(minutes=5),
        )
        c2 = MagicMock(
            case_id="108551",
            display_name="Already Processed Case",
            priority="MEDIUM",
            create_time=now - timedelta(minutes=10),
            update_time=now - timedelta(minutes=10),
        )
        c3 = MagicMock(
            case_id="108100",
            display_name="Old Case Outside Window",
            priority="LOW",
            create_time=now - timedelta(minutes=180),
            update_time=now - timedelta(minutes=180),
        )
        mgr.list_cases_workflow = MagicMock()
        mgr.list_cases_workflow.execute.return_value = MagicMock(cases=[c1, c2, c3])

        mgr.case_summary_workflow = MagicMock()
        mgr.case_summary_workflow.execute.return_value = MagicMock(
            state="IN_PROGRESS",
            summary=None,
        )

        res = mgr.prewarm_case_summaries(
            lookback_minutes=60,
            max_cases=25,
            processed_case_ids=["108551"],
        )
        self.assertEqual(res["cases_fetched"], 3)
        self.assertEqual(res["candidates_evaluated"], 1)
        self.assertEqual(res["skipped_already_processed"], 1)
        self.assertEqual(res["skipped_outside_window"], 1)
        self.assertEqual(res["initiated_in_progress_count"], 1)
        self.assertEqual(res["newly_processed_case_ids"], ["108552"])
        mgr.case_summary_workflow.execute.assert_called_once_with(case_id="108552")

    def test_homepage_dashboard_markdown_and_kpi_builders(self):
        """Validates Homepage Dashboard Markdown and KPI visualization builders."""
        from engine.workflows.homepage_dashboard import (
            _build_kpi_text_visualization,
            _format_ai_executive_summary_markdown,
            _format_header_markdown,
            _format_tenant_health_markdown,
        )

        kpi_vis = _build_kpi_text_visualization(label="24h UDM Events", field="event_count")
        self.assertIn("series", kpi_vis)
        self.assertEqual(kpi_vis["series"][0]["seriesType"], "TEXT")
        self.assertEqual(kpi_vis["series"][0]["field"], "event_count")

        mock_health = {
            "udm_events_24h": 7554851,
            "active_udm_log_types_24h": 42,
            "active_ingestion_log_types_24h": 31,
            "top_udm_log_types": [{"log_type": "WINDOWS_SYSMON", "count": 2659858}],
            "detections_7d": 599077,
            "open_cases_sampled": 100,
            "case_priorities": {"CRITICAL": 35, "HIGH": 65, "MEDIUM": 0, "LOW": 0},
            "rules_total": 100,
            "rules_enabled": 100,
            "rules_alerting": 61,
            "rules_silent": 39,
            "top_alerting_rules": [],
            "top_silent_rules": [],
            "active_feeds_count": 32,
            "total_feeds_count": 40,
            "data_tables_count": 28,
        }
        header_md = _format_header_markdown(
            dashboard_title="Google SecOps Homepage",
            active_incidents_count=0,
            recent_incidents_count=0,
            latest_release_date="October 30, 2026",
            community_count=6,
            community_filters=["community-blog-42", "news-announcements-9"],
            tenant_health=mock_health,
            refreshed_at_str="2026-10-31 10:30 UTC",
        )
        self.assertIn("Google SecOps Homepage", header_md)
        self.assertIn("ALL SECOPS SERVICES OPERATIONAL", header_md)

        ai_md = _format_ai_executive_summary_markdown(
            incidents=[],
            release_notes=[],
            community_data={"items": []},
            tenant_health=mock_health,
            refreshed_at_str="2026-10-31 10:30 UTC",
            custom_ai_summary="- **Priority Alert**: 35 Critical SOAR cases require triage.",
        )
        self.assertIn("AI Executive Summary", ai_md)
        self.assertIn("Priority Alert", ai_md)

        th_md = _format_tenant_health_markdown(
            tenant_health=mock_health,
            refreshed_at_str="2026-10-31 10:30 UTC",
        )
        self.assertIn("Live Tenant Health & Operations Pulse", th_md)
        self.assertIn("7,554,851 events", th_md)


if __name__ == "__main__":
    unittest.main()
