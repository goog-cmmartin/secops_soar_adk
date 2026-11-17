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

    def test_is_noisy_entity_type_aware_blocklist(self):
        """Validates type-aware entity sanitization for SIDs, PIDs, LOLBins, hex masks, and misclassified hostnames."""
        from engine.workflows.correlate_silent_detections import is_noisy_entity

        # 1. Well-known Windows SIDs & default domain RIDs
        self.assertTrue(is_noisy_entity("S-1-0-0", "USERUNIQNAME"))
        self.assertTrue(is_noisy_entity("S-1-5-10", "WINDOWS_SID"))
        self.assertTrue(is_noisy_entity("S-1-5-18", "USERUNIQNAME"))
        self.assertTrue(is_noisy_entity("S-1-5-20"))
        self.assertTrue(is_noisy_entity("S-1-5-32-544", "USERUNIQNAME"))
        self.assertTrue(is_noisy_entity("S-1-5-21-2257503846-711036283-1384706157-500", "USERUNIQNAME"))
        # Real domain user SID with non-default RID (e.g. -1104) should NOT be blocked
        self.assertFalse(is_noisy_entity("S-1-5-21-2257503846-711036283-1384706157-1104", "USERUNIQNAME"))

        # 2. Default cloud/OS/localized users & machine accounts
        self.assertTrue(is_noisy_entity("ec2-user", "USERUNIQNAME"))
        self.assertTrue(is_noisy_entity("CORP\\Administrator", "USERUNIQNAME"))
        self.assertTrue(is_noisy_entity("WINDOW MANAGER\\DWM-1", "USERUNIQNAME"))
        self.assertTrue(is_noisy_entity("WIN-SERVER01$", "USERUNIQNAME"))
        self.assertFalse(is_noisy_entity("marcus.vance@apexfinancial.com", "USERUNIQNAME"))

        # 3. Bare numeric PIDs, hex masks, timestamps, and generic AWS-managed policies
        self.assertTrue(is_noisy_entity("4572", "PROCESS"))
        self.assertTrue(is_noisy_entity("652", "PROCESS"))
        self.assertTrue(is_noisy_entity("0X1010", "DEPLOYMENT"))
        self.assertTrue(is_noisy_entity("0X1FFFFF", "DEPLOYMENT"))
        self.assertTrue(is_noisy_entity("2026-10-31 20:47:21.886", "DEPLOYMENT"))
        self.assertTrue(is_noisy_entity("ARN:AWS:IAM::AWS:POLICY/ADMINISTRATORACCESS", "DEPLOYMENT"))
        # Customer-specific AWS IAM role ARN should NOT be blocked
        self.assertFalse(is_noisy_entity("arn:aws:iam::222634381096:role/OrganizationAccountAccessRole", "DEPLOYMENT"))

        # 4. System binaries, LOLBins & hashes
        self.assertTrue(is_noisy_entity("C:\\WINDOWS\\SYSTEM32\\NET.EXE", "FILENAME"))
        self.assertTrue(is_noisy_entity("\\Device\\HarddiskVolume3\\Program Files\\CrowdStrike\\CSFalconService.exe", "FILENAME"))
        self.assertTrue(is_noisy_entity("/opt/CrowdStrike/falcon-sensor-bpf19403", "FILENAME"))
        self.assertTrue(is_noisy_entity("7d91e2704409593c233031b8f7a3c22cc12d653d92f85c5c77233403ee7cb0b4", "FILEHASH"))
        self.assertFalse(is_noisy_entity("C:\\Users\\Public\\Downloads\\mimikatz.exe", "FILENAME"))

        # 5. Misclassified HOSTNAME entities & console URLs
        self.assertTrue(is_noisy_entity("Windows PowerShell ISE Host", "HOSTNAME"))
        self.assertTrue(is_noisy_entity("maor.dokhanian@wiz.io", "HOSTNAME"))
        self.assertTrue(is_noisy_entity("user@corp.example.com", "HOSTNAME"))
        self.assertFalse(is_noisy_entity("wks-fin-042.corp.local", "HOSTNAME"))
        self.assertTrue(is_noisy_entity("https://console.aws.amazon.com/iam/home#/roles/Admin", "DESTINATIONURL"))
        self.assertFalse(is_noisy_entity("http://91.92.240.58:8080/payload.sh", "DESTINATIONURL"))

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

    def test_resolve_instance_resource_accepts_numeric_project_number_when_configured_with_project_id(self):
        from adapters.google_secops import GoogleSecOpsAdapter
        from engine.config import SecOpsConfig

        cfg = SecOpsConfig(
            project_id="sdl-preview-americas",
            customer_id="a556547c-1cff-43ef-a2e4-cf5b12a865df",
            project_number="sdl-preview-americas",
            location="us",
        )
        adapter = GoogleSecOpsAdapter(config=cfg)
        op_resource = (
            "projects/37679061640/locations/us/instances/"
            "a556547c-1cff-43ef-a2e4-cf5b12a865df/operations/s-udm-7ac2c41e-8133-42d8-816e-cd457498d6f7"
        )
        resolved = adapter._resolve_instance_resource(op_resource, "operations", use_project_number=True)
        self.assertEqual(resolved, op_resource)
        self.assertEqual(adapter.project_number, "37679061640")

        # Subsequent mismatched numeric project or mismatched customer_id must still raise ValueError
        with self.assertRaises(ValueError):
            adapter._resolve_instance_resource(
                "projects/99999999999/locations/us/instances/"
                "a556547c-1cff-43ef-a2e4-cf5b12a865df/operations/s-udm-other",
                "operations",
                use_project_number=True,
            )
        with self.assertRaises(ValueError):
            adapter._resolve_instance_resource(
                "projects/37679061640/locations/us/instances/"
                "00000000-0000-0000-0000-000000000000/operations/s-udm-other",
                "operations",
                use_project_number=True,
            )


if __name__ == "__main__":
    unittest.main()
