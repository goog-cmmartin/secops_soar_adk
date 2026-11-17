import json
import unittest
from actions.correlate_silent_detections import (
    _enforce_payload_ceiling,
    _format_markdown_report,
)


class MockCorrelationResult:
    def __init__(self):
        self.case_id = "108339"
        self.lookback_hours = 24
        self.entities_searched = [{"identifier": "10.0.0.1", "type": "IP", "role": "SRC"}]
        self.detections_found = [
            {
                "rule_name": "Suspicious VPN Access",
                "alert_state": "SILENT",
                "is_alerting": False,
                "severity": "HIGH",
                "event_id": "EVENT_ABC_123",
            }
        ]
        self.attached_evidences = []
        self.comment_id = "comment-456"


class TestSecOpsSDKActions(unittest.TestCase):
    def test_format_markdown_report(self):
        mock_res = MockCorrelationResult()
        report = _format_markdown_report(mock_res)
        self.assertIn("Silent Detection Correlation Report", report)
        self.assertIn("108339", report)
        self.assertIn("Suspicious VPN Access", report)
        self.assertIn("SILENT", report)
        self.assertIn("HIGH", report)
        self.assertIn("comment-456", report)

    def test_format_markdown_report_with_attached_entities(self):
        mock_res = MockCorrelationResult()
        mock_res.attached_entities = [
            {"identifier": "149.40.62.33", "type": "IP", "entity_id": "99901", "status": "ATTACHED"}
        ]
        report = _format_markdown_report(mock_res)
        self.assertIn("Attached Case Entities", report)
        self.assertIn("149.40.62.33", report)
        self.assertIn("99901", report)
        self.assertIn("ATTACHED", report)

    def test_correlate_silent_detections_hash_corroboration_and_ranking(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        from engine.workflows.correlate_silent_detections import CorrelateSilentDetectionsWorkflow

        adapter = MagicMock()
        wf = CorrelateSilentDetectionsWorkflow(adapter=adapter)
        ntds_hash = "08B052934E91C0CF0E4328FAD74BABE3A5CCD95D94C5124C205D4D1957F464A8"
        cmd_hash = "BC866CFCDDA37E24DC2634DC282C7A0E6F55209DA17A8FA105B07414C0E7C527"

        inv = SimpleNamespace(
            case_id="108709",
            title="Test Cluster",
            status="OPEN",
            priority="HIGH",
            stage="Triage",
            created_time=None,
            alerts=[
                SimpleNamespace(
                    identifier="ALERT_1",
                    name="cases/108709/caseAlerts/1",
                    rule_name="Cluster Match",
                    vendor="Google Chronicle",
                    raw={"ticketId": "de_111", "sourceSystemName": "Chronicle"},
                ),
                SimpleNamespace(
                    identifier="ALERT_3",
                    name="cases/108709/caseAlerts/3",
                    rule_name="Cluster Match 3",
                    vendor="Google Chronicle",
                    raw={"ticketId": "de_333", "sourceSystemName": "Chronicle"},
                ),
            ],
            entities=[
                SimpleNamespace(identifier="WIN-DESKTOP", entity_type="HOSTNAME", role="SRC", raw={"alertIdentifier": "ALERT_1"}),
                SimpleNamespace(identifier="SERHATG@WIN-DESKTOP", entity_type="USERUNIQNAME", role="SRC", raw={"alertIdentifier": "ALERT_1"}),
                SimpleNamespace(identifier="C:\\Windows\\System32\\cmd.exe", entity_type="FILE", role="SRC", raw={"alertIdentifier": "ALERT_3"}),
                SimpleNamespace(identifier=cmd_hash, entity_type="SHA256", role="SRC", raw={"alertIdentifier": "ALERT_3"}),
                SimpleNamespace(identifier="C:\\Windows\\System32\\ntdsutil.exe", entity_type="FILE", role="SRC", raw={"alertIdentifier": "ALERT_3"}),
                SimpleNamespace(identifier=ntds_hash, entity_type="SHA256", role="SRC", raw={"alertIdentifier": "ALERT_3"}),
            ],
            comments=[],
            raw={},
        )
        wf.investigate_workflow.execute = MagicMock(return_value=inv)

        mock_session = MagicMock()
        mock_session.events = [
            {
                "metadata": {"id": "ev_ntds", "eventTimestamp": "2026-10-31T23:00:00Z", "eventType": "PROCESS_LAUNCH"},
                "principal": {"hostname": "activedir.stackedpads.local", "user": {"userid": "frank.kolzig"}},
                "target": {"process": {"file": {"fullPath": "C:\\Windows\\System32\\ntdsutil.exe", "sha256": ntds_hash.lower()}}},
                "detections": [{"id": "de_silent_ntds", "ruleName": "Writing Ntds Dit To Uncommon Folder", "alertState": "NOT_ALERTING", "severity": "MEDIUM"}],
            },
            {
                "metadata": {"id": "ev_win", "eventTimestamp": "2026-10-31T22:00:00Z", "eventType": "NETWORK_CONNECTION"},
                "principal": {"hostname": "WIN-DESKTOP", "user": {"userid": "WIN-DESKTOP\\serhatg", "userDisplayName": "Serhat G"}, "ip": ["10.19.6.24"]},
                "target": {"ip": ["171.25.193.77"]},
                "detections": [{"id": "de_silent_proxy", "ruleName": "Network Connection to Anonymous Proxy IP", "alertState": "NOT_ALERTING", "severity": "HIGH"}],
            },
        ]
        wf.search_workflow.execute = MagicMock(return_value=mock_session)
        wf.attach_workflow.execute = MagicMock(return_value=MagicMock(evidence_items=[]))
        adapter.add_case_alert_entity.return_value = {"id": "ent_1"}

        res = wf.execute(case_id="108709", attach_to_case=True, attach_entities=True, post_wall_comment=False, max_entities_to_attach=4)
        # Verify generic cmd.exe hash was skipped while ntdsutil.exe hash was included in query
        self.assertIn(ntds_hash, res.query_used)
        self.assertNotIn(cmd_hash, res.query_used)
        # Verify both silent detections (including Alert 3 hash-anchored detection) were corroborated
        rule_names = [d["rule_name"] for d in res.detections_found]
        self.assertIn("Writing Ntds Dit To Uncommon Folder", rule_names)
        self.assertIn("Network Connection to Anonymous Proxy IP", rule_names)
        # Verify delta entity ranking: HOSTNAME -> External IP -> New User -> Internal IP (ahead of WIN-DESKTOP\serhatg alias)
        attached_ids = [ae["identifier"] for ae in res.attached_entities]
        self.assertEqual(attached_ids, ["activedir.stackedpads.local", "171.25.193.77", "frank.kolzig", "10.19.6.24"])

    def test_format_markdown_report_caps_rows_with_footer(self):
        mock_res = MockCorrelationResult()
        mock_res.detections_found = [
            {
                "rule_name": f"Rule_{(i % 3) + 1}",
                "alert_state": "SILENT",
                "is_alerting": False,
                "severity": "MEDIUM",
                "event_id": f"EVENT_{i:04d}_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            }
            for i in range(60)
        ]
        report = _format_markdown_report(mock_res)
        self.assertIn("- **Detections Discovered**: `60`", report)
        self.assertIn("- **Unique Rules Triggered**: `3`", report)
        self.assertIn("*...and 35 more detections across 3 unique rules.*", report)
        # Ensure all 3 rules are represented in the capped table
        self.assertIn("| Rule_1 |", report)
        self.assertIn("| Rule_2 |", report)
        self.assertIn("| Rule_3 |", report)

    def test_enforce_payload_ceiling_compacts_4mb_payload_under_150kb(self):
        huge_cmdline = "powershell.exe -enc " + ("A" * 5000)
        noisy_detections = [
            {
                "detection_id": f"de_{i:05d}",
                "rule_name": f"Silent_Rule_{(i % 4) + 1}",
                "rule_id": f"ru_{(i % 4) + 1}",
                "alert_state": "NOT_ALERTING",
                "is_alerting": False,
                "severity": "HIGH",
                "event_id": f"ev_{i:05d}",
                "summary": "Long summary " + ("X" * 1200),
                "principal": {
                    "hostname": "host-01.corp.local",
                    "process": {"command_line": huge_cmdline},
                    "raw": {"huge_blob": "B" * 4000},
                },
                "detectionFields": [{"key": f"k{j}", "value": "V" * 500} for j in range(30)],
            }
            for i in range(400)
        ]
        noisy_events = [
            {
                "event_id": f"udm_{i:05d}",
                "event_type": "PROCESS_LAUNCH",
                "product_log_id": f"pl_{i:05d}",
                "description": "D" * 1500,
                "udm": {"deep": "U" * 5000},
                "about": [{"labels": [{"key": "lbl", "value": "L" * 1000}]}],
            }
            for i in range(400)
        ]
        raw_payload = {
            "case_id": "109430",
            "lookback_hours": 48,
            "has_silent_detections": True,
            "detections_count": len(noisy_detections),
            "silent_detections_count": len(noisy_detections),
            "events_count": len(noisy_events),
            "attached_count": 50,
            "detections_found": noisy_detections,
            "events_found": noisy_events,
            "attached_evidences": [
                {"evidenceId": f"de_{i:05d}", "evidenceType": "EVIDENCE_TYPE_DETECTION", "raw": "R" * 2000}
                for i in range(100)
            ],
            "entities_searched": [f"10.0.0.{i}" for i in range(250)],
            "query_used": "Q" * 10000,
            "evidence_markdown": "M" * 30000,
        }
        # Raw payload is several megabytes
        self.assertGreater(len(json.dumps(raw_payload)), 4_000_000)

        bounded = _enforce_payload_ceiling(raw_payload, max_result_records=50)
        serialized = json.dumps(bounded)

        # Strictly below 150 KB ceiling
        self.assertLess(len(serialized), 150_000)
        # Counts remain accurate for the full totals
        self.assertEqual(bounded["detections_count"], 400)
        self.assertEqual(bounded["silent_detections_count"], 400)
        self.assertEqual(bounded["events_count"], 400)
        self.assertEqual(bounded["attached_count"], 50)
        self.assertEqual(
            bounded["rules_triggered"],
            ["Silent_Rule_1", "Silent_Rule_2", "Silent_Rule_3", "Silent_Rule_4"],
        )
        self.assertTrue(bounded["detections_truncated"])
        self.assertTrue(bounded["events_truncated"])
        self.assertLessEqual(len(bounded["detections_found"]), 50)
        self.assertLessEqual(len(bounded["events_found"]), 50)
        # Deep raw/detectionFields blobs stripped and oversized strings truncated
        first_det = bounded["detections_found"][0]
        self.assertNotIn("detectionFields", first_det)
        self.assertNotIn("raw", first_det.get("principal", {}))
        self.assertTrue(first_det["summary"].endswith("...[truncated]"))


if __name__ == "__main__":
    unittest.main()

