import unittest
from actions.correlate_silent_detections import _format_markdown_report


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


if __name__ == "__main__":
    unittest.main()

