"""SOAR Playbook Health Check and Governance Workflow.

Audits SOAR playbooks and modular blocks across Google SecOps by fusing
structural configuration governance with live operational telemetry from the
native 'Playbook Dashboard (SOAR)'.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine

logger = logging.getLogger(__name__)


class AuditPlaybookHealthWorkflow:
    """Orchestrates comprehensive health and operational auditing across SOAR playbooks."""

    def __init__(self, engine: SecOpsEngine):
        self.engine = engine

    def execute(
        self,
        days: int = 7,
        scan_deep: bool = True,
        fail_threshold_pct: float = 15.0,
        slow_threshold_minutes: float = 3.0,
    ) -> Dict[str, Any]:
        """Audits SOAR playbooks for configuration anomalies, failure spikes, faulted actions, and queue latency.

        Args:
            days: Lookback evaluation window in days (default: 7).
            scan_deep: Whether to execute deep query analytics from native Playbook Dashboard.
            fail_threshold_pct: Failure rate % threshold to flag playbooks as high risk.
            slow_threshold_minutes: Runtime duration in minutes to flag slow workflows.

        Returns:
            Dictionary containing executive summary, operational metrics, and prioritized findings.
        """
        from runbooks.operations.soar_playbook_health import generate_soar_playbook_health_report

        return generate_soar_playbook_health_report(
            engine=self.engine,
            days=days,
            scan_deep=scan_deep,
            fail_threshold_pct=fail_threshold_pct,
            slow_threshold_minutes=slow_threshold_minutes,
        )
