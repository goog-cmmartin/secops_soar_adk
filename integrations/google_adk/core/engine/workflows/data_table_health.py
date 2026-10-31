"""Google Chronicle SIEM Data Table Governance & Lineage Workflow.

Audits Data Tables across the tenant for lifecycle recency, schema integrity,
silent detection false-negative risks (active rules referencing empty tables),
and orphan/stale governance.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    DataTable,
    DataTableHealthFinding,
    DataTableHealthReport,
    DataTableHealthStatus,
)
from engine.workflows.data_tables import ListDataTablesWorkflow
from engine.workflows.detection_rules import ListRulesWorkflow

logger = logging.getLogger(__name__)


class AuditDataTableHealthWorkflow:
    """Orchestrates comprehensive health, lineage, and governance auditing for Data Tables."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        lookback_days: int = 14,
        stale_days: int = 180,
        correlate_rules: bool = True,
        max_tables: int = 200,
    ) -> DataTableHealthReport:
        """Executes Data Table health and lineage governance audit.

        Args:
            lookback_days: Days threshold to classify recently created/modified tables.
            stale_days: Days threshold of inactivity to flag stale unreferenced tables.
            correlate_rules: Whether to scan rule definitions for %table% references.
            max_tables: Maximum number of tables to audit in batch.

        Returns:
            DataTableHealthReport with summary counts and detailed findings.
        """
        now_utc = datetime.now(timezone.utc)

        # Step 1: List all Data Tables
        list_dt_wf = ListDataTablesWorkflow(self.adapter)
        tables_batch = list_dt_wf.execute(page_size=max_tables)
        tables = tables_batch.tables

        # Step 2: Correlate Rule References if requested
        table_to_rules_map: Dict[str, Set[str]] = {}
        if correlate_rules:
            table_to_rules_map = self._build_rule_lineage_index()

        findings: List[DataTableHealthFinding] = []
        healthy_count = 0
        empty_ref_count = 0
        orphan_count = 0
        recently_created_count = 0
        recently_modified_count = 0
        stale_count = 0
        schema_issue_count = 0

        for table in tables:
            finding = self._evaluate_table(
                table=table,
                rule_lineage=table_to_rules_map,
                lookback_days=lookback_days,
                stale_days=stale_days,
                now_utc=now_utc,
            )
            findings.append(finding)

            if finding.status == DataTableHealthStatus.HEALTHY:
                healthy_count += 1
            elif finding.status == DataTableHealthStatus.EMPTY_REFERENCED:
                empty_ref_count += 1
            elif finding.status == DataTableHealthStatus.ORPHAN:
                orphan_count += 1
            elif finding.status == DataTableHealthStatus.RECENTLY_CREATED:
                recently_created_count += 1
            elif finding.status == DataTableHealthStatus.RECENTLY_MODIFIED:
                recently_modified_count += 1
            elif finding.status == DataTableHealthStatus.SCHEMA_ISSUE:
                schema_issue_count += 1
            elif finding.status == DataTableHealthStatus.STALE:
                stale_count += 1

        return DataTableHealthReport(
            total_tables_audited=len(tables),
            healthy_count=healthy_count,
            empty_referenced_count=empty_ref_count,
            orphan_count=orphan_count,
            recently_created_count=recently_created_count,
            recently_modified_count=recently_modified_count,
            stale_count=stale_count,
            schema_issue_count=schema_issue_count,
            findings=findings,
            generated_at=now_utc,
        )

    def _build_rule_lineage_index(self) -> Dict[str, Set[str]]:
        """Scans detection rules to find YARA-L references to Data Tables (%table_name%)."""
        lineage: Dict[str, Set[str]] = {}
        try:
            list_rules_wf = ListRulesWorkflow(self.adapter)
            batch = list_rules_wf.execute(page_size=200)
            pattern = re.compile(r"%([a-zA-Z0-9_-]+)%")

            for rule in batch.rules:
                rule_text = rule.raw.get("text") or rule.raw.get("ruleText") or ""
                rule_name = rule.display_name or rule.raw.get("displayName") or rule.raw.get("ruleName") or rule.name
                matches = pattern.findall(rule_text)
                for ref_name in matches:
                    ref_key = ref_name.lower().strip()
                    if ref_key not in lineage:
                        lineage[ref_key] = set()
                    lineage[ref_key].add(rule_name)
        except Exception as e:
            logger.debug(f"Rule lineage correlation scan encountered an issue: {e}")
        return lineage

    def _evaluate_table(
        self,
        table: DataTable,
        rule_lineage: Dict[str, Set[str]],
        lookback_days: int,
        stale_days: int,
        now_utc: datetime,
    ) -> DataTableHealthFinding:
        """Evaluates health, lineage, and lifecycle status for a single Data Table."""
        # Calculate recency
        create_dt = table.create_time
        update_dt = table.update_time or create_dt

        days_since_create = (now_utc - create_dt).days if create_dt else None
        days_since_update = (now_utc - update_dt).days if update_dt else None

        is_recently_created = bool(days_since_create is not None and days_since_create <= lookback_days)
        is_recently_modified = bool(
            days_since_update is not None
            and days_since_update <= lookback_days
            and not is_recently_created
        )
        is_stale = bool(days_since_update is not None and days_since_update > stale_days)

        # Collect rule associations
        associated_rules_set: Set[str] = set(table.rules or [])

        # Match from lineage index
        table_key = (table.display_name or table.id).lower().strip()
        table_id_key = table.id.lower().strip()
        if table_key in rule_lineage:
            associated_rules_set.update(rule_lineage[table_key])
        if table_id_key in rule_lineage:
            associated_rules_set.update(rule_lineage[table_id_key])

        associated_rules = sorted(list(associated_rules_set))
        rule_associations_count = max(table.rule_associations_count or 0, len(associated_rules))

        # Schema evaluation
        key_columns = [col.original_column for col in table.column_info if col.key_column]
        has_key_column = len(key_columns) > 0
        has_columns = len(table.column_info) > 0
        schema_missing_key = has_columns and not has_key_column

        # Row population evaluation
        row_count = table.approximate_row_count
        is_empty_or_zero = row_count is not None and row_count == 0

        # Classification Hierarchy
        status = DataTableHealthStatus.HEALTHY
        details = "Data Table is healthy, populated, and operating normally."
        remediations: List[str] = []

        if is_empty_or_zero and rule_associations_count > 0:
            status = DataTableHealthStatus.EMPTY_REFERENCED
            details = (
                f"CRITICAL DETECTION RISK: Data table has 0 rows but is associated with {rule_associations_count} "
                f"detection rule(s). Rules utilizing '%{table.display_name}%' will silently fail to match events."
            )
            remediations.append(f"Populate rows into table '{table.display_name}' via API or CSV upload immediately.")
            remediations.append(f"Inspect referencing detection rules: {', '.join(associated_rules[:5])}")
        elif schema_missing_key:
            status = DataTableHealthStatus.SCHEMA_ISSUE
            details = f"Table has {len(table.column_info)} columns but no key column designated for fast indexing."
            remediations.append("Update table schema definition to designate at least one primary key column.")
        elif rule_associations_count == 0 and (row_count == 0 or row_count is None) and is_stale:
            status = DataTableHealthStatus.ORPHAN
            details = (
                f"Orphan data table: 0 rows, 0 associated detection rules, and no updates for "
                f"{days_since_update} days."
            )
            remediations.append("Archive or delete unreferenced data table if no longer required for threat hunts.")
        elif is_recently_created:
            status = DataTableHealthStatus.RECENTLY_CREATED
            details = f"Data table was newly created {days_since_create} day(s) ago (rows: {row_count or 0})."
            remediations.append("Verify column types, TTL expiration policies, and attach to relevant YARA-L rules.")
        elif is_recently_modified:
            status = DataTableHealthStatus.RECENTLY_MODIFIED
            details = f"Data table was modified {days_since_update} day(s) ago (rows: {row_count or 0})."
            remediations.append("Review recent row updates or schema modifications for data consistency.")
        elif is_stale and rule_associations_count == 0:
            status = DataTableHealthStatus.STALE
            details = f"Data table has had no updates for {days_since_update} days and has 0 attached rules."
            remediations.append("Confirm with table owner if table is still needed for SOAR playbooks or ad-hoc queries.")

        return DataTableHealthFinding(
            table_id=table.id,
            display_name=table.display_name or table.id,
            description=table.description,
            approximate_row_count=row_count,
            column_count=len(table.column_info),
            key_columns=key_columns,
            row_time_to_live=table.row_time_to_live,
            create_time=create_dt,
            update_time=update_dt,
            associated_rules=associated_rules,
            associated_dashboards=[],
            rule_associations_count=rule_associations_count,
            status=status,
            details=details,
            remediation_steps=remediations,
            raw=table.raw,
        )
