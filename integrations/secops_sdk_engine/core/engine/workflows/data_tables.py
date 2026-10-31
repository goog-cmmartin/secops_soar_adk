"""Google Chronicle SIEM Data Table workflows.

Orchestrates listing, creating, reading, updating, deleting, and populating
structured Data Tables and Data Table Rows in Chronicle SIEM.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    DataTable,
    DataTableColumnInfo,
    DataTableListResult,
    DataTableRow,
    DataTableRowListResult,
)


def _clean_id(raw_id: str) -> str:
    """Extracts terminal identifier from resource path."""
    return str(raw_id).strip().split("/")[-1]


def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parses RFC 3339 timestamp string into UTC datetime object."""
    if not ts_str:
        return None
    try:
        s = str(ts_str).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _map_column_info(raw_cols: List[Dict[str, Any]]) -> List[DataTableColumnInfo]:
    """Maps raw column metadata list to DataTableColumnInfo dataclasses."""
    cols = []
    for idx, c in enumerate(raw_cols):
        col_index = c.get("columnIndex", idx)
        cols.append(
            DataTableColumnInfo(
                column_index=col_index,
                original_column=c.get("originalColumn", f"col_{col_index}"),
                column_type=c.get("columnType", "STRING"),
                mapped_column_path=c.get("mappedColumnPath"),
                key_column=bool(c.get("keyColumn", False)),
                repeated_values=bool(c.get("repeatedValues", False)),
                raw=c,
            )
        )
    return cols


def _map_data_table(raw: Dict[str, Any]) -> DataTable:
    """Maps raw Chronicle API data table response to typed DataTable dataclass."""
    name = raw.get("name", "")
    table_id = _clean_id(name)
    display_name = raw.get("displayName", table_id)
    description = raw.get("description")

    raw_cols = raw.get("columnInfo", [])
    cols = _map_column_info(raw_cols)

    row_count_str = raw.get("approximateRowCount")
    row_count = int(row_count_str) if row_count_str is not None and str(row_count_str).isdigit() else None

    rules = raw.get("rules", [])
    rule_associations_count = raw.get("ruleAssociationsCount", len(rules))

    return DataTable(
        name=name,
        id=table_id,
        display_name=display_name,
        description=description,
        column_info=cols,
        approximate_row_count=row_count,
        rule_associations_count=rule_associations_count,
        rules=rules,
        row_time_to_live=raw.get("rowTimeToLive"),
        scope_info=raw.get("scopeInfo"),
        data_table_uuid=raw.get("dataTableUuid"),
        create_time=_parse_timestamp(raw.get("createTime")),
        update_time=_parse_timestamp(raw.get("updateTime")),
        raw=raw,
    )


def _map_data_table_row(raw: Dict[str, Any]) -> DataTableRow:
    """Maps raw Chronicle API row object to typed DataTableRow dataclass."""
    name = raw.get("name", "")
    row_id = _clean_id(name)
    values = [str(v) for v in raw.get("values", [])]

    return DataTableRow(
        name=name,
        id=row_id,
        values=values,
        create_time=_parse_timestamp(raw.get("createTime")),
        update_time=_parse_timestamp(raw.get("updateTime")),
        row_time_to_live=raw.get("rowTimeToLive"),
        raw=raw,
    )


class ListDataTablesWorkflow:
    """Retrieves list of structured data tables in Chronicle SIEM."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> DataTableListResult:
        res = self.adapter.list_data_tables(
            page_size=page_size,
            page_token=page_token,
            order_by=order_by,
        )
        raw_tables = res.get("dataTables", [])
        tables = [_map_data_table(t) for t in raw_tables]
        return DataTableListResult(
            tables=tables,
            next_page_token=res.get("nextPageToken"),
            total_size=len(tables),
            provenance={
                "call": "dataTables.list",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


class GetDataTableWorkflow:
    """Retrieves schema and metadata for a specific Chronicle SIEM Data Table."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, table_name_or_id: str) -> DataTable:
        raw = self.adapter.get_data_table(table_name_or_id=table_name_or_id)
        return _map_data_table(raw)


class CreateDataTableWorkflow:
    """Creates a new structured Data Table in Chronicle SIEM."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        table_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        column_info: Optional[List[Dict[str, Any]]] = None,
        row_time_to_live: Optional[str] = None,
        scope_info: Optional[Dict[str, Any]] = None,
    ) -> DataTable:
        raw = self.adapter.create_data_table(
            table_id=table_id,
            display_name=display_name,
            description=description,
            column_info=column_info,
            row_time_to_live=row_time_to_live,
            scope_info=scope_info,
        )
        return _map_data_table(raw)


class PatchDataTableWorkflow:
    """Updates metadata, TTL, or scope info for an existing Data Table."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        table_name_or_id: str,
        description: Optional[str] = None,
        row_time_to_live: Optional[str] = None,
        scope_info: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> DataTable:
        raw = self.adapter.patch_data_table(
            table_name_or_id=table_name_or_id,
            description=description,
            row_time_to_live=row_time_to_live,
            scope_info=scope_info,
            update_mask=update_mask,
        )
        return _map_data_table(raw)


class DeleteDataTableWorkflow:
    """Deletes a Chronicle SIEM Data Table."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, table_name_or_id: str) -> Dict[str, Any]:
        return self.adapter.delete_data_table(table_name_or_id=table_name_or_id)


class ListDataTableRowsWorkflow:
    """Lists rows inside a Chronicle SIEM Data Table."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        table_name_or_id: str,
        page_size: int = 50,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
    ) -> DataTableRowListResult:
        res = self.adapter.list_data_table_rows(
            table_name_or_id=table_name_or_id,
            page_size=page_size,
            page_token=page_token,
            filter_expr=filter_expr,
        )
        raw_rows = res.get("dataTableRows", [])
        rows = [_map_data_table_row(r) for r in raw_rows]
        return DataTableRowListResult(
            table_name=_clean_id(table_name_or_id),
            rows=rows,
            next_page_token=res.get("nextPageToken"),
            total_size=len(rows),
            provenance={
                "call": "dataTables.dataTableRows.list",
                "table": _clean_id(table_name_or_id),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


class AddDataTableRowsWorkflow:
    """Creates/appends rows in bulk into a Chronicle SIEM Data Table."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        table_name_or_id: str,
        rows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return self.adapter.bulk_create_data_table_rows(
            table_name_or_id=table_name_or_id,
            rows=rows,
        )


class DeleteDataTableRowWorkflow:
    """Deletes a specific row from a Chronicle SIEM Data Table."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        table_name_or_id: str,
        row_id: str,
    ) -> Dict[str, Any]:
        return self.adapter.delete_data_table_row(
            table_name_or_id=table_name_or_id,
            row_id=row_id,
        )
