"""Workflow handlers for Case Comments and Case Activity Wall (`case.list_comments` and `case.get_wall`)."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    CaseCommentRecord,
    CaseWallRecord,
    CaseWallResult,
)
from engine.parsing import parse_timestamp


def _parse_wall_description(activity_type: str, activity_kind: str, details: Dict[str, Any]) -> str:
    """Derives a human-readable description for a case wall activity record."""
    if not isinstance(details, dict):
        return str(details) if details else ""

    # Explicit activity description
    if details.get("activityDescription"):
        return str(details["activityDescription"]).strip()

    # Comment text
    if details.get("comment"):
        return str(details["comment"]).strip()

    # Granular SOAR Playbook Action executions
    if activity_type == "CASE_ACTION" or activity_kind == "ACTION":
        integration = details.get("Integration") or details.get("integration") or "SOAR"
        action_name = (
            details.get("ActionDisplayName")
            or details.get("ActionName")
            or details.get("ActionDefinitionName")
            or details.get("actionName")
            or "Action"
        )
        user = details.get("ExecutingUser") or details.get("user")
        status_code = details.get("Status")
        status_str = f" [Status: {status_code}]" if status_code is not None else ""
        user_str = f" by {user}" if user else ""
        return f"Executed '{integration}' action '{action_name}'{user_str}{status_str}"

    # Stage changes
    if details.get("stage"):
        return f"Case stage transitioned to '{details['stage']}'"

    # Tag changes
    if details.get("tag"):
        return f"Case tag '{details['tag']}' modified"

    # General fallback
    non_null_items = {k: v for k, v in details.items() if v is not None}
    if non_null_items:
        return ", ".join(f"{k}: {v}" for k, v in list(non_null_items.items())[:3])
    return f"{activity_type} - {activity_kind}"


def parse_case_comment_record(raw: Dict[str, Any]) -> CaseCommentRecord:
    """Parses a raw SecOps case comment dict into a strongly-typed CaseCommentRecord."""
    return CaseCommentRecord(
        name=raw.get("name", ""),
        comment=raw.get("comment", ""),
        author=raw.get("user") or raw.get("creator"),
        author_name=raw.get("userOwnerFullName") or raw.get("lastEditorFullName"),
        create_time=parse_timestamp(raw.get("createTime")),
        is_deleted=bool(raw.get("isDeleted", False)),
        raw=raw,
    )


class ListCaseCommentsWorkflow:
    """Lists all analyst comments and AI assessment notes for a SecOps case (`case.list_comments`)."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, case_id: str) -> List[CaseCommentRecord]:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")

        clean_case_id = str(case_id).strip().split("/")[-1]
        raw_comments = self.adapter.list_case_comments(clean_case_id) or []

        records = [parse_case_comment_record(c) for c in raw_comments]

        # Sort chronologically descending (newest first)
        def _comment_ts(cm: CaseCommentRecord) -> datetime:
            dt = cm.create_time
            if dt is None:
                return datetime.min.replace(tzinfo=timezone.utc)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

        records.sort(
            key=_comment_ts,
            reverse=True,
        )
        return records


class GetCaseWallWorkflow:
    """Retrieves and parses the complete SOAR Case Activity Wall (`case.get_wall`)."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        case_id: str,
        limit: int = 50,
        page_token: Optional[str] = None,
        activity_type: Optional[str] = None,
    ) -> CaseWallResult:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")

        clean_case_id = str(case_id).strip().split("/")[-1]
        filter_str = None
        if activity_type:
            filter_str = f"caseId = {clean_case_id} AND activityType = {activity_type}"

        raw_res = self.adapter.list_case_wall_records(
            case_id=clean_case_id,
            page_size=limit,
            page_token=page_token,
            filter_str=filter_str,
        )

        raw_records = raw_res.get("caseWallRecords", []) or []
        total_size = int(raw_res.get("totalSize", len(raw_records)) or len(raw_records))
        next_page_token = raw_res.get("nextPageToken")

        parsed_records: List[CaseWallRecord] = []
        for r in raw_records:
            details: Dict[str, Any] = {}
            raw_json = r.get("activityDataJson")
            if raw_json and isinstance(raw_json, str):
                try:
                    details = json.loads(raw_json)
                except Exception:
                    details = {"raw_text": raw_json}
            elif isinstance(raw_json, dict):
                details = raw_json

            atype = r.get("activityType", "UNKNOWN")
            akind = r.get("activityKind", "UNKNOWN")
            desc = _parse_wall_description(atype, akind, details)

            parsed_records.append(
                CaseWallRecord(
                    case_id=clean_case_id,
                    activity_id=str(r.get("activityId", "")),
                    activity_type=atype,
                    activity_kind=akind,
                    creator_user_id=r.get("creatorUserId"),
                    create_time=parse_timestamp(r.get("createTime")),
                    update_time=parse_timestamp(r.get("updateTime")),
                    alert_identifier=r.get("alertIdentifier"),
                    description=desc,
                    details=details,
                    favorite=bool(r.get("favorite", False)),
                    name=r.get("name"),
                    raw=r,
                )
            )

        provenance = {
            "workflow": "case.get_wall",
            "case_id": clean_case_id,
            "record_count": len(parsed_records),
            "total_size": total_size,
        }

        return CaseWallResult(
            case_id=clean_case_id,
            records=parsed_records,
            total_size=total_size,
            next_page_token=next_page_token,
            provenance=provenance,
        )
