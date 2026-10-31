from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    CaseAlertRecommendation,
    CaseAlertRecommendationJob,
    CaseAlertUpdateResult,
    CaseCommentRecord,
    CaseSummary,
    CaseUpdateResult,
)
from engine.parsing import parse_timestamp


def _clean_id(raw_id: str) -> str:
    """Extracts the terminal identifier from a resource path."""
    return str(raw_id).strip().split("/")[-1]


def _normalize_case_priority(priority: str) -> str:
    """Normalizes priority string to API format (e.g., PRIORITY_CRITICAL or CRITICAL)."""
    p = priority.strip().upper()
    if p.startswith("PRIORITY_"):
        return p
    if p in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO", "UNKNOWN"):
        return f"PRIORITY_{p}"
    return p


def _normalize_alert_priority(priority: str) -> str:
    """Normalizes alert priority string (e.g., LOW, MEDIUM, HIGH, CRITICAL, INFO)."""
    p = priority.strip().upper()
    if p.startswith("PRIORITY_"):
        return p[len("PRIORITY_") :]
    return p


class UpdateCaseWorkflow:
    """Mutates one or more attributes of a Google SecOps case."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        case_id: str,
        assignee: Optional[str] = None,
        stage: Optional[str] = None,
        incident: Optional[bool] = None,
        priority: Optional[str] = None,
        updates: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> CaseUpdateResult:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")

        clean_case_id = _clean_id(case_id)
        payload: Dict[str, Any] = dict(updates or {})
        masks: List[str] = []

        if assignee is not None:
            payload["assignee"] = assignee.strip()
            masks.append("assignee")

        if stage is not None:
            payload["stage"] = stage.strip()
            masks.append("stage")

        if incident is not None:
            payload["incident"] = bool(incident)
            masks.append("incident")

        if priority is not None:
            payload["priority"] = _normalize_case_priority(priority)
            masks.append("priority")

        if not payload:
            raise ValueError("No update fields provided for case update.")

        effective_mask = update_mask or (",".join(masks) if masks else None)

        raw = self.adapter.update_case(
            case_id=clean_case_id,
            updates=payload,
            update_mask=effective_mask,
        )

        return CaseUpdateResult(
            case_id=clean_case_id,
            name=raw.get("name") or f"projects/{self.adapter.project_id}/locations/{self.adapter.location}/instances/{self.adapter.customer_id}/cases/{clean_case_id}",
            assignee=raw.get("assignee") or payload.get("assignee"),
            stage=raw.get("stage") or payload.get("stage"),
            incident=raw.get("incident") if "incident" in raw else payload.get("incident"),
            priority=raw.get("priority") or payload.get("priority"),
            status=raw.get("status"),
            display_name=raw.get("displayName"),
            raw=raw,
            updated_at=datetime.now(timezone.utc),
        )


class AssignCaseWorkflow:
    """Assigns a Google SecOps case to a SOC role (e.g. @Tier1) or user GUID."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.update_workflow = UpdateCaseWorkflow(adapter=self.adapter)

    def execute(self, case_id: str, assignee: str) -> CaseUpdateResult:
        if not assignee or not assignee.strip():
            raise ValueError("assignee must be a non-empty string.")

        target = assignee.strip()

        # If user passed an email or plain username without @ prefix, check if it's a known user
        if not target.startswith("@") and "@" in target:
            # Check by email lookup
            try:
                users_res = self.adapter.list_soar_users(
                    filter=f"mail = '{target}' or email = '{target}' or displayName = '{target}'",
                    page_size=5,
                )
                users = users_res.get("legacySoarUsers", [])
                if users:
                    u0 = users[0]
                    # displayName on legacySoarUsers is typically the user's GUID
                    guid = u0.get("displayName") or u0.get("id") or target
                    target = guid
            except Exception:
                pass

        return self.update_workflow.execute(
            case_id=case_id,
            assignee=target,
            update_mask="assignee",
        )


class SetCaseStageWorkflow:
    """Updates the lifecycle stage of a Google SecOps case."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.update_workflow = UpdateCaseWorkflow(adapter=self.adapter)

    def execute(self, case_id: str, stage: str) -> CaseUpdateResult:
        if not stage or not stage.strip():
            raise ValueError("stage must be a non-empty string.")

        return self.update_workflow.execute(
            case_id=case_id,
            stage=stage.strip(),
            update_mask="stage",
        )


class SetCaseIncidentWorkflow:
    """Marks or unmarks a Google SecOps case as an Incident."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.update_workflow = UpdateCaseWorkflow(adapter=self.adapter)

    def execute(self, case_id: str, incident: bool = True) -> CaseUpdateResult:
        return self.update_workflow.execute(
            case_id=case_id,
            incident=incident,
            update_mask="incident",
        )


class AddCaseCommentWorkflow:
    """Orchestrates posting comments to a SecOps case with strict error visibility."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, case_id: str, comment: str) -> CaseCommentRecord:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")
        if not comment or not comment.strip():
            raise ValueError("comment cannot be empty or whitespace.")

        clean_case_id = _clean_id(case_id)
        raw_res = self.adapter.create_case_comment(case_id=clean_case_id, comment=comment.strip())
        from engine.workflows.case_wall import parse_case_comment_record

        return parse_case_comment_record(raw_res)


class UpdateCaseAlertWorkflow:
    """Mutates attributes (such as priority or status) of a specific case alert."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        case_id: str,
        alert_id: str,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        updates: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> CaseAlertUpdateResult:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")
        if not alert_id or not str(alert_id).strip():
            raise ValueError("alert_id must be a non-empty string.")

        clean_case_id = _clean_id(case_id)
        clean_alert_id = _clean_id(alert_id)
        payload: Dict[str, Any] = dict(updates or {})
        masks: List[str] = []

        if priority is not None:
            payload["priority"] = _normalize_alert_priority(priority)
            masks.append("priority")

        if status is not None:
            payload["status"] = status.strip().upper()
            masks.append("status")

        if not payload:
            raise ValueError("No update fields provided for case alert update.")

        effective_mask = update_mask or (",".join(masks) if masks else None)

        raw = self.adapter.update_case_alert(
            case_id=clean_case_id,
            alert_id=clean_alert_id,
            updates=payload,
            update_mask=effective_mask,
        )

        return CaseAlertUpdateResult(
            alert_name=raw.get("name")
            or f"projects/{self.adapter.project_id}/locations/{self.adapter.location}/instances/{self.adapter.customer_id}/cases/{clean_case_id}/caseAlerts/{clean_alert_id}",
            case_id=clean_case_id,
            alert_id=clean_alert_id,
            priority=raw.get("priority") or payload.get("priority"),
            status=raw.get("status") or payload.get("status"),
            display_name=raw.get("displayName"),
            raw=raw,
            updated_at=datetime.now(timezone.utc),
        )


class SetCaseAlertPriorityWorkflow:
    """Updates the priority level of a specific case alert."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.update_workflow = UpdateCaseAlertWorkflow(adapter=self.adapter)

    def execute(self, case_id: str, alert_id: str, priority: str) -> CaseAlertUpdateResult:
        if not priority or not priority.strip():
            raise ValueError("priority must be a non-empty string.")

        return self.update_workflow.execute(
            case_id=case_id,
            alert_id=alert_id,
            priority=priority.strip(),
            update_mask="priority",
        )


class CreateCaseAlertRecommendationWorkflow:
    """Initiates an asynchronous request to generate a Gemini AI recommendation for an alert."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, case_id: str, alert_id: str) -> CaseAlertRecommendationJob:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")
        if not alert_id or not str(alert_id).strip():
            raise ValueError("alert_id must be a non-empty string.")

        clean_case_id = _clean_id(case_id)
        clean_alert_id = _clean_id(alert_id)

        raw = self.adapter.create_case_alert_recommendation(
            case_id=clean_case_id,
            alert_id=clean_alert_id,
        )
        rec_id = raw.get("recommendationId")
        if not rec_id:
            raise RuntimeError(
                f"Failed to initiate recommendation for alert {clean_alert_id} in case {clean_case_id}: missing recommendationId in response."
            )

        return CaseAlertRecommendationJob(
            case_id=clean_case_id,
            alert_id=clean_alert_id,
            recommendation_id=rec_id,
            created_at=datetime.now(timezone.utc),
            raw=raw,
        )


class FetchCaseAlertRecommendationWorkflow:
    """Fetches a previously generated Gemini AI recommendation for a case alert."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, case_id: str, recommendation_id: str) -> CaseAlertRecommendation:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")
        if not recommendation_id or not str(recommendation_id).strip():
            raise ValueError("recommendation_id must be a non-empty string.")

        clean_case_id = _clean_id(case_id)
        clean_rec_id = str(recommendation_id).strip()

        try:
            raw = self.adapter.fetch_case_alert_recommendation(
                case_id=clean_case_id,
                recommendation_id=clean_rec_id,
            )
            state = raw.get("state", "UNSPECIFIED")
            return CaseAlertRecommendation(
                case_id=clean_case_id,
                recommendation_id=clean_rec_id,
                state=state,
                recommendation=raw.get("recommendation"),
                alert_identifier_to_case_id=raw.get("alertIdentifierToCaseId", {}),
                marketplace_actions_triggered_manually=raw.get("marketplaceActionsTriggeredManually", []),
                status_message=None,
                raw=raw,
                fetched_at=datetime.now(timezone.utc),
            )
        except RuntimeError as e:
            err_msg = str(e)
            if "insufficient historical data" in err_msg.lower() or "[409]" in err_msg:
                return CaseAlertRecommendation(
                    case_id=clean_case_id,
                    recommendation_id=clean_rec_id,
                    state="FAILED",
                    recommendation=None,
                    status_message=err_msg,
                    raw={"error": err_msg},
                    fetched_at=datetime.now(timezone.utc),
                )
            if "rst_stream" in err_msg.lower() or "[500]" in err_msg:
                return CaseAlertRecommendation(
                    case_id=clean_case_id,
                    recommendation_id=clean_rec_id,
                    state="RUNNING",
                    recommendation=None,
                    status_message=f"Recommendation is computing on Google SecOps backend ({err_msg}).",
                    raw={"status": "computing", "error": err_msg},
                    fetched_at=datetime.now(timezone.utc),
                )
            raise


class GetCaseAlertRecommendationWorkflow:
    """End-to-end workflow: creates a Gemini recommendation for an alert and polls until completion."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.create_workflow = CreateCaseAlertRecommendationWorkflow(adapter=self.adapter)
        self.fetch_workflow = FetchCaseAlertRecommendationWorkflow(adapter=self.adapter)

    def execute(
        self,
        case_id: str,
        alert_id: str,
        timeout_sec: float = 30.0,
        poll_interval_sec: float = 2.0,
    ) -> CaseAlertRecommendation:
        import time

        job = self.create_workflow.execute(case_id=case_id, alert_id=alert_id)
        start_time = time.time()

        while True:
            rec = self.fetch_workflow.execute(
                case_id=job.case_id,
                recommendation_id=job.recommendation_id,
            )
            if rec.state in ("SUCCEEDED", "FAILED"):
                return rec

            elapsed = time.time() - start_time
            if elapsed >= timeout_sec:
                return CaseAlertRecommendation(
                    case_id=job.case_id,
                    recommendation_id=job.recommendation_id,
                    state="RUNNING",
                    recommendation=rec.recommendation,
                    status_message=f"Polling timed out after {timeout_sec:.1f}s while state was {rec.state}.",
                    raw=rec.raw,
                    fetched_at=datetime.now(timezone.utc),
                )

            time.sleep(poll_interval_sec)


class GetOrCreateCaseSummaryWorkflow:
    """Gets or initiates creation of an AI-driven summary for a SOAR case."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, case_id: str) -> CaseSummary:
        clean_case_id = _clean_id(case_id)
        try:
            raw = self.adapter.get_or_create_case_summary(case_id=clean_case_id)
            state = raw.get("state", "SUMMARY_STATE_UNSPECIFIED")
            markdown_results = raw.get("markdownResults") or {}
            if isinstance(markdown_results, dict):
                summary = raw.get("summary") or markdown_results.get("summary")
                reasons = raw.get("reasons") or markdown_results.get("reasons") or []
                next_steps = raw.get("nextSteps") or markdown_results.get("nextSteps") or []
            else:
                summary = raw.get("summary")
                reasons = raw.get("reasons", [])
                next_steps = raw.get("nextSteps", [])

            update_time = None
            raw_update_time = raw.get("updateTime")
            if raw_update_time:
                try:
                    if str(raw_update_time).isdigit():
                        update_time = datetime.fromtimestamp(int(raw_update_time) / 1000.0, tz=timezone.utc)
                    else:
                        update_time = datetime.fromisoformat(str(raw_update_time).replace("Z", "+00:00"))
                except Exception:
                    update_time = None

            return CaseSummary(
                case_id=clean_case_id,
                state=state,
                summary=summary,
                reasons=reasons,
                next_steps=next_steps,
                markdown_results=markdown_results if isinstance(markdown_results, dict) else None,
                update_time=update_time,
                raw=raw,
                fetched_at=datetime.now(timezone.utc),
            )
        except RuntimeError as e:
            err_msg = str(e)
            if "rst_stream" in err_msg.lower() or "[500]" in err_msg:
                return CaseSummary(
                    case_id=clean_case_id,
                    state="IN_PROGRESS",
                    summary=None,
                    reasons=[],
                    next_steps=[],
                    markdown_results=None,
                    update_time=None,
                    raw={"status": "computing", "error": err_msg},
                    fetched_at=datetime.now(timezone.utc),
                )
            raise


class GetCaseSummaryWorkflow:
    """End-to-end workflow: requests Gemini AI case summary and polls until complete."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.summary_workflow = GetOrCreateCaseSummaryWorkflow(adapter=self.adapter)

    def execute(
        self,
        case_id: str,
        timeout_sec: float = 90.0,
        poll_interval_sec: float = 3.0,
    ) -> CaseSummary:
        import time

        start_time = time.time()
        while True:
            summary = self.summary_workflow.execute(case_id=case_id)
            if summary.state in ("SUCCESSFUL", "ERROR"):
                return summary

            elapsed = time.time() - start_time
            if elapsed >= timeout_sec:
                return summary

            time.sleep(poll_interval_sec)
