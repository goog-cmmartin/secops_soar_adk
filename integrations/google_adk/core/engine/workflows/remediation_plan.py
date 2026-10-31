"""Workflows for Google SecOps AI-Driven Agentic Response / Remediation Plans."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    RemediationAction,
    RemediationPlan,
    RemediationPlanBatch,
)
from engine.parsing import parse_timestamp


def _clean_id(raw_id: Union[str, int]) -> str:
    """Extracts the terminal identifier from a resource path or string."""
    return str(raw_id).strip().split("/")[-1]


def parse_remediation_action(raw: Dict[str, Any]) -> RemediationAction:
    """Parses a raw remediation action dictionary into a strongly-typed RemediationAction."""
    name = raw.get("name", "")
    action_id = _clean_id(name) if name else str(raw.get("id", ""))
    return RemediationAction(
        name=name,
        action_id=action_id,
        integration_id=raw.get("integrationId"),
        integration_instance=raw.get("integrationInstance"),
        display_name=raw.get("displayName"),
        type=raw.get("type"),
        creator=raw.get("creator"),
        action_reasoning=raw.get("actionReasoning"),
        parameters=raw.get("parameters") or {},
        target_entities=raw.get("targetEntities") or [],
        additional_data=raw.get("additionalData") or {},
        metadata=raw.get("metadata") or {},
        created_at=parse_timestamp(raw.get("createTime")),
        updated_at=parse_timestamp(raw.get("updateTime")),
        raw=raw,
    )


def parse_remediation_plan(raw: Dict[str, Any]) -> RemediationPlan:
    """Parses a raw remediation plan dictionary into a strongly-typed RemediationPlan."""
    name = raw.get("name", "")
    plan_id = _clean_id(name) if name else str(raw.get("id", ""))

    plan_data = raw.get("planData") or {}
    planning_summary = plan_data.get("planning_summary")
    usage_metadata = plan_data.get("usage_metadata") or {}
    involved_entities = plan_data.get("involved_entities") or []

    raw_actions = raw.get("actions") or []
    actions = [parse_remediation_action(a) for a in raw_actions if isinstance(a, dict)]

    case_id_val = raw.get("caseId")
    case_id_int: Optional[int] = None
    if case_id_val is not None:
        try:
            case_id_int = int(case_id_val)
        except (ValueError, TypeError):
            pass

    return RemediationPlan(
        name=name,
        plan_id=plan_id,
        alert_name=raw.get("alertName"),
        case_id=case_id_int,
        alert_id=raw.get("alertId"),
        siem_alert_id=raw.get("siemAlertId"),
        agent_session_id=raw.get("agentSessionId"),
        state=raw.get("state", "REMEDIATION_PLAN_STATE_UNSPECIFIED"),
        trigger_type=raw.get("triggerType"),
        status_details=raw.get("statusDetails"),
        agent_classified_use_case=raw.get("agentClassifiedUseCase"),
        plan_data=plan_data,
        planning_summary=planning_summary,
        usage_metadata=usage_metadata,
        involved_entities=involved_entities,
        actions=actions,
        created_at=parse_timestamp(raw.get("createTime")),
        updated_at=parse_timestamp(raw.get("updateTime")),
        raw=raw,
    )


class ListRemediationPlansWorkflow:
    """Retrieves a batch of remediation plans filtered by case ID or custom filter."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        case_id: Optional[Union[str, int]] = None,
        filter: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> RemediationPlanBatch:
        res = self.adapter.list_remediation_plans(
            case_id=case_id,
            filter=filter,
            page_size=page_size,
            page_token=page_token,
        )
        raw_plans = res.get("remediationPlans") or []
        plans = [parse_remediation_plan(p) for p in raw_plans if isinstance(p, dict)]
        total_size = int(res.get("totalSize", len(plans)))
        next_page_token = res.get("nextPageToken")

        parsed_case_id: Optional[int] = None
        if case_id is not None:
            try:
                parsed_case_id = int(_clean_id(case_id))
            except (ValueError, TypeError):
                pass

        return RemediationPlanBatch(
            plans=plans,
            total_size=total_size,
            next_page_token=next_page_token,
            case_id=parsed_case_id,
        )


class GetRemediationPlanWorkflow:
    """Retrieves an individual remediation plan by its plan ID or resource name."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, plan_id: Union[str, int]) -> RemediationPlan:
        res = self.adapter.get_remediation_plan(str(plan_id))
        return parse_remediation_plan(res)


class GetAgenticResponsePlanWorkflow:
    """Composed workflow to retrieve an agentic response plan by case ID or plan ID."""

    def __init__(
        self,
        adapter: Optional["GoogleSecOpsAdapter"] = None,
        list_workflow: Optional[ListRemediationPlansWorkflow] = None,
        get_workflow: Optional[GetRemediationPlanWorkflow] = None,
    ):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.list_workflow = list_workflow or ListRemediationPlansWorkflow(adapter)
        self.get_workflow = get_workflow or GetRemediationPlanWorkflow(adapter)

    def execute(
        self,
        case_id: Optional[Union[str, int]] = None,
        plan_id: Optional[Union[str, int]] = None,
    ) -> Optional[RemediationPlan]:
        if plan_id is not None:
            return self.get_workflow.execute(plan_id)
        if case_id is not None:
            batch = self.list_workflow.execute(case_id=case_id, page_size=1)
            if batch.plans:
                # Also fetch full plan details if actions were not included in list view
                top_plan = batch.plans[0]
                if not top_plan.actions:
                    try:
                        return self.get_workflow.execute(top_plan.plan_id)
                    except Exception:
                        return top_plan
                return top_plan
            return None
        raise ValueError("Either case_id or plan_id must be provided to retrieve an agentic response plan.")


class ListRemediationActionsWorkflow:
    """Lists actions for a specific remediation plan."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        plan_id: Union[str, int],
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> List[RemediationAction]:
        res = self.adapter.list_remediation_actions(
            plan_id=str(plan_id),
            page_size=page_size,
            page_token=page_token,
        )
        raw_actions = res.get("remediationActions") or []
        return [parse_remediation_action(a) for a in raw_actions if isinstance(a, dict)]


class GetRemediationActionWorkflow:
    """Retrieves a specific remediation action by action ID."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        plan_id: Union[str, int],
        action_id: Union[str, int],
    ) -> RemediationAction:
        res = self.adapter.get_remediation_action(
            plan_id=str(plan_id),
            action_id=str(action_id),
        )
        return parse_remediation_action(res)
