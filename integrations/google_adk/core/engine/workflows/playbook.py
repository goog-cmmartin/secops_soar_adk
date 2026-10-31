"""SOAR Playbook Workflow Engine Components.

Implements playbook search, multi-facet filtering, category hierarchy retrieval,
and step-level execution DAG inspection.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    PlaybookBatch,
    PlaybookCategory,
    PlaybookDetail,
    PlaybookInstanceCard,
    PlaybookInstanceRelation,
    PlaybookInstanceRun,
    PlaybookInstanceStep,
    PlaybookSearchQuery,
    PlaybookStep,
    PlaybookStepParameter,
    PlaybookSummary,
    PlaybookTrigger,
    PlaybookTriggerCondition,
    PlaybookType,
)


def _parse_playbook_timestamp(iso_val: Any, ms_val: Any) -> Optional[datetime]:
    """Parses a playbook timestamp from either an ISO-8601 string or Unix epoch milliseconds."""
    if iso_val:
        try:
            dt = datetime.fromisoformat(str(iso_val).replace("Z", "+00:00"))
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except Exception:
            pass
    if ms_val is not None and ms_val != "":
        try:
            ms = int(ms_val)
            return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        except Exception:
            pass
    return None


class SearchPlaybooksWorkflow:
    """Orchestrates SOAR Playbook discovery and multi-facet filtering."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, query: Optional[PlaybookSearchQuery] = None) -> PlaybookBatch:
        q = query or PlaybookSearchQuery()
        types = None
        if q.playbook_type:
            types = [q.playbook_type.value]

        raw_cards = self.adapter.get_playbook_menu_cards(playbook_types=types)
        summaries: List[PlaybookSummary] = []

        query_str = q.query.lower().strip() if q.query else None
        cat_filter = q.category.lower().strip() if q.category else None
        env_filter = q.environment.lower().strip() if q.environment else None

        for card in raw_cards:
            name = card.get("name", "")
            creator_name = card.get("creatorFullName", "")
            identifier = card.get("identifier", "")
            card_id = str(card.get("id", ""))
            category_name = card.get("categoryName", "")
            is_enabled = bool(card.get("isEnabled", False))
            environments = card.get("environments", [])
            pt_str = card.get("playbookType", "REGULAR")

            # Keyword filter
            if query_str:
                matched = (
                    query_str in name.lower()
                    or query_str in creator_name.lower()
                    or query_str in identifier.lower()
                    or query_str == card_id
                )
                if not matched:
                    continue

            # Category filter
            if cat_filter:
                if cat_filter != category_name.lower():
                    continue

            # Enabled filter
            if q.is_enabled is not None:
                if is_enabled != q.is_enabled:
                    continue

            # Environment filter
            if env_filter:
                if not any(env_filter == env.lower() for env in environments):
                    continue

            # Playbook Type enum
            try:
                playbook_type = PlaybookType(pt_str)
            except ValueError:
                playbook_type = PlaybookType.UNKNOWN

            # Parse timestamps
            created_at = _parse_playbook_timestamp(
                card.get("creationTime"), card.get("creationTimeUnixTimeInMs")
            )
            modified_at = _parse_playbook_timestamp(
                card.get("modificationTime"), card.get("modificationTimeUnixTimeInMs")
            )

            summaries.append(
                PlaybookSummary(
                    id=card_id,
                    identifier=identifier,
                    original_identifier=card.get("originalWorkflowIdentifier", identifier),
                    name=name,
                    is_enabled=is_enabled,
                    is_debug_mode=bool(card.get("isDebugMode", False)),
                    priority=int(card.get("priority", 0)),
                    category_id=int(card.get("categoryId", 0)),
                    category_name=category_name,
                    creator=card.get("creator", ""),
                    creator_full_name=creator_name,
                    environments=environments,
                    playbook_type=playbook_type,
                    has_restricted_environments=bool(card.get("hasRestrictedEnvironments", False)),
                    creation_time=created_at,
                    modification_time=modified_at,
                    raw=card,
                )
            )

        total = len(summaries)
        if q.limit and q.limit > 0:
            summaries = summaries[: q.limit]

        return PlaybookBatch(
            results=summaries,
            total_count=total,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetPlaybookWorkflow:
    """Orchestrates full playbook retrieval and step-level DAG inspection."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, identifier_or_id: str) -> PlaybookDetail:
        target = identifier_or_id.strip()
        if not target:
            raise ValueError("Playbook identifier or ID must not be empty.")

        workflow_identifier = target

        # If numeric ID provided (e.g. "2277"), resolve to UUID identifier via index
        if target.isdigit() or "-" not in target:
            cards = self.adapter.get_playbook_menu_cards()
            found = False
            for c in cards:
                if str(c.get("id")) == target or c.get("name", "").lower() == target.lower():
                    workflow_identifier = c.get("identifier", target)
                    found = True
                    break
            if not found:
                # Still try target directly
                workflow_identifier = target

        raw_info = self.adapter.get_playbook_full_info(workflow_identifier=workflow_identifier)
        if not raw_info:
            raise RuntimeError(f"Playbook '{target}' not found on live Google SecOps endpoint.")

        # Parse Trigger
        trigger_obj = None
        raw_trig = raw_info.get("trigger")
        if isinstance(raw_trig, dict):
            conditions: List[PlaybookTriggerCondition] = []
            for cond in raw_trig.get("conditions", []):
                conditions.append(
                    PlaybookTriggerCondition(
                        value=cond.get("value", ""),
                        match_type=cond.get("matchType", "EQUAL"),
                    )
                )
            trigger_obj = PlaybookTrigger(
                id=str(raw_trig.get("id", "")),
                identifier=raw_trig.get("identifier", ""),
                trigger_type=raw_trig.get("type", ""),
                logical_operator=raw_trig.get("logicalOperator", "AND"),
                conditions=conditions,
                reaction_logical_operator=raw_trig.get("reactionLogicalOperator", "OR"),
                raw=raw_trig,
            )

        # Parse Steps
        steps: List[PlaybookStep] = []
        for s in raw_info.get("steps", []):
            params: List[PlaybookStepParameter] = []
            for p in s.get("parameters", []):
                params.append(
                    PlaybookStepParameter(
                        name=p.get("name", ""),
                        value=p.get("value"),
                        is_mandatory=bool(p.get("isMandatory", False)),
                    )
                )
            steps.append(
                PlaybookStep(
                    identifier=s.get("identifier", ""),
                    original_step_identifier=s.get("originalStepIdentifier", ""),
                    name=s.get("name", ""),
                    instance_name=s.get("instanceName", ""),
                    integration=s.get("integration", ""),
                    action_name=s.get("actionName", ""),
                    action_provider=s.get("actionProvider", ""),
                    step_type=s.get("type", "ACTION"),
                    description=s.get("description", ""),
                    is_automatic=bool(s.get("isAutomatic", True)),
                    is_skippable=bool(s.get("isSkippable", False)),
                    auto_skip_on_failure=bool(s.get("autoSkipOnFailure", False)),
                    parameters=params,
                    workflow_identifier=s.get("workflowIdentifier", workflow_identifier),
                    raw=s,
                )
            )

        # Parse playbook type
        pt_str = raw_info.get("playbookType", "REGULAR")
        try:
            playbook_type = PlaybookType(pt_str)
        except ValueError:
            playbook_type = PlaybookType.UNKNOWN

        # Parse timestamps
        created_at = _parse_playbook_timestamp(
            raw_info.get("creationTime"), raw_info.get("creationTimeUnixTimeInMs")
        )
        modified_at = _parse_playbook_timestamp(
            raw_info.get("modificationTime"), raw_info.get("modificationTimeUnixTimeInMs")
        )

        return PlaybookDetail(
            id=str(raw_info.get("id", "")),
            identifier=raw_info.get("identifier", workflow_identifier),
            name=raw_info.get("name", "Untitled Playbook"),
            description=raw_info.get("description", ""),
            is_enabled=bool(raw_info.get("isEnabled", False)),
            is_debug_mode=bool(raw_info.get("isDebugMode", False)),
            priority=int(raw_info.get("priority", 0)),
            category_id=int(raw_info.get("categoryId", 0)),
            category_name=raw_info.get("categoryName", ""),
            creator=raw_info.get("creator", ""),
            modified_by=raw_info.get("modifiedBy"),
            environments=raw_info.get("environments", []),
            playbook_type=playbook_type,
            trigger=trigger_obj,
            steps=steps,
            creation_time=created_at,
            modification_time=modified_at,
            raw=raw_info,
        )


class ListPlaybookCategoriesWorkflow:
    """Lists all SOAR Playbook categories/folders."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> List[PlaybookCategory]:
        raw_cats = self.adapter.get_playbook_categories()
        categories: List[PlaybookCategory] = []
        for cat in raw_cats:
            categories.append(
                PlaybookCategory(
                    id=str(cat.get("id", "")),
                    name=cat.get("name", ""),
                    category_state=cat.get("categoryState", "FULL"),
                    category_type=cat.get("type", "REGULAR"),
                    is_default=bool(cat.get("isDefaultCategory", False)),
                    raw=cat,
                )
            )
        return categories


def _ms_to_dt(value: Any) -> Optional[datetime]:
    """Coerces a Unix-epoch-milliseconds value (str|int) into a tz-aware datetime."""
    if value is None or value == "":
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1000.0, tz=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


class GetAlertPlaybookInstancesWorkflow:
    """Tier-2: retrieves authoritative playbook *run instances* for an alert.

    Two modes:
      * :meth:`execute` -> lightweight summary cards (instances + status).
      * :meth:`execute_full` -> a single full run instance incl. the step DAG.

    Both accept either the raw opaque ``alertGroupIdentifier`` OR a plain alert id
    (which is resolved to the group identifier via a case-investigation lookup).
    """

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    # -- identifier resolution -------------------------------------------------

    @staticmethod
    def _looks_like_group_identifier(value: str) -> bool:
        """Heuristic: the opaque alertGroupIdentifier embeds a base64 hash + UUID.

        Real examples look like ``<RuleName>.<base64>=_<uuid>``. A bare numeric or
        short id does not contain the ``=_`` separator, so we treat that as a
        plain alert id requiring resolution.
        """
        return "=_" in value or (len(value) > 40 and "_" in value)

    def _resolve_alert_identifier(self, case_id: str, alert_ref: str) -> str:
        """Returns the opaque alertGroupIdentifier for an alert reference.

        If ``alert_ref`` already looks like a group identifier it is returned
        verbatim (raw passthrough). Otherwise the case alerts are fetched and the
        matching alert's ``alertGroupIdentifier`` is resolved by id/name.
        """
        if self._looks_like_group_identifier(alert_ref):
            return alert_ref

        alerts_raw = self.adapter.list_case_alerts(str(case_id))
        for a in alerts_raw:
            candidates = {
                str(a.get("identifier", "")),
                str(a.get("name", "")),
                str(a.get("name", "")).split("/")[-1],
                str(a.get("id", "")),
            }
            if alert_ref in candidates:
                gid = a.get("alertGroupIdentifier") or a.get("groupIdentifier")
                if gid:
                    return gid
        # Fall back to the caller-supplied value; the API will reject if invalid.
        return alert_ref

    # -- parsing ---------------------------------------------------------------

    def _parse_card(self, card: Dict[str, Any]) -> PlaybookInstanceCard:
        return PlaybookInstanceCard(
            instance_id=str(card.get("id", "")),
            definition_identifier=(
                card.get("definitionIdentifier")
                or card.get("identifier")
                or card.get("originalPlaybookIdentifier", "")
            ),
            name=card.get("name", ""),
            status=card.get("status") or card.get("workflowInstanceStatus"),
            is_enabled=bool(card.get("isEnabled", True)),
            environments=card.get("environments", []) or [],
            creation_time=_ms_to_dt(card.get("creationTimeUnixTimeInMs")),
            modification_time=_ms_to_dt(card.get("modificationTimeUnixTimeInMs")),
            raw=card,
        )

    def _parse_trigger(self, raw_trig: Any) -> Optional[PlaybookTrigger]:
        if not isinstance(raw_trig, dict):
            return None
        conditions = [
            PlaybookTriggerCondition(
                value=c.get("value", ""),
                match_type=c.get("matchType", "EQUAL"),
            )
            for c in raw_trig.get("conditions", [])
        ]
        return PlaybookTrigger(
            id=str(raw_trig.get("id", "")),
            identifier=raw_trig.get("identifier", ""),
            trigger_type=raw_trig.get("type", ""),
            logical_operator=raw_trig.get("logicalOperator", "AND"),
            conditions=conditions,
            reaction_logical_operator=raw_trig.get("reactionLogicalOperator", "OR"),
            raw=raw_trig,
        )

    def _parse_run(
        self, raw: Dict[str, Any], case_id: str, alert_identifier: str
    ) -> PlaybookInstanceRun:
        steps: List[PlaybookInstanceStep] = []
        for st in raw.get("steps", []):
            steps.append(
                PlaybookInstanceStep(
                    identifier=st.get("identifier", ""),
                    name=st.get("name", ""),
                    status=st.get("status") or st.get("actionStatus"),
                    action_name=st.get("actionName", ""),
                    integration=st.get("integration", ""),
                    instance_name=st.get("instanceName", ""),
                    is_automatic=bool(st.get("isAutomatic", True)),
                    result_summary=st.get("resultSummary") or st.get("result"),
                    start_time=_ms_to_dt(st.get("startTimeUnixTimeInMs")),
                    end_time=_ms_to_dt(st.get("endTimeUnixTimeInMs")),
                    raw=st,
                )
            )

        relations: List[PlaybookInstanceRelation] = []
        for rel in raw.get("stepsRelations", []):
            relations.append(
                PlaybookInstanceRelation(
                    from_step=rel.get("fromStep", ""),
                    to_step=rel.get("toStep", ""),
                    destination_action_status=rel.get("destinationActionStatus"),
                    condition=rel.get("condition"),
                    raw=rel,
                )
            )

        return PlaybookInstanceRun(
            instance_id=str(raw.get("id", "")),
            identifier=raw.get("identifier", ""),
            name=raw.get("name", ""),
            case_id=str(case_id),
            alert_identifier=alert_identifier,
            status=raw.get("status") or raw.get("workflowInstanceStatus"),
            is_enabled=bool(raw.get("isEnabled", True)),
            is_debug_mode=bool(raw.get("isDebugMode", False)),
            priority=int(raw.get("priority", 0) or 0),
            category_name=raw.get("categoryName", ""),
            original_playbook_identifier=raw.get("originalPlaybookIdentifier"),
            environments=raw.get("environments", []) or [],
            trigger=self._parse_trigger(raw.get("trigger")),
            steps=steps,
            relations=relations,
            creation_time=_ms_to_dt(raw.get("creationTimeUnixTimeInMs")),
            modification_time=_ms_to_dt(raw.get("modificationTimeUnixTimeInMs")),
            raw=raw,
        )

    # -- public API ------------------------------------------------------------

    def execute(self, case_id: str, alert_identifier: str) -> List[PlaybookInstanceCard]:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")
        if not alert_identifier or not str(alert_identifier).strip():
            raise ValueError("alert_identifier must be a non-empty string.")

        clean_case = str(case_id).strip().split("/")[-1]
        resolved = self._resolve_alert_identifier(clean_case, str(alert_identifier).strip())
        raw_cards = self.adapter.get_workflow_instances_cards(
            case_id=clean_case, alert_identifier=resolved
        )
        return [self._parse_card(c) for c in raw_cards]

    def execute_full(
        self,
        case_id: str,
        alert_identifier: str,
        definition_identifier: Optional[str] = None,
        should_fetch_steps: bool = True,
        collapse_blocks: bool = True,
        loops_requested_iterations: Optional[List[Any]] = None,
    ) -> PlaybookInstanceRun:
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string.")
        if not alert_identifier or not str(alert_identifier).strip():
            raise ValueError("alert_identifier must be a non-empty string.")

        clean_case = str(case_id).strip().split("/")[-1]
        resolved = self._resolve_alert_identifier(clean_case, str(alert_identifier).strip())

        # If no definition identifier supplied, resolve via the cards endpoint.
        def_id = definition_identifier
        if not def_id:
            cards = self.adapter.get_workflow_instances_cards(
                case_id=clean_case, alert_identifier=resolved
            )
            if not cards:
                raise RuntimeError(
                    f"No playbook instances found for alert on case {clean_case}; "
                    "cannot resolve definition_identifier."
                )
            first = self._parse_card(cards[0])
            def_id = first.definition_identifier

        raw = self.adapter.get_workflow_instance(
            case_id=clean_case,
            alert_identifier=resolved,
            definition_identifier=def_id,
            should_fetch_steps=should_fetch_steps,
            collapse_blocks=collapse_blocks,
            loops_requested_iterations=loops_requested_iterations,
        )
        if not raw:
            raise RuntimeError(
                f"Playbook instance '{def_id}' not found for alert on case {clean_case}."
            )
        return self._parse_run(raw, clean_case, resolved)


class SavePlaybookWorkflow:
    """Creates or updates a SOAR Playbook definition with automatic category ID/name synchronization."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def _sync_category_fields(
        self,
        payload: Dict[str, Any],
        category_name_override: Optional[str] = None,
    ) -> None:
        """Ensures categoryId and categoryName are consistent so SOAR UI folder assignment is preserved."""
        target_name = category_name_override or payload.get("categoryName")
        target_id = payload.get("categoryId")
        try:
            categories = self.adapter.get_playbook_categories() or []
        except Exception:
            categories = []

        if target_name and categories:
            for cat in categories:
                if str(cat.get("name", "")).strip().lower() == str(target_name).strip().lower():
                    payload["categoryName"] = cat.get("name")
                    if cat.get("id") is not None:
                        payload["categoryId"] = int(cat["id"])
                    return
        if target_id is not None and categories:
            for cat in categories:
                if str(cat.get("id")) == str(target_id):
                    if not payload.get("categoryName") and cat.get("name"):
                        payload["categoryName"] = cat.get("name")
                    return

    def execute(
        self,
        playbook_payload: Dict[str, Any],
        category_name: Optional[str] = None,
        is_enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if not isinstance(playbook_payload, dict) or not playbook_payload:
            raise ValueError("playbook_payload must be a non-empty dictionary.")

        import copy
        payload = copy.deepcopy(playbook_payload)
        if is_enabled is not None:
            payload["isEnabled"] = bool(is_enabled)
        self._sync_category_fields(payload, category_name_override=category_name)
        return self.adapter.save_playbook(payload)


class UpdatePlaybookWidgetWorkflow:
    """Updates an embedded HTML widget inside a SOAR Playbook's ViewsTemplates and saves the playbook."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        identifier_or_id: str,
        html_content: str,
        step_name_or_id: Optional[str] = None,
        widget_title: Optional[str] = None,
        widget_index: Optional[int] = None,
        update_step_parameter: Optional[str] = None,
        update_step_parameter_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        import json

        pb_detail = GetPlaybookWorkflow(self.adapter).execute(identifier_or_id)
        raw_pb = pb_detail.raw
        if not isinstance(raw_pb, dict) or not raw_pb:
            raise RuntimeError(f"Unable to load raw playbook payload for '{identifier_or_id}'.")

        target_step_id: Optional[str] = None
        if step_name_or_id:
            q = step_name_or_id.strip().lower()
            for s in raw_pb.get("steps", []):
                s_id = str(s.get("identifier", ""))
                s_orig = str(s.get("originalStepIdentifier", ""))
                s_name = str(s.get("name", ""))
                s_inst = str(s.get("instanceName", ""))
                if q in (s_id.lower(), s_orig.lower(), s_name.lower(), s_inst.lower()):
                    target_step_id = s_id
                    if update_step_parameter is not None and update_step_parameter_value is not None:
                        for p in s.get("parameters", []):
                            if str(p.get("name", "")).lower() == update_step_parameter.strip().lower():
                                p["value"] = update_step_parameter_value
                    break

        updated_widgets = 0
        for vt in raw_pb.get("viewsTemplates", []):
            cards = vt.get("cards", [])
            if widget_index is not None and 0 <= widget_index < len(cards):
                candidate_cards = [cards[widget_index]]
            else:
                candidate_cards = cards

            for card in candidate_cards:
                wdef_str = card.get("widgetDefinition")
                wdef: Dict[str, Any] = {}
                if isinstance(wdef_str, str) and wdef_str.strip():
                    try:
                        wdef = json.loads(wdef_str)
                    except Exception:
                        wdef = {}
                elif isinstance(wdef_str, dict):
                    wdef = wdef_str

                card_title = str(card.get("title") or wdef.get("title") or "")
                card_step_id = str(card.get("stepIdentifier") or wdef.get("stepIdentifier") or "")

                matches = False
                if widget_index is not None:
                    matches = True
                elif widget_title and widget_title.strip().lower() in card_title.lower():
                    matches = True
                elif target_step_id and card_step_id == target_step_id:
                    matches = True
                elif not widget_title and not target_step_id and ("htmlContent" in wdef or card.get("type") == 3):
                    matches = True

                if matches:
                    wdef["htmlContent"] = html_content
                    if widget_title:
                        wdef["title"] = widget_title
                        card["title"] = widget_title
                    card["widgetDefinition"] = json.dumps(wdef) if isinstance(wdef_str, str) else wdef
                    updated_widgets += 1

        if updated_widgets == 0:
            raise ValueError(
                f"No matching HTML widget found in playbook '{pb_detail.name}' "
                f"(step={step_name_or_id}, widget_title={widget_title}, widget_index={widget_index})."
            )

        saved = SavePlaybookWorkflow(self.adapter).execute(raw_pb)
        return {
            "playbook_id": pb_detail.id,
            "playbook_identifier": pb_detail.identifier,
            "playbook_name": pb_detail.name,
            "updated_widgets_count": updated_widgets,
            "saved_playbook": saved,
        }


class DeletePlaybooksWorkflow:
    """Deletes one or more SOAR Playbooks by UUID identifier, numeric ID, or exact name."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, identifiers_or_ids: List[str]) -> Dict[str, Any]:
        if not identifiers_or_ids:
            raise ValueError("identifiers_or_ids must be a non-empty list.")
        resolved_uuids: List[str] = []
        cards: Optional[List[Dict[str, Any]]] = None
        for item in identifiers_or_ids:
            target = str(item).strip()
            if not target:
                continue
            if target.isdigit() or "-" not in target:
                if cards is None:
                    cards = self.adapter.get_playbook_menu_cards() or []
                matched_uuid = None
                for c in cards:
                    if str(c.get("id")) == target or str(c.get("name", "")).lower() == target.lower():
                        matched_uuid = c.get("identifier")
                        break
                resolved_uuids.append(matched_uuid or target)
            else:
                resolved_uuids.append(target)

        res = self.adapter.delete_playbooks(resolved_uuids)
        return {
            "deleted_identifiers": resolved_uuids,
            "raw": res,
        }

