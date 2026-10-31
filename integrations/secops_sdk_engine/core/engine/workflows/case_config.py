"""Workflows for Case Configuration Data (Milestone 6.1).

Orchestrates discovery and inspection of Case Tag Definitions, Case Stage Definitions,
Case Close Definitions, Close Dynamic Form Parameters, and Case Title Setting Properties.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    AlertGroupingCategoryDetail,
    AlertGroupingRuleBatch,
    AlertGroupingRuleDetail,
    AlertGroupingRuleSummary,
    AlertGroupingSettingProperty,
    AlertGroupingSettingsBatch,
    CalculatedFieldBatch,
    CalculatedFieldDetail,
    CalculatedFieldSummary,
    CaseCloseDefinitionBatch,
    CaseCloseDefinitionSummary,
    CaseCloseDynamicParameterBatch,
    CaseCloseDynamicParameterSummary,
    CaseStageDefinitionBatch,
    CaseStageDefinitionSummary,
    CaseTagDefinitionBatch,
    CaseTagDefinitionSummary,
    CaseTitleSettingProperty,
    CaseTitleSettingsBatch,
    CaseViewBatch,
    CaseViewDetail,
    CaseViewSummary,
    CustomFieldBatch,
    CustomFieldDetail,
    CustomFieldSummary,
    ViewWidget,
    ViewWidgetMetadata,
)


class SearchCaseTagDefinitionsWorkflow:
    """Discovers and filters case tag classification definitions."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        match_criteria: str = "ALL",
        limit: int = 100,
    ) -> CaseTagDefinitionBatch:
        raw = self.adapter.list_case_tag_definitions(page_size=1000)
        raw_tags = raw.get("caseTagDefinitions", [])

        tags: List[CaseTagDefinitionSummary] = []
        for t in raw_tags:
            name = t.get("name", "")
            tid = name.split("/")[-1] if "/" in name else name
            display_name = t.get("displayName", "")
            criteria = t.get("matchCriteria", "")
            comp_type = t.get("comparisonType", "")
            priority = t.get("priority", 0)
            can_title = t.get("canBeCaseTitle", False)

            if match_criteria and match_criteria.upper() != "ALL":
                if criteria.upper() != match_criteria.upper():
                    continue

            if query:
                q = query.lower()
                match = (
                    q in tid.lower()
                    or q in display_name.lower()
                    or q in criteria.lower()
                    or q in comp_type.lower()
                )
                if not match:
                    continue

            tags.append(
                CaseTagDefinitionSummary(
                    id=tid,
                    name=name,
                    display_name=display_name,
                    match_criteria=criteria,
                    comparison_type=comp_type,
                    priority=priority,
                    can_be_case_title=can_title,
                    raw=t,
                )
            )

        total_count = len(tags)
        if limit > 0:
            tags = tags[:limit]

        return CaseTagDefinitionBatch(
            tags=tags,
            total_count=total_count,
            next_page_token=raw.get("nextPageToken"),
            retrieved_at=datetime.now(timezone.utc),
        )


class ListCaseStageDefinitionsWorkflow:
    """Lists ordered SOC case lifecycle stage definitions."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, limit: int = 100) -> CaseStageDefinitionBatch:
        raw = self.adapter.list_case_stage_definitions(page_size=1000, order_by="order")
        raw_stages = raw.get("caseStageDefinitions", [])

        stages: List[CaseStageDefinitionSummary] = []
        for s in raw_stages:
            name = s.get("name", "")
            sid = name.split("/")[-1] if "/" in name else name

            stages.append(
                CaseStageDefinitionSummary(
                    id=sid,
                    name=name,
                    display_name=s.get("displayName", ""),
                    order=s.get("order", 0),
                    raw=s,
                )
            )

        total_count = len(stages)
        if limit > 0:
            stages = stages[:limit]

        return CaseStageDefinitionBatch(
            stages=stages,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class ListCaseCloseDefinitionsWorkflow:
    """Lists predefined case close reasons and root causes."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, limit: int = 100) -> CaseCloseDefinitionBatch:
        raw = self.adapter.list_case_close_definitions(page_size=1000)
        raw_defs = raw.get("caseCloseDefinitions", [])

        definitions: List[CaseCloseDefinitionSummary] = []
        for d in raw_defs:
            name = d.get("name", "")
            did = name.split("/")[-1] if "/" in name else name

            definitions.append(
                CaseCloseDefinitionSummary(
                    id=did,
                    name=name,
                    close_reason=d.get("closeReason", ""),
                    root_cause=d.get("rootCause", ""),
                    raw=d,
                )
            )

        total_count = len(definitions)
        if limit > 0:
            definitions = definitions[:limit]

        return CaseCloseDefinitionBatch(
            definitions=definitions,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class ListCaseCloseDynamicParametersWorkflow:
    """Lists dynamic form parameters and custom field schemas for case closure."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, limit: int = 100) -> CaseCloseDynamicParameterBatch:
        raw = self.adapter.list_case_close_dynamic_parameters(page_size=1000)
        raw_params = raw.get("formDynamicParameters", [])

        params: List[CaseCloseDynamicParameterSummary] = []
        for p in raw_params:
            pid = p.get("id", "")
            rel_custom = p.get("relatedCustomField", {})
            opt_dict = rel_custom.get("multipleOptions", {})
            values = opt_dict.get("values", [])

            params.append(
                CaseCloseDynamicParameterSummary(
                    id=str(pid),
                    form_type=p.get("formType", "CLOSE_CASE"),
                    order=p.get("order", 0),
                    related_custom_field_id=str(p.get("relatedCustomFieldId", "")),
                    custom_field_display_name=rel_custom.get("displayName", ""),
                    custom_field_type=rel_custom.get("type", "STRING"),
                    allowed_values=values,
                    raw=p,
                )
            )

        total_count = len(params)
        if limit > 0:
            params = params[:limit]

        return CaseCloseDynamicParameterBatch(
            parameters=params,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetCaseTitleSettingsWorkflow:
    """Retrieves case title formatting priority rules."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> CaseTitleSettingsBatch:
        raw = self.adapter.get_case_title_settings()
        raw_props = raw.get("moduleSettingsProperties", [])

        props: List[CaseTitleSettingProperty] = []
        for p in raw_props:
            name = p.get("name", "")
            pkey = name.split("/")[-1] if "/" in name else name

            props.append(
                CaseTitleSettingProperty(
                    name=name,
                    property_key=pkey,
                    display_name=p.get("displayName", pkey),
                    value=p.get("value", ""),
                    type=p.get("type", "STRING"),
                    raw=p,
                )
            )

        return CaseTitleSettingsBatch(
            properties=props,
            total_count=len(props),
            retrieved_at=datetime.now(timezone.utc),
        )


# --- Milestone 6.2 Workflows: Views, Custom Fields & Calculated Fields ---

class SearchCaseViewsWorkflow:
    """Discovers and filters layout view templates for Cases, Alerts, and Detections."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        view_type: str = "",
        limit: int = 100,
    ) -> CaseViewBatch:
        raw = self.adapter.list_views(page_size=1000)
        raw_views = raw.get("views", [])

        views: List[CaseViewSummary] = []
        for v in raw_views:
            name = v.get("name", "")
            vid = name.split("/")[-1] if "/" in name else name
            display_name = v.get("displayName", "")
            identifier = v.get("identifier", vid)
            vtype = v.get("type")
            is_def = v.get("isDefault")

            if view_type and view_type.upper() != "ALL":
                if not vtype or vtype.upper() != view_type.upper():
                    continue

            if query:
                q = query.lower()
                match = (
                    q in vid.lower()
                    or q in display_name.lower()
                    or q in identifier.lower()
                    or (vtype and q in vtype.lower())
                )
                if not match:
                    continue

            views.append(
                CaseViewSummary(
                    id=vid,
                    name=name,
                    display_name=display_name,
                    identifier=identifier,
                    type=vtype,
                    is_default=is_def,
                    raw=v,
                )
            )

        total_count = len(views)
        if limit > 0:
            views = views[:limit]

        return CaseViewBatch(
            views=views,
            total_count=total_count,
            next_page_token=raw.get("nextPageToken"),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetCaseViewWorkflow:
    """Retrieves deep inspection of a specific view layout template and widgets."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, view_id: str) -> CaseViewDetail:
        raw = self.adapter.get_view(view_id)
        name = raw.get("name", "")
        vid = raw.get("id") or (name.split("/")[-1] if "/" in name else view_id)
        display_name = raw.get("displayName", "")
        identifier = raw.get("identifier", vid)
        vtype = raw.get("type")
        is_def = raw.get("isDefault")

        summary = CaseViewSummary(
            id=str(vid),
            name=name,
            display_name=display_name,
            identifier=identifier,
            type=vtype,
            is_default=is_def,
            raw=raw,
        )

        widgets: List[ViewWidget] = []
        for w in raw.get("widgets", []):
            meta = w.get("metadata", {})
            cfg = w.get("config", {})

            widget_meta = ViewWidgetMetadata(
                id=str(meta.get("id", "")),
                identifier=meta.get("identifier", ""),
                title=meta.get("title", ""),
                width=meta.get("width", "FULL_WIDTH"),
                order=meta.get("order", 0),
                description=meta.get("description", ""),
                type=meta.get("type", "UNKNOWN"),
                template_identifier=meta.get("templateIdentifier", ""),
                present_if_empty=meta.get("presentIfEmpty", False),
                raw=meta,
            )

            widgets.append(
                ViewWidget(
                    metadata=widget_meta,
                    config=cfg,
                    raw=w,
                )
            )

        return CaseViewDetail(
            summary=summary,
            widgets=widgets,
            raw=raw,
        )


class SearchCustomFieldsWorkflow:
    """Lists and filters custom typed fields across Case and Alert scopes."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        field_type: str = "",
        scope: str = "",
        limit: int = 100,
    ) -> CustomFieldBatch:
        raw = self.adapter.list_custom_fields(page_size=1000)
        raw_fields = raw.get("customFields", [])

        fields: List[CustomFieldSummary] = []
        for cf in raw_fields:
            name = cf.get("name", "")
            cid = cf.get("id") or (name.split("/")[-1] if "/" in name else name)
            display_name = cf.get("displayName", "")
            ftype = cf.get("type", "STRING")
            fscopes = cf.get("scopes", "")
            opt_dict = cf.get("multipleOptions", {})
            values = opt_dict.get("values", [])

            if field_type and field_type.upper() != "ALL":
                if ftype.upper() != field_type.upper():
                    continue

            if scope and scope.upper() != "ALL":
                if scope.upper() not in fscopes.upper():
                    continue

            if query:
                q = query.lower()
                match = (
                    q in str(cid).lower()
                    or q in display_name.lower()
                    or q in ftype.lower()
                    or q in fscopes.lower()
                )
                if not match:
                    continue

            fields.append(
                CustomFieldSummary(
                    id=str(cid),
                    name=name,
                    display_name=display_name,
                    type=ftype,
                    scopes=fscopes,
                    values=values,
                    raw=cf,
                )
            )

        total_count = len(fields)
        if limit > 0:
            fields = fields[:limit]

        return CustomFieldBatch(
            custom_fields=fields,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetCustomFieldWorkflow:
    """Retrieves deep inspection of a single custom field definition."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, field_id: str) -> CustomFieldDetail:
        raw = self.adapter.get_custom_field(field_id)
        name = raw.get("name", "")
        cid = raw.get("id") or (name.split("/")[-1] if "/" in name else field_id)
        display_name = raw.get("displayName", "")
        ftype = raw.get("type", "STRING")
        fscopes = raw.get("scopes", "")
        opt_dict = raw.get("multipleOptions", {})
        values = opt_dict.get("values", [])
        ordered_values = opt_dict.get("orderedValues", [])

        summary = CustomFieldSummary(
            id=str(cid),
            name=name,
            display_name=display_name,
            type=ftype,
            scopes=fscopes,
            values=values,
            raw=raw,
        )

        return CustomFieldDetail(
            summary=summary,
            ordered_values=ordered_values,
            raw=raw,
        )


class SearchCalculatedFieldsWorkflow:
    """Lists and filters calculated field formula definitions."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        limit: int = 100,
    ) -> CalculatedFieldBatch:
        raw = self.adapter.list_calculated_fields(page_size=1000)
        raw_defs = raw.get("calculatedFieldDefinitions", [])

        defs: List[CalculatedFieldSummary] = []
        for d in raw_defs:
            name = d.get("name", "")
            cid = d.get("id") or (name.split("/")[-1] if "/" in name else name)
            target = d.get("targetField", "")
            formula = d.get("formula", "")
            enabled = d.get("enabled", True)
            desc = d.get("description")

            if query:
                q = query.lower()
                match = (
                    q in str(cid).lower()
                    or q in target.lower()
                    or q in formula.lower()
                    or (desc and q in desc.lower())
                )
                if not match:
                    continue

            defs.append(
                CalculatedFieldSummary(
                    id=str(cid),
                    name=name,
                    target_field=target,
                    formula=formula,
                    enabled=enabled,
                    description=desc,
                    raw=d,
                )
            )

        total_count = len(defs)
        if limit > 0:
            defs = defs[:limit]

        return CalculatedFieldBatch(
            definitions=defs,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetCalculatedFieldWorkflow:
    """Retrieves deep inspection of a single calculated field definition."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, definition_id: str) -> CalculatedFieldDetail:
        raw = self.adapter.get_calculated_field(definition_id)
        name = raw.get("name", "")
        cid = raw.get("id") or (name.split("/")[-1] if "/" in name else definition_id)
        target = raw.get("targetField", "")
        formula = raw.get("formula", "")
        enabled = raw.get("enabled", True)
        desc = raw.get("description")

        summary = CalculatedFieldSummary(
            id=str(cid),
            name=name,
            target_field=target,
            formula=formula,
            enabled=enabled,
            description=desc,
            raw=raw,
        )

        return CalculatedFieldDetail(
            summary=summary,
            raw=raw,
        )


class SearchAlertGroupingRulesWorkflow:
    """Discovers and filters SOAR alert grouping rules."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        category: str = "",
        limit: int = 100,
    ) -> AlertGroupingRuleBatch:
        raw = self.adapter.list_alert_grouping_rules(page_size=1000)
        raw_rules = raw.get("alertGroupingRules", [])

        rules: List[AlertGroupingRuleSummary] = []
        for r in raw_rules:
            name = r.get("name", "")
            rid = name.split("/")[-1] if "/" in name else name
            cat = r.get("category", "")
            gtype = r.get("groupingType", "")
            etypes = r.get("entityType", [])
            cat_details = r.get("categoryDetails", [])

            # Apply category filter
            if category and cat.upper() != category.upper():
                continue

            # Apply query keyword filter
            if query:
                q_lower = query.lower()
                cat_match = any(
                    q_lower in cd.get("identifier", "").lower()
                    or q_lower in cd.get("displayName", "").lower()
                    for cd in cat_details
                )
                entity_match = any(q_lower in et.lower() for et in etypes)
                if (
                    q_lower not in rid.lower()
                    and q_lower not in name.lower()
                    and q_lower not in cat.lower()
                    and q_lower not in gtype.lower()
                    and not cat_match
                    and not entity_match
                ):
                    continue

            rules.append(
                AlertGroupingRuleSummary(
                    id=rid,
                    name=name,
                    category=cat,
                    grouping_type=gtype,
                    entity_types=etypes,
                    category_details_count=len(cat_details),
                    raw=r,
                )
            )

        total_count = len(rules)
        if limit > 0:
            rules = rules[:limit]

        return AlertGroupingRuleBatch(
            rules=rules,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetAlertGroupingRuleWorkflow:
    """Retrieves deep inspection of a single alert grouping rule."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, rule_id: str) -> AlertGroupingRuleDetail:
        raw = self.adapter.get_alert_grouping_rule(rule_id)
        name = raw.get("name", "")
        rid = name.split("/")[-1] if "/" in name else rule_id
        cat = raw.get("category", "")
        gtype = raw.get("groupingType", "")
        etypes = raw.get("entityType", [])
        raw_cat_details = raw.get("categoryDetails", [])

        summary = AlertGroupingRuleSummary(
            id=rid,
            name=name,
            category=cat,
            grouping_type=gtype,
            entity_types=etypes,
            category_details_count=len(raw_cat_details),
            raw=raw,
        )

        cat_details = [
            AlertGroupingCategoryDetail(
                identifier=cd.get("identifier", ""),
                display_name=cd.get("displayName", ""),
            )
            for cd in raw_cat_details
        ]

        return AlertGroupingRuleDetail(
            summary=summary,
            category_details=cat_details,
            raw=raw,
        )


class GetAlertGroupingSettingsWorkflow:
    """Retrieves global alert grouping module settings properties."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> AlertGroupingSettingsBatch:
        raw = self.adapter.get_alert_grouping_settings()
        raw_props = raw.get("moduleSettingsProperties", [])

        props: List[AlertGroupingSettingProperty] = []
        for p in raw_props:
            name = p.get("name", "")
            pkey = name.split("/")[-1] if "/" in name else name

            props.append(
                AlertGroupingSettingProperty(
                    name=name,
                    property_key=pkey,
                    display_name=p.get("displayName", pkey),
                    value=p.get("value", ""),
                    type=p.get("type", "STRING"),
                    raw=p,
                )
            )

        return AlertGroupingSettingsBatch(
            properties=props,
            total_count=len(props),
            retrieved_at=datetime.now(timezone.utc),
        )

