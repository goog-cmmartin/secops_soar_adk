"""Workflow implementations for SIEM Settings and Data Processing Pipelines."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    EntityRiskConfig,
    GeminiAgentSettings,
    LogProcessingPipelineBatch,
    LogProcessingPipelineDetail,
    LogProcessingPipelineSummary,
    ManagedDomain,
    ManagedDomainSettings,
    TenantInstanceDetails,
)


def _normalize_managed_domains(raw: Dict[str, Any]) -> ManagedDomainSettings:
    """Transforms raw managedDomainSettings response into typed ManagedDomainSettings."""
    raw_domains = raw.get("domains", [])
    domains = [
        ManagedDomain(
            domain=d.get("domain", ""),
            added_time=d.get("addedTime", ""),
            added_by=d.get("addedBy", ""),
        )
        for d in raw_domains
    ]
    return ManagedDomainSettings(
        domains=domains,
        retrieved_at=datetime.now(timezone.utc),
    )


def _normalize_pipeline_summary(raw: Dict[str, Any]) -> LogProcessingPipelineSummary:
    """Extracts summary and Bindplane SaaS links from raw pipeline JSON."""
    name = raw.get("name", "")
    pid = name.split("/")[-1] if name else ""
    streams = [s.get("logType", "") for s in raw.get("streams", []) if isinstance(s, dict)]
    processors = raw.get("processors", [])

    # Extract bindplane SaaS URL from customMetadata
    bindplane_url = None
    for meta in raw.get("customMetadata", []):
        if isinstance(meta, dict) and meta.get("key") == "bindplaneURL":
            bindplane_url = meta.get("value")
            break

    return LogProcessingPipelineSummary(
        id=pid,
        name=name,
        display_name=raw.get("displayName", pid),
        description=raw.get("description", ""),
        streams=streams,
        processors_count=len(processors),
        bindplane_url=bindplane_url,
        create_time=raw.get("createTime", ""),
        update_time=raw.get("updateTime", ""),
        raw=raw,
    )


class GetManagedDomainSettingsWorkflow:
    """Workflow to retrieve configured approved email domains."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(self) -> ManagedDomainSettings:
        res = self.adapter.get_managed_domain_settings()
        return _normalize_managed_domains(res)


class SearchLogProcessingPipelinesWorkflow:
    """Workflow to list and search Data Processing Pipelines."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        log_type: Optional[str] = None,
        limit: int = 50,
    ) -> LogProcessingPipelineBatch:
        raw_res = self.adapter.list_log_processing_pipelines(page_size=1000)
        items = raw_res.get("logProcessingPipelines", [])
        summaries = [_normalize_pipeline_summary(item) for item in items]

        if query:
            q_lower = query.lower()
            summaries = [
                s
                for s in summaries
                if q_lower in s.display_name.lower()
                or q_lower in s.description.lower()
                or q_lower in s.id.lower()
            ]

        if log_type:
            lt_lower = log_type.lower()
            summaries = [
                s
                for s in summaries
                if any(lt_lower in st.lower() for st in s.streams)
            ]

        limited = summaries[:limit]
        return LogProcessingPipelineBatch(
            pipelines=limited,
            total_count=len(summaries),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetLogProcessingPipelineDetailWorkflow:
    """Workflow to retrieve full pipeline transform statements and bindings."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(self, identifier_or_title: str) -> LogProcessingPipelineDetail:
        # Check if caller passed display name
        clean_id = identifier_or_title.split("/")[-1]
        if not identifier_or_title.startswith("projects/") and len(clean_id.split("-")) < 4:
            # Might be display name, search first
            search_wf = SearchLogProcessingPipelinesWorkflow(self.adapter)
            batch = search_wf.execute(query=identifier_or_title, limit=10)
            for p in batch.pipelines:
                if (
                    p.display_name.lower() == identifier_or_title.lower()
                    or p.id.lower() == identifier_or_title.lower()
                ):
                    clean_id = p.id
                    break

        raw = self.adapter.get_log_processing_pipeline(clean_id)
        summary = _normalize_pipeline_summary(raw)
        return LogProcessingPipelineDetail(
            summary=summary,
            processors=raw.get("processors", []),
            raw=raw,
        )


class GetAgentSettingsWorkflow:
    """Workflow to retrieve Gemini Triage & Investigation Agent settings."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(self) -> GeminiAgentSettings:
        raw = self.adapter.get_agent_settings()
        quota = raw.get("quotaInfo", {})
        return GeminiAgentSettings(
            name=raw.get("name", ""),
            auto_investigation_enabled=raw.get("autoInvestigationEnabled", False),
            alert_filter=raw.get("alertFilter", ""),
            auto_investigation_delay=raw.get("autoInvestigationDelay", ""),
            auto_quota_limit=str(quota.get("autoInvestigationsQuotaLimit", "")),
            manual_quota_limit=str(quota.get("manualInvestigationsQuotaLimit", "")),
            raw=raw,
        )


class GetEntityRiskConfigWorkflow:
    """Workflow to retrieve UEBA entity risk scoring configuration."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(self) -> EntityRiskConfig:
        raw = self.adapter.get_risk_config()
        return EntityRiskConfig(
            name=raw.get("name", ""),
            default_detection_risk_score=int(raw.get("defaultDetectionRiskScore", 0)),
            default_alert_risk_score=int(raw.get("defaultAlertRiskScore", 0)),
            default_weighting_factor=float(raw.get("defaultWeightingFactor", 0.0)),
            default_closed_alert_coefficient=float(raw.get("defaultClosedAlertCoefficient", 0.0)),
            raw=raw,
        )


class GetTenantInstanceWorkflow:
    """Workflow to retrieve root tenant instance details."""

    def __init__(self, adapter):
        self.adapter = adapter

    def execute(self) -> TenantInstanceDetails:
        raw = self.adapter.get_tenant_instance()
        name = raw.get("name", "")
        cid = name.split("/")[-1] if name else ""
        cfg = raw.get("instanceConfig", {})
        return TenantInstanceDetails(
            id=cid,
            name=name,
            state=raw.get("state", ""),
            display_name=raw.get("displayName", ""),
            customer_code=raw.get("customerCode", ""),
            create_time=raw.get("createTime", ""),
            secops_urls=raw.get("secopsUrls", []),
            secops_ui_enabled=cfg.get("secopsUiEnabled", False),
            data_rbac_enabled=cfg.get("dataRbacEnabled", False),
            triage_agent_enabled=cfg.get("triageAgentEnabled", False),
            frontend_paths=raw.get("frontendPathConfigs", []),
            raw=raw,
        )

