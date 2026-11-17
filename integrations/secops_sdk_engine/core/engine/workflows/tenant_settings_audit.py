"""Tenant Settings & Posture Configuration Audit Workflow."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine


def generate_tenant_settings_report(
    engine: Optional["SecOpsEngine"] = None,
) -> Dict[str, Any]:
    """Generates a complete tenant settings and configuration audit report."""
    if engine is None:
        from engine.facade import SecOpsEngine

        engine = SecOpsEngine()

    report: Dict[str, Any] = {}

    # 1. Root Instance
    ti = engine.get_tenant_instance()
    report["tenant_id"] = ti.customer_code or ti.id or "default"
    report["instance"] = {
        "id": ti.id,
        "display_name": ti.display_name,
        "customer_code": ti.customer_code,
        "state": ti.state,
        "secops_ui_enabled": ti.secops_ui_enabled,
        "data_rbac_enabled": ti.data_rbac_enabled,
        "triage_agent_enabled": ti.triage_agent_enabled,
        "endpoints": ti.secops_urls,
    }

    # 2. Gemini AI & UEBA
    ag = engine.get_agent_settings()
    rc = engine.get_entity_risk_config()
    report["gemini_ai"] = {
        "auto_investigation": ag.auto_investigation_enabled,
        "alert_filter": ag.alert_filter,
        "delay": ag.auto_investigation_delay,
        "quotas": f"{ag.auto_quota_limit}/{ag.manual_quota_limit}",
    }
    report["ueba_risk"] = {
        "detection_score": rc.default_detection_risk_score,
        "alert_score": rc.default_alert_risk_score,
        "weighting_factor": rc.default_weighting_factor,
        "closed_coefficient": rc.default_closed_alert_coefficient,
    }

    # 3. Pipelines & RBAC
    md = engine.get_managed_domain_settings()
    pipelines = engine.search_log_processing_pipelines(limit=50)
    scopes = engine.search_data_access_scopes(limit=50)
    labels = engine.search_data_access_labels(limit=50)
    report["governance"] = {
        "managed_domains": [d.domain for d in md.domains],
        "pipelines": [
            {"name": p.display_name, "streams": p.streams, "processors": p.processors_count}
            for p in pipelines.pipelines
        ],
        "rbac_scopes": [{"id": s.id, "desc": s.description} for s in scopes.scopes],
        "rbac_labels": [{"id": l.id, "desc": l.description} for l in labels.labels],
    }

    # 4. SOAR Global Settings
    cs = engine.get_company_settings()
    dr = engine.get_data_retention_settings()
    es = engine.get_email_settings()
    ss = engine.get_support_settings()
    ag_set = engine.get_alert_grouping_settings()
    ct_set = engine.get_case_title_settings()
    report["soar_settings"] = {
        "company": {
            p.property_key: p.value
            for p in cs.properties
            if not p.property_key.endswith("Base64") and not p.property_key.endswith("Logo")
        },
        "data_retention": {p.property_key: p.value for p in dr.properties},
        "email_custom": es.use_custom,
        "support_access": {p.property_key: p.value for p in ss.properties},
        "alert_grouping": {p.property_key: p.value for p in ag_set.properties},
        "case_title_format": {p.property_key: p.value for p in ct_set.properties},
    }

    # 5. Environments, Roles & Networks
    roles = engine.list_soc_roles()
    envs = engine.search_environments(limit=50)
    agents = engine.search_remote_agents(limit=50)
    nets = engine.search_soar_networks(limit=50)
    doms = engine.search_soar_domains(limit=50)
    lists = engine.search_soar_custom_lists(limit=50)
    report["topography"] = {
        "roles": [{"id": r.id, "display_name": r.display_name} for r in roles.roles],
        "environments": [
            {"id": e.id, "name": e.display_name, "is_default": getattr(e, "system", False)}
            for e in envs.environments
        ],
        "remote_agents": [{"name": a.display_name, "state": a.agent_state} for a in agents.remote_agents],
        "networks": [{"name": n.display_name, "cidr": n.address, "envs": n.environments} for n in nets.networks],
        "domains": [{"domain": d.display_name, "envs": d.environments} for d in doms.domains],
        "custom_lists": [
            {"category": l.category, "entity": l.entity_identifier, "envs": l.environments}
            for l in lists.custom_lists
        ],
    }

    return report
