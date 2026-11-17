"""Curated Detections Health Check & Misconfiguration Audit Workflow."""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from engine.domain import CuratedDetectionHealthReport

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine


def generate_curated_detections_health_report(
    engine: Optional["SecOpsEngine"] = None,
    days: int = 7,
    scan_deployments: bool = True,
) -> CuratedDetectionHealthReport:
    """Generates a complete health, deployment, and hygiene audit for Curated Detections."""
    if engine is None:
        from engine.facade import SecOpsEngine

        engine = SecOpsEngine()

    adapter = engine.adapter
    days = max(1, days)
    now = datetime.now(timezone.utc)
    start_iso = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_iso = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # 1. Fetch Categories and Rule Sets
    cat_res = adapter.list_curated_ruleset_categories()
    raw_cats = cat_res.get("curatedRuleSetCategories", []) if isinstance(cat_res, dict) else []
    cat_map: Dict[str, str] = {
        c.get("name", "").split("/")[-1]: c.get("displayName", "")
        for c in raw_cats
        if c.get("name")
    }

    rs_res = adapter.list_curated_rulesets(page_size=1000)
    raw_rulesets = rs_res.get("curatedRuleSets", []) if isinstance(rs_res, dict) else []

    health_findings: List[Dict[str, Any]] = []

    # 2. Fetch Detection Metrics & Tenant Quotas with explicit degraded finding on failure
    tenant_metrics = None
    top_firing: List[Dict[str, Any]] = []
    firing_map: Dict[str, int] = {}
    try:
        metrics = engine.get_curated_detection_metrics(start_time=start_iso, end_time=end_iso)
        tenant_metrics = metrics.tenant_metrics
        top_firing = metrics.top_firing_rulesets or []
        firing_map = {
            f.get("resource_name", ""): int(f.get("count", 0))
            for f in top_firing
            if f.get("resource_name")
        }
    except Exception as e:
        health_findings.append(
            {
                "severity": "MEDIUM",
                "code": "METRICS_TIMEOUT_DEGRADED",
                "message": (
                    f"Detection metrics aggregation timed out or failed ({e}). "
                    "Inventory and configuration audits succeeded."
                ),
                "recommendation": "Try evaluating detection metrics over a shorter timeframe (e.g. days=1).",
            }
        )

    # 3. Fetch Curated Individual Rules (for content freshness)
    rules_res = adapter.list_curated_rules(page_size=1000)
    raw_rules = rules_res.get("curatedRules", []) if isinstance(rules_res, dict) else []

    # 4. Analyze Rule Sets and Deployments
    ruleset_audits: List[Dict[str, Any]] = []

    total_broad_enabled = 0
    total_broad_alerting = 0
    total_precise_enabled = 0
    total_precise_alerting = 0
    total_rulesets_with_active_deployments = 0

    category_stats: Dict[str, Dict[str, Any]] = {}
    log_source_stats: Dict[str, Dict[str, Any]] = {}

    for _cat_id, cat_title in cat_map.items():
        category_stats[cat_title] = {
            "category_name": cat_title,
            "total_rulesets": 0,
            "broad_enabled": 0,
            "precise_enabled": 0,
            "precise_alerting": 0,
        }

    rules_per_ruleset: Dict[str, int] = {}
    for r in raw_rules:
        parent_rs = r.get("curatedRuleSet", "")
        if parent_rs:
            rules_per_ruleset[parent_rs] = rules_per_ruleset.get(parent_rs, 0) + 1

    deployments_cache: Dict[str, List[Dict[str, Any]]] = {}
    deployment_errors: Dict[str, str] = {}
    if scan_deployments:

        def _fetch_dep(rs_n: str):
            try:
                dres = adapter.get_curated_ruleset_deployments(rs_n)
                return rs_n, dres.get("curatedRuleSetDeployments", []) if isinstance(dres, dict) else [], None
            except Exception as exc:
                return rs_n, [], str(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            fut_to_rs = {
                executor.submit(_fetch_dep, rs.get("name", "")): rs.get("name", "")
                for rs in raw_rulesets
                if rs.get("name")
            }
            for fut in concurrent.futures.as_completed(fut_to_rs):
                rs_k, rdeps, dep_err = fut.result()
                deployments_cache[rs_k] = rdeps
                if dep_err:
                    deployment_errors[rs_k] = dep_err

    for rs in raw_rulesets:
        rs_name = rs.get("name", "")
        rs_id = rs_name.split("/")[-1] if rs_name else ""
        rs_title = rs.get("displayName", "") or rs_id

        cat_id = ""
        if "/curatedRuleSetCategories/" in rs_name:
            cat_id = rs_name.split("/curatedRuleSetCategories/")[1].split("/")[0]
        cat_display = cat_map.get(cat_id, "General Threats")
        log_types = rs.get("logSources", []) or []
        member_rule_count = rules_per_ruleset.get(rs_name, 0)
        hits_count = firing_map.get(rs_name, 0)

        if cat_display in category_stats:
            category_stats[cat_display]["total_rulesets"] += 1

        for lt in log_types:
            if lt not in log_source_stats:
                log_source_stats[lt] = {"log_source": lt, "total_rulesets": 0, "active_rulesets": 0}
            log_source_stats[lt]["total_rulesets"] += 1

        deployments: List[Dict[str, Any]] = []
        has_active = False
        broad_enabled = False
        broad_alerting = False
        precise_enabled = False
        precise_alerting = False

        if scan_deployments:
            raw_deps = deployments_cache.get(rs_name, [])
            for d in raw_deps:
                d_name = d.get("name", "")
                precision_str = d_name.split("/")[-1].upper() if d_name else "UNKNOWN"
                is_enabled = bool(d.get("enabled", False))
                is_alerting = bool(d.get("alerting", False))
                deployments.append(
                    {
                        "precision": precision_str,
                        "enabled": is_enabled,
                        "alerting": is_alerting,
                        "resource_name": d_name,
                    }
                )

                if precision_str == "BROAD":
                    broad_enabled = is_enabled
                    broad_alerting = is_alerting
                    if is_enabled:
                        total_broad_enabled += 1
                    if is_alerting:
                        total_broad_alerting += 1
                elif precision_str == "PRECISE":
                    precise_enabled = is_enabled
                    precise_alerting = is_alerting
                    if is_enabled:
                        total_precise_enabled += 1
                    if is_alerting:
                        total_precise_alerting += 1

                if is_enabled:
                    has_active = True

        if has_active:
            total_rulesets_with_active_deployments += 1
            if cat_display in category_stats:
                if broad_enabled:
                    category_stats[cat_display]["broad_enabled"] += 1
                if precise_enabled:
                    category_stats[cat_display]["precise_enabled"] += 1
                if precise_alerting:
                    category_stats[cat_display]["precise_alerting"] += 1
            for lt in log_types:
                if lt in log_source_stats:
                    log_source_stats[lt]["active_rulesets"] += 1

        dep_error = deployment_errors.get(rs_name)
        if dep_error:
            health_findings.append(
                {
                    "severity": "MEDIUM",
                    "code": "DEPLOYMENT_FETCH_FAILED",
                    "ruleset_id": rs_id,
                    "ruleset_title": rs_title,
                    "category": cat_display,
                    "message": f"Failed to retrieve deployment state for rule set '{rs_title}': {dep_error}",
                    "recommendation": f"Verify API permissions and retry deployment inspection: secops curated get {rs_id}",
                }
            )

        if broad_enabled and broad_alerting:
            health_findings.append(
                {
                    "severity": "HIGH",
                    "code": "BROAD_ALERTING_ENABLED",
                    "ruleset_id": rs_id,
                    "ruleset_title": rs_title,
                    "category": cat_display,
                    "message": f"Rule set '{rs_title}' has BROAD precision deployment configured with Alerting ON.",
                    "recommendation": (
                        f"Set BROAD deployment to Alerting OFF (Silent Detection) to avoid alert fatigue:\n"
                        f"  secops curated set-deployment {rs_id} --precision BROAD --no-alerting"
                    ),
                }
            )

        if broad_enabled and not precise_enabled:
            health_findings.append(
                {
                    "severity": "MEDIUM",
                    "code": "BROAD_ENABLED_PRECISE_DISABLED",
                    "ruleset_id": rs_id,
                    "ruleset_title": rs_title,
                    "category": cat_display,
                    "message": f"Rule set '{rs_title}' has BROAD mode enabled but PRECISE mode is disabled.",
                    "recommendation": (
                        f"Enable PRECISE deployment with Alerting ON for high-confidence detections:\n"
                        f"  secops curated set-deployment {rs_id} --precision PRECISE --enabled --alerting"
                    ),
                }
            )

        if hits_count > 500 and (broad_alerting or precise_alerting):
            health_findings.append(
                {
                    "severity": "LOW",
                    "code": "HIGH_FIRING_VOLUME",
                    "ruleset_id": rs_id,
                    "ruleset_title": rs_title,
                    "category": cat_display,
                    "message": f"Rule set '{rs_title}' generated {hits_count:,} detections in the last {days} days.",
                    "recommendation": "Review detection tuning exclusions or verify alert thresholds.",
                }
            )

        if has_active and member_rule_count == 0:
            health_findings.append(
                {
                    "severity": "INFO",
                    "code": "EMPTY_ENABLED_RULESET",
                    "ruleset_id": rs_id,
                    "ruleset_title": rs_title,
                    "category": cat_display,
                    "message": f"Rule set '{rs_title}' is enabled but currently has 0 active member rules.",
                    "recommendation": "Check if updated content is pending publication from Google Cloud Threat Intelligence.",
                }
            )

        ruleset_audits.append(
            {
                "ruleset_id": rs_id,
                "title": rs_title,
                "category": cat_display,
                "log_sources": log_types,
                "member_rules_count": member_rule_count,
                "detections_count": hits_count,
                "broad_enabled": broad_enabled,
                "broad_alerting": broad_alerting,
                "precise_enabled": precise_enabled,
                "precise_alerting": precise_alerting,
                "deployments": deployments,
                "deployment_error": dep_error,
            }
        )

    valid_rules: List[Dict[str, Any]] = []
    for r in raw_rules:
        r_name = r.get("name", "")
        r_id = r_name.split("/")[-1] if r_name else ""
        up_time = r.get("updateTime", "")
        techs = [t.get("id", "") for t in r.get("techniques", []) if isinstance(t, dict)]
        raw_sev = r.get("severity")
        sev_str = (
            raw_sev.get("displayName", "MEDIUM")
            if isinstance(raw_sev, dict)
            else (str(raw_sev) if raw_sev else "MEDIUM")
        )
        valid_rules.append(
            {
                "rule_id": r_id,
                "title": r.get("displayName", "") or r_id,
                "severity": sev_str,
                "precision": r.get("precision", "PRECISE"),
                "rule_type": r.get("type", "SINGLE_EVENT"),
                "update_time": up_time,
                "techniques": techs,
                "parent_ruleset_name": r.get("curatedRuleSet", ""),
            }
        )

    sorted_by_newest = sorted(
        [r for r in valid_rules if r["update_time"]], key=lambda x: x["update_time"], reverse=True
    )
    sorted_by_oldest = sorted([r for r in valid_rules if r["update_time"]], key=lambda x: x["update_time"])

    newest_rules = sorted_by_newest[:10]
    oldest_rules = sorted_by_oldest[:10]

    total_detections_period = sum(f.get("count", 0) for f in top_firing)
    unhealthy_ids = {f["ruleset_id"] for f in health_findings if f.get("ruleset_id")}
    healthy_count = len(raw_rulesets) - len(unhealthy_ids)

    res_dict = {
        "evaluation_period": {
            "days": days,
            "start_time": start_iso,
            "end_time": end_iso,
            "retrieved_at": now.isoformat(),
        },
        "summary": {
            "total_categories": len(raw_cats),
            "total_rulesets": len(raw_rulesets),
            "total_curated_rules": len(raw_rules),
            "total_rulesets_deployed": total_rulesets_with_active_deployments,
            "broad_enabled_count": total_broad_enabled,
            "broad_alerting_count": total_broad_alerting,
            "precise_enabled_count": total_precise_enabled,
            "precise_alerting_count": total_precise_alerting,
            "total_detections_period": total_detections_period,
            "total_findings_count": len(health_findings),
            "healthy_rulesets_count": max(0, healthy_count),
        },
        "tenant_quotas": {
            "quota_usage": tenant_metrics.quota_usage if tenant_metrics else 0,
            "quota_limit": tenant_metrics.quota_limit if tenant_metrics else 0,
            "total_live_rule_count": tenant_metrics.total_live_rule_count if tenant_metrics else 0,
            "max_live_rule_count": tenant_metrics.max_live_rule_count if tenant_metrics else 0,
            "total_active_count": tenant_metrics.total_active_count if tenant_metrics else 0,
        },
        "health_findings": health_findings,
        "top_firing_rulesets": top_firing[:15],
        "newest_rules": newest_rules,
        "oldest_rules": oldest_rules,
        "category_coverage": list(category_stats.values()),
        "log_source_coverage": sorted(
            list(log_source_stats.values()), key=lambda x: x["total_rulesets"], reverse=True
        ),
        "ruleset_audits": ruleset_audits,
    }

    return CuratedDetectionHealthReport(**res_dict, raw=res_dict)
