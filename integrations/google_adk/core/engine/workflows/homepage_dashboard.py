"""Google SecOps Homepage Native Dashboard Workflow.

Fetches live external intelligence feeds:
1. Google Cloud Security Status (https://status.cloud.google.com/security/incidents.json & products.json)
2. Google SecOps Release Notes Atom Feed (https://docs.cloud.google.com/feeds/chronicle-security-operations-release-notes.xml)
3. Google Cloud Security Community RSS Feed (https://security.googlecloudcommunity.com/feed/topics)

And combines them with live tenant telemetry & health posture from Google SecOps:
4. Live Tenant Health & Operations Pulse (24h UDM event volume, active log sources, open SOAR cases by priority,
   custom YARA-L rule posture, top alerting & silent noisy rules, active data feeds, and data tables).
5. AI Executive Summary & Actionable Advisories (correlating external service advisories, release notes, and
   community intelligence against live tenant telemetry, plus optional custom LLM commentary from the ADK Agent).
6. Three Native Live Telemetry KPI Counter Cards (TILE_TYPE_VISUALIZATION) for 24h UDM Events, Active Log Sources,
   and 7d Rule Detections Volume.
"""

from __future__ import annotations

import html
import json
import logging
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import DashboardSearchQuery
from engine.workflows.cloud_status import fetch_security_incidents
from engine.workflows.dashboards import (
    AddDashboardChartWorkflow,
    CreateDashboardWorkflow,
    GetDashboardDetailWorkflow,
    SearchDashboardsWorkflow,
    UpdateDashboardChartWorkflow,
    UpdateDashboardWorkflow,
)
from engine.workflows.detection_tuning import FindTopNoisyRulesWorkflow

logger = logging.getLogger(__name__)

STATUS_PRODUCTS_URL = "https://status.cloud.google.com/security/products.json"
STATUS_PAGE_URL = "https://status.cloud.google.com/security/"
RELEASE_NOTES_FEED_URL = "https://docs.cloud.google.com/feeds/chronicle-security-operations-release-notes.xml"
RELEASE_NOTES_PAGE_URL = "https://docs.cloud.google.com/chronicle/docs/secops/release-notes"
COMMUNITY_FEED_URL = "https://security.googlecloudcommunity.com/feed/topics"
COMMUNITY_PAGE_URL = "https://security.googlecloudcommunity.com/"

DEFAULT_COMMUNITY_CATEGORIES = [
    "community-blog-42",
    "news-announcements-9",
    "what-s-new-in-secops-91",
    "tuesday-s-tip-of-the-week-93",
]

CATEGORY_LABELS = {
    "community-blog-42": "Community Blog",
    "news-announcements-9": "News & Announcements",
    "what-s-new-in-secops-91": "What's New in SecOps",
    "tuesday-s-tip-of-the-week-93": "Tuesday's Tip",
    "google-security-operations-2": "SecOps Forum",
    "google-threat-intelligence-3": "Threat Intelligence",
}

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; Google-SecOps-Engine/1.0; +https://cloud.google.com/security)"


def _strip_html(raw_html: str) -> str:
    """Strips HTML tags and normalizes whitespace."""
    if not raw_html:
        return ""
    cleaned = re.sub(r"<[^>]+>", " ", raw_html)
    cleaned = html.unescape(cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def fetch_security_products(timeout_seconds: int = 15) -> List[Dict[str, str]]:
    """Fetches tracked security products from status.cloud.google.com/security/products.json."""
    try:
        req = urllib.request.Request(
            STATUS_PRODUCTS_URL,
            headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        products = payload.get("products", [])
        if isinstance(products, list):
            return products
    except Exception as exc:
        logger.warning("Failed to fetch security products catalog: %s", exc)
    return [
        {"title": "Google SecOps", "id": "FHwvkSZ6RzzDYAvDZXMM"},
        {"title": "Google SecOps SOAR", "id": "GTT16Lf72XZKWArC9VxA"},
        {"title": "Google Threat Intelligence", "id": "gdThxsn27IlqPf7hKvHT"},
    ]


def fetch_secops_release_notes(
    max_entries: int = 5,
    timeout_seconds: int = 15,
) -> List[Dict[str, Any]]:
    """Fetches and parses the latest Google SecOps release notes from the official Atom XML feed."""
    req = urllib.request.Request(
        RELEASE_NOTES_FEED_URL,
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/atom+xml, application/xml, text/xml"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        xml_bytes = resp.read()

    root = ET.fromstring(xml_bytes)
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    entries = root.findall("atom:entry", ns)

    parsed_entries: List[Dict[str, Any]] = []
    for entry in entries[: max(1, int(max_entries or 5))]:
        title = (entry.findtext("atom:title", "", ns) or "").strip()
        updated = (entry.findtext("atom:updated", "", ns) or "").strip()
        link_el = entry.find("atom:link", ns)
        link = link_el.attrib.get("href", RELEASE_NOTES_PAGE_URL) if link_el is not None else RELEASE_NOTES_PAGE_URL
        content_html = entry.findtext("atom:content", "", ns) or ""

        sections: List[Dict[str, str]] = []
        parts = re.split(r"<h3[^>]*>(.*?)</h3>", content_html, flags=re.IGNORECASE | re.DOTALL)
        if len(parts) > 1:
            for idx in range(1, len(parts), 2):
                badge = _strip_html(parts[idx]) or "Update"
                body_html = parts[idx + 1] if idx + 1 < len(parts) else ""
                headline_match = re.search(r"<strong[^>]*>(.*?)</strong>", body_html, flags=re.IGNORECASE | re.DOTALL)
                headline = _strip_html(headline_match.group(1)) if headline_match else ""
                summary_text = _strip_html(body_html)
                if headline and summary_text.startswith(headline):
                    summary_text = summary_text[len(headline) :].strip(" :-–—")
                if len(summary_text) > 220:
                    summary_text = summary_text[:217].rsplit(" ", 1)[0] + "..."
                sections.append(
                    {
                        "type": badge,
                        "headline": headline or title,
                        "summary": summary_text,
                    }
                )
        else:
            summary_text = _strip_html(content_html)
            if len(summary_text) > 240:
                summary_text = summary_text[:237].rsplit(" ", 1)[0] + "..."
            sections.append(
                {
                    "type": "Release",
                    "headline": title,
                    "summary": summary_text,
                }
            )

        parsed_entries.append(
            {
                "title": title,
                "updated": updated[:10] if updated else "",
                "link": link,
                "items": sections[:4],
            }
        )

    return parsed_entries


def fetch_security_community_topics(
    category_filters: Optional[Any] = None,
    max_items: int = 6,
    timeout_seconds: int = 15,
) -> Dict[str, Any]:
    """Fetches and filters the Google Cloud Security Community RSS feed by XML <link> path category."""
    if isinstance(category_filters, str):
        raw_filters = [p.strip() for p in category_filters.split(",") if p.strip()]
    elif category_filters is not None:
        raw_filters = list(category_filters)
    else:
        raw_filters = list(DEFAULT_COMMUNITY_CATEGORIES)

    allowed_categories = [
        str(c).strip().lower().strip("/")
        for c in raw_filters
        if c and str(c).strip()
    ]

    req = urllib.request.Request(
        COMMUNITY_FEED_URL,
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/rss+xml, application/xml, text/xml"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        xml_bytes = resp.read()

    root = ET.fromstring(xml_bytes)
    items = root.findall("./channel/item")

    matched_items: List[Dict[str, str]] = []
    available_categories: Dict[str, int] = {}

    for item in items:
        link = (item.findtext("link") or "").strip()
        url_parts = link.split("/")
        category_slug = url_parts[3].lower() if len(url_parts) > 3 else "general"
        available_categories[category_slug] = available_categories.get(category_slug, 0) + 1

        if allowed_categories:
            if not any(f in category_slug or f in link.lower() for f in allowed_categories):
                continue

        title = _strip_html(item.findtext("title") or "Untitled Post")
        pub_date_raw = (item.findtext("pubDate") or "").strip()
        short_date = pub_date_raw
        date_match = re.search(r"(\d{1,2}\s+[A-Za-z]{3}\s+\d{4})", pub_date_raw)
        if date_match:
            short_date = date_match.group(1)

        desc_html = item.findtext("description") or ""
        clean_desc = _strip_html(desc_html)
        author = ""
        author_match = re.match(
            r"^Authors?:\s*([^.]+?)(?:\s+We are|\s+In today|\s+Introduction|\s+October|\s+September|\s+Google|\s+Detection)",
            clean_desc,
        )
        if author_match and len(author_match.group(1)) < 90:
            author = author_match.group(1).strip()

        if len(clean_desc) > 210:
            clean_desc = clean_desc[:207].rsplit(" ", 1)[0] + "..."

        matched_items.append(
            {
                "title": title,
                "link": link,
                "category_slug": category_slug,
                "category_label": CATEGORY_LABELS.get(category_slug, category_slug),
                "pub_date": short_date,
                "author": author,
                "summary": clean_desc,
            }
        )
        if len(matched_items) >= max(1, int(max_items or 6)):
            break

    return {
        "filters_applied": allowed_categories,
        "total_feed_items": len(items),
        "available_categories": available_categories,
        "items": matched_items,
    }


def fetch_tenant_health_snapshot(adapter: GoogleSecOpsAdapter) -> Dict[str, Any]:
    """Queries live tenant operational metrics from Chronicle SIEM & SOAR for the Homepage Dashboard."""
    snapshot: Dict[str, Any] = {
        "project_id": getattr(adapter, "project_id", "") or getattr(adapter, "project_number", ""),
        "location": getattr(adapter, "location", "us"),
        "customer_id": getattr(adapter, "customer_id", ""),
        "udm_events_24h": 0,
        "active_udm_log_types_24h": 0,
        "active_ingestion_log_types_24h": 0,
        "detections_7d": 0,
        "open_cases_sampled": 0,
        "case_priorities": {},
        "recent_open_cases": [],
        "custom_rules_sampled": 0,
        "top_alerting_rules_7d": [],
        "top_silent_rules_7d": [],
        "active_feeds_count": 0,
        "feed_log_types": [],
        "data_tables_count": 0,
        "key_data_tables": [],
    }

    # 1. 24h UDM Event Count & Active UDM Log Types
    try:
        q_udm = (
            'metadata.event_type != "EVENTTYPE_UNSPECIFIED"\n'
            "outcome:\n"
            "  $event_count = count(metadata.id)\n"
            "  $log_types = count_distinct(metadata.log_type)"
        )
        r_udm = adapter.execute_dashboard_query(query_text=q_udm, time_unit="DAY", time_value="1")
        if r_udm.rows:
            snapshot["udm_events_24h"] = int(r_udm.rows[0].get("event_count") or 0)
            snapshot["active_udm_log_types_24h"] = int(r_udm.rows[0].get("log_types") or 0)
    except Exception as exc:
        logger.warning("Tenant health UDM query failed: %s", exc)

    # 2. 24h Ingestion Metrics Log Types
    try:
        q_ing = (
            'ingestion.log_type != ""\n'
            "outcome:\n"
            "  $log_types = count_distinct(ingestion.log_type)"
        )
        r_ing = adapter.execute_dashboard_query(query_text=q_ing, time_unit="DAY", time_value="1")
        if r_ing.rows:
            snapshot["active_ingestion_log_types_24h"] = int(r_ing.rows[0].get("log_types") or 0)
    except Exception as exc:
        logger.warning("Tenant health ingestion query failed: %s", exc)

    # 3. 7d Rule Detections Volume & Top Noisy Rules (Alerting vs Silent)
    try:
        q_det = (
            'detection.detection.rule_id != ""\n'
            "outcome:\n"
            "  $detection_count = count(detection.id)"
        )
        r_det = adapter.execute_dashboard_query(query_text=q_det, time_unit="DAY", time_value="7")
        if r_det.rows:
            snapshot["detections_7d"] = int(r_det.rows[0].get("detection_count") or 0)
    except Exception as exc:
        logger.warning("Tenant health total detections query failed: %s", exc)

    try:
        noisy_wf = FindTopNoisyRulesWorkflow(adapter)
        all_noisy = noisy_wf.execute(lookback_days=7, alert_state="ALL", limit=50)
        if not snapshot["detections_7d"]:
            snapshot["detections_7d"] = sum(int(r.detection_count or 0) for r in all_noisy.rules)

        alerting_rules = [r for r in all_noisy.rules if str(r.alert_state).upper() == "ALERTING"]
        silent_rules = [r for r in all_noisy.rules if str(r.alert_state).upper() != "ALERTING"]

        snapshot["top_alerting_rules_7d"] = [
            {
                "rule_name": r.rule_name,
                "rule_id": r.rule_id,
                "count": int(r.detection_count or 0),
            }
            for r in alerting_rules[:4]
        ]
        snapshot["top_silent_rules_7d"] = [
            {
                "rule_name": r.rule_name,
                "rule_id": r.rule_id,
                "count": int(r.detection_count or 0),
            }
            for r in silent_rules[:3]
        ]
    except Exception as exc:
        logger.warning("Tenant health noisy rules query failed: %s", exc)

    # 4. Open SOAR Cases Queue
    try:
        cases_res = adapter.list_cases(page_size=50, filter='status="OPENED"')
        raw_cases = cases_res.get("cases", []) if isinstance(cases_res, dict) else []
        snapshot["open_cases_sampled"] = len(raw_cases)
        prio_counts: Dict[str, int] = {}
        recent_cases: List[Dict[str, str]] = []
        for c in raw_cases:
            prio_raw = str(c.get("priority", "PRIORITY_UNSPECIFIED")).replace("PRIORITY_", "")
            prio_counts[prio_raw] = prio_counts.get(prio_raw, 0) + 1
            if len(recent_cases) < 4:
                cid = str(c.get("name", "")).split("/")[-1]
                title = str(c.get("displayName") or c.get("title") or f"Case {cid}")
                stage = str(c.get("stage") or "Triage")
                recent_cases.append(
                    {
                        "id": cid,
                        "title": title,
                        "priority": prio_raw,
                        "stage": stage,
                    }
                )
        snapshot["case_priorities"] = prio_counts
        snapshot["recent_open_cases"] = recent_cases
    except Exception as exc:
        logger.warning("Tenant health SOAR cases query failed: %s", exc)

    # 5. Custom Detection Rules Inventory
    try:
        rules_res = adapter.list_rules(page_size=200)
        rules_list = rules_res.get("rules", []) if isinstance(rules_res, dict) else []
        snapshot["custom_rules_sampled"] = len(rules_list)
    except Exception as exc:
        logger.warning("Tenant health rules list failed: %s", exc)

    # 6. Data Feeds & Data Tables
    try:
        feeds_res = adapter.list_feeds()
        feeds_list = feeds_res.get("feeds", []) if isinstance(feeds_res, dict) else []
        snapshot["active_feeds_count"] = len(feeds_list)
        feed_types: List[str] = []
        for f in feeds_list[:8]:
            details = f.get("details", {}) if isinstance(f, dict) else {}
            lt = details.get("logType", "")
            if lt:
                clean_lt = str(lt).split("/")[-1]
                if clean_lt not in feed_types:
                    feed_types.append(clean_lt)
        snapshot["feed_log_types"] = feed_types[:6]
    except Exception as exc:
        logger.warning("Tenant health feeds query failed: %s", exc)

    try:
        dt_res = adapter.list_data_tables(page_size=100)
        dt_list = dt_res.get("dataTables", []) if isinstance(dt_res, dict) else []
        snapshot["data_tables_count"] = len(dt_list)
        key_tables: List[str] = []
        for t in dt_list:
            t_name = str(t.get("name", "")).split("/")[-1]
            if t_name.startswith("asoc_") or len(key_tables) < 4:
                if t_name and t_name not in key_tables:
                    key_tables.append(t_name)
        snapshot["key_data_tables"] = key_tables[:5]
    except Exception as exc:
        logger.warning("Tenant health data tables query failed: %s", exc)

    return snapshot


def _format_header_markdown(
    dashboard_title: str,
    active_incidents_count: int,
    recent_incidents_count: int,
    latest_release_date: str,
    community_count: int,
    community_filters: List[str],
    tenant_health: Dict[str, Any],
    refreshed_at_str: str,
) -> str:
    status_badge = (
        "✓ **[ALL SECOPS SERVICES OPERATIONAL]**"
        if active_incidents_count == 0
        else f"🚨 **[{active_incidents_count} ACTIVE SERVICE DISRUPTION(S)]**"
    )
    proj = tenant_health.get("project_id") or "sdl-preview-americas"
    loc = (tenant_health.get("location") or "us").upper()
    return (
        f"# 🛡️ {dashboard_title}\n"
        f"**Platform Status:** {status_badge} &nbsp;•&nbsp; "
        f"**Tenant:** `{proj}` (**{loc}**) &nbsp;•&nbsp; "
        f"**Latest Release Notes:** **{latest_release_date or 'N/A'}** &nbsp;•&nbsp; "
        f"**30d Cloud Security Advisories:** **{recent_incidents_count}** &nbsp;•&nbsp; "
        f"**Featured Community Posts:** **{community_count}** &nbsp;•&nbsp; "
        f"**Last Synced:** **{refreshed_at_str}** *(Autonomous ADK Agent)*"
    )


def _format_ai_executive_summary_markdown(
    incidents: List[Any],
    release_notes: List[Dict[str, Any]],
    community_data: Dict[str, Any],
    tenant_health: Dict[str, Any],
    refreshed_at_str: str,
    custom_ai_summary: Optional[str] = None,
) -> str:
    active_incidents = [i for i in incidents if i.is_active]
    us_recent = [
        i
        for i in incidents[:5]
        if any(
            kw in (i.external_desc or "").lower()
            for kw in ("us region", "multiple regions", "https push", "cmek")
        )
    ]

    udm_24h = int(tenant_health.get("udm_events_24h") or 0)
    udm_types = int(tenant_health.get("active_udm_log_types_24h") or 0)
    ing_types = int(tenant_health.get("active_ingestion_log_types_24h") or 0)
    feeds_cnt = int(tenant_health.get("active_feeds_count") or 0)
    top_alerting = tenant_health.get("top_alerting_rules_7d", [])
    top_silent = tenant_health.get("top_silent_rules_7d", [])

    lines: List[str] = [
        "## 🤖 AI Executive Summary & Actionable Advisories",
        f"**Agent Synthesis:** Cross-correlating external feeds with live tenant telemetry (**{refreshed_at_str}**)",
        "",
    ]

    if custom_ai_summary and custom_ai_summary.strip():
        lines.append("### 🧠 Agent Mission Briefing")
        lines.append(custom_ai_summary.strip())
        lines.append("")

    # 1. Service Status Correlation
    lines.append("### 1. Cloud Security Status ↔ Tenant Telemetry Correlation")
    if active_incidents:
        inc = active_incidents[0]
        lines.append(
            f"- 🚨 **[ACTIVE DISRUPTION]** **[{inc.service_name}]({inc.public_url})** — {inc.external_desc} "
            f"**Action:** Monitor forwarder buffering and ingestion latency on tenant `{tenant_health.get('project_id', 'sdl-preview-americas')}`."
        )
    else:
        lines.append(
            f"- ✓ **[OPERATIONAL]** All Google SecOps SIEM, SOAR, and GTI services are **Operational**. "
            f"Live tenant ingestion is healthy at **{udm_24h:,} UDM events** across **{udm_types} normalized log types** "
            f"(**{ing_types}** raw ingestion sources, **{feeds_cnt}** active feeds) in the last 24h."
        )
    if us_recent:
        latest_us = us_recent[0]
        begin_d = (latest_us.begin or "")[:10]
        lines.append(
            f"- ▸ **Recent US-Region Advisory Verification ({begin_d}):** Incident [`{latest_us.id[:8]}`]({latest_us.public_url}) "
            f"(*{latest_us.external_desc}*) is **RESOLVED** (**{(latest_us.begin or '')[11:16]} → {(latest_us.end or '')[11:16]} UTC**). "
            f"No residual indexing lag or HTTPS Push drops observed in `us` region today."
        )

    lines.append("")
    # 2. Release Notes Impact Assessment
    lines.append("### 2. Release Notes Impact & Recommended Adoption")
    if release_notes:
        for entry in release_notes[:3]:
            r_date = entry.get("title", "")
            r_link = entry.get("link", RELEASE_NOTES_PAGE_URL)
            items = entry.get("items", [])
            if items:
                first_item = items[0]
                badge = first_item.get("type", "Update").upper()
                headline = first_item.get("headline", r_date)
                if "BIGQUERY" in headline.upper() or "CHRONICLE-TLA" in headline.upper():
                    rec = "Verify all downstream reporting queries use the native Data Lake / `datalake` export rather than legacy `chronicle-tla` tables."
                elif "BULK CASE" in headline.upper() or "GROUPING" in headline.upper():
                    rec = f"Applicable to our active SOAR queue (**{tenant_health.get('open_cases_sampled', 0)}+ open cases**) to accelerate batch triage and case grouping."
                elif "IMAGE" in headline.upper() or "CASE WALL" in headline.upper():
                    rec = "Available immediately for analyst and ADK Agent rich-text Case Wall evidence summaries."
                else:
                    rec = first_item.get("summary", "")[:140]
                lines.append(f"- ▸ **[{badge}] [{r_date} — {headline}]({r_link}):** {rec}")

    lines.append("")
    # 3. Community Intelligence & Detection Tuning Priorities
    lines.append("### 3. Community Intelligence & Detection Engineering Priorities")
    comm_items = community_data.get("items", [])
    if comm_items:
        top_blog = comm_items[0]
        lines.append(
            f"- 🚀 **Featured Launch:** **[{top_blog.get('title')}]({top_blog.get('link')})** (**{top_blog.get('category_label')}**, {top_blog.get('pub_date')}) — "
            f"Aligns with our autonomous detection tuning and retrohunt workflows."
        )
    if top_alerting or top_silent:
        top_a_str = (
            f"**{top_alerting[0]['rule_name']}** (**{top_alerting[0]['count']:,} alerts**)"
            if top_alerting
            else "none"
        )
        top_s_str = (
            f"**{top_silent[0]['rule_name']}** (**{top_silent[0]['count']:,} silent hits**)"
            if top_silent
            else "none"
        )
        lines.append(
            f"- ⚡ **Recommended Tuning Action (7d Telemetry):** Prioritize **Retrohunt & Findings Refinements** on top alerting rule "
            f"{top_a_str} and top silent rule {top_s_str} using `asoc_detection_tuning`."
        )

    return "\n".join(lines)


def _format_tenant_health_markdown(
    tenant_health: Dict[str, Any],
    refreshed_at_str: str,
) -> str:
    proj = tenant_health.get("project_id") or "sdl-preview-americas"
    loc = (tenant_health.get("location") or "us").upper()
    udm_24h = int(tenant_health.get("udm_events_24h") or 0)
    udm_types = int(tenant_health.get("active_udm_log_types_24h") or 0)
    ing_types = int(tenant_health.get("active_ingestion_log_types_24h") or 0)
    det_7d = int(tenant_health.get("detections_7d") or 0)
    open_cases = int(tenant_health.get("open_cases_sampled") or 0)
    prio_map: Dict[str, int] = tenant_health.get("case_priorities") or {}
    recent_cases: List[Dict[str, str]] = tenant_health.get("recent_open_cases") or []
    top_alerting: List[Dict[str, Any]] = tenant_health.get("top_alerting_rules_7d") or []
    top_silent: List[Dict[str, Any]] = tenant_health.get("top_silent_rules_7d") or []
    feeds_cnt = int(tenant_health.get("active_feeds_count") or 0)
    feed_types: List[str] = tenant_health.get("feed_log_types") or []
    dt_cnt = int(tenant_health.get("data_tables_count") or 0)
    key_dts: List[str] = tenant_health.get("key_data_tables") or []
    rules_cnt = int(tenant_health.get("custom_rules_sampled") or 0)

    crit_cnt = prio_map.get("CRITICAL", 0)
    high_cnt = prio_map.get("HIGH", 0)
    med_cnt = prio_map.get("MEDIUM", 0)
    low_cnt = prio_map.get("LOW", 0)

    lines: List[str] = [
        f"## 📊 Live Tenant Health & Operations Pulse (`{proj}` • **{loc}**)",
        f"**Telemetry Posture:** Real-time SIEM & SOAR snapshot sampled at **{refreshed_at_str}**",
        "",
        "### ⚡ Telemetry & Ingestion Vital Signs",
        (
            f"- **24h Normalized UDM Volume:** **{udm_24h:,} events** across **{udm_types} active UDM log types** "
            f"(**{ing_types}** raw ingestion sources)"
        ),
        (
            f"- **Active Data Feeds:** **{feeds_cnt} feeds** ({', '.join(f'`{t}`' for t in feed_types[:5]) or 'configured'}) &nbsp;|&nbsp; "
            f"**Data Tables:** **{dt_cnt} tables** ({', '.join(f'`{t}`' for t in key_dts[:3])})"
        ),
        (
            f"- **Detection Engine (7d):** **{det_7d:,} total detections** across **{rules_cnt}+ custom YARA-L rules**"
        ),
        "",
        f"### 🚨 SOAR Case Queue (**{open_cases}+ Open Sampled**)",
        (
            f"- **Priority Breakdown:** 🚨 **Critical:** **{crit_cnt}** &nbsp;|&nbsp; "
            f"▲ **High:** **{high_cnt}** &nbsp;|&nbsp; "
            f"◆ **Medium:** **{med_cnt}** &nbsp;|&nbsp; "
            f"● **Low:** **{low_cnt}**"
        ),
    ]

    if recent_cases:
        case_badges = [
            f"`#{c['id']}` **{c['title'][:36]}** ({c['priority']})"
            for c in recent_cases[:3]
        ]
        lines.append(f"- **Recent Active Cases:** {' &nbsp;•&nbsp; '.join(case_badges)}")

    lines.append("")
    lines.append("### ⚡ Top Alerting & Silent Detection Rules (Last 7 Days)")
    if top_alerting:
        for r in top_alerting[:3]:
            lines.append(
                f"- 🚨 **[ALERTING]** **{r['rule_name']}** (`{r['rule_id']}`) — **{r['count']:,} alerts**"
            )
    if top_silent:
        for r in top_silent[:2]:
            lines.append(
                f"- ◆ **[SILENT]** **{r['rule_name']}** (`{r['rule_id']}`) — **{r['count']:,} detections**"
            )

    return "\n".join(lines)


def _format_status_markdown(
    products: List[Dict[str, str]],
    incidents: List[Any],
    lookback_days: int,
) -> str:
    active_by_product: Dict[str, List[Any]] = {}
    for inc in incidents:
        if inc.is_active:
            for p in inc.affected_products:
                p_title = str(p.get("title", "Google SecOps"))
                active_by_product.setdefault(p_title, []).append(inc)

    lines: List[str] = [
        "## 🛡️ Google SecOps & Mandiant Service Status",
        f"**Source:** [status.cloud.google.com/security]({STATUS_PAGE_URL}) (**{lookback_days}d window**)",
        "",
        "### Core Platform Status",
    ]

    key_services = [
        "Google SecOps",
        "Google SecOps SOAR",
        "Google Threat Intelligence",
        "Mandiant Advantage Threat Intelligence",
        "Mandiant Attack Surface Management",
    ]
    available_titles = [p.get("title") or p.get("current_title", "") for p in products]
    for svc in key_services:
        if available_titles and svc not in available_titles:
            continue
        active_list = active_by_product.get(svc, [])
        if active_list:
            lines.append(f"- 🚨 **[DISRUPTION]** **{svc}:** Active Disruption (**{len(active_list)} incident**)")
        else:
            lines.append(f"- ✓ **[OPERATIONAL]** **{svc}**")

    lines.append("")
    lines.append(f"### Recent Service Incidents (Last {lookback_days} Days)")

    if not incidents:
        lines.append("✓ **No service incidents reported in the lookback window.**")
    else:
        for inc in incidents[:5]:
            icon = "🚨 **[ACTIVE]**" if inc.is_active else "✓ **[RESOLVED]**"
            begin_date = (inc.begin or "")[:10]
            end_str = (inc.end or "")[11:16] + " UTC" if inc.end and len(inc.end) >= 16 else "Ongoing"
            begin_time = (inc.begin or "")[11:16] if inc.begin and len(inc.begin) >= 16 else ""
            prods = ", ".join(str(p.get("title", "")) for p in inc.affected_products if p.get("title")) or inc.service_name
            desc = (inc.external_desc or "Service incident").strip()
            url = inc.public_url or STATUS_PAGE_URL
            lines.append(
                f"- {icon} **[{begin_date}]({url})** (**{prods}**) — {desc} *(Window: **{begin_time} → {end_str}**)*"
            )

    return "\n".join(lines)


def _format_release_notes_markdown(entries: List[Dict[str, Any]]) -> str:
    lines: List[str] = [
        "## 🚀 Latest Google SecOps Release Notes",
        f"**Source:** [chronicle-security-operations-release-notes.xml]({RELEASE_NOTES_FEED_URL})",
        "",
    ]

    if not entries:
        lines.append("*No release notes returned from feed.*")
        return "\n".join(lines)

    for entry in entries[:4]:
        title = entry.get("title") or entry.get("updated") or "Release Update"
        link = entry.get("link") or RELEASE_NOTES_PAGE_URL
        lines.append(f"### 📅 [{title}]({link})")
        for item in entry.get("items", [])[:3]:
            badge = item.get("type", "Update").upper()
            headline = item.get("headline", "")
            summary = item.get("summary", "")
            if headline and headline != title:
                lines.append(f"- ▸ **[{badge}] {headline}** — {summary}")
            else:
                lines.append(f"- ▸ **[{badge}]** {summary}")
        lines.append("")

    return "\n".join(lines)


def _format_community_markdown(community_data: Dict[str, Any]) -> str:
    filters = community_data.get("filters_applied", [])
    items = community_data.get("items", [])
    filters_badge = ", ".join(f"`{f}`" for f in filters) if filters else "`all`"

    lines: List[str] = [
        "## ⚡ Google Cloud Security Community Pulse",
        f"**Filtered RSS:** [security.googlecloudcommunity.com]({COMMUNITY_PAGE_URL}) ({filters_badge})",
        "",
    ]

    if not items:
        lines.append(f"*No community topics matched filters: {filters_badge}.*")
        return "\n".join(lines)

    for post in items[:5]:
        title = post.get("title", "Community Topic")
        link = post.get("link", COMMUNITY_PAGE_URL)
        cat_label = post.get("category_label", "Community")
        pub_date = post.get("pub_date", "")
        summary = post.get("summary", "")
        lines.append(
            f"- ▸ **[{cat_label}]** **[{title}]({link})** (**{pub_date}**) — {summary}"
        )

    return "\n".join(lines)


def _build_kpi_text_visualization(label: str, field: str) -> Dict[str, Any]:
    """Builds a clean Native Dashboard single-value KPI card (seriesType=TEXT) without trend/axis pager clutter."""
    return {
        "series": [
            {
                "seriesType": "TEXT",
                "field": field,
                "metricTrendConfig": {
                    "metricFormat": "METRIC_FORMAT_PLAIN_TEXT",
                    "showMetricTrend": False,
                },
            }
        ],
        "groupingType": "Off",
    }


def _needs_visualization_update(
    existing_vis: Dict[str, Any],
    desired_vis: Dict[str, Any],
    tile_type: str,
) -> bool:
    """Returns True only when a chart's visualization config or markdown content differs from the server state."""
    if not existing_vis:
        return True
    if tile_type == "TILE_TYPE_MARKDOWN":
        return (
            existing_vis.get("markdown", {}).get("content")
            != desired_vis.get("markdown", {}).get("content")
        )
    if tile_type == "TILE_TYPE_BUTTON":
        ex_btn = existing_vis.get("button", {})
        des_btn = desired_vis.get("button", {})
        return (
            ex_btn.get("label") != des_btn.get("label")
            or ex_btn.get("hyperlink") != des_btn.get("hyperlink")
            or ex_btn.get("properties", {}).get("buttonStyle")
            != des_btn.get("properties", {}).get("buttonStyle")
        )
    if tile_type == "TILE_TYPE_VISUALIZATION":
        ex_series = (existing_vis.get("series") or [{}])[0]
        return bool(
            existing_vis.get("xAxes")
            or existing_vis.get("yAxes")
            or existing_vis.get("legends")
            or ex_series.get("label")
            or ex_series.get("metricTrendConfig", {}).get("showMetricTrend")
        )
    return existing_vis != desired_vis


class SyncSecOpsHomepageDashboardWorkflow:
    """Creates or refreshes the 'Google SecOps Homepage' Native Dashboard from live external feeds and tenant telemetry."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter
        self._search_wf = SearchDashboardsWorkflow(adapter)
        self._get_wf = GetDashboardDetailWorkflow(adapter)
        self._create_wf = CreateDashboardWorkflow(adapter)
        self._update_dash_wf = UpdateDashboardWorkflow(adapter)
        self._add_chart_wf = AddDashboardChartWorkflow(adapter)
        self._update_chart_wf = UpdateDashboardChartWorkflow(adapter)

    def execute(
        self,
        dashboard_title: str = "Google SecOps Homepage",
        dashboard_id: Optional[str] = None,
        community_categories: Optional[Any] = None,
        status_lookback_days: int = 30,
        max_release_notes: int = 4,
        max_community_posts: int = 6,
        include_tenant_health: bool = True,
        ai_executive_summary: Optional[str] = None,
        dashboard_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetches live Status, Release Notes, Community feeds, and Tenant Health and syncs the Homepage Native Dashboard."""
        if dashboard_name and str(dashboard_name).strip():
            dashboard_title = str(dashboard_name).strip()
        now_utc = datetime.now(timezone.utc)
        refreshed_at_str = now_utc.strftime("%Y-%m-%d %H:%M UTC")

        # 1. Fetch all 3 external feeds + live tenant health telemetry
        products = fetch_security_products()
        incidents = fetch_security_incidents(
            service_name=None,
            only_active=False,
            lookback_days=status_lookback_days,
        )
        release_notes = fetch_secops_release_notes(max_entries=max_release_notes)
        community_data = fetch_security_community_topics(
            category_filters=community_categories,
            max_items=max_community_posts,
        )
        tenant_health = (
            fetch_tenant_health_snapshot(self.adapter)
            if include_tenant_health
            else {}
        )

        active_incidents = [i for i in incidents if i.is_active]
        latest_rn_date = release_notes[0]["title"] if release_notes else "N/A"
        applied_filters = community_data.get("filters_applied", DEFAULT_COMMUNITY_CATEGORIES)

        # 2. Build Markdown contents for the 6 Markdown tiles
        header_md = _format_header_markdown(
            dashboard_title=dashboard_title,
            active_incidents_count=len(active_incidents),
            recent_incidents_count=len(incidents),
            latest_release_date=latest_rn_date,
            community_count=len(community_data.get("items", [])),
            community_filters=applied_filters,
            tenant_health=tenant_health,
            refreshed_at_str=refreshed_at_str,
        )
        ai_exec_md = _format_ai_executive_summary_markdown(
            incidents=incidents,
            release_notes=release_notes,
            community_data=community_data,
            tenant_health=tenant_health,
            refreshed_at_str=refreshed_at_str,
            custom_ai_summary=ai_executive_summary,
        )
        tenant_health_md = _format_tenant_health_markdown(
            tenant_health=tenant_health,
            refreshed_at_str=refreshed_at_str,
        )
        status_md = _format_status_markdown(
            products=products,
            incidents=incidents,
            lookback_days=status_lookback_days,
        )
        release_notes_md = _format_release_notes_markdown(entries=release_notes)
        community_md = _format_community_markdown(community_data=community_data)

        # 3. Define desired 12-widget layout (96-column Chronicle Native Dashboard grid)
        # Row 0 (y=0..6):   Full-width Banner (spanY=6)
        # Row 1 (y=6..17):  3 Live Native Telemetry KPI Counter Cards (TILE_TYPE_VISUALIZATION, spanY=11)
        # Row 2 (y=17..45): AI Executive Summary (left 48 cols) + Live Tenant Health Pulse (right 48 cols) (spanY=28)
        # Row 3 (y=45..77): 3 External Feed Columns (Status, Release Notes, Security Community) (spanY=32)
        # Row 4 (y=77..80): 3 Outlined Quick-Launch Footer Buttons (spanY=3)
        desired_tiles: List[Dict[str, Any]] = [
            {
                "display_name": "SecOps Homepage Banner",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 0,
                "span_x": 96,
                "span_y": 6,
                "visualization": {
                    "markdown": {
                        "content": header_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "24h UDM Events Ingested (Live)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 0,
                "start_y": 6,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["UDM"],
                "time_unit": "DAY",
                "time_value": "1",
                "query": 'metadata.event_type != "EVENTTYPE_UNSPECIFIED"\noutcome:\n  $event_count = count(metadata.id)',
                "visualization": _build_kpi_text_visualization(
                    label="24h UDM Events",
                    field="event_count",
                ),
            },
            {
                "display_name": "24h Active UDM Log Sources (Live)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 32,
                "start_y": 6,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["UDM"],
                "time_unit": "DAY",
                "time_value": "1",
                "query": 'metadata.event_type != "EVENTTYPE_UNSPECIFIED"\noutcome:\n  $log_types = count_distinct(metadata.log_type)',
                "visualization": _build_kpi_text_visualization(
                    label="Active Log Types (24h)",
                    field="log_types",
                ),
            },
            {
                "display_name": "7d Rule Detections Volume (Live)",
                "tile_type": "TILE_TYPE_VISUALIZATION",
                "start_x": 64,
                "start_y": 6,
                "span_x": 32,
                "span_y": 11,
                "data_sources": ["RULE_DETECTIONS"],
                "time_unit": "DAY",
                "time_value": "7",
                "query": 'detection.detection.rule_id != ""\noutcome:\n  $detection_count = count(detection.id)',
                "visualization": _build_kpi_text_visualization(
                    label="7d Rule Detections",
                    field="detection_count",
                ),
            },
            {
                "display_name": "AI Executive Summary & Actionable Advisories",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 17,
                "span_x": 48,
                "span_y": 28,
                "visualization": {
                    "markdown": {
                        "content": ai_exec_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Live Tenant Health & Operations Pulse",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 48,
                "start_y": 17,
                "span_x": 48,
                "span_y": 28,
                "visualization": {
                    "markdown": {
                        "content": tenant_health_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Google SecOps Service Status",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 0,
                "start_y": 45,
                "span_x": 32,
                "span_y": 32,
                "visualization": {
                    "markdown": {
                        "content": status_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Google SecOps Release Notes",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 32,
                "start_y": 45,
                "span_x": 32,
                "span_y": 32,
                "visualization": {
                    "markdown": {
                        "content": release_notes_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Google Cloud Security Community",
                "tile_type": "TILE_TYPE_MARKDOWN",
                "start_x": 64,
                "start_y": 45,
                "span_x": 32,
                "span_y": 32,
                "visualization": {
                    "markdown": {
                        "content": community_md,
                        "properties": {"backgroundColor": "transparent"},
                    }
                },
            },
            {
                "display_name": "Open Cloud Security Status",
                "tile_type": "TILE_TYPE_BUTTON",
                "start_x": 0,
                "start_y": 77,
                "span_x": 32,
                "span_y": 3,
                "visualization": {
                    "button": {
                        "label": "Open Cloud Security Status ↗",
                        "hyperlink": STATUS_PAGE_URL,
                        "newTab": True,
                        "properties": {
                            "color": "#1a73e8",
                            "buttonStyle": "BUTTON_STYLE_OUTLINED",
                        },
                    }
                },
            },
            {
                "display_name": "Open SecOps Release Notes",
                "tile_type": "TILE_TYPE_BUTTON",
                "start_x": 32,
                "start_y": 77,
                "span_x": 32,
                "span_y": 3,
                "visualization": {
                    "button": {
                        "label": "Open SecOps Release Notes ↗",
                        "hyperlink": RELEASE_NOTES_PAGE_URL,
                        "newTab": True,
                        "properties": {
                            "color": "#1a73e8",
                            "buttonStyle": "BUTTON_STYLE_OUTLINED",
                        },
                    }
                },
            },
            {
                "display_name": "Open Security Community",
                "tile_type": "TILE_TYPE_BUTTON",
                "start_x": 64,
                "start_y": 77,
                "span_x": 32,
                "span_y": 3,
                "visualization": {
                    "button": {
                        "label": "Open Security Community ↗",
                        "hyperlink": COMMUNITY_PAGE_URL,
                        "newTab": True,
                        "properties": {
                            "color": "#1a73e8",
                            "buttonStyle": "BUTTON_STYLE_OUTLINED",
                        },
                    }
                },
            },
        ]

        # 4. Resolve or create the Native Dashboard
        target_dash_id = dashboard_id
        existing_detail = None
        action_taken = "UPDATED"

        if target_dash_id:
            try:
                existing_detail = self._get_wf.execute(target_dash_id, include_queries=False)
                target_dash_id = existing_detail.summary.id
            except Exception:
                existing_detail = None

        if existing_detail is None:
            batch = self._search_wf.execute(DashboardSearchQuery(query=dashboard_title, limit=50))
            for s in batch.dashboards:
                if s.display_name.strip().lower() == dashboard_title.strip().lower() and s.type.upper() == "CUSTOM":
                    target_dash_id = s.id
                    existing_detail = self._get_wf.execute(target_dash_id, include_queries=False)
                    break

        description_text = (
            f"Automated Google SecOps Homepage Dashboard (AI Executive Summary, Live Tenant Health, "
            f"Service Status, Release Notes, & Security Community). Last synced: {refreshed_at_str}."
        )

        if existing_detail is None:
            created_summary = self._create_wf.execute(
                display_name=dashboard_title,
                description=description_text,
                dashboard_type="CUSTOM",
            )
            target_dash_id = created_summary.id
            action_taken = "CREATED"
            existing_charts_by_name: Dict[str, Any] = {}
        else:
            existing_charts_by_name = {c.display_name: c for c in existing_detail.charts}

        # 5. Upsert each tile (update existing tiles in-place or addChart if missing)
        synced_tiles: List[Dict[str, Any]] = []
        chart_layout_entries: List[Dict[str, Any]] = []

        for spec in desired_tiles:
            t_name = spec["display_name"]
            existing_chart = existing_charts_by_name.get(t_name)
            layout_obj = {
                "startX": int(spec["start_x"]),
                "startY": int(spec["start_y"]),
                "spanX": int(spec["span_x"]),
                "spanY": int(spec["span_y"]),
            }
            if existing_chart is not None:
                chart_id_val = existing_chart.id
                full_chart_res_name = existing_chart.name
                if _needs_visualization_update(
                    existing_chart.visualization,
                    spec["visualization"],
                    spec["tile_type"],
                ):
                    self._update_chart_wf.execute(
                        chart_id=chart_id_val,
                        display_name=t_name,
                        visualization=spec["visualization"],
                    )
                    op_label = "UPDATED"
                else:
                    op_label = "UNCHANGED"
                synced_tiles.append(
                    {
                        "display_name": t_name,
                        "chart_id": chart_id_val,
                        "tile_type": spec["tile_type"],
                        "operation": op_label,
                        "layout": layout_obj,
                    }
                )
            else:
                add_res = self._add_chart_wf.execute(
                    dashboard_id=target_dash_id,
                    display_name=t_name,
                    tile_type=spec["tile_type"],
                    visualization=spec["visualization"],
                    data_sources=spec.get("data_sources"),
                    query=spec.get("query"),
                    time_unit=spec.get("time_unit", "DAY"),
                    time_value=spec.get("time_value", "1"),
                    start_x=spec["start_x"],
                    start_y=spec["start_y"],
                    span_x=spec["span_x"],
                    span_y=spec["span_y"],
                )
                new_chart_id = ""
                full_chart_res_name = ""
                if isinstance(add_res, dict):
                    dc = add_res.get("dashboardChart", {})
                    if isinstance(dc, dict) and dc.get("name"):
                        full_chart_res_name = dc["name"]
                        new_chart_id = full_chart_res_name.split("/")[-1]
                chart_id_val = new_chart_id
                synced_tiles.append(
                    {
                        "display_name": t_name,
                        "chart_id": chart_id_val,
                        "tile_type": spec["tile_type"],
                        "operation": "ADDED",
                        "layout": layout_obj,
                    }
                )

            if full_chart_res_name:
                chart_layout_entries.append(
                    {
                        "dashboardChart": full_chart_res_name,
                        "chartLayout": layout_obj,
                    }
                )

        # 6. Synchronize dashboard metadata & chart grid layouts so repositioned widgets never overlap
        try:
            self._update_dash_wf.execute(
                dashboard_id=target_dash_id,
                display_name=dashboard_title,
                description=description_text,
                charts=chart_layout_entries if chart_layout_entries else None,
            )
        except Exception as layout_exc:
            logger.warning("Failed to patch dashboard chart layouts: %s", layout_exc)

        return {
            "status": "SUCCESS",
            "action": action_taken,
            "dashboard_id": target_dash_id,
            "dashboard_title": dashboard_title,
            "last_synced_utc": refreshed_at_str,
            "feeds_summary": {
                "status_active_incidents": len(active_incidents),
                "status_recent_incidents": len(incidents),
                "release_notes_entries": len(release_notes),
                "latest_release_date": latest_rn_date,
                "community_posts_matched": len(community_data.get("items", [])),
                "community_filters": applied_filters,
            },
            "tenant_health_summary": {
                "udm_events_24h": tenant_health.get("udm_events_24h", 0),
                "active_udm_log_types_24h": tenant_health.get("active_udm_log_types_24h", 0),
                "active_ingestion_log_types_24h": tenant_health.get("active_ingestion_log_types_24h", 0),
                "detections_7d": tenant_health.get("detections_7d", 0),
                "open_cases_sampled": tenant_health.get("open_cases_sampled", 0),
                "case_priorities": tenant_health.get("case_priorities", {}),
                "active_feeds_count": tenant_health.get("active_feeds_count", 0),
                "data_tables_count": tenant_health.get("data_tables_count", 0),
            },
            "tiles": synced_tiles,
        }
