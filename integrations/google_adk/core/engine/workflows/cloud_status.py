"""Google Cloud SecOps Service Status and Upstream Incident Monitor Workflow.

Fetches and normalizes live external incident telemetry from the official Google Cloud
Security Status feed (https://status.cloud.google.com/security/incidents.json).
"""

from __future__ import annotations

import json
import logging
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    CloudStatusIncident,
    CloudStatusLocation,
    CloudStatusReport,
    CloudStatusUpdate,
)

logger = logging.getLogger(__name__)

STATUS_INCIDENTS_ENDPOINT = "https://status.cloud.google.com/security/incidents.json"
DEFAULT_USER_AGENT = "Google-SecOps-Engine/1.0 (Workflow Engine Cloud Status Monitor)"


def fetch_security_incidents(
    service_name: Optional[str] = "Google SecOps",
    only_active: bool = False,
    region: Optional[str] = None,
    lookback_days: int = 30,
    timeout_seconds: int = 15,
) -> List[CloudStatusIncident]:
    """Fetches and filters live security incidents from Google Cloud Status.

    Args:
        service_name: Filter by service name or product (default: 'Google SecOps'). Set to None to include all.
        only_active: If True, only returns incidents that are currently active (unresolved).
        region: Optional cloud region filter (e.g. 'europe-west3', 'us').
        lookback_days: Maximum lookback days for modified/begin timestamp (default: 30 days).
        timeout_seconds: HTTP request timeout in seconds.

    Returns:
        List of parsed and filtered CloudStatusIncident objects.

    Raises:
        urllib.error.URLError: If the remote endpoint cannot be reached or returns an HTTP error.
        json.JSONDecodeError: If the remote payload is not valid JSON.
    """
    req = urllib.request.Request(
        STATUS_INCIDENTS_ENDPOINT,
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
    )

    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        raw_bytes = resp.read()
        raw_data = json.loads(raw_bytes.decode("utf-8"))

    if not isinstance(raw_data, list):
        raise ValueError(f"Expected list of incident records from {STATUS_INCIDENTS_ENDPOINT}, got {type(raw_data)}")

    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    incidents: List[CloudStatusIncident] = []

    for item in raw_data:
        if not isinstance(item, dict):
            continue

        incident = CloudStatusIncident.from_dict(item)

        # 1. Filter by Service / Product
        if service_name:
            norm_target = service_name.lower().replace(" ", "").replace("-", "")
            match = False
            # Check service_name
            if norm_target in incident.service_name.lower().replace(" ", "").replace("-", ""):
                match = True
            # Check affected products
            for prod in incident.affected_products:
                prod_title = str(prod.get("title", "")).lower().replace(" ", "").replace("-", "")
                prod_id = str(prod.get("id", "")).lower()
                if norm_target in prod_title or norm_target in prod_id:
                    match = True
                    break
            # SecOps alias check: "chronicle" or "secops"
            if ("secops" in norm_target or "chronicle" in norm_target) and (
                "secops" in incident.service_name.lower() or "chronicle" in incident.service_name.lower()
            ):
                match = True

            if not match:
                continue

        # 2. Filter by Active status
        if only_active and not incident.is_active:
            continue

        # 3. Filter by Region if requested
        if region:
            norm_region = region.lower().strip()
            loc_ids = {
                loc.id.lower()
                for loc in (incident.currently_affected_locations + incident.previously_affected_locations)
            }
            loc_titles = {
                loc.title.lower()
                for loc in (incident.currently_affected_locations + incident.previously_affected_locations)
            }
            region_hit = any(norm_region in lid for lid in loc_ids) or any(norm_region in lt for lt in loc_titles)
            if not region_hit:
                # Check updates text
                region_hit = any(norm_region in u.text.lower() for u in incident.updates)
            if not region_hit:
                continue

        # 4. Filter by Lookback Window
        ref_time_str = incident.modified or incident.begin or incident.created
        if ref_time_str:
            try:
                dt = datetime.fromisoformat(ref_time_str.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt < cutoff_dt:
                    continue
            except Exception:
                pass

        incidents.append(incident)

    return incidents


def audit_cloud_service_status(
    service_name: str = "Google SecOps",
    region: Optional[str] = None,
    lookback_days: int = 14,
) -> CloudStatusReport:
    """Generates a comprehensive availability report for Google SecOps cloud services.

    Args:
        service_name: Product name to filter (default: 'Google SecOps').
        region: Optional cloud region filter (e.g. 'europe-west3', 'us').
        lookback_days: Time window for recent resolved incidents.

    Returns:
        Structured CloudStatusReport dataclass.
    """
    all_incidents = fetch_security_incidents(
        service_name=service_name,
        only_active=False,
        region=region,
        lookback_days=lookback_days,
    )

    active_incidents = [i for i in all_incidents if i.is_active]
    recent_resolved = [i for i in all_incidents if not i.is_active]

    # Evaluate health state
    overall_health = "HEALTHY"
    status_summary = f"All {service_name} services operating normally."

    if active_incidents:
        severities = {i.severity.lower() for i in active_incidents}
        impacts = {i.status_impact.upper() for i in active_incidents}

        if "high" in severities or "SERVICE_OUTAGE" in impacts:
            overall_health = "OUTAGE"
            status_summary = (
                f"Critical outage affecting {service_name}: {len(active_incidents)} active disruption(s)."
            )
        elif "SERVICE_DISRUPTION" in impacts or "medium" in severities:
            overall_health = "DEGRADED"
            status_summary = (
                f"Service degradation affecting {service_name}: {len(active_incidents)} active incident(s)."
            )
        else:
            overall_health = "ADVISORY"
            status_summary = (
                f"Informational advisory on {service_name}: {len(active_incidents)} active advisory item(s)."
            )

    return CloudStatusReport(
        as_of=datetime.now(timezone.utc).isoformat(),
        total_incidents=len(all_incidents),
        active_incidents=active_incidents,
        recent_resolved=recent_resolved,
        status_summary=status_summary,
        overall_health=overall_health,
    )


def correlate_incident_with_telemetry(
    incident_id: str,
    engine: Optional[Any] = None,
) -> Dict[str, Any]:
    """Cross-references a Google Cloud Status incident with tenant telemetry and forwarder latency.

    Args:
        incident_id: The unique incident identifier (e.g. 'XAZXzkY1Yg2GwXWnFw6M').
        engine: Optional SecOpsEngine facade instance.

    Returns:
        Correlation assessment mapping incident symptoms to potential internal impact.
    """
    all_incidents = fetch_security_incidents(service_name=None, only_active=False, lookback_days=90)
    target = next((i for i in all_incidents if i.id == incident_id), None)

    if not target:
        return {
            "incident_id": incident_id,
            "status": "NOT_FOUND",
            "message": f"Incident '{incident_id}' not found in Google Cloud Security Status feed.",
        }

    affected_regions = [loc.id for loc in (target.currently_affected_locations + target.previously_affected_locations)]
    recommendation = "No local action required; monitor Google Cloud Status dashboard for updates."

    if target.is_active:
        if "ingestion" in target.external_desc.lower() or "delays" in target.external_desc.lower():
            recommendation = (
                f"Ingestion delays in {affected_regions or 'affected regions'}. Forwarders and pipelines "
                "will safely queue logs. Suppress pipeline drop alerts and do not restart forwarders."
            )
        elif "sync" in target.external_desc.lower() or "case" in target.external_desc.lower():
            recommendation = (
                "Case linkage synchronization is degraded upstream. Alert triage and case wall updates "
                "may experience UI lag. Underlying raw event ingestion is unaffected."
            )
        elif "detection" in target.external_desc.lower() or "latency" in target.external_desc.lower():
            recommendation = (
                "Detection rule evaluation latency observed. Rules are running behind real-time. "
                "Detections will backfill once Google Cloud engineering mitigation completes."
            )

    return {
        "incident_id": target.id,
        "is_active": target.is_active,
        "status_impact": target.status_impact,
        "severity": target.severity,
        "external_desc": target.external_desc,
        "affected_regions": affected_regions,
        "public_url": target.public_url,
        "correlated_recommendation": recommendation,
        "most_recent_update": target.most_recent_update.to_dict() if target.most_recent_update else None,
    }
