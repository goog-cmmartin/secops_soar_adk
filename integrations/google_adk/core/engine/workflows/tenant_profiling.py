"""Tenant Cartography & Telemetry Profiling Workflows.

Implements deep profiling of live Google SecOps tenant data using native GoogleSQL
pipe syntax to produce Attested Tenant Context:
- Identity Fidelity Density Matrix (events table)
- Entity Graph Lineage & Longevity (graph table)
- Ingestion Volume Pareto & Time Coverage (events table)

Invariants:
- Live data origin exclusively from live GoogleSecOpsAdapter.
- Zero synthetic data structures or fallbacks.
- Transparent error propagation and explicit bounds.
- Context-oriented: non-disruptive, does not open operational issues.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    EntityGraphSource,
    IdentityFidelityMetric,
    LogSourceVolumeMetric,
    TenantTelemetryProfile,
)


class TenantProfilingWorkflow:
    """Orchestrates GoogleSQL pipe queries against live events and graph tables to profile tenant telemetry."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def get_identity_fidelity(self, days: int = 7, limit: int = 50) -> List[IdentityFidelityMetric]:
        """Profiles the population density of distinct user identity keys across all active log types."""
        query = f"""
FROM events
|> WHERE TIMESTAMP_SECONDS(metadata.event_timestamp.seconds) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {int(days)} DAY)
|> AGGREGATE
     COUNT(DISTINCT NULLIF(principal.user.userid, '')) AS principal_user_id,
     COUNT(DISTINCT NULLIF(ARRAY_TO_STRING(principal.user.email_addresses, ','), '')) AS principal_user_email_address,
     COUNT(DISTINCT NULLIF(principal.user.windows_sid, '')) AS principal_user_windows_sid,
     COUNT(DISTINCT NULLIF(principal.user.product_object_id, '')) AS principal_user_product_object_id,
     COUNT(DISTINCT NULLIF(target.user.userid, '')) AS target_user_id,
     COUNT(DISTINCT NULLIF(ARRAY_TO_STRING(target.user.email_addresses, ','), '')) AS target_user_email_address,
     COUNT(DISTINCT NULLIF(target.user.windows_sid, '')) AS target_user_windows_sid,
     COUNT(DISTINCT NULLIF(target.user.product_object_id, '')) AS target_user_product_object_id
   GROUP BY UPPER(metadata.log_type) AS log_type
|> ORDER BY principal_user_id DESC
|> LIMIT {int(limit)}
"""
        res = self.adapter.execute_dashboard_query(
            query_text=query.strip(),
            dialect="SQL",
            time_unit="DAY",
            time_value=str(days),
        )
        return [IdentityFidelityMetric.from_dict(row) for row in res.rows]

    def get_entity_graph_lineage(self, days: int = 7, limit: int = 50) -> List[EntityGraphSource]:
        """Profiles the provenance, vendors, products, and longevity of entity graph bindings."""
        query = f"""
FROM graph
LEFT JOIN UNNEST(metadata.event_metadata.base_labels.log_types) AS log_type
|> AGGREGATE
     COUNT(metadata.product_entity_id) AS total,
     DATE(TIMESTAMP_SECONDS(MIN(metadata.collected_timestamp.seconds))) AS first_seen,
     DATE(TIMESTAMP_SECONDS(MAX(metadata.collected_timestamp.seconds))) AS last_seen
   GROUP BY
     UPPER(COALESCE(log_type, 'UNKNOWN')) AS log_type,
     metadata.source_type AS entity_source,
     metadata.vendor_name,
     metadata.product_name
|> ORDER BY total DESC
|> LIMIT {int(limit)}
"""
        res = self.adapter.execute_dashboard_query(
            query_text=query.strip(),
            dialect="SQL",
            time_unit="DAY",
            time_value=str(days),
        )
        return [EntityGraphSource.from_dict(row) for row in res.rows]

    def get_log_source_volume_pareto(self, days: int = 7, limit: int = 50) -> List[LogSourceVolumeMetric]:
        """Profiles total event volume and ingestion temporal bounds per log source."""
        query = f"""
FROM events
|> WHERE TIMESTAMP_SECONDS(metadata.event_timestamp.seconds) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {int(days)} DAY)
|> AGGREGATE
     COUNT(1) AS event_count,
     DATE(TIMESTAMP_SECONDS(MIN(metadata.event_timestamp.seconds))) AS earliest_event,
     DATE(TIMESTAMP_SECONDS(MAX(metadata.event_timestamp.seconds))) AS latest_event
   GROUP BY UPPER(metadata.log_type) AS log_type
|> ORDER BY event_count DESC
|> LIMIT {int(limit)}
"""
        res = self.adapter.execute_dashboard_query(
            query_text=query.strip(),
            dialect="SQL",
            time_unit="DAY",
            time_value=str(days),
        )
        return [LogSourceVolumeMetric.from_dict(row) for row in res.rows]

    def generate_tenant_telemetry_profile(self, days: int = 7, limit: int = 50) -> TenantTelemetryProfile:
        """Executes full tenant survey and synthesizes a TenantTelemetryProfile."""
        identity_metrics = self.get_identity_fidelity(days=days, limit=limit)
        graph_sources = self.get_entity_graph_lineage(days=days, limit=limit)
        volume_metrics = self.get_log_source_volume_pareto(days=days, limit=limit)

        total_events = sum(v.event_count for v in volume_metrics)
        total_entities = sum(g.total_entities for g in graph_sources)

        summary = (
            f"Surveyed {len(volume_metrics)} log sources representing {total_events:,} events over {days}d. "
            f"Discovered {len(graph_sources)} entity graph sources covering {total_entities:,} entities. "
            f"Top identity log source: {identity_metrics[0].log_type if identity_metrics else 'None'}."
        )

        return TenantTelemetryProfile(
            profiled_at=datetime.now(timezone.utc).isoformat(),
            observation_window_days=days,
            identity_metrics=identity_metrics,
            graph_sources=graph_sources,
            volume_metrics=volume_metrics,
            total_events_observed=total_events,
            total_graph_entities_observed=total_entities,
            summary=summary,
        )

    def export_attested_computation_markdown(
        self, profile: TenantTelemetryProfile, output_path: Optional[str] = None
    ) -> str:
        """Formats the profile as an Open Knowledge Format (OKF v0.2) Attested Computation document."""
        profile_json = str(profile.to_dict())
        durability_hash = hashlib.sha256(profile_json.encode("utf-8")).hexdigest()[:16]

        lines = [
            "---",
            "id: computation.tenant_telemetry_profile",
            "type: computation",
            "title: Live Tenant Telemetry & Identity Cartography Profile",
            "status: stable",
            "runtime: python",
            "parameters:",
            "  - name: days",
            "    type: integer",
            "    required: false",
            "executor:",
            "  resource: knowledge/tasks/platform_engineer/audit_tenant_configuration_posture.md",
            "  receipt: [query_text, executed_time_range, result_rows]",
            "attester:",
            "  resource: knowledge/attesters/yaral_equality.py",
            f"generated: {{ by: 'agent/tenant-cartographer', at: '{profile.profiled_at}' }}",
            "verified:",
            f"  - {{ by: 'process:secops-engine', at: '{profile.profiled_at}' }}",
            "stale_after: '2027-09-24T19:50:00Z'",
            f"durability_hash: '{durability_hash}'",
            "tags:",
            "  - tenant-profile",
            "  - cartography",
            "  - udm",
            "  - identity-matrix",
            "---",
            "",
            "# Live Tenant Telemetry & Identity Cartography Profile",
            "",
            f"> **Executive Summary**: {profile.summary}",
            f"> **Attested At**: `{profile.profiled_at}` &bull; **Observation Window**: {profile.observation_window_days} Days",
            "",
            "---",
            "",
            "## 1. Top Identity Providers & Graph Sources (`graph` table)",
            "",
            "| Log Type | Source Type | Vendor | Product | Total Entities | First Seen | Last Seen |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for g in profile.graph_sources[:15]:
            lines.append(
                f"| `{g.log_type}` | {g.entity_source} | {g.vendor_name or '-'} | {g.product_name or '-'} | {g.total_entities:,} | {g.first_seen or '-'} | {g.last_seen or '-'} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 2. UDM Identity Fidelity Density Matrix (`events` table)",
            "",
            "Distinct population counts for principal and target user keys across active telemetry sources:",
            "",
            "| Log Type | Principal User ID | Principal Email | Principal SID | Principal Obj ID | Target User ID | Target Email | Target SID | Target Obj ID |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for i in profile.identity_metrics[:20]:
            lines.append(
                f"| `{i.log_type}` | {i.principal_user_id:,} | {i.principal_user_email_address:,} | {i.principal_user_windows_sid:,} | {i.principal_user_product_object_id:,} | {i.target_user_id:,} | {i.target_user_email_address:,} | {i.target_user_windows_sid:,} | {i.target_user_product_object_id:,} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Telemetry Volume & Temporal Ingestion Pareto (`events` table)",
            "",
            "| Rank | Log Type | Event Count | Ingestion Start | Ingestion End |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        for idx, v in enumerate(profile.volume_metrics[:20]):
            lines.append(
                f"| {idx + 1} | `{v.log_type}` | {v.event_count:,} | {v.earliest_event or '-'} | {v.latest_event or '-'} |"
            )

        lines.append("")
        content = "\n".join(lines)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

        return content
