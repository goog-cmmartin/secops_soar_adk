# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import annotations

"""Google SecOps Log Cost & FinOps Optimization Workflows.

Analyzes raw ingestion telemetry from Chronicle's native ingestion namespace,
computes binary and decimal log volume sizing, isolates bloated log types,
projects monthly spend across Google SecOps subscription tiers, and formulates
strategic FinOps recommendations for upstream drop filters and micro-tuning.
"""

from datetime import datetime, timezone
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    FinOpsRecommendation,
    LogCostAnalysisReport,
    LogPricingTier,
    LogTypeCostMetric,
    Provenance,
)

logger = logging.getLogger(__name__)

# Chronicle native ingestion telemetry aggregation query
INGESTION_TELEMETRY_QUERY = """
$log_type = ingestion.log_type
match:
  $log_type
outcome:
  $lc = sum(ingestion.log_count)
  $lv = sum(ingestion.log_volume)
"""

DEFAULT_BLOAT_THRESHOLD_BYTES = 2048  # 2 KB per event


class AnalyzeLogCostWorkflow:
    """Executes ingestion telemetry analysis, multi-tier pricing, and FinOps evaluation."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        self.store = store

    def execute(
        self,
        lookback_days: int = 7,
        pricing_tier: str = "ENTERPRISE",
        bloat_threshold_bytes: int = DEFAULT_BLOAT_THRESHOLD_BYTES,
    ) -> LogCostAnalysisReport:
        """Executes ingestion telemetry query and computes complete FinOps report."""
        effective_days = max(1, lookback_days)
        tier_enum = getattr(LogPricingTier, pricing_tier.strip().upper(), LogPricingTier.ENTERPRISE)

        # 1. Execute live telemetry query against Chronicle ingestion namespace
        res = self.adapter.execute_dashboard_query(
            query_text=INGESTION_TELEMETRY_QUERY,
            time_unit="DAY",
            time_value=str(effective_days),
        )

        metrics: List[LogTypeCostMetric] = []
        total_events = 0
        total_bytes = 0

        # Parse rows
        for row in res.rows:
            lt = str(row.get("log_type") or "").strip()
            if not lt:
                continue

            lc_str = row.get("lc") or "0"
            lv_str = row.get("lv") or "0"
            try:
                c_events = int(lc_str)
                c_bytes = int(lv_str)
            except (ValueError, TypeError):
                c_events = 0
                c_bytes = 0

            total_events += c_events
            total_bytes += c_bytes

            # Sizing conversions
            gb_dec = float(c_bytes) / 1_000_000_000.0
            gib_bin = float(c_bytes) / 1_073_741_824.0
            avg_size = (float(c_bytes) / float(c_events)) if c_events > 0 else 0.0
            is_bloated = (avg_size > bloat_threshold_bytes) and (c_events > 100)

            # Pricing: scaled to 30-day projection
            # Monthly Projected Volume = (GB in period / days) * 30
            monthly_gb = (gb_dec / effective_days) * 30.0
            cost_std = monthly_gb * LogPricingTier.STANDARD.rate_per_gb
            cost_ent = monthly_gb * LogPricingTier.ENTERPRISE.rate_per_gb
            cost_plus = monthly_gb * LogPricingTier.ENTERPRISE_PLUS.rate_per_gb

            metrics.append(
                LogTypeCostMetric(
                    log_type=lt,
                    event_count=c_events,
                    volume_bytes=c_bytes,
                    volume_gb_decimal=gb_dec,
                    volume_gib_binary=gib_bin,
                    avg_event_size_bytes=avg_size,
                    is_bloated=is_bloated,
                    cost_standard=cost_std,
                    cost_enterprise=cost_ent,
                    cost_enterprise_plus=cost_plus,
                )
            )

        # Calculate percentages of total volume
        for m in metrics:
            if total_bytes > 0:
                m.pct_total_volume = (float(m.volume_bytes) / float(total_bytes)) * 100.0

        # Rank metrics descending by volume
        metrics.sort(key=lambda x: x.volume_bytes, reverse=True)

        total_gb = float(total_bytes) / 1_000_000_000.0
        total_gib = float(total_bytes) / 1_073_741_824.0
        monthly_total_gb = (total_gb / effective_days) * 30.0

        total_spend_std = monthly_total_gb * LogPricingTier.STANDARD.rate_per_gb
        total_spend_ent = monthly_total_gb * LogPricingTier.ENTERPRISE.rate_per_gb
        total_spend_plus = monthly_total_gb * LogPricingTier.ENTERPRISE_PLUS.rate_per_gb

        top_drivers = metrics[:10]
        bloated_sources = [m for m in metrics if m.is_bloated]

        # 2. Formulate FinOps recommendations
        recommendations = self._generate_finops_recommendations(
            metrics=metrics,
            effective_days=effective_days,
            tier_rate=tier_enum.rate_per_gb,
        )

        total_potential_savings = sum(r.potential_monthly_savings_usd for r in recommendations)

        provenance = Provenance(
            source="dashboardQueries:execute",
            timestamp=datetime.now(timezone.utc).isoformat(),
            details={
                "endpoint_or_query": INGESTION_TELEMETRY_QUERY.strip(),
                "total_events": total_events,
                "total_bytes": total_bytes,
                "log_types": len(metrics),
            },
        )

        report = LogCostAnalysisReport(
            lookback_window=f"{effective_days}d",
            pricing_tier=tier_enum.value,
            total_events=total_events,
            total_volume_bytes=total_bytes,
            total_volume_gb=total_gb,
            total_volume_gib=total_gib,
            total_projected_monthly_spend_standard=total_spend_std,
            total_projected_monthly_spend_enterprise=total_spend_ent,
            total_projected_monthly_spend_enterprise_plus=total_spend_plus,
            metrics_by_log_type=metrics,
            top_volume_drivers=top_drivers,
            bloated_sources=bloated_sources,
            recommendations=recommendations,
            total_potential_savings_usd=total_potential_savings,
            generated_at=datetime.now(timezone.utc),
            provenance=provenance,
        )

        # 3. Persist to Evidence Fabric Store if available
        if self.store is not None and hasattr(self.store, "save_log_cost_analysis"):
            try:
                self.store.save_log_cost_analysis(report.to_dict())
            except Exception as e:
                logger.warning("Could not persist log cost analysis to store: %s", e)

        return report

    def _generate_finops_recommendations(
        self,
        metrics: List[LogTypeCostMetric],
        effective_days: int,
        tier_rate: float,
    ) -> List[FinOpsRecommendation]:
        """Synthesizes actionable, data-driven FinOps recommendations."""
        recs: List[FinOpsRecommendation] = []
        metrics_by_name = {m.log_type.upper(): m for m in metrics}

        # 1. Cloud Audit Log Noise Pruning (Read-only Data Access & Automated Service Accounts)
        audit_types = ["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_ACTIVITY"]
        for at in audit_types:
            for m_key, m in metrics_by_name.items():
                if at in m_key and m.volume_gb_decimal > 5.0:
                    monthly_gb = (m.volume_gb_decimal / effective_days) * 30.0
                    # Estimated 25% reduction by pruning high-frequency read-only Data Access operations
                    est_savings_gb = monthly_gb * 0.25
                    est_savings_usd = est_savings_gb * tier_rate
                    recs.append(
                        FinOpsRecommendation(
                            log_type=m.log_type,
                            category="UPSTREAM_DROP_FILTER",
                            title=f"Prune High-Volume Read-Only Data Access Noise on {m.log_type}",
                            description=(
                                f"{m.log_type} accounts for {m.volume_gb_decimal:.1f} GB ({m.pct_total_volume:.1f}% of tenant volume). "
                                "High-frequency benign read-only Data Access operations (e.g. storage.objects.get, bigquery getQueryResults) "
                                "and automated machine service accounts create extreme volume overhead with negligible threat detection value."
                            ),
                            potential_volume_savings_gb=est_savings_gb,
                            potential_monthly_savings_usd=est_savings_usd,
                            implementation_guidance=(
                                "In Google Cloud Log Router, configure exclusion filters on the sink forwarding to Chronicle:\n"
                                'protoPayload.methodName = "storage.objects.get" OR '
                                '(protoPayload.serviceName = "bigquery.googleapis.com" AND protoPayload.methodName = "bigquery.jobs.getQueryResults")'
                            ),
                        )
                    )
                    break

        # 2. Cloud Load Balancing Health Check Noise (GoogleHC / kube-probe / static CDN traffic)
        lb_types = ["GCP_LOADBALANCING", "LOADBALANCER", "LOAD_BALANCER", "ALB", "ELB"]
        for lt in lb_types:
            for m_key, m in metrics_by_name.items():
                if lt in m_key and m.volume_gb_decimal > 2.0:
                    monthly_gb = (m.volume_gb_decimal / effective_days) * 30.0
                    # Estimated 35% reduction by dropping synthetic health check probes and CDN static hits
                    est_savings_gb = monthly_gb * 0.35
                    est_savings_usd = est_savings_gb * tier_rate
                    recs.append(
                        FinOpsRecommendation(
                            log_type=m.log_type,
                            category="UPSTREAM_DROP_FILTER",
                            title=f"Filter Synthetic Health Check Probes and CDN Static Requests on {m.log_type}",
                            description=(
                                f"{m.log_type} accounts for {m.volume_gb_decimal:.1f} GB ({m.pct_total_volume:.1f}% of tenant volume). "
                                "Automated synthetic health check probes (GoogleHC/*, kube-probe/*) and HTTP 200 CDN static checks represent "
                                "over a third of total load balancer events."
                            ),
                            potential_volume_savings_gb=est_savings_gb,
                            potential_monthly_savings_usd=est_savings_usd,
                            implementation_guidance=(
                                "In Google Cloud Log Router, configure exclusion filters on the sink forwarding to Chronicle:\n"
                                'httpRequest.userAgent =~ "^GoogleHC" OR httpRequest.userAgent =~ "^kube-probe" OR '
                                '(httpRequest.status = 200 AND httpRequest.requestUrl =~ "\\.(css|js|png|ico|woff)$")'
                            ),
                        )
                    )
                    break

        # 3. Windows Event Log Drop Filter (Event ID 4663 / 4624 micro-tuning)
        win_types = ["WINEVTLOG", "MICROSOFT_WINDOWS_SECURITY", "WINDOWS_SECURITY"]
        for wt in win_types:
            if wt in metrics_by_name:
                m = metrics_by_name[wt]
                monthly_gb = (m.volume_gb_decimal / effective_days) * 30.0
                # Estimated 35% reduction by pruning WinEvent 4663 noise and machine account logon spam
                est_savings_gb = monthly_gb * 0.35
                est_savings_usd = est_savings_gb * tier_rate
                recs.append(
                    FinOpsRecommendation(
                        log_type=m.log_type,
                        category="UPSTREAM_DROP_FILTER",
                        title="Filter Windows File Access Noise (4663) and Automated Machine Logons",
                        description=(
                            f"Windows Security events represent {m.volume_gb_decimal:.1f} GB ({m.pct_total_volume:.1f}% of tenant volume). "
                            "Filtering high-frequency benign Event ID 4663 (file access attempts) and micro-filtering Event ID 4624 "
                            "(Type 3 network logons from machine accounts ending in '$') can reduce volume by ~35% without impacting detection."
                        ),
                        potential_volume_savings_gb=est_savings_gb,
                        potential_monthly_savings_usd=est_savings_usd,
                        implementation_guidance=(
                            "Deploy an XPath query filter on Windows Forwarders / BindPlane Agent:\n"
                            "<QueryList><Query Id='0'><Select Path='Security'>*</Select>"
                            "<Suppress Path='Security'>*[System[(EventID=4663)]]</Suppress></Query></QueryList>"
                        ),
                    )
                )
                break

        # 2. Web Proxy Noise Pruning (Static assets and CDN health checks)
        proxy_types = ["ZSCALER", "BLUECOAT", "PAN_URL", "SQUID", "APACHE", "NGINX"]
        for pt in proxy_types:
            for m_key, m in metrics_by_name.items():
                if pt in m_key:
                    monthly_gb = (m.volume_gb_decimal / effective_days) * 30.0
                    # Estimated 25% reduction by dropping GET requests for static assets
                    est_savings_gb = monthly_gb * 0.25
                    est_savings_usd = est_savings_gb * tier_rate
                    recs.append(
                        FinOpsRecommendation(
                            log_type=m.log_type,
                            category="PROXY_NOISE_PRUNING",
                            title=f"Prune Static Web Asset Telemetry on {m.log_type}",
                            description=(
                                f"{m.log_type} accounts for {m.volume_gb_decimal:.1f} GB. HTTP 200 responses for static assets "
                                "(.css, .jpg, .png, .woff, .svg) and automated health check pings provide minimal security value."
                            ),
                            potential_volume_savings_gb=est_savings_gb,
                            potential_monthly_savings_usd=est_savings_usd,
                            implementation_guidance=(
                                "Configure log forwarder or proxy export policy to drop HTTP 200 responses matching file extensions: "
                                "\\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|svg)$"
                            ),
                        )
                    )
                    break

        # 3. Network Flow & VPC Flow Sampling
        flow_types = ["FLOW", "GCP_VPC_FLOW", "NETFLOW", "ZEEK", "PAN_TRAFFIC"]
        for ft in flow_types:
            for m_key, m in metrics_by_name.items():
                if ft in m_key and m.volume_gb_decimal > 1.0:
                    monthly_gb = (m.volume_gb_decimal / effective_days) * 30.0
                    # Estimated 40% reduction through sampling ephemeral connections
                    est_savings_gb = monthly_gb * 0.40
                    est_savings_usd = est_savings_gb * tier_rate
                    recs.append(
                        FinOpsRecommendation(
                            log_type=m.log_type,
                            category="SAMPLING_AGGREGATION",
                            title=f"Sample High-Volume Intra-VPC Ephemeral Connections on {m.log_type}",
                            description=(
                                f"{m.log_type} generates {m.volume_gb_decimal:.1f} GB. Intra-subnet ephemeral flows between internal "
                                "workloads create severe volume bloat with minimal perimeter threat visibility."
                            ),
                            potential_volume_savings_gb=est_savings_gb,
                            potential_monthly_savings_usd=est_savings_usd,
                            implementation_guidance=(
                                "Apply VPC flow log sampling rate (e.g. 0.25 or 0.10) for internal RFC 1918 to RFC 1918 traffic, "
                                "or filter broadcast/multicast ports (5353, 1900) at the subnet level."
                            ),
                        )
                    )
                    break

        # 4. Bloated Event Normalization
        for m in metrics:
            if m.is_bloated and m.volume_gb_decimal > 0.5:
                # If not already covered by specific recommendations
                if not any(r.log_type == m.log_type for r in recs):
                    monthly_gb = (m.volume_gb_decimal / effective_days) * 30.0
                    est_savings_gb = monthly_gb * 0.20
                    est_savings_usd = est_savings_gb * tier_rate
                    recs.append(
                        FinOpsRecommendation(
                            log_type=m.log_type,
                            category="PARSER_NORMALIZATION",
                            title=f"Truncate or Normalize Bloated Event Payloads in {m.log_type}",
                            description=(
                                f"{m.log_type} has an unusually high average event size of {m.avg_event_size_bytes:.0f} bytes/event "
                                f"(exceeding standard {DEFAULT_BLOAT_THRESHOLD_BYTES} byte threshold). Raw stack traces, embedded JSON, "
                                "or debugging blobs are likely being ingested unparsed."
                            ),
                            potential_volume_savings_gb=est_savings_gb,
                            potential_monthly_savings_usd=est_savings_usd,
                            implementation_guidance=(
                                "Configure parser extension or forwarder processor to strip debug fields, stack traces, and verbose payload attributes "
                                "before transmission to Chronicle."
                            ),
                        )
                    )

        # Sort recommendations by highest potential savings descending
        recs.sort(key=lambda x: x.potential_monthly_savings_usd, reverse=True)
        return recs


class GetLatestLogCostWorkflow:
    """Retrieves the latest cached or persisted Log Cost Analysis Report from Evidence Fabric."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        self.store = store

    def execute(self, fallback_if_empty: bool = True) -> Optional[Dict[str, Any]]:
        """Retrieves latest log cost report from store or triggers fresh analysis."""
        if self.store is not None and hasattr(self.store, "get_latest_log_cost_analysis"):
            latest = self.store.get_latest_log_cost_analysis()
            if latest:
                return latest

        if fallback_if_empty:
            wf = AnalyzeLogCostWorkflow(self.adapter, store=self.store)
            rep = wf.execute(lookback_days=7)
            return rep.to_dict()

        return None
