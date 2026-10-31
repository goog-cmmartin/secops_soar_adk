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

"""Google SecOps Ingestion Label & Namespace Hygiene Workflows.

Audits active Ingestion Labels, UDM Namespaces, default untagged telemetry,
and cross-references them with Data RBAC Scopes and Data Access Labels.

Operational Invariants:
1. Ingestion Labels are arbitrary and not centrally defined; when used, they
   must be applied consistently across log types. Some labels are injected
   automatically (e.g., gcp_organization_id on GCP_CLOUDAUDIT).
2. Namespaces are optional; telemetry without a namespace defaults to the
   untagged default namespace (not displayed in the UI). Namespaces exist to
   disambiguate overlapping IP address ranges (RFC 1918) across separate sites/VPCs.
3. Data RBAC depends strictly on consistent and accurate labeling and namespacing;
   hygiene gaps directly degrade data access isolation.
"""

from datetime import datetime, timezone
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    DataRbacLabelReference,
    IngestionLabelMetric,
    NamespaceLabelAnalysisReport,
    NamespaceLabelHygieneFinding,
    NamespaceMetric,
    Provenance,
    UntaggedTelemetrySummary,
)
from engine.workflows.data_rbac import (
    SearchDataAccessLabelsWorkflow,
    SearchDataAccessScopesWorkflow,
)

logger = logging.getLogger(__name__)

# Native Chronicle GoogleSQL queries against events table
INGESTION_LABELS_QUERY = """
SELECT
  label.key AS ingestion_label_key,
  ARRAY_AGG(DISTINCT metadata.log_type) AS log_types,
  COUNT(1) AS event_count
FROM events,
UNNEST(metadata.ingestion_labels) AS label
WHERE
  NULLIF(label.key, '') IS NOT NULL
GROUP BY 1
ORDER BY event_count DESC
"""

NAMESPACES_QUERY = """
SELECT
  namespace,
  ARRAY_AGG(DISTINCT metadata.log_type) AS log_types,
  COUNT(1) AS event_count
FROM events,
UNNEST(metadata.base_labels.namespaces) AS namespace
WHERE
  NULLIF(namespace, '') IS NOT NULL
GROUP BY 1
ORDER BY event_count DESC
"""

UNTAGGED_NAMESPACES_QUERY = """
SELECT
  metadata.log_type,
  COUNT(1) AS event_count
FROM events
WHERE ARRAY_LENGTH(metadata.base_labels.namespaces) = 0 OR metadata.base_labels.namespaces IS NULL
GROUP BY 1
ORDER BY event_count DESC
"""

UNLABELLED_INGESTION_QUERY = """
SELECT
  metadata.log_type,
  COUNT(1) AS event_count
FROM events
WHERE ARRAY_LENGTH(metadata.ingestion_labels) = 0 OR metadata.ingestion_labels IS NULL
GROUP BY 1
ORDER BY event_count DESC
"""

# Known automatic provider labels
AUTO_GENERATED_LABEL_PREFIXES = (
    "gcp_",
    "aws_",
    "azure_",
    "google_",
)

# Network-centric log types susceptible to RFC 1918 private IP collisions
RFC1918_SENSITIVE_LOG_TYPES = {
    "PAN_FIREWALL",
    "GCP_FIREWALL",
    "GCP_DNS",
    "GCP_VPC_FLOW",
    "ZSCALER_WEBPROXY",
    "SQUID_WEBPROXY",
    "BRO_JSON",
    "SURICATA_EVE",
    "INFOBLOX_DHCP",
    "WINDOWS_DHCP",
    "OPNSENSE",
    "CISCO_ASA_FIREWALL",
    "CHECKPOINT_FIREWALL",
    "FORTINET_FIREWALL",
    "KUBERNETES_NODE",
}

# Identity & compliance sensitive log types requiring strict Data RBAC coverage
SENSITIVE_AUDIT_LOG_TYPES = {
    "GCP_CLOUDAUDIT",
    "WORKSPACE_ACTIVITY",
    "OKTA",
    "AZURE_AD",
    "CHRONICLE_SOAR_AUDIT",
    "AWS_CLOUDTRAIL",
}


def _is_auto_label(key: str) -> bool:
    """Classifies whether an ingestion label key is provider-injected."""
    lower_key = key.lower()
    return any(lower_key.startswith(pfx) for pfx in AUTO_GENERATED_LABEL_PREFIXES)


def _is_rfc1918_relevant(log_types: List[str]) -> bool:
    """Checks whether the log types include network telemetry prone to IP collision."""
    return any(lt in RFC1918_SENSITIVE_LOG_TYPES for lt in log_types)


class AnalyzeIngestionLabelsWorkflow:
    """Analyzes active ingestion labels and evaluates tagging consistency."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        self.store = store

    def execute(self, lookback_days: int = 7) -> List[IngestionLabelMetric]:
        """Runs GoogleSQL query for active Ingestion Labels."""
        effective_days = max(1, lookback_days)
        res = self.adapter.execute_dashboard_query(
            query_text=INGESTION_LABELS_QUERY,
            dialect="SQL",
            time_unit="DAY",
            time_value=str(effective_days),
        )

        metrics: List[IngestionLabelMetric] = []
        for row in res.rows:
            key = str(row.get("ingestion_label_key") or "").strip()
            if not key:
                continue
            raw_types = row.get("log_types")
            if isinstance(raw_types, list):
                log_types = [str(t).strip() for t in raw_types if t]
            elif isinstance(raw_types, str) and raw_types:
                log_types = [raw_types.strip()]
            else:
                log_types = []

            cnt_val = row.get("event_count")
            cnt = int(cnt_val) if cnt_val is not None else 0

            metrics.append(
                IngestionLabelMetric(
                    label_key=key,
                    log_types=sorted(log_types),
                    event_count=cnt,
                    is_auto_generated=_is_auto_label(key),
                )
            )

        return metrics


class AnalyzeNamespacesWorkflow:
    """Analyzes active UDM namespaces and flags network asset collision risks."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        self.store = store

    def execute(self, lookback_days: int = 7) -> List[NamespaceMetric]:
        """Runs GoogleSQL query for active Namespaces."""
        effective_days = max(1, lookback_days)
        res = self.adapter.execute_dashboard_query(
            query_text=NAMESPACES_QUERY,
            dialect="SQL",
            time_unit="DAY",
            time_value=str(effective_days),
        )

        metrics: List[NamespaceMetric] = []
        for row in res.rows:
            ns = str(row.get("namespace") or "").strip()
            if not ns:
                continue
            raw_types = row.get("log_types")
            if isinstance(raw_types, list):
                log_types = [str(t).strip() for t in raw_types if t]
            elif isinstance(raw_types, str) and raw_types:
                log_types = [raw_types.strip()]
            else:
                log_types = []

            cnt_val = row.get("event_count")
            cnt = int(cnt_val) if cnt_val is not None else 0

            metrics.append(
                NamespaceMetric(
                    namespace=ns,
                    log_types=sorted(log_types),
                    event_count=cnt,
                    is_network_rfc1918_relevant=_is_rfc1918_relevant(log_types),
                )
            )

        return metrics


class AuditDataRbacAlignmentWorkflow:
    """Cross-references Data Access Labels and Scopes against live telemetry tags."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        self.store = store

    def execute(
        self,
        active_label_keys: Optional[Set[str]] = None,
        active_namespaces: Optional[Set[str]] = None,
    ) -> List[DataRbacLabelReference]:
        """Audits all configured Data Access Labels for live telemetry backing."""
        label_wf = SearchDataAccessLabelsWorkflow(self.adapter)
        batch = label_wf.execute()

        if active_label_keys is None:
            lbl_wf = AnalyzeIngestionLabelsWorkflow(self.adapter, self.store)
            active_labels = {m.label_key for m in lbl_wf.execute()}
        else:
            active_labels = active_label_keys

        if active_namespaces is None:
            ns_wf = AnalyzeNamespacesWorkflow(self.adapter, self.store)
            active_ns = {m.namespace for m in ns_wf.execute()}
        else:
            active_ns = active_namespaces

        references: List[DataRbacLabelReference] = []

        # Regex patterns to isolate label keys and namespaces in UDM filter expressions
        label_pattern = re.compile(
            r'metadata\.ingestion_labels(?:\["([^"]+)"\]|\.([a-zA-Z0-9_]+))',
            re.IGNORECASE,
        )
        namespace_pattern = re.compile(
            r'(?:metadata\.base_labels\.namespaces|namespace)\s*=\s*"([^"]+)"',
            re.IGNORECASE,
        )

        for item in batch.labels:
            query = item.udm_query or ""
            extracted_labels: List[str] = []
            for match in label_pattern.finditer(query):
                key = match.group(1) or match.group(2)
                if key and key not in extracted_labels:
                    extracted_labels.append(key)

            extracted_namespaces: List[str] = []
            for match in namespace_pattern.finditer(query):
                ns_val = match.group(1)
                if ns_val and ns_val not in extracted_namespaces:
                    extracted_namespaces.append(ns_val)

            # Determine telemetry backing
            has_label_refs = len(extracted_labels) > 0
            has_ns_refs = len(extracted_namespaces) > 0

            if not has_label_refs and not has_ns_refs:
                # Query filters on something else (e.g. hostname, event_type)
                status = "ACTIVE_MATCH"
                is_backed = True
            else:
                label_backed = all(lbl in active_labels for lbl in extracted_labels) if has_label_refs else True
                ns_backed = all(ns in active_ns for ns in extracted_namespaces) if has_ns_refs else True
                is_backed = label_backed and ns_backed
                status = "ACTIVE_MATCH" if is_backed else "UNREFERENCED_IN_TELEMETRY"

            references.append(
                DataRbacLabelReference(
                    label_id=item.id,
                    display_name=item.display_name,
                    udm_query=query,
                    extracted_label_keys=extracted_labels,
                    extracted_namespaces=extracted_namespaces,
                    is_telemetry_backed=is_backed,
                    status=status,
                )
            )

        return references


class AnalyzeNamespaceLabelsCompositeWorkflow:
    """Holistic workflow uniting ingestion labels, namespaces, and Data RBAC alignment."""

    def __init__(self, adapter: GoogleSecOpsAdapter, store: Any = None):
        self.adapter = adapter
        self.store = store

    def execute(self, lookback_days: int = 7) -> NamespaceLabelAnalysisReport:
        """Executes full audit pipeline and produces unified hygiene findings."""
        effective_days = max(1, lookback_days)

        # 1. Active Ingestion Labels
        label_wf = AnalyzeIngestionLabelsWorkflow(self.adapter, self.store)
        label_metrics = label_wf.execute(lookback_days=effective_days)
        active_label_keys = {m.label_key for m in label_metrics}
        total_labelled_events = sum(m.event_count for m in label_metrics)

        # 2. Active Namespaces
        ns_wf = AnalyzeNamespacesWorkflow(self.adapter, self.store)
        namespace_metrics = ns_wf.execute(lookback_days=effective_days)
        active_namespaces = {m.namespace for m in namespace_metrics}
        total_namespaced_events = sum(m.event_count for m in namespace_metrics)

        # 3. Untagged Telemetry (Default Namespace & Unlabelled events)
        untagged_map: Dict[str, UntaggedTelemetrySummary] = {}
        try:
            ns_untagged_res = self.adapter.execute_dashboard_query(
                query_text=UNTAGGED_NAMESPACES_QUERY,
                dialect="SQL",
                time_unit="DAY",
                time_value=str(effective_days),
            )
            for row in ns_untagged_res.rows:
                lt = str(row.get("log_type") or "").strip()
                if not lt:
                    continue
                cnt_val = row.get("event_count")
                cnt = int(cnt_val) if cnt_val is not None else 0
                if lt not in untagged_map:
                    untagged_map[lt] = UntaggedTelemetrySummary(log_type=lt)
                untagged_map[lt].untagged_namespace_event_count = cnt
        except Exception as e:
            logger.warning("Failed executing untagged namespaces query: %s", e)

        try:
            lbl_untagged_res = self.adapter.execute_dashboard_query(
                query_text=UNLABELLED_INGESTION_QUERY,
                dialect="SQL",
                time_unit="DAY",
                time_value=str(effective_days),
            )
            for row in lbl_untagged_res.rows:
                lt = str(row.get("log_type") or "").strip()
                if not lt:
                    continue
                cnt_val = row.get("event_count")
                cnt = int(cnt_val) if cnt_val is not None else 0
                if lt not in untagged_map:
                    untagged_map[lt] = UntaggedTelemetrySummary(log_type=lt)
                untagged_map[lt].unlabelled_event_count = cnt
        except Exception as e:
            logger.warning("Failed executing unlabelled ingestion query: %s", e)

        untagged_summaries = sorted(
            untagged_map.values(),
            key=lambda u: max(u.untagged_namespace_event_count, u.unlabelled_event_count),
            reverse=True,
        )
        total_untagged = sum(u.untagged_namespace_event_count for u in untagged_summaries)

        # 4. Data RBAC Alignment
        rbac_wf = AuditDataRbacAlignmentWorkflow(self.adapter, self.store)
        rbac_refs = rbac_wf.execute(
            active_label_keys=active_label_keys,
            active_namespaces=active_namespaces,
        )

        # 5. Formulate Hygiene Findings
        findings: List[NamespaceLabelHygieneFinding] = []

        # Check for unreferenced Data RBAC labels
        unreferenced_rbac = [r for r in rbac_refs if r.status == "UNREFERENCED_IN_TELEMETRY"]
        for r in unreferenced_rbac:
            missing_parts = []
            if r.extracted_label_keys:
                missing_labels = [k for k in r.extracted_label_keys if k not in active_label_keys]
                if missing_labels:
                    missing_parts.append(f"labels: {missing_labels}")
            if r.extracted_namespaces:
                missing_ns = [ns for ns in r.extracted_namespaces if ns not in active_namespaces]
                if missing_ns:
                    missing_parts.append(f"namespaces: {missing_ns}")

            findings.append(
                NamespaceLabelHygieneFinding(
                    finding_id=f"FINDING-RBAC-UNREFERENCED-{r.label_id}",
                    category="DATA_RBAC_GAP",
                    severity="HIGH",
                    title=f"Data Access Label '{r.display_name}' references absent telemetry tags",
                    description=(
                        f"Data RBAC Label '{r.label_id}' contains UDM expression '{r.udm_query}' "
                        f"referencing tags not observed in telemetry ({', '.join(missing_parts)}). "
                        "Users governed by this label may experience broken access boundaries."
                    ),
                    remediation_guidance=(
                        "Verify upstream collector and ingestion feed tag configurations, "
                        "or update Data Access Label query syntax in Google SecOps settings."
                    ),
                )
            )

        # Check for RFC 1918 overlap risks in untagged default namespace
        rfc1918_untagged = [
            u for u in untagged_summaries
            if u.log_type in RFC1918_SENSITIVE_LOG_TYPES and u.untagged_namespace_event_count > 10000
        ]
        if rfc1918_untagged:
            affected_types = [u.log_type for u in rfc1918_untagged]
            total_vol = sum(u.untagged_namespace_event_count for u in rfc1918_untagged)
            findings.append(
                NamespaceLabelHygieneFinding(
                    finding_id="FINDING-RFC1918-UNTAGGED-COLLISION-RISK",
                    category="RFC1918_OVERLAP_RISK",
                    severity="HIGH",
                    title="High-volume network telemetry in default untagged namespace",
                    description=(
                        f"Observed {total_vol:,} network events across {len(affected_types)} log types "
                        f"({', '.join(affected_types[:5])}) residing in the untagged default namespace. "
                        "If multiple sites or VPCs re-use RFC 1918 private subnets, assets will collide in UDM views."
                    ),
                    affected_log_types=affected_types,
                    remediation_guidance=(
                        "Assign distinct UDM Namespaces per site, datacenter, or VPC at ingestion "
                        "(e.g., via BindPlane OP or Chronicle Ingestion API namespace parameter) "
                        "to isolate private IP addresses and enable granular Data RBAC scoping."
                    ),
                )
            )

        # Check for unlabelled sensitive audit telemetry
        sensitive_unlabelled = [
            u for u in untagged_summaries
            if u.log_type in SENSITIVE_AUDIT_LOG_TYPES and u.unlabelled_event_count > 0
        ]
        if sensitive_unlabelled:
            affected_types = [u.log_type for u in sensitive_unlabelled]
            findings.append(
                NamespaceLabelHygieneFinding(
                    finding_id="FINDING-AUDIT-LOGS-MISSING-INGESTION-LABELS",
                    category="MISSING_INGESTION_LABELS",
                    severity="MEDIUM",
                    title="Sensitive audit telemetry lacks ingestion label tagging",
                    description=(
                        f"Observed unlabelled audit telemetry across {len(affected_types)} types "
                        f"({', '.join(affected_types)}). Without consistent ingestion labels "
                        "(e.g. environment, department, or organization tags), Data RBAC rules cannot "
                        "partition sensitive logs between operational groups."
                    ),
                    affected_log_types=affected_types,
                    remediation_guidance=(
                        "Standardize ingestion label keys across cloud audit feeds and forwarders. "
                        "While labels are arbitrary, consistent application is essential for Data RBAC policies."
                    ),
                )
            )

        # Check for arbitrary label naming inconsistencies (casing and separator drift)
        label_keys = list(active_label_keys)
        normalized_keys: Dict[str, List[str]] = {}
        for k in label_keys:
            norm = re.sub(r"[-_]", "", k).lower()
            normalized_keys.setdefault(norm, []).append(k)

        inconsistent_keys = [variants for variants in normalized_keys.values() if len(variants) > 1]
        for variants in inconsistent_keys:
            findings.append(
                NamespaceLabelHygieneFinding(
                    finding_id=f"FINDING-LABEL-INCONSISTENT-{variants[0]}",
                    category="INCONSISTENT_TAGGING",
                    severity="LOW",
                    title=f"Inconsistent ingestion label naming convention: {variants}",
                    description=(
                        f"Detected multiple variants of the same conceptual label key: {variants}. "
                        "Ingestion labels are arbitrary, but case or separator mismatches prevent "
                        "UDM search filters and Data Access Labels from matching all intended logs."
                    ),
                    remediation_guidance=(
                        f"Normalize collectors to use a single canonical key (e.g., '{variants[0]}') "
                        "across all forwarders and feeds."
                    ),
                )
            )

        provenance = Provenance(
            source="Google SecOps Live Chronicle Events",
            details={
                "source_id": "events_dashboard_queries",
                "source_version": "v1alpha",
                "evidence_path": "evidence/ingestion/namespace_labels",
                "collection_method": "Native GoogleSQL on Chronicle events table",
            },
        )

        return NamespaceLabelAnalysisReport(
            lookback_window=f"{effective_days}d",
            total_labelled_events=total_labelled_events,
            total_namespaced_events=total_namespaced_events,
            total_untagged_events=total_untagged,
            active_ingestion_labels=label_metrics,
            active_namespaces=namespace_metrics,
            untagged_telemetry=untagged_summaries[:25],
            data_rbac_references=rbac_refs,
            findings=findings,
            provenance=provenance,
        )
