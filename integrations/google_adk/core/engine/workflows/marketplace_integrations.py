"""Content Hub Marketplace Response Integrations Workflows.

Implements discovery, keyword search, multi-facet filtering, deep-inspection,
commercial upgrade diffs, and downstream impact analysis for Google SecOps
Marketplace Response Integrations.

Invariants:
- Live data origin exclusively from GoogleSecOpsAdapter.
- Zero synthetic data structures or fallbacks.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    AffectedDownstreamInstance,
    AffectedDownstreamPlaybook,
    MarketplaceAffectedItems,
    MarketplaceCommercialDiff,
    MarketplaceIntegrationBatch,
    MarketplaceIntegrationDetail,
    MarketplaceIntegrationReleaseNote,
    MarketplaceIntegrationSearchQuery,
    MarketplaceIntegrationSummary,
)


def _map_marketplace_integration_summary(item: Dict[str, Any]) -> MarketplaceIntegrationSummary:
    """Translates raw marketplace integration payload into canonical summary entity."""
    return MarketplaceIntegrationSummary(
        identifier=item.get("identifier", ""),
        title=item.get("title", item.get("displayName", "")),
        version=item.get("version", "0.0"),
        installed_version=item.get("installedVersion", "0.0"),
        installed=item.get("installed", False),
        update_available=item.get("updateAvailable", False),
        categories=item.get("categories", []),
        python_version=item.get("pythonVersion", "V3_11"),
        certified=item.get("certified", False),
        custom=item.get("custom", False),
        description=item.get("description", ""),
        documentation_uri=item.get("documentationUri", ""),
        item_update_status=item.get("itemUpdateStatus", "REGULAR"),
        resource_name=item.get("name", ""),
    )


def _map_marketplace_integration_detail(raw: Dict[str, Any]) -> MarketplaceIntegrationDetail:
    """Translates raw integration composite into canonical detail entity."""
    summary = _map_marketplace_integration_summary(raw)
    item_info = raw.get("integrationItemInfo", {})

    actions = item_info.get("actions", [])
    connectors = item_info.get("connectors", [])
    jobs = item_info.get("jobs", [])
    managers = item_info.get("managers", [])
    mapping_rules = item_info.get("mappingRules", [])

    release_notes: List[MarketplaceIntegrationReleaseNote] = []
    for rn in item_info.get("releaseNotes", []):
        release_notes.append(
            MarketplaceIntegrationReleaseNote(
                version=rn.get("version", ""),
                publish_time=str(rn.get("publishTime", "")),
                changelog_items=rn.get("changelogItems", []),
            )
        )

    snapshots = raw.get("integrationSnapshots", [])

    return MarketplaceIntegrationDetail(
        integration=summary,
        actions=actions,
        connectors=connectors,
        jobs=jobs,
        managers=managers,
        mapping_rules=mapping_rules,
        release_notes=release_notes,
        snapshots=snapshots,
        raw=raw,
    )


def _map_commercial_diff(raw: Dict[str, Any]) -> MarketplaceCommercialDiff:
    """Translates commercial diff response into canonical domain entity."""
    return MarketplaceCommercialDiff(
        integration_identifier=raw.get("integrationIdentifier", ""),
        version=str(raw.get("version", "")),
        python_version=raw.get("pythonVersion", ""),
        actions=raw.get("actions", []),
        connectors=raw.get("connectors", []),
        jobs=raw.get("jobs", []),
        managers=raw.get("managers", []),
        diff=raw.get("diff", {}),
        mapping_rules_exist=raw.get("mappingRulesExist", False),
        raw=raw,
    )


def _map_affected_items(raw: Dict[str, Any], identifier: str) -> MarketplaceAffectedItems:
    """Translates affected items payload into canonical domain entity."""
    affected_instances: List[AffectedDownstreamInstance] = []
    for inst in raw.get("affectedIntegrationInstances", []):
        affected_instances.append(
            AffectedDownstreamInstance(
                display_name=inst.get("displayName", ""),
                environment=inst.get("environment", ""),
            )
        )

    affected_playbooks: List[AffectedDownstreamPlaybook] = []
    for pb in raw.get("affectedPlaybooks", []):
        affected_playbooks.append(
            AffectedDownstreamPlaybook(
                display_name=pb.get("displayName", ""),
                environments=pb.get("environments", []),
            )
        )

    return MarketplaceAffectedItems(
        integration_identifier=identifier,
        affected_instances=affected_instances,
        affected_playbooks=affected_playbooks,
        raw=raw,
    )


class SearchMarketplaceIntegrationsWorkflow:
    """Orchestrates discovery, multi-facet filtering, and ranking of Marketplace Integrations."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, query: MarketplaceIntegrationSearchQuery) -> MarketplaceIntegrationBatch:
        """Executes live search against Google SecOps Marketplace Integrations catalog."""
        res = self.adapter.list_marketplace_integrations(
            query_filter="powerUp = false",
            order_by="identifier asc",
            page_size=1000,
        )

        raw_items = res.get("marketplaceIntegrations", [])
        all_summaries = [_map_marketplace_integration_summary(it) for it in raw_items]

        installed_count = sum(1 for s in all_summaries if s.installed)
        updates_count = sum(1 for s in all_summaries if s.update_available)

        filtered: List[MarketplaceIntegrationSummary] = []
        for s in all_summaries:
            # Keyword filter (matches identifier, title, description, or categories)
            if query.query:
                q = query.query.lower()
                text_corpus = f"{s.identifier} {s.title} {s.description} {' '.join(s.categories)}".lower()
                if q not in text_corpus:
                    continue

            # Category filter
            if query.category:
                cat_target = query.category.lower()
                if not any(cat_target in c.lower() for c in s.categories):
                    continue

            # Installed filter
            if query.installed is not None:
                if s.installed != query.installed:
                    continue

            # Update available filter
            if query.update_available is not None:
                if s.update_available != query.update_available:
                    continue

            # Certified filter
            if query.certified is not None:
                if s.certified != query.certified:
                    continue

            filtered.append(s)

        total_matching = len(filtered)
        paged_results = filtered[: query.limit] if query.limit > 0 else filtered

        return MarketplaceIntegrationBatch(
            results=paged_results,
            total_count=total_matching,
            installed_count=installed_count,
            updates_count=updates_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetMarketplaceIntegrationDetailWorkflow:
    """Orchestrates deep inspection of a Marketplace Response Integration."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, identifier_or_title: str) -> MarketplaceIntegrationDetail:
        """Retrieves and constructs complete composite for a Marketplace Response Integration."""
        clean_target = identifier_or_title.strip()
        if not clean_target:
            raise ValueError("Integration identifier or title must be provided")

        # Strip resource name prefix if passed
        clean_id = clean_target.split("/")[-1]

        # 1. Attempt direct retrieval by identifier
        raw = self.adapter.get_marketplace_integration(clean_id)
        if raw and raw.get("name"):
            return _map_marketplace_integration_detail(raw)

        # 2. Fallback: Search catalog by title/identifier to resolve exact identifier
        res = self.adapter.list_marketplace_integrations(
            query_filter="powerUp = false",
            order_by="identifier asc",
            page_size=1000,
        )
        items = res.get("marketplaceIntegrations", [])
        matched_id = None
        for it in items:
            ident = it.get("identifier", "")
            title = it.get("title", it.get("displayName", ""))
            if clean_id.lower() in [ident.lower(), title.lower()]:
                matched_id = ident
                break

        if matched_id:
            raw_resolved = self.adapter.get_marketplace_integration(matched_id)
            if raw_resolved and raw_resolved.get("name"):
                return _map_marketplace_integration_detail(raw_resolved)

        raise ValueError(f"Marketplace Integration '{identifier_or_title}' not found in live catalog")


class GetMarketplaceIntegrationDiffWorkflow:
    """Orchestrates commercial upgrade diff comparison for a Marketplace Integration."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, identifier_or_title: str) -> MarketplaceCommercialDiff:
        """Retrieves commercial upgrade diff for target integration."""
        clean_id = identifier_or_title.strip().split("/")[-1]
        raw = self.adapter.get_marketplace_integration_diff(clean_id)
        if raw and "integrationIdentifier" in raw:
            return _map_commercial_diff(raw)

        # Fallback resolve identifier if title was passed
        detail_wf = GetMarketplaceIntegrationDetailWorkflow(self.adapter)
        detail = detail_wf.execute(identifier_or_title)
        resolved_id = detail.integration.identifier

        raw_diff = self.adapter.get_marketplace_integration_diff(resolved_id)
        return _map_commercial_diff(raw_diff)


class GetMarketplaceIntegrationAffectedItemsWorkflow:
    """Orchestrates downstream dependency and impact analysis for an integration."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, identifier_or_title: str) -> MarketplaceAffectedItems:
        """Retrieves affected downstream instances and active playbooks for an integration."""
        clean_id = identifier_or_title.strip().split("/")[-1]
        raw = self.adapter.get_integration_affected_items(clean_id)
        if raw:
            return _map_affected_items(raw, clean_id)

        # Fallback resolve identifier if title was passed
        detail_wf = GetMarketplaceIntegrationDetailWorkflow(self.adapter)
        detail = detail_wf.execute(identifier_or_title)
        resolved_id = detail.integration.identifier

        raw_affected = self.adapter.get_integration_affected_items(resolved_id)
        return _map_affected_items(raw_affected, resolved_id)
