"""Content Hub (Marketplace) Content Packs Workflows (Milestone 5.6).

Implements discovery, search, multi-facet filtering, category hierarchy inspection,
and component bundle deep-inspection for Google SecOps Content Hub Content Packs.
Invariants: Strict live API provenance, zero synthetic data, explicit error visibility.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    ContentPackBatch,
    ContentPackDetail,
    ContentPackItem,
    ContentPackSearchQuery,
    ContentPackSummary,
    ContentPackType,
)


def _map_content_pack_summary(raw: Dict[str, Any]) -> ContentPackSummary:
    """Maps raw Content Pack dictionary from SecOps API into a typed ContentPackSummary."""
    raw_identifier = raw.get("identifier", "")
    raw_name = raw.get("name", "")
    pack_id = raw_identifier or (raw_name.split("/")[-1] if raw_name else "")

    categories = raw.get("categories", [])
    if isinstance(categories, str):
        categories = [categories]
    elif not isinstance(categories, list):
        categories = []

    playbooks = raw.get("playbooks") or []
    integrations = raw.get("integrations") or []
    dashboards = raw.get("dashboards") or []
    rulesets = raw.get("ruleSets") or []
    queries = raw.get("searchQueries") or []
    rules = raw.get("detectionRules") or []

    return ContentPackSummary(
        id=pack_id,
        identifier=raw_identifier or pack_id,
        name=raw_name,
        title=raw.get("title", "") or pack_id,
        pack_type=raw.get("type", ContentPackType.UNKNOWN.value),
        categories=categories,
        description=raw.get("description", "") or "",
        deployed=bool(raw.get("deployed", False)),
        custom=bool(raw.get("custom", False)),
        community=bool(raw.get("community", False)),
        uploader=raw.get("uploader", "") or "",
        playbooks_count=len(playbooks) if isinstance(playbooks, list) else 0,
        integrations_count=len(integrations) if isinstance(integrations, list) else 0,
        dashboards_count=len(dashboards) if isinstance(dashboards, list) else 0,
        rulesets_count=len(rulesets) if isinstance(rulesets, list) else 0,
        queries_count=len(queries) if isinstance(queries, list) else 0,
        rules_count=len(rules) if isinstance(rules, list) else 0,
        raw=raw,
    )


def _map_content_pack_detail(raw: Dict[str, Any]) -> ContentPackDetail:
    """Maps raw Content Pack dictionary into a complete composite ContentPackDetail."""
    summary = _map_content_pack_summary(raw)

    def _extract_items(items_raw: Any, item_type: str) -> List[ContentPackItem]:
        results: List[ContentPackItem] = []
        if not items_raw or not isinstance(items_raw, list):
            return results
        for item in items_raw:
            if isinstance(item, dict):
                item_id = str(item.get("id") or item.get("identifier") or item.get("name") or "")
                item_title = str(item.get("title") or item.get("name") or item.get("id") or item_id)
                results.append(
                    ContentPackItem(
                        id=item_id,
                        title=item_title,
                        item_type=item_type,
                        raw=item,
                    )
                )
            elif isinstance(item, str):
                results.append(
                    ContentPackItem(
                        id=item,
                        title=item,
                        item_type=item_type,
                        raw={"id": item, "title": item},
                    )
                )
        return results

    return ContentPackDetail(
        pack=summary,
        playbooks=_extract_items(raw.get("playbooks"), "playbook"),
        integrations=_extract_items(raw.get("integrations"), "integration"),
        dashboards=_extract_items(raw.get("dashboards"), "dashboard"),
        rulesets=_extract_items(raw.get("ruleSets"), "ruleset"),
        queries=_extract_items(raw.get("searchQueries"), "search_query"),
        rules=_extract_items(raw.get("detectionRules"), "detection_rule"),
        pre_guidance=raw.get("preInstallationGuidance"),
        post_guidance=raw.get("postInstallationGuidance"),
        raw=raw,
    )


class SearchContentPacksWorkflow:
    """Executes search, multi-facet filtering, and catalog discovery of Content Packs."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, query: ContentPackSearchQuery) -> ContentPackBatch:
        raw_res = self.adapter.list_content_packs(page_size=100)
        raw_packs = raw_res.get("contentPacks", []) if isinstance(raw_res, dict) else []

        summaries = [_map_content_pack_summary(p) for p in raw_packs]

        # Apply multi-facet filtering
        filtered: List[ContentPackSummary] = []
        for s in summaries:
            # 1. Keyword search across title, description, categories, uploader
            if query.query:
                q_term = query.query.lower()
                title_match = q_term in s.title.lower()
                desc_match = q_term in s.description.lower()
                cat_match = any(q_term in c.lower() for c in s.categories)
                uploader_match = q_term in s.uploader.lower()
                if not (title_match or desc_match or cat_match or uploader_match):
                    continue

            # 2. Category filter
            if query.category:
                cat_req = query.category.lower()
                if not any(cat_req == c.lower() for c in s.categories):
                    continue

            # 3. Pack Type filter
            if query.pack_type:
                if s.pack_type.lower() != query.pack_type.lower():
                    continue

            # 4. Deployed status filter
            if query.deployed is not None:
                if s.deployed != query.deployed:
                    continue

            filtered.append(s)

        total_matching = len(filtered)
        limit = query.limit if query.limit > 0 else 100
        results = filtered[:limit]

        return ContentPackBatch(
            results=results,
            total_count=total_matching,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetContentPackDetailWorkflow:
    """Executes deep inspection of a specific Content Pack including bundled components."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, pack_id_or_title: str) -> ContentPackDetail:
        if not pack_id_or_title or not pack_id_or_title.strip():
            raise ValueError("Content Pack identifier or title is required")

        identifier = pack_id_or_title.strip()

        # 1. Try direct fetch if it looks like a UUID or resource path
        is_uuid_or_path = ("/" in identifier) or ("-" in identifier and len(identifier) > 30)
        if is_uuid_or_path:
            clean_id = identifier.split("/")[-1]
            try:
                raw_pack = self.adapter.get_content_pack(clean_id)
                if raw_pack and isinstance(raw_pack, dict) and raw_pack.get("name"):
                    return _map_content_pack_detail(raw_pack)
            except Exception:
                pass

        # 2. Fallback: Search all catalog packs by exact title/identifier first, then substring
        raw_res = self.adapter.list_content_packs(page_size=100)
        raw_packs = raw_res.get("contentPacks", []) if isinstance(raw_res, dict) else []

        target_lower = identifier.lower()
        for p in raw_packs:
            p_id = p.get("identifier", "")
            p_name = p.get("name", "")
            p_title = p.get("title", "")

            if (
                target_lower == p_id.lower()
                or target_lower == p_name.lower()
                or target_lower == p_title.lower()
            ):
                return _map_content_pack_detail(p)

        for p in raw_packs:
            p_title = p.get("title", "")
            if target_lower in p_title.lower():
                return _map_content_pack_detail(p)

        raise ValueError(f"Content Pack not found: '{pack_id_or_title}'")


class ListContentPackCategoriesWorkflow:
    """Discovers and aggregates the taxonomy of Content Hub categories with pack counts."""

    def __init__(self, adapter: Optional[Any] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> List[Dict[str, Any]]:
        raw_res = self.adapter.list_content_packs(page_size=100)
        raw_packs = raw_res.get("contentPacks", []) if isinstance(raw_res, dict) else []

        cat_counts: Dict[str, int] = {}
        for p in raw_packs:
            categories = p.get("categories", [])
            if isinstance(categories, str):
                categories = [categories]
            for c in categories:
                c_clean = c.strip()
                if c_clean:
                    cat_counts[c_clean] = cat_counts.get(c_clean, 0) + 1

        results = [
            {"category": cat, "pack_count": count}
            for cat, count in sorted(cat_counts.items(), key=lambda x: (-x[1], x[0]))
        ]
        return results
