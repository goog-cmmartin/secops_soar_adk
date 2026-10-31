"""Workflows for SOAR Settings (Milestone 6.1).

Orchestrates discovery and inspection of SOAR Users, SOC Roles, and Company Rebranding Settings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    CompanySettingProperty,
    CompanySettingsBatch,
    DataRetentionSettingProperty,
    DataRetentionSettingsBatch,
    EmailSettingProperty,
    EmailSettingsBatch,
    EnvironmentBatch,
    EnvironmentDetail,
    EnvironmentGroupBatch,
    EnvironmentGroupSummary,
    EnvironmentSummary,
    RemoteAgentBatch,
    RemoteAgentDetail,
    RemoteAgentSummary,
    SocRoleBatch,
    SocRoleSummary,
    SoarUserBatch,
    SoarUserDetail,
    SoarUserSummary,
    SupportSettingProperty,
    SupportSettingsBatch,
    SoarNetworkSummary,
    SoarNetworkDetail,
    SoarNetworkBatch,
    SoarDomainSummary,
    SoarDomainDetail,
    SoarDomainBatch,
    SoarCustomListSummary,
    SoarCustomListDetail,
    SoarCustomListBatch,
    EmailTemplateSummary,
    EmailTemplateDetail,
    EmailTemplateBatch,
    EntitiesBlocklistSummary,
    EntitiesBlocklistDetail,
    EntitiesBlocklistBatch,
    SlaDefinitionSummary,
    SlaDefinitionDetail,
    SlaDefinitionBatch,
    RequestTemplateFieldDefinition,
    RequestTemplateSummary,
    RequestTemplateDetail,
    RequestTemplateBatch,
    SoarIngestionConnectorSummary,
    SoarIngestionConnectorDetail,
    SoarIngestionConnectorBatch,
    SoarWebhookSummary,
    SoarWebhookDetail,
    SoarWebhookBatch,
)


def _normalize_soar_user_summary(raw: Dict[str, Any]) -> SoarUserSummary:
    name = raw.get("name", "")
    uid = name.split("/")[-1] if "/" in name else name

    return SoarUserSummary(
        id=uid,
        name=name,
        user_full_name=raw.get("userFullName", ""),
        first_name=raw.get("firstName", ""),
        last_name=raw.get("lastName", ""),
        email=raw.get("email", ""),
        login_identifier=raw.get("loginIdentifier", ""),
        provider_name=raw.get("providerName", "UNKNOWN"),
        user_type=raw.get("userType", "EXTERNAL"),
        account_state=raw.get("accountState", "ACTIVE"),
        last_login_time=raw.get("lastLoginTime"),
        soc_roles=raw.get("socRoles", []),
        permission_groups=raw.get("permissionGroups", []),
        has_all_environments_access=raw.get("hasAllEnvironmentsAccess", False),
        raw=raw,
    )


class SearchSoarUsersWorkflow:
    """Searches and filters SOAR users and external identity profiles."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: str = "",
        role_filter: Optional[int] = None,
        limit: int = 100,
    ) -> SoarUserBatch:
        raw = self.adapter.list_soar_users(page_size=1000)
        raw_users = raw.get("legacySoarUsers", [])

        users: List[SoarUserSummary] = []
        for u in raw_users:
            summary = _normalize_soar_user_summary(u)

            if role_filter is not None and role_filter not in summary.soc_roles:
                continue

            if query:
                q = query.lower()
                match = (
                    q in summary.id.lower()
                    or q in summary.user_full_name.lower()
                    or q in summary.email.lower()
                    or q in summary.login_identifier.lower()
                    or q in summary.provider_name.lower()
                )
                if not match:
                    continue

            users.append(summary)

        total_count = len(users)
        if limit > 0:
            users = users[:limit]

        return SoarUserBatch(
            users=users,
            total_count=total_count,
            next_page_token=raw.get("nextPageToken"),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSoarUserWorkflow:
    """Deep inspection of a single SOAR user profile."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, user_id: str) -> SoarUserDetail:
        raw = self.adapter.get_soar_user(user_id)
        summary = _normalize_soar_user_summary(raw)

        return SoarUserDetail(
            summary=summary,
            environments_json=raw.get("environmentsJson", "[]"),
            allowed_platforms=raw.get("allowedPlatforms", []),
            raw=raw,
        )


class ListSocRolesWorkflow:
    """Lists configured SOC roles and workflow assignment hierarchies."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, limit: int = 100) -> SocRoleBatch:
        raw = self.adapter.list_soc_roles(page_size=1000)
        raw_roles = raw.get("socRoles", [])

        roles: List[SocRoleSummary] = []
        for r in raw_roles:
            name = r.get("name", "")
            rid = name.split("/")[-1] if "/" in name else name

            roles.append(
                SocRoleSummary(
                    id=rid,
                    name=name,
                    display_name=r.get("displayName", ""),
                    additional_roles_access=r.get("additionalRolesAccess", []),
                    raw=r,
                )
            )

        total_count = len(roles)
        if limit > 0:
            roles = roles[:limit]

        return SocRoleBatch(
            roles=roles,
            total_count=total_count,
            retrieved_at=datetime.now(timezone.utc),
        )


class GetCompanySettingsWorkflow:
    """Retrieves tenant company rebranding and reporting settings."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> CompanySettingsBatch:
        raw = self.adapter.get_company_settings()
        raw_props = raw.get("moduleSettingsProperties", [])

        props: List[CompanySettingProperty] = []
        for p in raw_props:
            name = p.get("name", "")
            pkey = name.split("/")[-1] if "/" in name else name

            props.append(
                CompanySettingProperty(
                    name=name,
                    property_key=pkey,
                    display_name=p.get("displayName", pkey),
                    value=p.get("value", ""),
                    type=p.get("type", "STRING"),
                    raw=p,
                )
            )

        return CompanySettingsBatch(
            properties=props,
            total_count=len(props),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetDataRetentionSettingsWorkflow:
    """Retrieves tenant data retention and environment policy settings."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> DataRetentionSettingsBatch:
        raw = self.adapter.get_data_retention_settings()
        raw_props = raw.get("moduleSettingsProperties", [])

        props: List[DataRetentionSettingProperty] = []
        for p in raw_props:
            name = p.get("name", "")
            pkey = name.split("/")[-1] if "/" in name else name

            props.append(
                DataRetentionSettingProperty(
                    name=name,
                    property_key=pkey,
                    display_name=p.get("displayName", pkey),
                    value=p.get("value", ""),
                    type=p.get("type", "STRING"),
                    raw=p,
                )
            )

        return DataRetentionSettingsBatch(
            properties=props,
            total_count=len(props),
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_environment_summary(raw: Dict[str, Any]) -> EnvironmentSummary:
    name = raw.get("name", "")
    eid = name.split("/")[-1] if "/" in name else name

    aliases: List[str] = []
    aliases_str = raw.get("aliasesJson")
    if aliases_str:
        try:
            aliases = json.loads(aliases_str)
        except Exception:
            aliases = [aliases_str]

    scopes: List[str] = []
    scopes_str = raw.get("dataAccessScopesJson")
    if scopes_str:
        try:
            scopes = json.loads(scopes_str)
        except Exception:
            scopes = [scopes_str]

    return EnvironmentSummary(
        id=eid,
        name=name,
        display_name=raw.get("displayName", eid),
        retention_duration=int(raw.get("retentionDuration", 0)),
        system=bool(raw.get("system", False)),
        weight=int(raw.get("weight", 0)),
        aliases=aliases,
        data_access_scopes=scopes,
        raw=raw,
    )


class SearchEnvironmentsWorkflow:
    """Discovers and filters multi-tenancy environments."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        limit: int = 100,
    ) -> EnvironmentBatch:
        raw = self.adapter.list_environments(page_size=1000)
        items = raw.get("environments", [])

        environments: List[EnvironmentSummary] = []
        q_lower = query.lower() if query else None

        for item in items:
            summary = _normalize_environment_summary(item)
            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                match_alias = any(q_lower in a.lower() for a in summary.aliases)
                if not (match_id or match_name or match_alias):
                    continue

            environments.append(summary)
            if limit > 0 and len(environments) >= limit:
                break

        return EnvironmentBatch(
            environments=environments,
            total_count=len(environments),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetEnvironmentWorkflow:
    """Retrieves deep configuration of a single multi-tenancy environment."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, env_id: str) -> EnvironmentDetail:
        if not env_id or not env_id.strip():
            raise ValueError("Environment ID must not be empty.")

        raw = self.adapter.get_environment(env_id.strip())
        summary = _normalize_environment_summary(raw)
        return EnvironmentDetail(
            summary=summary,
            raw=raw,
        )


class SearchEnvironmentGroupsWorkflow:
    """Discovers and lists logical groupings of multi-tenancy environments."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        limit: int = 100,
    ) -> EnvironmentGroupBatch:
        raw = self.adapter.list_environment_groups(page_size=1000)
        items = raw.get("environmentGroups", [])

        groups: List[EnvironmentGroupSummary] = []
        q_lower = query.lower() if query else None

        for item in items:
            name = item.get("name", "")
            gid = name.split("/")[-1] if "/" in name else name
            dname = item.get("displayName", gid)
            envs = item.get("environments", [])

            if q_lower:
                match_id = q_lower in gid.lower()
                match_name = q_lower in dname.lower()
                if not (match_id or match_name):
                    continue

            groups.append(
                EnvironmentGroupSummary(
                    id=gid,
                    name=name,
                    display_name=dname,
                    environments=envs if isinstance(envs, list) else [envs],
                    raw=item,
                )
            )
            if limit > 0 and len(groups) >= limit:
                break

        return EnvironmentGroupBatch(
            groups=groups,
            total_count=len(groups),
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_remote_agent_summary(raw: Dict[str, Any]) -> RemoteAgentSummary:
    name = raw.get("name", "")
    aid = name.split("/")[-1] if "/" in name else name

    envs: List[str] = []
    envs_val = raw.get("environments")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    return RemoteAgentSummary(
        id=aid,
        name=name,
        display_name=raw.get("displayName", aid),
        identifier=raw.get("identifier", ""),
        environments=envs,
        agent_state=raw.get("agentState", "UNKNOWN"),
        logging_level=raw.get("loggingLevel", "UNKNOWN"),
        installer_link=raw.get("installerLink", ""),
        raw=raw,
    )


class SearchRemoteAgentsWorkflow:
    """Discovers and filters remote SOAR agents."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        environment: Optional[str] = None,
        agent_state: Optional[str] = None,
        limit: int = 100,
    ) -> RemoteAgentBatch:
        raw = self.adapter.list_remote_agents(page_size=1000)
        items = raw.get("remoteAgents", [])

        remote_agents: List[RemoteAgentSummary] = []
        q_lower = query.lower() if query else None
        env_lower = environment.lower() if environment else None
        state_upper = agent_state.upper() if agent_state else None

        for item in items:
            summary = _normalize_remote_agent_summary(item)

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                match_uuid = q_lower in summary.identifier.lower()
                if not (match_id or match_name or match_uuid):
                    continue

            if env_lower:
                if not any(env_lower == e.lower() or env_lower in e.lower() for e in summary.environments):
                    continue

            if state_upper and summary.agent_state.upper() != state_upper:
                continue

            remote_agents.append(summary)
            if limit > 0 and len(remote_agents) >= limit:
                break

        return RemoteAgentBatch(
            remote_agents=remote_agents,
            total_count=len(remote_agents),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetRemoteAgentWorkflow:
    """Retrieves deep configuration of a single remote agent."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, agent_id: str) -> RemoteAgentDetail:
        if not agent_id or not agent_id.strip():
            raise ValueError("Agent ID must not be empty.")

        raw = self.adapter.get_remote_agent(agent_id.strip())
        summary = _normalize_remote_agent_summary(raw)
        return RemoteAgentDetail(
            summary=summary,
            certificate=raw.get("certificate", ""),
            raw=raw,
        )


class GetEmailSettingsWorkflow:
    """Retrieves composite email transport configuration."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> EmailSettingsBatch:
        type_res = self.adapter.get_email_settings_type()
        type_props = type_res.get("moduleSettingsProperties", [])
        use_custom = False
        for tp in type_props:
            if "UseCustom" in tp.get("name", ""):
                use_custom = str(tp.get("value", "")).lower() in ["true", "1"]

        settings_res = self.adapter.get_email_settings()
        raw_props = settings_res.get("moduleSettingsProperties", [])

        props: List[EmailSettingProperty] = []
        for p in raw_props:
            name = p.get("name", "")
            pkey = name.split("/")[-1] if "/" in name else name

            props.append(
                EmailSettingProperty(
                    name=name,
                    property_key=pkey,
                    display_name=p.get("displayName", pkey),
                    value=p.get("value", ""),
                    type=p.get("type", "STRING"),
                    raw=p,
                )
            )

        return EmailSettingsBatch(
            properties=props,
            use_custom=use_custom,
            total_count=len(props),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSupportSettingsWorkflow:
    """Retrieves Google Support access delegation properties."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self) -> SupportSettingsBatch:
        raw = self.adapter.get_support_settings()
        raw_props = raw.get("moduleSettingsProperties", [])

        props: List[SupportSettingProperty] = []
        for p in raw_props:
            name = p.get("name", "")
            pkey = name.split("/")[-1] if "/" in name else name

            props.append(
                SupportSettingProperty(
                    name=name,
                    property_key=pkey,
                    display_name=p.get("displayName", pkey),
                    value=p.get("value", ""),
                    type=p.get("type", "STRING"),
                    raw=p,
                )
            )

        return SupportSettingsBatch(
            properties=props,
            total_count=len(props),
            retrieved_at=datetime.now(timezone.utc),
        )


# ==============================================================================
# MILESTONE 6.5: NETWORKS, DOMAINS, CUSTOM LISTS, TEMPLATES, SLAS, REQUESTS
# ==============================================================================

def _normalize_soar_network_summary(raw: Dict[str, Any]) -> SoarNetworkSummary:
    name = raw.get("name", "")
    nid = name.split("/")[-1] if "/" in name else name

    envs: List[str] = []
    envs_val = raw.get("environmentsJson") or raw.get("environments")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    return SoarNetworkSummary(
        id=nid,
        name=name,
        display_name=raw.get("displayName", nid),
        address=raw.get("address", ""),
        environments=envs,
        priority=int(raw.get("priority", 0)),
        raw=raw,
    )


class SearchSoarNetworksWorkflow:
    """Discovers and filters customer-defined CIDR network address ranges."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> SoarNetworkBatch:
        raw = self.adapter.list_soar_networks(page_size=1000)
        items = raw.get("soarNetworks", [])

        networks: List[SoarNetworkSummary] = []
        q_lower = query.lower() if query else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_soar_network_summary(item)

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                match_addr = q_lower in summary.address.lower()
                if not (match_id or match_name or match_addr):
                    continue

            if env_lower:
                if not any(env_lower in e.lower() or e == "*" for e in summary.environments):
                    continue

            networks.append(summary)
            if limit > 0 and len(networks) >= limit:
                break

        return SoarNetworkBatch(
            networks=networks,
            total_count=len(networks),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSoarNetworkWorkflow:
    """Retrieves complete configuration for a single customer-defined CIDR network."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, network_id: str) -> SoarNetworkDetail:
        raw = self.adapter.get_soar_network(network_id)
        summary = _normalize_soar_network_summary(raw)
        return SoarNetworkDetail(
            summary=summary,
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_soar_domain_summary(raw: Dict[str, Any]) -> SoarDomainSummary:
    name = raw.get("name", "")
    did = name.split("/")[-1] if "/" in name else name

    envs: List[str] = []
    envs_val = raw.get("environmentsJson") or raw.get("environments")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    return SoarDomainSummary(
        id=did,
        name=name,
        display_name=raw.get("displayName", did),
        environments=envs,
        raw=raw,
    )


class SearchSoarDomainsWorkflow:
    """Discovers and filters approved customer domain names."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> SoarDomainBatch:
        raw = self.adapter.list_soar_domains(page_size=1000)
        items = raw.get("soarDomains", [])

        domains: List[SoarDomainSummary] = []
        q_lower = query.lower() if query else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_soar_domain_summary(item)

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                if not (match_id or match_name):
                    continue

            if env_lower:
                if not any(env_lower in e.lower() or e == "*" for e in summary.environments):
                    continue

            domains.append(summary)
            if limit > 0 and len(domains) >= limit:
                break

        return SoarDomainBatch(
            domains=domains,
            total_count=len(domains),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSoarDomainWorkflow:
    """Retrieves complete configuration for a single approved customer domain."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, domain_id: str) -> SoarDomainDetail:
        raw = self.adapter.get_soar_domain(domain_id)
        summary = _normalize_soar_domain_summary(raw)
        return SoarDomainDetail(
            summary=summary,
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_soar_custom_list_summary(raw: Dict[str, Any]) -> SoarCustomListSummary:
    name = raw.get("name", "")
    cid = name.split("/")[-1] if "/" in name else name

    envs: List[str] = []
    envs_val = raw.get("environments") or raw.get("environmentsJson")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    return SoarCustomListSummary(
        id=cid,
        name=name,
        category=raw.get("category", ""),
        entity_identifier=raw.get("entityIdentifier", ""),
        environments=envs,
        raw=raw,
    )


class SearchSoarCustomListsWorkflow:
    """Discovers and filters SOAR custom list key-value retention entries."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> SoarCustomListBatch:
        raw = self.adapter.list_soar_custom_lists(page_size=1000)
        items = raw.get("customLists", [])

        custom_lists: List[SoarCustomListSummary] = []
        q_lower = query.lower() if query else None
        cat_lower = category.lower() if category else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_soar_custom_list_summary(item)

            if cat_lower and cat_lower not in summary.category.lower():
                continue

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_ident = q_lower in summary.entity_identifier.lower()
                match_cat = q_lower in summary.category.lower()
                if not (match_id or match_ident or match_cat):
                    continue

            if env_lower:
                if not any(env_lower in e.lower() or e == "*" for e in summary.environments):
                    continue

            custom_lists.append(summary)
            if limit > 0 and len(custom_lists) >= limit:
                break

        return SoarCustomListBatch(
            custom_lists=custom_lists,
            total_count=len(custom_lists),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSoarCustomListWorkflow:
    """Retrieves complete configuration for a single SOAR custom list entry."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, list_id: str) -> SoarCustomListDetail:
        raw = self.adapter.get_soar_custom_list(list_id)
        summary = _normalize_soar_custom_list_summary(raw)
        return SoarCustomListDetail(
            summary=summary,
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_email_template_summary(raw: Dict[str, Any]) -> EmailTemplateSummary:
    name = raw.get("name", "")
    tid = name.split("/")[-1] if "/" in name else name

    envs: List[str] = []
    envs_val = raw.get("environments") or raw.get("environmentsJson")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    return EmailTemplateSummary(
        id=tid,
        name=name,
        display_name=raw.get("displayName", tid),
        template_type=raw.get("templateType", "TEMPLATE"),
        author=raw.get("author", ""),
        environments=envs,
        raw=raw,
    )


class SearchEmailTemplatesWorkflow:
    """Discovers and filters email templates (plain text and HTML)."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        template_type: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> EmailTemplateBatch:
        raw = self.adapter.list_email_templates(page_size=1000)
        items = raw.get("emailTemplates", [])

        templates: List[EmailTemplateSummary] = []
        q_lower = query.lower() if query else None
        type_upper = template_type.upper() if template_type else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_email_template_summary(item)

            if type_upper and summary.template_type != type_upper:
                continue

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                match_content = q_lower in str(item.get("content", "")).lower()
                if not (match_id or match_name or match_content):
                    continue

            if env_lower:
                if not any(env_lower in e.lower() or e == "*" for e in summary.environments):
                    continue

            templates.append(summary)
            if limit > 0 and len(templates) >= limit:
                break

        return EmailTemplateBatch(
            email_templates=templates,
            total_count=len(templates),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetEmailTemplateWorkflow:
    """Retrieves complete configuration and content for a single email template."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, template_id: str) -> EmailTemplateDetail:
        raw = self.adapter.get_email_template(template_id)
        summary = _normalize_email_template_summary(raw)
        return EmailTemplateDetail(
            summary=summary,
            content=raw.get("content", ""),
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_entities_blocklist_summary(raw: Dict[str, Any]) -> EntitiesBlocklistSummary:
    name = raw.get("name", "")
    bid = name.split("/")[-1] if "/" in name else name

    envs: List[str] = []
    envs_val = raw.get("environmentsJson") or raw.get("environments")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    return EntitiesBlocklistSummary(
        id=bid,
        name=name,
        entity_identifier=raw.get("entityIdentifier", ""),
        entity_type=raw.get("entityType", ""),
        action=raw.get("action", "DO_NOT_GROUP_ALERTS"),
        environments=envs,
        raw=raw,
    )


class SearchEntitiesBlocklistsWorkflow:
    """Discovers and filters entity noise-reduction blocklist rules."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        entity_type: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> EntitiesBlocklistBatch:
        raw = self.adapter.list_entities_blocklists(page_size=1000)
        items = raw.get("entitiesBlocklists", [])

        entries: List[EntitiesBlocklistSummary] = []
        q_lower = query.lower() if query else None
        type_upper = entity_type.upper() if entity_type else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_entities_blocklist_summary(item)

            if type_upper and summary.entity_type.upper() != type_upper:
                continue

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_ident = q_lower in summary.entity_identifier.lower()
                match_type = q_lower in summary.entity_type.lower()
                if not (match_id or match_ident or match_type):
                    continue

            if env_lower:
                if not any(env_lower in e.lower() or e == "*" for e in summary.environments):
                    continue

            entries.append(summary)
            if limit > 0 and len(entries) >= limit:
                break

        return EntitiesBlocklistBatch(
            blocklist_entries=entries,
            total_count=len(entries),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetEntitiesBlocklistWorkflow:
    """Retrieves complete configuration for a single entity blocklist entry."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, blocklist_id: str) -> EntitiesBlocklistDetail:
        raw = self.adapter.get_entities_blocklist(blocklist_id)
        summary = _normalize_entities_blocklist_summary(raw)
        return EntitiesBlocklistDetail(
            summary=summary,
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_sla_definition_summary(raw: Dict[str, Any]) -> SlaDefinitionSummary:
    name = raw.get("name", "")
    sid = name.split("/")[-1] if "/" in name else name

    type_values: List[str] = []
    tv_val = raw.get("slaTypeValue")
    if isinstance(tv_val, str) and tv_val.strip().startswith("["):
        try:
            type_values = json.loads(tv_val)
        except Exception:
            type_values = [tv_val]
    elif isinstance(tv_val, list):
        type_values = tv_val
    elif tv_val:
        type_values = [str(tv_val)]

    envs: List[str] = []
    envs_val = raw.get("environments") or raw.get("environmentsJson")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    return SlaDefinitionSummary(
        id=sid,
        name=name,
        sla_type=raw.get("slaType", "UNKNOWN"),
        sla_type_values=type_values,
        sla_period=int(raw.get("slaPeriod", 0)),
        sla_period_time_unit=raw.get("slaPeriodTimeUnit", "MINUTES"),
        critical_sla_period=int(raw.get("criticalSlaPeriod", 0)),
        critical_sla_period_time_unit=raw.get("criticalSlaPeriodTimeUnit", "MINUTES"),
        environments=envs,
        raw=raw,
    )


class SearchSlaDefinitionsWorkflow:
    """Discovers and filters Service Level Agreement definitions."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        sla_type: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> SlaDefinitionBatch:
        raw = self.adapter.list_sla_definitions(page_size=1000)
        items = raw.get("slaDefinitions", [])

        slas: List[SlaDefinitionSummary] = []
        q_lower = query.lower() if query else None
        type_upper = sla_type.upper() if sla_type else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_sla_definition_summary(item)

            if type_upper and summary.sla_type.upper() != type_upper:
                continue

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_type = q_lower in summary.sla_type.lower()
                match_vals = any(q_lower in v.lower() for v in summary.sla_type_values)
                if not (match_id or match_type or match_vals):
                    continue

            if env_lower:
                if not any(env_lower in e.lower() or e == "*" for e in summary.environments):
                    continue

            slas.append(summary)
            if limit > 0 and len(slas) >= limit:
                break

        return SlaDefinitionBatch(
            sla_definitions=slas,
            total_count=len(slas),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSlaDefinitionWorkflow:
    """Retrieves complete configuration for a single SLA definition."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, sla_id: str) -> SlaDefinitionDetail:
        raw = self.adapter.get_sla_definition(sla_id)
        summary = _normalize_sla_definition_summary(raw)
        return SlaDefinitionDetail(
            summary=summary,
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_request_template_summary(raw: Dict[str, Any]) -> RequestTemplateSummary:
    name = raw.get("name", "")
    rid = str(raw.get("requestTemplateId") or (name.split("/")[-1] if "/" in name else name))

    envs: List[str] = []
    envs_val = raw.get("environments") or raw.get("environmentsJson")
    if isinstance(envs_val, str) and envs_val.strip().startswith("["):
        try:
            envs = json.loads(envs_val)
        except Exception:
            envs = [envs_val]
    elif isinstance(envs_val, list):
        envs = envs_val
    elif envs_val:
        envs = [str(envs_val)]

    fields_list = raw.get("eventFieldDefinitions", [])

    return RequestTemplateSummary(
        id=rid,
        name=name,
        display_name=raw.get("displayName", f"Request Template {rid}"),
        visual_family=raw.get("visualFamily", "Default"),
        allow_description=bool(raw.get("allowDescription", False)),
        environments=envs,
        field_count=len(fields_list),
        raw=raw,
    )


class SearchRequestTemplatesWorkflow:
    """Discovers and filters manual case request form templates."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> RequestTemplateBatch:
        raw = self.adapter.list_request_templates(page_size=1000)
        items = raw.get("requestTemplates", [])

        templates: List[RequestTemplateSummary] = []
        q_lower = query.lower() if query else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_request_template_summary(item)

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                fields_raw = item.get("eventFieldDefinitions", [])
                match_field = any(q_lower in f.get("name", "").lower() for f in fields_raw)
                if not (match_id or match_name or match_field):
                    continue

            if env_lower:
                if not any(env_lower in e.lower() or e == "*" for e in summary.environments):
                    continue

            templates.append(summary)
            if limit > 0 and len(templates) >= limit:
                break

        return RequestTemplateBatch(
            request_templates=templates,
            total_count=len(templates),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetRequestTemplateWorkflow:
    """Retrieves complete configuration for a single manual case request form template."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, template_id: str) -> RequestTemplateDetail:
        raw = self.adapter.get_request_template(template_id)
        summary = _normalize_request_template_summary(raw)

        field_defs: List[RequestTemplateFieldDefinition] = []
        for f in raw.get("eventFieldDefinitions", []):
            field_defs.append(
                RequestTemplateFieldDefinition(
                    name=f.get("name", ""),
                    entity_types=f.get("entityTypes", []),
                    watermark=f.get("watermark", ""),
                    field_type=f.get("type", "STRING"),
                    raw=f,
                )
            )

        return RequestTemplateDetail(
            summary=summary,
            event_field_definitions=field_defs,
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


# ==============================================================================
# Milestone 6.6: Ingestion Connectors & Webhooks Workflows
# ==============================================================================

def _normalize_soar_ingestion_connector_summary(raw: Dict[str, Any]) -> SoarIngestionConnectorSummary:
    name = raw.get("name", "")
    cid = str(raw.get("id") or (name.split("/")[-1] if "/" in name else name))

    return SoarIngestionConnectorSummary(
        id=cid,
        name=name,
        display_name=raw.get("displayName", f"Connector {cid}"),
        identifier=raw.get("identifier", ""),
        integration=raw.get("integration", ""),
        connector_id=str(raw.get("connectorId", "")),
        connector_definition_name=raw.get("connectorDefinitionName", ""),
        environment=raw.get("environment", ""),
        enabled=bool(raw.get("enabled", False)),
        remote=bool(raw.get("remote", False)),
        interval_seconds=int(raw.get("intervalSeconds", 0)),
        raw=raw,
    )


class SearchSoarIngestionConnectorsWorkflow:
    """Discovers and filters configured SOAR ingestion connector instances."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        integration: str = "-",
        connector_id: str = "-",
        environment: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 100,
    ) -> SoarIngestionConnectorBatch:
        raw = self.adapter.list_soar_ingestion_connectors(
            integration=integration,
            connector_id=connector_id,
            page_size=1000,
        )
        items = raw.get("connectorInstances", [])

        connectors: List[SoarIngestionConnectorSummary] = []
        q_lower = query.lower() if query else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_soar_ingestion_connector_summary(item)

            if enabled_only and not summary.enabled:
                continue

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                match_ident = q_lower in summary.identifier.lower()
                match_integ = q_lower in summary.integration.lower()
                match_def = q_lower in summary.connector_definition_name.lower()
                if not (match_id or match_name or match_ident or match_integ or match_def):
                    continue

            if env_lower:
                if env_lower not in summary.environment.lower() and summary.environment != "*":
                    continue

            connectors.append(summary)
            if limit > 0 and len(connectors) >= limit:
                break

        return SoarIngestionConnectorBatch(
            connectors=connectors,
            total_count=len(connectors),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSoarIngestionConnectorWorkflow:
    """Retrieves complete configuration for a single SOAR ingestion connector instance."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        instance_id: str,
        integration: str = "-",
        connector_id: str = "-",
    ) -> SoarIngestionConnectorDetail:
        raw = self.adapter.get_soar_ingestion_connector(
            instance_id=instance_id,
            integration=integration,
            connector_id=connector_id,
        )
        summary = _normalize_soar_ingestion_connector_summary(raw)
        return SoarIngestionConnectorDetail(
            summary=summary,
            description=raw.get("description", ""),
            product_field_name=raw.get("productFieldName", ""),
            event_field_name=raw.get("eventFieldName", ""),
            timeout_seconds=str(raw.get("timeoutSeconds", "")),
            integration_version=str(raw.get("integrationVersion", "")),
            version=str(raw.get("version", "")),
            update_available=bool(raw.get("updateAvailable", False)),
            status=raw.get("status", "UNKNOWN"),
            documentation_link=raw.get("documentationLink", ""),
            parameters=raw.get("parameters", []),
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )


def _normalize_soar_webhook_summary(raw: Dict[str, Any]) -> SoarWebhookSummary:
    name = raw.get("name", "")
    wid = name.split("/")[-1] if "/" in name else name

    return SoarWebhookSummary(
        id=wid,
        name=name,
        display_name=raw.get("displayName", wid),
        environment=raw.get("environment", ""),
        enabled=bool(raw.get("enabled", False)),
        description=raw.get("description", ""),
        raw=raw,
    )


class SearchSoarWebhooksWorkflow:
    """Discovers and filters configured SOAR event ingestion webhooks."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        query: Optional[str] = None,
        environment: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 100,
    ) -> SoarWebhookBatch:
        raw = self.adapter.list_soar_webhooks(page_size=1000)
        items = raw.get("webhooks", [])

        webhooks: List[SoarWebhookSummary] = []
        q_lower = query.lower() if query else None
        env_lower = environment.lower() if environment else None

        for item in items:
            summary = _normalize_soar_webhook_summary(item)

            if enabled_only and not summary.enabled:
                continue

            if q_lower:
                match_id = q_lower in summary.id.lower()
                match_name = q_lower in summary.display_name.lower()
                match_desc = q_lower in summary.description.lower()
                if not (match_id or match_name or match_desc):
                    continue

            if env_lower:
                if env_lower not in summary.environment.lower() and summary.environment != "*":
                    continue

            webhooks.append(summary)
            if limit > 0 and len(webhooks) >= limit:
                break

        return SoarWebhookBatch(
            webhooks=webhooks,
            total_count=len(webhooks),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetSoarWebhookWorkflow:
    """Retrieves complete configuration and schema mapping for a single SOAR event ingestion webhook."""

    def __init__(self, adapter: Optional[GoogleSecOpsAdapter] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(self, webhook_id: str) -> SoarWebhookDetail:
        raw = self.adapter.get_soar_webhook(webhook_id)
        summary = _normalize_soar_webhook_summary(raw)

        mapping: Dict[str, str] = {}
        raw_mapping = raw.get("webhookMapping", {})
        if isinstance(raw_mapping, dict):
            mapping = {str(k): str(v) for k, v in raw_mapping.items()}

        return SoarWebhookDetail(
            summary=summary,
            webhook_mapping=mapping,
            postfix=raw.get("postfix", ""),
            raw=raw,
            retrieved_at=datetime.now(timezone.utc),
        )

