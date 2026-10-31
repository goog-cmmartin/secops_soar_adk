"""Workflow implementation for Google SecOps Identity & Access Governance.

Queries GCP Cloud Resource Manager and IAM APIs to audit predefined Chronicle IAM roles,
custom project IAM roles with chronicle.* permissions, role assignments (users, groups,
service accounts, workforce identity pools), and correlates with SecOps Inventory reports.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.request

from engine.config import SecOpsConfigurationError

from engine.domain import (
    ChronicleCustomRole,
    ChronicleIamMember,
    ChronicleIamRoleBinding,
    IdentityGovernanceReport,
)

logger = logging.getLogger(__name__)

# Standard Predefined Google Cloud IAM Roles that provide Google SecOps / Chronicle access
PREDEFINED_CHRONICLE_ROLES: Dict[str, str] = {
    "roles/chronicle.admin": "Chronicle API Admin",
    "roles/chronicle.dataGovernor": "Chronicle API Data Governor",
    "roles/chronicle.editor": "Chronicle API Editor",
    "roles/chronicle.federationAdmin": "Chronicle API Federation Admin",
    "roles/chronicle.federationViewer": "Chronicle API Federation Viewer",
    "roles/chronicle.globalDataAccess": "Chronicle API Global Data Access",
    "roles/chronicle.limitedViewer": "Chronicle API Limited Viewer",
    "roles/chronicle.orgServiceAgent": "Chronicle Organization Service Agent",
    "roles/chronicle.restrictedDataAccess": "Chronicle API Restricted Data Access",
    "roles/chronicle.restrictedDataAccessViewer": "Chronicle API Restricted Data Access Viewer",
    "roles/chronicle.viewer": "Chronicle API Viewer",
    "roles/chronicle.serviceAgent": "Chronicle Service Agent",
    "roles/chronicle.soarAdmin": "Chronicle SOAR Admin",
    "roles/chronicle.soarAnalyst": "Chronicle SOAR Analyst",
    "roles/chronicle.soarEngineer": "Chronicle SOAR Engineer",
    "roles/chronicle.soarServiceAgent": "Chronicle SOAR Service Agent",
    "roles/chronicle.soarThreatManager": "Chronicle SOAR Threat Manager",
    "roles/chronicle.soarViewer": "Chronicle SOAR Viewer",
    "roles/chronicle.soarVulnerabilityManager": "Chronicle SOAR Vulnerability Manager",
    "roles/chronicle.securityValidationAdmin": "Chronicle Security Validation Admin",
}


def classify_member(raw_member: str) -> ChronicleIamMember:
    """Classifies a member string into principal type and identifier."""
    if raw_member.startswith("user:"):
        return ChronicleIamMember(raw_member=raw_member, member_type="user", principal_id=raw_member[5:])
    elif raw_member.startswith("group:"):
        return ChronicleIamMember(raw_member=raw_member, member_type="group", principal_id=raw_member[6:])
    elif raw_member.startswith("serviceAccount:"):
        return ChronicleIamMember(raw_member=raw_member, member_type="serviceAccount", principal_id=raw_member[15:])
    elif raw_member.startswith("principalSet://") or raw_member.startswith("principal://"):
        return ChronicleIamMember(raw_member=raw_member, member_type="workforcePool", principal_id=raw_member)
    elif raw_member.startswith("domain:"):
        return ChronicleIamMember(raw_member=raw_member, member_type="domain", principal_id=raw_member[7:])
    return ChronicleIamMember(raw_member=raw_member, member_type="other", principal_id=raw_member)


class IdentityGovernanceWorkflow:
    """Workflow engine orchestrating GCP IAM inspection, custom role analysis, and SecOps identity governance."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    @property
    def default_project_id(self) -> str:
        """Resolves target GCP project ID from adapter or config."""
        project_id = getattr(self.adapter, "project_id", None)
        if not project_id:
            raise SecOpsConfigurationError(
                "No GCP project_id configured on the adapter; pass project_id explicitly or set SECOPS_PROJECT_ID."
            )
        return project_id

    def get_chronicle_iam_bindings(
        self,
        project_id: Optional[str] = None,
    ) -> List[ChronicleIamRoleBinding]:
        """Queries GCP Cloud Resource Manager getIamPolicy for Chronicle-related role assignments.

        Args:
            project_id: Optional GCP project ID to inspect (defaults to engine project).

        Returns:
            List of ChronicleIamRoleBinding objects detailing members and role types.
        """
        proj = project_id or self.default_project_id
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{proj}:getIamPolicy"
        policy = self.adapter._request("POST", url, body={})

        bindings_raw = policy.get("bindings", [])
        chronicle_bindings: List[ChronicleIamRoleBinding] = []

        for b in bindings_raw:
            role = b.get("role", "")
            role_lower = role.lower()
            is_predefined = role in PREDEFINED_CHRONICLE_ROLES or role_lower.startswith("roles/chronicle.")
            is_custom = role.startswith(f"projects/{proj}/roles/")

            # Keep if predefined Chronicle role or project custom role mentioning chronicle or soar
            if is_predefined or (is_custom and ("chronicle" in role_lower or "secops" in role_lower)):
                title = PREDEFINED_CHRONICLE_ROLES.get(role)
                if not title:
                    if is_custom:
                        title = f"Custom Role ({role.split('/')[-1]})"
                    else:
                        title = role

                chronicle_bindings.append(
                    ChronicleIamRoleBinding(
                        role=role,
                        role_title=title,
                        is_custom=is_custom,
                        members=list(b.get("members", [])),
                        condition=b.get("condition"),
                    )
                )

        # Sort bindings by role name
        chronicle_bindings.sort(key=lambda x: x.role)
        return chronicle_bindings

    def get_chronicle_custom_roles(
        self,
        project_id: Optional[str] = None,
    ) -> List[ChronicleCustomRole]:
        """Queries GCP IAM API to list all custom roles containing chronicle.* permissions.

        Args:
            project_id: Optional GCP project ID to inspect.

        Returns:
            List of ChronicleCustomRole objects with included chronicle permissions.
        """
        proj = project_id or self.default_project_id
        url = f"https://iam.googleapis.com/v1/projects/{proj}/roles?view=FULL"
        resp = self.adapter._request("GET", url)

        roles_raw = resp.get("roles", [])
        custom_roles: List[ChronicleCustomRole] = []

        for r in roles_raw:
            included_perms = r.get("includedPermissions", [])
            chronicle_perms = [p for p in included_perms if p.startswith("chronicle.")]
            if chronicle_perms:
                custom_roles.append(
                    ChronicleCustomRole(
                        role_name=r.get("name", ""),
                        title=r.get("title", ""),
                        description=r.get("description", ""),
                        stage=r.get("stage", "GA"),
                        chronicle_permissions=sorted(chronicle_perms),
                        total_permissions_count=len(included_perms),
                    )
                )

        custom_roles.sort(key=lambda x: x.title or x.role_name)
        return custom_roles

    def fetch_inventory_identity_report(
        self,
        inventory_base_url: str = "http://localhost:8000",
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries SecOps Inventory service on local port 8000 for SecOps Access audit or Identity reports."""
        target_tenant = tenant_id or getattr(self.adapter, "tenant_id", None) or getattr(self.adapter, "project_id", None)
        if not target_tenant:
            raise SecOpsConfigurationError(
                "No inventory tenant_id configured; pass tenant_id explicitly or configure the adapter project_id."
            )

        # Resolve project name to numeric tenant ID if needed
        if not target_tenant.isdigit():
            try:
                t_req = urllib.request.Request(f"{inventory_base_url}/api/tenants", headers={"Accept": "application/json"})
                with urllib.request.urlopen(t_req, timeout=5.0) as t_resp:
                    tenants_data = json.loads(t_resp.read().decode("utf-8"))
                    for t in tenants_data:
                        if t.get("project_name") == target_tenant or t.get("project_id") == target_tenant:
                            target_tenant = t.get("project_id", target_tenant)
                            break
            except Exception as e:
                logger.debug("Failed to resolve tenant ID from %s: %s", target_tenant, e)

        audit_url = f"{inventory_base_url}/api/tenants/{target_tenant}/audits/SecOps%20Access/view"

        try:
            req = urllib.request.Request(audit_url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "source": "secops_inventory",
                    "status": "SUCCESS",
                    "tenant_id": target_tenant,
                    "roles_summary": data.get("results", {}).get("roles", {}),
                    "item_count": data.get("item_count", 0),
                    "download_url": data.get("download_url", ""),
                }
        except Exception as exc:
            logger.info("SecOps Inventory API not reachable at %s: %s", audit_url, exc)
            return {
                "source": "secops_inventory",
                "status": "UNAVAILABLE",
                "error": str(exc),
                "tenant_id": target_tenant,
            }

    def generate_governance_report(
        self,
        project_id: Optional[str] = None,
        inventory_base_url: str = "http://localhost:8000",
    ) -> IdentityGovernanceReport:
        """Generates a complete Identity Governance report combining IAM bindings, custom roles, and inventory data."""
        proj = project_id or self.default_project_id
        bindings = self.get_chronicle_iam_bindings(project_id=proj)
        custom_roles = self.get_chronicle_custom_roles(project_id=proj)
        inventory_summary = self.fetch_inventory_identity_report(
            inventory_base_url=inventory_base_url,
            tenant_id=proj,
        )

        all_members: Set[str] = set()
        for b in bindings:
            all_members.update(b.members)

        users_count = 0
        groups_count = 0
        sa_count = 0
        wf_count = 0

        for m in all_members:
            classified = classify_member(m)
            if classified.member_type == "user":
                users_count += 1
            elif classified.member_type == "group":
                groups_count += 1
            elif classified.member_type == "serviceAccount":
                sa_count += 1
            elif classified.member_type == "workforcePool":
                wf_count += 1

        return IdentityGovernanceReport(
            project_id=proj,
            timestamp=datetime.now(timezone.utc).isoformat(),
            chronicle_bindings=bindings,
            custom_roles=custom_roles,
            total_privileged_users=users_count,
            total_groups=groups_count,
            total_service_accounts=sa_count,
            total_workforce_pools=wf_count,
            inventory_summary=inventory_summary,
        )
