"""
SecOpsSDKEngineManager.py - Manager layer for Google SecOps SDK Engine SOAR Integration.

Completely decoupled from SOAR SDK following the Siemplify / Chronicle Manager Pattern.
Provides high-performance, deterministic SIEM/SOAR correlation, silent non-alerting
detection discovery, entity investigation, and native case evidence attachment.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import types
from typing import Any, Dict, List, Optional, Union

# Set up virtual namespace shims for flattened SOAR execution environment
def _setup_secops_shims():
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    core_dir = os.path.join(os.path.dirname(cur_dir), "core")
    
    if os.path.isdir(os.path.join(cur_dir, "engine")):
        engine_path = [os.path.join(cur_dir, "engine")]
        wf_path = [os.path.join(cur_dir, "engine", "workflows")]
        adapters_path = [os.path.join(cur_dir, "adapters")]
    elif os.path.isdir(core_dir) and os.path.isdir(os.path.join(core_dir, "engine")):
        engine_path = [os.path.join(core_dir, "engine")]
        wf_path = [os.path.join(core_dir, "engine", "workflows")]
        adapters_path = [os.path.join(core_dir, "adapters")]
    else:
        engine_path = [cur_dir]
        wf_path = [cur_dir]
        adapters_path = [cur_dir]

    if "engine" not in sys.modules:
        mod = types.ModuleType("engine")
        mod.__path__ = engine_path
        sys.modules["engine"] = mod
    else:
        sys.modules["engine"].__path__ = engine_path

    if "engine.workflows" not in sys.modules:
        mod_wf = types.ModuleType("engine.workflows")
        mod_wf.__path__ = wf_path
        sys.modules["engine.workflows"] = mod_wf
        setattr(sys.modules["engine"], "workflows", mod_wf)
    else:
        sys.modules["engine.workflows"].__path__ = wf_path

    if "adapters" not in sys.modules:
        mod_ad = types.ModuleType("adapters")
        mod_ad.__path__ = adapters_path
        sys.modules["adapters"] = mod_ad
    else:
        sys.modules["adapters"].__path__ = adapters_path
_setup_secops_shims()

import google.auth
from google.auth import impersonated_credentials
from google.auth.transport.requests import Request
from google.oauth2 import service_account

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from engine.auth import AUTH_SCOPES, CredentialProvider
from engine.config import SecOpsConfig
from adapters.google_secops import GoogleSecOpsAdapter
from engine.workflows.case_actions import (
    CreateCaseAlertRecommendationWorkflow,
    GetOrCreateCaseSummaryWorkflow,
)
from engine.workflows.case_evidence import AttachCaseEvidenceWorkflow, DetachCaseEvidenceWorkflow
from engine.workflows.case_investigation import InvestigateCaseWorkflow
from engine.workflows.case_list import ListCasesWorkflow
from engine.workflows.correlate_silent_detections import CorrelateSilentDetectionsWorkflow
from engine.workflows.homepage_dashboard import SyncSecOpsHomepageDashboardWorkflow
from engine.workflows.related_cases_by_entity import RelatedCasesByEntityWorkflow
from engine.workflows.search_udm import SearchUDMWorkflow

logger_default = logging.getLogger("SecOpsSDKEngineManager")


class SafeLogger:
    """
    Wrapper for SiemplifyLogger and standard logging.Logger.
    Ensures that .warning(), .error(), .info(), and .debug() never fail
    due to missing methods on Siemplify's logger interface.
    """
    def __init__(self, logger: Any):
        self._logger = logger

    def info(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "info"):
            self._logger.info(msg, *args, **kwargs)
        elif hasattr(self._logger, "log"):
            self._logger.log(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "error"):
            self._logger.error(msg, *args, **kwargs)
        elif hasattr(self._logger, "info"):
            self._logger.info(f"ERROR: {msg}")

    def warning(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "warning"):
            self._logger.warning(msg, *args, **kwargs)
        elif hasattr(self._logger, "warn"):
            self._logger.warn(msg, *args, **kwargs)
        elif hasattr(self._logger, "info"):
            self._logger.info(f"WARNING: {msg}")

    def debug(self, msg: str, *args, **kwargs) -> None:
        if hasattr(self._logger, "debug"):
            self._logger.debug(msg, *args, **kwargs)
        elif hasattr(self._logger, "info"):
            self._logger.info(f"DEBUG: {msg}")


class SecOpsSDKCredentialProvider(CredentialProvider):
    """
    CredentialProvider that integrates with SOAR parameter resolution:
    - Priority 1: Workload Identity Federation (WIF) / Service Account Impersonation
    - Priority 2: Service Account JSON private key
    - Priority 3: Application Default Credentials (ADC) / Environment
    """
    def __init__(
        self,
        service_account_json: Optional[Union[str, Dict[str, Any]]] = None,
        workload_identity_email: Optional[str] = None,
        project_id: Optional[str] = None,
        logger: Optional[SafeLogger] = None,
    ):
        super().__init__()
        self.service_account_json = service_account_json
        self.workload_identity_email = workload_identity_email
        self.project_id = project_id
        self.logger = logger or SafeLogger(logging.getLogger("SecOpsSDKCredentialProvider"))
        self._resolved_creds = None
        self._creds_lock = threading.Lock()

    def _get_credentials_object(self) -> Any:
        with self._creds_lock:
            if self._resolved_creds is not None:
                return self._resolved_creds

            scopes = list(AUTH_SCOPES)

            # 1. Workload Identity Federation (Keyless)
            if self.workload_identity_email and str(self.workload_identity_email).strip():
                target_email = str(self.workload_identity_email).strip()
                try:
                    from TIPCommon.rest.auth import build_credentials_from_sa
                    self._resolved_creds = build_credentials_from_sa(
                        target_principal=target_email,
                        scopes=scopes,
                        quota_project_id=self.project_id,
                    )
                    self.logger.info(
                        f"Successfully established Workload Identity credentials for {target_email} via TIPCommon."
                    )
                    return self._resolved_creds
                except (ImportError, Exception) as e:
                    self.logger.info(
                        f"TIPCommon not available ({e}); falling back to standard google.auth impersonation."
                    )

                try:
                    source_creds, _ = google.auth.default(scopes=scopes)
                    impersonated = impersonated_credentials.Credentials(
                        source_credentials=source_creds,
                        target_principal=target_email,
                        target_scopes=scopes,
                        lifetime=3600,
                        quota_project_id=self.project_id,
                    )
                    req = Request()
                    impersonated.refresh(req)
                    self._resolved_creds = impersonated
                    self.logger.info(
                        f"Successfully generated impersonated Workload Identity credentials for {target_email}"
                    )
                    return self._resolved_creds
                except Exception as e:
                    self.logger.warning(
                        f"Workload Identity token generation for '{target_email}' raised: {e}. Falling back to Service Account / ADC."
                    )

            # 2. Service Account JSON Key
            if self.service_account_json and str(self.service_account_json).strip() not in ("", "{}"):
                try:
                    if isinstance(self.service_account_json, str):
                        info = json.loads(self.service_account_json)
                    else:
                        info = self.service_account_json
                    self._resolved_creds = service_account.Credentials.from_service_account_info(
                        info, scopes=scopes
                    )
                    self.logger.info("Successfully loaded credentials from Service Account JSON.")
                    return self._resolved_creds
                except Exception as e:
                    self.logger.warning(
                        f"Failed to load Service Account JSON credentials: {e}. Falling back to ADC."
                    )

            # 3. Fallback to default google-auth ADC
            try:
                creds, _ = google.auth.default(scopes=scopes)
                req = Request()
                if not creds.valid or not creds.token:
                    creds.refresh(req)
                self._resolved_creds = creds
                self.logger.info("Loaded credentials via Application Default Credentials (ADC).")
                return self._resolved_creds
            except Exception as e:
                self.logger.warning(f"Could not load Application Default Credentials: {e}")
                raise RuntimeError(
                    f"Authentication failed: Unable to acquire credentials via Workload Identity, Service Account JSON, or ADC: {e}"
                )

    def get_token(self) -> str:
        creds = self._get_credentials_object()
        req = Request()
        if not creds.valid or not creds.token:
            creds.refresh(req)
        return str(creds.token)


class SecOpsSDKEngineManager:
    """
    High-level manager orchestrating SecOps SDK workflows inside SOAR actions.
    """
    def __init__(
        self,
        customer_id: str,
        project_id: Optional[str] = None,
        region: str = "us",
        service_account_json: Optional[Union[str, Dict[str, Any]]] = None,
        workload_identity_email: Optional[str] = None,
        verify_ssl: bool = True,
        logger: Any = None,
    ):
        self.logger = SafeLogger(logger or logger_default)
        self.customer_id = str(customer_id or "").strip()
        self.region = str(region or "us").strip().lower()
        self.service_account_json = (
            service_account_json if service_account_json and str(service_account_json).strip() else None
        )
        self.workload_identity_email = (
            str(workload_identity_email).strip() if workload_identity_email and str(workload_identity_email).strip() else None
        )
        self.project_id = str(project_id).strip() if project_id and str(project_id).strip() else None

        # Auto-infer project_id if missing
        if not self.project_id and self.workload_identity_email and "@" in self.workload_identity_email:
            domain = self.workload_identity_email.split("@")[1]
            if ".iam.gserviceaccount.com" in domain:
                self.project_id = domain.replace(".iam.gserviceaccount.com", "")

        if not self.project_id and self.service_account_json:
            try:
                sa_data = (
                    json.loads(self.service_account_json)
                    if isinstance(self.service_account_json, str)
                    else self.service_account_json
                )
                self.project_id = sa_data.get("project_id")
            except Exception:
                pass

        if not self.project_id:
            self.project_id = os.environ.get("GCP_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT") or "sdl-preview-americas"

        self.api_base = f"https://{self.region}-chronicle.googleapis.com"
        self.config = SecOpsConfig(
            project_id=self.project_id,
            customer_id=self.customer_id,
            project_number=self.project_id,
            location=self.region,
            api_base=self.api_base,
        )

        self.credential_provider = SecOpsSDKCredentialProvider(
            service_account_json=self.service_account_json,
            workload_identity_email=self.workload_identity_email,
            project_id=self.project_id,
            logger=self.logger,
        )

        self.adapter = GoogleSecOpsAdapter(
            config=self.config,
            credential_provider=self.credential_provider,
        )

        self.correlate_workflow = CorrelateSilentDetectionsWorkflow(adapter=self.adapter)
        self.related_cases_workflow = RelatedCasesByEntityWorkflow(adapter=self.adapter)
        self.attach_workflow = AttachCaseEvidenceWorkflow(adapter=self.adapter)
        self.investigate_workflow = InvestigateCaseWorkflow(adapter=self.adapter)
        self.list_cases_workflow = ListCasesWorkflow(adapter=self.adapter)
        self.case_summary_workflow = GetOrCreateCaseSummaryWorkflow(adapter=self.adapter)
        self.alert_recommendation_workflow = CreateCaseAlertRecommendationWorkflow(adapter=self.adapter)
        self.homepage_dashboard_workflow = SyncSecOpsHomepageDashboardWorkflow(adapter=self.adapter)

    def test_connection(self) -> Dict[str, Any]:
        """
        Validates API authentication and performs live handshake with Google SecOps.
        """
        token = self.credential_provider.get_token()
        if not token:
            raise RuntimeError("Failed to obtain OAuth2 access token for Google SecOps.")

        cases = self.adapter.list_cases(page_size=1)
        total_found = len(cases.cases) if hasattr(cases, "cases") else 0
        self.logger.info(f"Handshake confirmed. Connected to customer {self.customer_id} in {self.region}.")
        return {
            "status": "connected",
            "customer_id": self.customer_id,
            "project_id": self.project_id,
            "region": self.region,
            "api_base": self.api_base,
            "cases_accessible": total_found,
        }

    def correlate_silent_detections(
        self,
        case_id: Union[str, int],
        lookback_hours: int = 24,
        attach_to_case: bool = False,
        attach_entities: bool = True,
        post_wall_comment: bool = True,
        entity_filter: Optional[List[str]] = None,
        entity_filter_mode: str = "AUTO",
        max_events: int = 1000,
        correlate_detections: bool = True,
        correlate_udm_events: bool = False,
        attach_udm_events: bool = False,
        extract_entities_from_events: bool = False,
        alert_vendor_filter: Optional[str] = "Google Chronicle",
        max_entities_to_attach: int = 5,
    ) -> Any:
        """
        Executes CorrelateSilentDetectionsWorkflow.
        """
        return self.correlate_workflow.execute(
            case_id=case_id,
            lookback_hours=lookback_hours,
            attach_to_case=attach_to_case,
            attach_entities=attach_entities,
            post_wall_comment=post_wall_comment,
            entity_filter=entity_filter,
            entity_filter_mode=entity_filter_mode,
            max_events=max_events,
            correlate_detections=correlate_detections,
            correlate_udm_events=correlate_udm_events,
            attach_udm_events=attach_udm_events,
            extract_entities_from_events=extract_entities_from_events,
            alert_vendor_filter=alert_vendor_filter,
            max_entities_to_attach=max_entities_to_attach,
        )

    def add_case_alert_entity(
        self,
        case_id: Union[str, int],
        case_alert_id: Union[str, int],
        identifier: str,
        entity_type: str = "IP",
    ) -> Dict[str, Any]:
        """Manually attaches an involved entity to a specific case alert."""
        return self.adapter.add_case_alert_entity(
            case_id=str(case_id),
            case_alert_id=str(case_alert_id),
            identifier=identifier,
            entity_type=entity_type,
        )

    def search_unique_entities(
        self,
        filter_expr: Optional[str] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Searches unique entities across the SecOps instance."""
        return self.adapter.search_unique_entities(
            filter_expr=filter_expr,
            page_size=page_size,
            page_token=page_token,
        )

    def related_cases_by_entity(
        self,
        case_id: Union[str, int],
        lookback_days: int = 90,
        case_status_scope: str = "ALL",
        min_shared_entities: int = 1,
        max_related_cases: int = 50,
        max_entities_to_search: int = 25,
        include_threat_actors: bool = False,
        entity_filter: Optional[List[str]] = None,
        entity_filter_mode: str = "AUTO",
        post_wall_comment: bool = False,
        secops_ui_base_url: str = "",
    ) -> Any:
        """Executes RelatedCasesByEntityWorkflow to find active and historical cases sharing entities."""
        return self.related_cases_workflow.execute(
            case_id=case_id,
            lookback_days=lookback_days,
            case_status_scope=case_status_scope,
            min_shared_entities=min_shared_entities,
            max_related_cases=max_related_cases,
            max_entities_to_search=max_entities_to_search,
            include_threat_actors=include_threat_actors,
            entity_filter=entity_filter,
            entity_filter_mode=entity_filter_mode,
            post_wall_comment=post_wall_comment,
            secops_ui_base_url=secops_ui_base_url,
        )

    def prewarm_case_summaries(
        self,
        lookback_minutes: int = 60,
        max_cases: int = 25,
        priorities: Optional[List[str]] = None,
        environments: Optional[List[str]] = None,
        include_alert_recommendations: bool = False,
        processed_case_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Polls for recently created open SOAR cases and initiates the Gemini AI Case Triage Summary
        (:getOrCreateCaseSummary) in advance so the summary is pre-computed and cached in the GUI
        before an analyst opens the case. Optionally also initiates Alert-level Gemini recommendations.
        """
        max_cases = max(1, min(200, int(max_cases or 25)))
        lookback_minutes = int(lookback_minutes if lookback_minutes is not None else 60)
        already_processed = set(str(cid).strip() for cid in (processed_case_ids or []) if str(cid).strip())

        batch = self.list_cases_workflow.execute(
            status="OPENED",
            priorities=priorities if priorities else None,
            environments=environments if environments else None,
            order_by="createTime desc",
            max_results=max_cases,
            page_size=min(max_cases, 100),
        )

        now_utc = datetime.now(timezone.utc)
        cutoff_time = (
            now_utc - timedelta(minutes=lookback_minutes)
            if lookback_minutes > 0
            else None
        )

        candidate_cases = []
        skipped_already_processed = 0
        skipped_outside_window = 0

        for item in batch.cases:
            cid = str(item.case_id).strip()
            if not cid:
                continue
            if cid in already_processed:
                skipped_already_processed += 1
                continue
            if cutoff_time is not None:
                ref_time = item.create_time or item.update_time
                if ref_time is not None and ref_time < cutoff_time:
                    skipped_outside_window += 1
                    continue
            candidate_cases.append(item)

        self.logger.info(
            f"Discovered {len(batch.cases)} open cases (candidates={len(candidate_cases)}, "
            f"skipped_already_processed={skipped_already_processed}, "
            f"skipped_outside_window={skipped_outside_window})."
        )

        case_details: List[Dict[str, Any]] = []
        newly_processed_ids: List[str] = []
        already_cached_count = 0
        initiated_in_progress_count = 0
        error_count = 0
        alert_recs_triggered = 0

        def _trigger_for_case(case_item: Any) -> Dict[str, Any]:
            cid = str(case_item.case_id).strip()
            entry: Dict[str, Any] = {
                "case_id": cid,
                "display_name": case_item.display_name,
                "priority": str(getattr(case_item.priority, "value", case_item.priority)),
                "create_time": case_item.create_time.isoformat() if case_item.create_time else None,
                "summary_state": "UNKNOWN",
                "alert_recommendations_triggered": 0,
                "error": None,
            }
            try:
                summary_res = self.case_summary_workflow.execute(case_id=cid)
                entry["summary_state"] = summary_res.state
                if summary_res.summary:
                    entry["summary_preview"] = str(summary_res.summary)[:160]
            except Exception as exc:
                entry["summary_state"] = "ERROR"
                entry["error"] = str(exc)

            if include_alert_recommendations and entry["summary_state"] != "ERROR":
                try:
                    alerts = self.adapter.list_case_alerts(cid)
                    triggered_for_case = 0
                    for a in alerts[:10]:
                        aid = str(a.get("identifier") or a.get("name", "").split("/")[-1]).strip()
                        if not aid:
                            continue
                        try:
                            self.alert_recommendation_workflow.execute(case_id=cid, alert_id=aid)
                            triggered_for_case += 1
                        except Exception as alert_exc:
                            self.logger.debug(
                                f"Alert recommendation trigger skipped/failed for case {cid} alert {aid}: {alert_exc}"
                            )
                    entry["alert_recommendations_triggered"] = triggered_for_case
                except Exception as list_exc:
                    self.logger.debug(f"Could not list alerts for case {cid}: {list_exc}")

            return entry

        if candidate_cases:
            workers = min(8, len(candidate_cases))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(_trigger_for_case, c): c
                    for c in candidate_cases
                }
                for fut in as_completed(future_map):
                    res_entry = fut.result()
                    case_details.append(res_entry)
                    st = res_entry.get("summary_state", "")
                    alert_recs_triggered += int(res_entry.get("alert_recommendations_triggered", 0) or 0)
                    if st == "SUCCESSFUL":
                        already_cached_count += 1
                        newly_processed_ids.append(res_entry["case_id"])
                    elif st in ("IN_PROGRESS", "PENDING", "SUMMARY_STATE_UNSPECIFIED", "RUNNING"):
                        initiated_in_progress_count += 1
                        newly_processed_ids.append(res_entry["case_id"])
                    else:
                        error_count += 1

        case_details.sort(key=lambda d: int(d["case_id"]) if str(d["case_id"]).isdigit() else str(d["case_id"]), reverse=True)

        return {
            "cases_fetched": len(batch.cases),
            "candidates_evaluated": len(candidate_cases),
            "skipped_already_processed": skipped_already_processed,
            "skipped_outside_window": skipped_outside_window,
            "initiated_in_progress_count": initiated_in_progress_count,
            "already_cached_count": already_cached_count,
            "error_count": error_count,
            "alert_recommendations_triggered": alert_recs_triggered,
            "newly_processed_case_ids": newly_processed_ids,
            "cases": case_details,
        }

    def sync_secops_homepage_dashboard(
        self,
        dashboard_title: str = "Google SecOps Homepage",
        dashboard_id: Optional[str] = None,
        community_categories: Optional[List[str]] = None,
        status_lookback_days: int = 30,
        max_release_notes: int = 4,
        max_community_posts: int = 6,
        include_tenant_health: bool = True,
        ai_executive_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synchronizes the Google SecOps Homepage Native Dashboard."""
        return self.homepage_dashboard_workflow.execute(
            dashboard_title=dashboard_title,
            dashboard_id=dashboard_id,
            community_categories=community_categories,
            status_lookback_days=status_lookback_days,
            max_release_notes=max_release_notes,
            max_community_posts=max_community_posts,
            include_tenant_health=include_tenant_health,
            ai_executive_summary=ai_executive_summary,
        )



