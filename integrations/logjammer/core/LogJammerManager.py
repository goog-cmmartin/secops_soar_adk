"""
LogJammer Manager for Google SecOps SOAR.

Orchestrates AI-driven synthetic security log generation using Google Gemini,
curated YARA-L detection rule deconstruction, schema guide lookup, Google Threat
Intelligence (GTI) enrichment, and direct Chronicle v1alpha log ingestion.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

# Ensure core directory is on sys.path for internal imports
CORE_DIR = str(Path(__file__).resolve().parent)
if CORE_DIR not in sys.path:
    sys.path.insert(0, CORE_DIR)

try:
    from core.config import LogJammerConfig, get_genai_client
    from core.generator import ScenarioGenerator
    from core.gti import GTIClient
    from core.models import GeneratedScenario, SecOpsRule
    from core.playbook import PlaybookService
    from core.rule_analyzer import RuleAnalyzer
    from core.rules import RuleService
    from core.sinks.secops import SecOpsSink
    from core.templates import extract_timestamp_from_text, parse_base_timestamp
except ImportError:
    from config import LogJammerConfig, get_genai_client
    from generator import ScenarioGenerator
    from gti import GTIClient
    from models import GeneratedScenario, SecOpsRule
    from playbook import PlaybookService
    from rule_analyzer import RuleAnalyzer
    from rules import RuleService
    from sinks.secops import SecOpsSink
    from templates import extract_timestamp_from_text, parse_base_timestamp

logger_default = logging.getLogger("LogJammerManager")


class SafeLogger:
    """Wrapper ensuring logger calls never fail across Siemplify and standard logging."""
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


class LogJammerManager:
    """Core manager facade for LogJammer SOAR Integration."""

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        gti_api_key: Optional[str] = None,
        service_account_json: Optional[str] = None,
        workload_identity_email: Optional[str] = None,
        gcp_project_id: Optional[str] = None,
        secops_customer_id: Optional[str] = None,
        secops_region: Optional[str] = "us",
        model_name: Optional[str] = "gemini-3.7-flash",
        logger: Optional[Any] = None,
    ):
        self.logger = SafeLogger(logger or logger_default)

        # 1. API Keys & Identifiers
        self.gemini_api_key = (
            gemini_api_key
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
            or None
        )
        self.gti_api_key = (
            gti_api_key
            or os.environ.get("GTI_API_KEY")
            or os.environ.get("VIRUSTOTAL_API_KEY")
            or None
        )
        self.service_account_json = service_account_json
        self.workload_identity_email = (
            str(workload_identity_email).strip()
            if workload_identity_email and str(workload_identity_email).strip()
            else None
        )
        self.model_name = model_name or "gemini-3.7-flash"

        # 2. GCP & SecOps Parameters
        self.gcp_project_id = (
            gcp_project_id
            or os.environ.get("GCP_PROJECT_NUMBER")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT_ID")
            or "37679061640"
        )
        self.secops_customer_id = (
            secops_customer_id
            or os.environ.get("SECOPS_CUSTOMER_ID")
            or os.environ.get("CHRONICLE_CUSTOMER_ID")
            or "a556547c-1cff-43ef-a2e4-cf5b12a865df"
        )
        self.secops_region = (secops_region or os.environ.get("CHRONICLE_REGION") or "us").lower()

        # Inferred project from service account email if applicable
        if not self.gcp_project_id and self.workload_identity_email and "@" in self.workload_identity_email:
            try:
                domain = self.workload_identity_email.split("@")[1]
                if ".iam.gserviceaccount.com" in domain:
                    self.gcp_project_id = domain.replace(".iam.gserviceaccount.com", "")
            except Exception:
                pass

        # 3. Path Configurations (Bundled Assets) & LogJammerConfig
        self.config = LogJammerConfig(
            api_key=self.gemini_api_key,
            gti_api_key=self.gti_api_key,
            model=self.model_name,
            customer_id=self.secops_customer_id,
            project_id=self.gcp_project_id,
            region=self.secops_region,
        )
        self.guides_dir = self.config.guides_dir
        self.rules_dir = self.config.rules_dir

        self._credentials = None

        # Attach resolved credentials if needed
        creds = self._get_cached_credentials()
        if creds:
            self.config.credentials = creds
            if not self.gemini_api_key:
                self.config.use_vertex = True

        # 5. Initialize Sub-services
        self.rule_service = RuleService(self.config)
        self.playbook_service = PlaybookService(self.config)
        available_types = [f.stem for f in self.guides_dir.glob("*.txt")] if self.guides_dir.exists() else []
        self.rule_analyzer = RuleAnalyzer(available_log_types=available_types)
        self.gti_client = GTIClient(api_key=self.gti_api_key)
        self.generator = ScenarioGenerator(self.config)

    def _get_cached_credentials(self) -> Any:
        """Retrieves Google OAuth2 credentials via WIF, Service Account, or ADC."""
        if self._credentials:
            return self._credentials

        scopes = ["https://www.googleapis.com/auth/cloud-platform"]

        # 1. Workload Identity Federation / SA Impersonation
        if self.workload_identity_email:
            try:
                from TIPCommon.rest.auth import build_credentials_from_sa
                self._credentials = build_credentials_from_sa(
                    target_principal=self.workload_identity_email,
                    scopes=scopes,
                    quota_project_id=self.gcp_project_id,
                )
                self.logger.info(f"Using WIF credentials via TIPCommon for {self.workload_identity_email}")
                return self._credentials
            except ImportError:
                pass
            except Exception as e:
                self.logger.warning(f"TIPCommon WIF resolution failed: {e}. Falling back to google.auth.")

            try:
                import google.auth
                from google.auth import impersonated_credentials
                source_creds, _ = google.auth.default(scopes=scopes)
                self._credentials = impersonated_credentials.Credentials(
                    source_credentials=source_creds,
                    target_principal=self.workload_identity_email,
                    target_scopes=scopes,
                    lifetime=3600,
                    quota_project_id=self.gcp_project_id,
                )
                return self._credentials
            except Exception as e:
                self.logger.warning(f"Workload identity impersonation failed: {e}")

        # 2. Service Account JSON key
        if self.service_account_json:
            try:
                from google.oauth2 import service_account
                if isinstance(self.service_account_json, dict):
                    self._credentials = service_account.Credentials.from_service_account_info(
                        self.service_account_json, scopes=scopes
                    )
                else:
                    sa_str = str(self.service_account_json).strip()
                    if sa_str.startswith("{"):
                        sa_info = json.loads(sa_str)
                        self._credentials = service_account.Credentials.from_service_account_info(
                            sa_info, scopes=scopes
                        )
                    elif os.path.exists(sa_str):
                        self._credentials = service_account.Credentials.from_service_account_file(
                            sa_str, scopes=scopes
                        )
                if self._credentials:
                    return self._credentials
            except Exception as e:
                self.logger.warning(f"Failed to load Service Account JSON credentials: {e}")

        # 3. Application Default Credentials (ADC)
        try:
            import google.auth
            self._credentials, _ = google.auth.default(scopes=scopes)
            return self._credentials
        except Exception as e:
            self.logger.debug(f"ADC authentication check: {e}")

        return None

    def test_connectivity(self) -> Dict[str, Any]:
        """Validates connection to Gemini / Vertex AI, bundled data, and SecOps parameters."""
        results = {
            "gemini_ok": False,
            "rules_catalog_ok": False,
            "guides_ok": False,
            "secops_destination_ok": False,
            "total_curated_rules": 0,
            "total_guides": 0,
            "errors": [],
        }

        # 1. Check bundled guides
        try:
            guides = list(self.guides_dir.glob("*.txt"))
            results["total_guides"] = len(guides)
            results["guides_ok"] = len(guides) > 0
            if not results["guides_ok"]:
                results["errors"].append(f"No guides found in {self.guides_dir}")
        except Exception as e:
            results["errors"].append(f"Guides directory check failed: {e}")

        # 2. Check bundled curated rules catalog
        try:
            cached_rules = self.rule_service.load_rules_from_cache(rule_type="curated")
            results["total_curated_rules"] = len(cached_rules)
            results["rules_catalog_ok"] = len(cached_rules) > 0
            if not results["rules_catalog_ok"]:
                results["errors"].append("Curated rules catalog empty or missing.")
        except Exception as e:
            results["errors"].append(f"Curated catalog check failed: {e}")

        # 3. Check Gemini / Vertex AI client
        try:
            client = get_genai_client(self.config)
            # Lightweight test prompt
            resp = client.models.generate_content(
                model=self.model_name,
                contents="ping",
            )
            results["gemini_ok"] = bool(resp and resp.text)
        except Exception as e:
            results["errors"].append(f"Gemini / Vertex AI ping failed: {e}")

        # 4. Check SecOps Destination config
        if self.secops_customer_id and self.gcp_project_id:
            results["secops_destination_ok"] = True
        else:
            results["errors"].append("Missing SecOps customer_id or project_id")

        return results

    def search_curated_rules(
        self,
        query: Optional[str] = None,
        technique: Optional[str] = None,
        tactic: Optional[str] = None,
        category: Optional[str] = None,
        precision: Optional[str] = None,
        alerting_only: bool = False,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Search across bundled curated detection rules."""
        raw_rules = self.rule_service.search_rules(
            query=query,
            technique=technique,
            tactic=tactic,
            rule_type="curated",
            precision=precision,
            alerting_only=alerting_only,
        )

        matched: List[Dict[str, Any]] = []
        for r in raw_rules:
            rule_cat = r.raw_data.get("category", "")
            if category and category.lower() not in rule_cat.lower():
                continue

            matched.append({
                "rule_id": r.rule_id,
                "display_name": r.display_name,
                "severity": r.severity,
                "precision": r.raw_data.get("precision", ""),
                "alerting": r.raw_data.get("alerting", False),
                "category": rule_cat,
                "ruleset_name": r.raw_data.get("ruleset_name", ""),
                "techniques": r.techniques,
                "tactics": r.tactics,
                "text": r.text,
            })
            if len(matched) >= limit:
                break

        return matched

    def get_curated_rule(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific curated rule by ID or display name."""
        rule = self.rule_service.get_rule(identifier)
        if not rule:
            return None
        return {
            "rule_id": rule.rule_id,
            "display_name": rule.display_name,
            "severity": rule.severity,
            "category": rule.raw_data.get("category", ""),
            "ruleset_name": rule.raw_data.get("ruleset_name", ""),
            "techniques": rule.techniques,
            "tactics": rule.tactics,
            "text": rule.text,
        }

    def generate_scenario(
        self,
        scenario_prompt: str,
        log_types: Optional[List[str]] = None,
        rule_identifier: Optional[str] = None,
        rule_outcome: str = "fire",
        count: int = 5,
        enrich_gti: bool = False,
        ingest_to_secops: bool = True,
        scenario_name: Optional[str] = None,
        base_time: Optional[Union[str, int, float, datetime]] = None,
    ) -> Dict[str, Any]:
        """
        Generate synthetic security logs for an attack scenario or curated detection rule,
        with optional GTI enrichment, anchor timestamp backdating, and direct Google SecOps ingestion.
        """
        self.logger.info(f"Generating synthetic logs (Scenario: '{scenario_prompt[:60]}...', Rule: {rule_identifier})")
        start_time = datetime.now(timezone.utc)
        resolved_base_time = (
            parse_base_timestamp(base_time)
            or extract_timestamp_from_text(scenario_prompt)
            or start_time
        )
        self.logger.info(
            f"Resolved anchor base timestamp for log generation: "
            f"{resolved_base_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )

        # 1. Optional Google Threat Intelligence enrichment
        gti_context = None
        prompt_to_use = scenario_prompt
        if enrich_gti:
            if self.gti_client.is_configured():
                try:
                    self.logger.info("Enriching scenario with Google Threat Intelligence (GTI)...")
                    gti_context = self.gti_client.enrich_scenario(scenario_prompt)
                    prompt_to_use = f"{scenario_prompt}\n\n[Google Threat Intelligence Grounding & IOCs]:\n{gti_context}"
                except Exception as e:
                    self.logger.warning(f"GTI enrichment failed ({e}), proceeding with original prompt.")
            else:
                self.logger.warning("GTI enrichment requested but GTI API Key is not configured.")

        # 2. Rule Resolution & Scenario Generation (supports AUTO_PRECISE / AUTO or single/comma-separated rule IDs)
        rule_obj: Optional[SecOpsRule] = None
        unresolved_rules: List[str] = []
        if rule_identifier and rule_identifier.strip():
            norm_rule_id = rule_identifier.strip().upper()
            if norm_rule_id in ("AUTO_PRECISE", "AUTO", "PRECISE"):
                self.logger.info(
                    f"Auto-selecting best matching PRECISE (alerting=True) Curated Detection Rule for scenario..."
                )
                rule_obj = self.rule_service.find_best_curated_rule(
                    scenario_text=scenario_prompt,
                    log_types=log_types,
                    precision="PRECISE",
                    alerting_only=True,
                    live_only=True,
                )
                if rule_obj:
                    self.logger.info(
                        f"Selected PRECISE Curated Rule: {rule_obj.rule_id} "
                        f"('{rule_obj.display_name}', ruleset='{rule_obj.raw_data.get('ruleset_name', '')}', "
                        f"alerting={rule_obj.raw_data.get('alerting', True)})"
                    )
                else:
                    self.logger.warning(
                        "No matching PRECISE curated rule found for scenario; proceeding with free-form scenario generation."
                    )
            elif norm_rule_id in ("AUTO_BROAD", "BROAD"):
                rule_obj = self.rule_service.find_best_curated_rule(
                    scenario_text=scenario_prompt,
                    log_types=log_types,
                    precision="BROAD",
                    alerting_only=False,
                    live_only=True,
                )
                if rule_obj:
                    self.logger.info(f"Selected BROAD Curated Rule: {rule_obj.rule_id} ('{rule_obj.display_name}')")
            else:
                raw_ids = [r.strip() for r in rule_identifier.split(",") if r.strip()]
                resolved_rules: List[SecOpsRule] = []
                for rid in raw_ids:
                    r_match = self.rule_service.get_rule(rid)
                    if r_match:
                        resolved_rules.append(r_match)
                    else:
                        unresolved_rules.append(rid)

                if len(resolved_rules) == 1:
                    rule_obj = resolved_rules[0]
                elif len(resolved_rules) > 1:
                    combined_ids = ",".join(r.rule_id for r in resolved_rules)
                    combined_names = " + ".join(r.display_name for r in resolved_rules)
                    combined_text = "\n\n".join(
                        f"// === STAGE RULE {idx + 1}: {r.display_name} ({r.rule_id}) ===\n{r.text}"
                        for idx, r in enumerate(resolved_rules)
                    )
                    combined_tactics = sorted(list({t for r in resolved_rules for t in (r.tactics or [])}))
                    combined_techniques = sorted(list({t for r in resolved_rules for t in (r.techniques or [])}))
                    rule_obj = SecOpsRule(
                        rule_id=combined_ids,
                        display_name=combined_names,
                        text=combined_text,
                        severity=resolved_rules[0].severity,
                        tactics=combined_tactics,
                        techniques=combined_techniques,
                        rule_owner=resolved_rules[0].rule_owner,
                    )

                if unresolved_rules:
                    self.logger.warning(
                        f"Rule identifier(s) not found in local catalog or tenant API: {unresolved_rules}. "
                        "Incorporating rule IDs and outcome objective into scenario narrative context."
                    )
                    prompt_to_use = (
                        f"{prompt_to_use}\n\n"
                        f"[Target Detection Rule IDs]: {', '.join(raw_ids)}\n"
                        f"[Rule Simulation Objective]: {rule_outcome.upper()} "
                        "(Ensure every stage, threshold, byte size, HTTP status, and process tree in the narrative is satisfied)."
                    )
                    if not resolved_rules and (not scenario_prompt or len(scenario_prompt.strip()) < 10):
                        raise ValueError(
                            f"Detection rule(s) '{rule_identifier}' could not be found in catalog or tenant API, "
                            "and no detailed Scenario Prompt was provided for fallback generation."
                        )

        if rule_obj:
            self.logger.info(f"Generating logs from rule '{rule_obj.display_name}' (outcome: {rule_outcome})")
            scenario: GeneratedScenario = self.generator.generate_from_rule(
                rule=rule_obj,
                log_types=log_types,
                outcome=rule_outcome,
                base_time=resolved_base_time,
                count=count,
                additional_context=prompt_to_use,
            )
        else:
            self.logger.info(f"Generating logs for requested types: {log_types or 'Auto-infer'}")
            scenario: GeneratedScenario = self.generator.generate(
                scenario=prompt_to_use,
                log_types=log_types,
                base_time=resolved_base_time,
                count=count,
            )

        duration_sec = round((datetime.now(timezone.utc) - start_time).total_seconds(), 2)

        # 3. Format generated telemetry
        categorized_logs: Dict[str, List[str]] = {}
        for lt, entry_list in scenario.logs.items():
            upper_lt = lt.upper()
            if upper_lt not in categorized_logs:
                categorized_logs[upper_lt] = []
            for entry in entry_list:
                categorized_logs[upper_lt].append(entry.content)

        total_event_count = scenario.total_log_count

        # 4. Optional SecOps Chronicle Ingestion
        short_scenario_id = (scenario.scenario_id or "")[:8]
        effective_tag = (
            str(scenario_name).strip()
            if scenario_name and str(scenario_name).strip()
            else f"logjammer-{short_scenario_id}"
        )
        default_labels = {
            "SOURCE": "LOGJAMMER",
            "SCENARIO_ID": short_scenario_id,
            "SCENARIO_TAG": effective_tag,
        }
        udm_query = f'metadata.ingestion_labels.value = "{short_scenario_id}"'
        udm_query_full = (
            'metadata.ingestion_labels.key = "SCENARIO_ID" AND '
            f'metadata.ingestion_labels.value = "{short_scenario_id}"'
        )
        udm_tag_query = (
            'metadata.ingestion_labels.key = "SCENARIO_TAG" AND '
            f'metadata.ingestion_labels.value = "{effective_tag}"'
        )

        ingestion_result: Dict[str, Any] = {
            "attempted": ingest_to_secops,
            "status": "SKIPPED" if not ingest_to_secops else "PENDING",
            "ingested_count": 0,
            "customer_id": self.secops_customer_id,
            "project_id": self.gcp_project_id,
            "region": self.secops_region,
            "log_types": list(categorized_logs.keys()),
            "scenario_id_label": short_scenario_id,
            "scenario_tag": effective_tag,
            "labels": default_labels,
            "udm_query": udm_query,
            "udm_query_full": udm_query_full,
            "udm_tag_query": udm_tag_query,
            "details": [],
        }

        if ingest_to_secops and total_event_count > 0:
            try:
                self.logger.info(f"Ingesting {total_event_count} synthetic events directly to Google SecOps...")
                sink = SecOpsSink(
                    customer_id=self.secops_customer_id,
                    project_number=self.gcp_project_id,
                    region=self.secops_region,
                    scenario_name=scenario_name or scenario.title,
                    credentials=self.config.credentials,
                )
                count_ingested = sink.emit(scenario)
                ingestion_result["status"] = "SUCCESS"
                ingestion_result["ingested_count"] = count_ingested
                ingestion_result["labels"] = sink.last_export_metadata.get("labels", default_labels)
                ingestion_result["scenario_tag"] = sink.last_export_metadata.get("scenario_tag", effective_tag)
                ingestion_result["details"] = sink.last_export_metadata.get("batches", [])
                self.logger.info(
                    f"Successfully ingested {count_ingested} events into Google SecOps "
                    f"(UDM Search: {udm_query})."
                )
            except Exception as e:
                self.logger.error(f"SecOps log ingestion failed: {e}")
                ingestion_result["status"] = "ERROR"
                ingestion_result["error_message"] = str(e)

        # 5. Build Result Dictionary
        return {
            "scenario_id": scenario.scenario_id,
            "scenario_id_label": short_scenario_id,
            "scenario_tag": ingestion_result.get("scenario_tag", effective_tag),
            "base_timestamp": resolved_base_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "udm_query": udm_query,
            "udm_query_full": udm_query_full,
            "udm_tag_query": udm_tag_query,
            "title": scenario.title,
            "summary": scenario.summary,
            "log_types": list(categorized_logs.keys()),
            "total_events": total_event_count,
            "duration_seconds": duration_sec,
            "model": self.model_name,
            "gti_enriched": bool(gti_context),
            "gti_summary": gti_context[:500] + "..." if gti_context else None,
            "rule": {
                "rule_id": rule_obj.rule_id,
                "display_name": rule_obj.display_name,
                "severity": rule_obj.severity,
                "precision": rule_obj.raw_data.get("precision", "PRECISE"),
                "alerting": rule_obj.raw_data.get("alerting", True),
                "ruleset_name": rule_obj.raw_data.get("ruleset_name", ""),
                "outcome": rule_outcome,
                "techniques": rule_obj.techniques,
                "tactics": rule_obj.tactics,
            } if rule_obj else None,
            "secops_ingestion": ingestion_result,
            "logs": categorized_logs,
        }
