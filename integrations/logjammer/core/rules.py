"""Google SecOps (Chronicle) rule management and retrieval service."""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional
import urllib.error
import urllib.request

from .config import LogJammerConfig
from .models import SecOpsRule

logger = logging.getLogger(__name__)


def slugify(s: str) -> str:
  """Create clean filesystem slug."""
  if not s:
    return "uncategorized"
  cleaned = re.sub(r"[^\w]+", "_", s.strip().lower()).strip("_")
  return cleaned or "uncategorized"


def extract_mitre_ids(rule_data: Dict[str, Any], text: str = "") -> tuple[List[str], List[str]]:
  """Extract MITRE ATT&CK techniques and tactics from rule tags and YARA-L text."""
  techniques = set()
  tactics = set()

  # 1. Tags extraction (e.g., projects/.../tags/google.mitre.technique.t1564)
  tags = rule_data.get("tags", [])
  for tag in tags:
    tag_str = str(tag).lower()
    tech_match = re.search(r"technique\.(t\d{4}(?:\.\d{3})?)", tag_str)
    if tech_match:
      techniques.add(tech_match.group(1).upper())
    tac_match = re.search(r"tactic\.(ta\d{4})", tag_str)
    if tac_match:
      tactics.add(tac_match.group(1).upper())

  # 2. Text regex extraction from meta section
  search_corpus = f"{text} {' '.join(tags)}"
  found_techs = re.findall(r"\b(T\d{4}(?:\.\d{3})?)\b", search_corpus, re.IGNORECASE)
  for t in found_techs:
    techniques.add(t.upper())

  found_tacs = re.findall(r"\b(TA\d{4})\b", search_corpus, re.IGNORECASE)
  for t in found_tacs:
    tactics.add(t.upper())

  return sorted(list(techniques)), sorted(list(tactics))


class RuleService:
  """Manages Google SecOps YARA-L rules retrieval, local disk caching, and querying."""

  def __init__(self, config: Optional[LogJammerConfig] = None):
    self.config = config or LogJammerConfig()
    self.cache_file = self.config.rules_dir / "catalog.json"
    self.curated_cache_file = self.config.rules_dir / "curated_catalog.json"
    self.curated_dir = self.config.rules_dir / "curated"

  def _get_auth_token(self) -> str:
    """Retrieve Google OAuth2 access token via google-auth or gcloud CLI."""
    try:
      import google.auth
      import google.auth.transport.requests

      scopes = ["https://www.googleapis.com/auth/chronicle-siem", "https://www.googleapis.com/auth/cloud-platform"]
      if getattr(self.config, "credentials", None) is not None:
        creds = self.config.credentials
        if not getattr(creds, "valid", False) or getattr(creds, "expired", True):
          req = google.auth.transport.requests.Request()
          creds.refresh(req)
        return creds.token
      elif self.config.credentials_file:
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(
            self.config.credentials_file, scopes=scopes
        )
      else:
        creds, _ = google.auth.default(scopes=scopes)
      req = google.auth.transport.requests.Request()
      creds.refresh(req)
      return creds.token
    except Exception as e:
      import subprocess

      try:
        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if token:
          return token
      except Exception:
        pass
      raise RuntimeError(
          f"Failed to obtain GCP authentication credentials for Google SecOps: {e}\n"
          "Please authenticate via: gcloud auth application-default login\n"
          "Or set GOOGLE_APPLICATION_CREDENTIALS to a valid service account JSON."
      ) from None

  def _get_rules_base_url(self) -> str:
    """Construct base URL for Chronicle v1alpha rules API."""
    if not self.config.customer_id:
      raise ValueError(
          "RuleService requires 'customer_id'.\n"
          "Specify --customer-id or export SECOPS_CUSTOMER_ID='your-customer-id'"
      )
    if not self.config.project_id:
      raise ValueError(
          "RuleService requires 'project_id'.\n"
          "Specify --project or export GOOGLE_CLOUD_PROJECT='your-project-id'"
      )
    return (
        f"https://{self.config.region}-chronicle.googleapis.com/v1alpha"
        f"/projects/{self.config.project_id}/locations/{self.config.region}"
        f"/instances/{self.config.customer_id}/rules"
    )

  def sync_rules(
      self,
      rule_filter: str = 'rule_owner:"*"',
      page_size: int = 1000,
      max_rules: Optional[int] = None,
      progress_callback: Optional[Callable[[int, int], None]] = None,
  ) -> List[SecOpsRule]:
    """Download full rules catalog from Google SecOps and cache locally."""
    token = self._get_auth_token()
    base_url = self._get_rules_base_url()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    all_rules: List[SecOpsRule] = []
    page_token = None

    while True:
      params = {
          "filter": rule_filter,
          "pageSize": page_size,
          "view": "FULL",
      }
      if page_token:
        params["pageToken"] = page_token

      query_str = "&".join(f"{k}={v}" for k, v in params.items())
      url = f"{base_url}?{query_str}"
      req = urllib.request.Request(url, headers=headers, method="GET")

      try:
        with urllib.request.urlopen(req) as resp:
          data = json.loads(resp.read().decode("utf-8"))
      except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise RuntimeError(
            f"Failed to fetch rules from Google SecOps API (HTTP {e.code}): {error_body}"
        ) from e

      raw_rules = data.get("rules", [])
      for r in raw_rules:
        text = r.get("text", "") or r.get("ruleText", "")
        techs, tacs = extract_mitre_ids(r, text)
        r_obj = SecOpsRule(
            rule_id=r.get("name", "").split("/")[-1],
            display_name=r.get("displayName", "Unnamed Rule"),
            text=text,
            severity=(
                r.get("severity")
                if isinstance(r.get("severity"), str)
                else r.get("severity", {}).get("displayName", "Medium")
            ),
            description=r.get("description"),
            author=r.get("author"),
            rule_owner=r.get("ruleOwner"),
            live_mode_enabled=bool(r.get("liveModeEnabled", False)),
            tactics=tacs,
            techniques=techs,
            tags=r.get("tags", []),
            raw_data=r,
        )
        all_rules.append(r_obj)

      if progress_callback:
        progress_callback(len(raw_rules), len(all_rules))

      if max_rules and len(all_rules) >= max_rules:
        all_rules = all_rules[:max_rules]
        break

      page_token = data.get("nextPageToken")
      if not page_token:
        break

    self.save_rules_to_cache(all_rules)
    return all_rules

  def save_rules_to_cache(self, rules: List[SecOpsRule]) -> None:
    """Save rules to local JSON cache."""
    self.config.rules_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(rules),
        "customer_id": self.config.customer_id,
        "project_id": self.config.project_id,
        "region": self.config.region,
        "rules": [r.to_dict() for r in rules],
    }
    with open(self.cache_file, "w", encoding="utf-8") as f:
      json.dump(payload, f, indent=2)

  def sync_curated_rules(
      self,
      output_dir: Optional[Path] = None,
      catalog_path: Optional[Path] = None,
      page_size: int = 100,
      save_yaral_files: bool = True,
      progress_callback: Optional[Callable[[int, int], None]] = None,
  ) -> List[SecOpsRule]:
    """Download Curated Detection Rules from Content Hub and cache locally.

    Extracts curated detection rules with executable YARA-L 2.0 text,
    saves individual .yaral files organized by Category/Ruleset, and builds
    a curated catalog index.
    """
    if not self.config.customer_id:
      raise ValueError(
          "RuleService requires 'customer_id'.\n"
          "Specify --customer-id or export SECOPS_CUSTOMER_ID='your-customer-id'"
      )
    if not self.config.project_id:
      raise ValueError(
          "RuleService requires 'project_id'.\n"
          "Specify --project or export GOOGLE_CLOUD_PROJECT='your-project-id'"
      )

    token = self._get_auth_token()
    base_url = (
        f"https://{self.config.region}-chronicle.googleapis.com/v1alpha"
        f"/projects/{self.config.project_id}/locations/{self.config.region}"
        f"/instances/{self.config.customer_id}/contentHub/featuredContentRules"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    out_dir = output_dir or self.curated_dir
    cat_path = catalog_path or self.curated_cache_file

    if save_yaral_files:
      out_dir.mkdir(parents=True, exist_ok=True)
    cat_path.parent.mkdir(parents=True, exist_ok=True)

    all_rules: List[SecOpsRule] = []
    page_token = None
    total_with_logic = 0
    total_unpublished = 0

    while True:
      params = {"pageSize": page_size}
      if page_token:
        params["pageToken"] = page_token

      query_str = "&".join(f"{k}={v}" for k, v in params.items())
      url = f"{base_url}?{query_str}"
      req = urllib.request.Request(url, headers=headers, method="GET")

      try:
        with urllib.request.urlopen(req) as resp:
          data = json.loads(resp.read().decode("utf-8"))
      except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        raise RuntimeError(f"Failed to fetch curated rules (HTTP {e.code}): {err_msg}") from e

      batch = data.get("featuredContentRules", [])
      for r in batch:
        name = r.get("name", "")
        rule_id = name.split("/")[-1]
        meta = r.get("contentMetadata", {})
        rule_content = r.get("curatedRuleContent", {})
        rule_set = r.get("ruleSet", {})

        display_name = meta.get("displayName") or "Unnamed Curated Rule"
        categories = meta.get("categories", [])
        primary_category = categories[0] if categories else "Uncategorized"
        ruleset_name = rule_set.get("displayName") or "General"
        ruleset_id = rule_set.get("id") or "general"
        rule_text = r.get("ruleText", "")
        live_status = bool(r.get("liveStatusEnabled", False))
        precision = rule_content.get("precision", "UNKNOWN")
        severity = (
            meta.get("severity", {}).get("displayName")
            if isinstance(meta.get("severity"), dict)
            else (meta.get("severity") or "Medium")
        )
        description = meta.get("description", "")
        author = meta.get("author", "Google Cloud Threat Intelligence")

        tech_objs = rule_content.get("techniques", [])
        techniques = [t.get("id") for t in tech_objs if t.get("id")]
        tac_objs = rule_content.get("tactics", [])
        tactics = [t.get("id") for t in tac_objs if t.get("id")]

        if not techniques and rule_text:
          t_ext, tac_ext = extract_mitre_ids({}, rule_text)
          techniques.extend(t_ext)
          tactics.extend(tac_ext)
          techniques = sorted(list(set(techniques)))
          tactics = sorted(list(set(tactics)))

        file_path_str = ""
        if save_yaral_files:
          cat_slug = slugify(primary_category)
          rs_slug = slugify(ruleset_name)
          rule_dir = out_dir / cat_slug / rs_slug
          rule_dir.mkdir(parents=True, exist_ok=True)
          yaral_file = rule_dir / f"{rule_id}.yaral"

          header = (
              f"// ========================================================\n"
              f"// Title      : {display_name}\n"
              f"// Rule ID    : {rule_id}\n"
              f"// Ruleset    : {ruleset_name} ({ruleset_id})\n"
              f"// Category   : {primary_category}\n"
              f"// Severity   : {severity}\n"
              f"// Precision  : {precision}\n"
              f"// MITRE Tech : {', '.join(techniques) if techniques else 'None'}\n"
              f"// MITRE Tacs : {', '.join(tactics) if tactics else 'None'}\n"
              f"// Author     : {author}\n"
              f"// Live Mode  : {live_status}\n"
              f"// Description: {description}\n"
              f"// ========================================================\n\n"
          )

          if rule_text:
            yaral_file.write_text(header + rule_text.strip() + "\n", encoding="utf-8")
            total_with_logic += 1
          else:
            placeholder = header + "// [Notice] Raw YARA-L logic is not published by Google for this rule.\n"
            yaral_file.write_text(placeholder, encoding="utf-8")
            total_unpublished += 1
          file_path_str = str(yaral_file)
        else:
          if rule_text:
            total_with_logic += 1
          else:
            total_unpublished += 1

        r_obj = SecOpsRule(
            rule_id=rule_id,
            display_name=display_name,
            text=rule_text,
            severity=severity,
            description=description,
            author=author,
            rule_owner="GOOGLE_CURATED",
            live_mode_enabled=live_status,
            tactics=tactics,
            techniques=techniques,
            tags=[f"category:{primary_category}", f"ruleset:{ruleset_name}"],
            raw_data={
                **r,
                "category": primary_category,
                "ruleset_name": ruleset_name,
                "ruleset_id": ruleset_id,
                "precision": precision,
                "file_path": file_path_str,
            },
        )
        all_rules.append(r_obj)

      if progress_callback:
        progress_callback(len(batch), len(all_rules))

      page_token = data.get("nextPageToken")
      if not page_token:
        break

    catalog_payload = {
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(all_rules),
        "total_with_logic": total_with_logic,
        "total_unpublished": total_unpublished,
        "customer_id": self.config.customer_id,
        "project_id": self.config.project_id,
        "region": self.config.region,
        "rules": [
            {
                **r.to_dict(),
                "category": r.raw_data.get("category", ""),
                "ruleset_name": r.raw_data.get("ruleset_name", ""),
                "ruleset_id": r.raw_data.get("ruleset_id", ""),
                "precision": r.raw_data.get("precision", ""),
                "file_path": r.raw_data.get("file_path", ""),
            }
            for r in all_rules
        ],
    }

    with open(cat_path, "w", encoding="utf-8") as f:
      json.dump(catalog_payload, f, indent=2)

    return all_rules

  def load_rules_from_cache(self, rule_type: str = "all") -> List[SecOpsRule]:
    """Load cached rules from disk.

    Args:
      rule_type: Filter by 'all', 'curated' (Content Hub), or 'custom' (Customer rules).
    """
    rules: List[SecOpsRule] = []

    # 1. Custom / Imported Rules (catalog.json)
    if rule_type in ("all", "custom") and self.cache_file.exists():
      try:
        with open(self.cache_file, "r", encoding="utf-8") as f:
          data = json.load(f)
        rules_data = data.get("rules", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        for r in rules_data:
          r_obj = SecOpsRule.from_dict(r)
          if not r_obj.rule_owner:
            r_obj.rule_owner = "CUSTOMER"
          rules.append(r_obj)
      except Exception as e:
        logger.warning(f"Failed to read custom rules from {self.cache_file}: {e}")

    # 2. Curated Detection Rules from Content Hub (curated_catalog.json)
    if rule_type in ("all", "curated") and self.curated_cache_file.exists():
      try:
        with open(self.curated_cache_file, "r", encoding="utf-8") as f:
          data = json.load(f)
        rules_data = data.get("rules", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        for r in rules_data:
          r_obj = SecOpsRule.from_dict(r)
          if not r_obj.rule_owner:
            r_obj.rule_owner = "GOOGLE_CURATED"
          rules.append(r_obj)
      except Exception as e:
        logger.warning(f"Failed to read curated rules from {self.curated_cache_file}: {e}")

    return rules

  def list_rules(
      self,
      query: Optional[str] = None,
      technique: Optional[str] = None,
      tactic: Optional[str] = None,
      live_only: bool = False,
      rule_type: str = "all",
  ) -> List[SecOpsRule]:
    """Convenience alias for search_rules."""
    return self.search_rules(
        query=query, technique=technique, tactic=tactic, live_only=live_only, rule_type=rule_type
    )

  def get_rule(self, identifier: str) -> Optional[SecOpsRule]:
    """Retrieve a rule by local file path, rule_id, or display_name."""
    # 1. Check if identifier is a local file
    file_path = Path(identifier)
    if file_path.exists() and file_path.is_file():
      content = file_path.read_text(encoding="utf-8")
      if file_path.suffix.lower() == ".json":
        try:
          data = json.loads(content)
          if isinstance(data, dict):
            return SecOpsRule.from_dict(data)
        except Exception:
          pass
      # Treat as raw YARA-L rule file
      techs, tacs = extract_mitre_ids({}, content)
      rule_name_match = re.search(r"rule\s+([A-Za-z0-9_]+)", content)
      display_name = rule_name_match.group(1) if rule_name_match else file_path.stem
      return SecOpsRule(
          rule_id=file_path.stem,
          display_name=display_name,
          text=content,
          techniques=techs,
          tactics=tacs,
          rule_owner="LOCAL",
      )

    # 2. Check cached rules (both custom and curated)
    cached = self.load_rules_from_cache(rule_type="all")
    norm_id = identifier.strip().lower()
    for r in cached:
      if r.rule_id.lower() == norm_id or r.display_name.lower() == norm_id:
        return r

    # 3. Check if stored in curated directory on disk
    if self.curated_dir.exists():
      matched_files = list(self.curated_dir.rglob(f"{norm_id}.yaral"))
      if matched_files:
        return self.get_rule(str(matched_files[0]))

    # 4. Fetch directly from API if not found in cache
    try:
      token = self._get_auth_token()
      base_url = self._get_rules_base_url()
      # Determine if identifier looks like a full resource name or rule_id
      rule_resource = identifier if "/" in identifier else f"{base_url}/{identifier}"
      headers = {
          "Authorization": f"Bearer {token}",
          "Content-Type": "application/json",
      }
      url = f"{rule_resource}?view=FULL" if "view=FULL" not in rule_resource else rule_resource
      req = urllib.request.Request(url, headers=headers, method="GET")
      with urllib.request.urlopen(req) as resp:
        r = json.loads(resp.read().decode("utf-8"))
      text = r.get("text", "") or r.get("ruleText", "")
      techs, tacs = extract_mitre_ids(r, text)
      return SecOpsRule(
          rule_id=r.get("name", "").split("/")[-1],
          display_name=r.get("displayName", "Unnamed Rule"),
          text=text,
          severity=(
              r.get("severity")
              if isinstance(r.get("severity"), str)
              else r.get("severity", {}).get("displayName", "Medium")
          ),
          description=r.get("description"),
          author=r.get("author"),
          rule_owner=r.get("ruleOwner") or "CUSTOMER",
          live_mode_enabled=bool(r.get("liveModeEnabled", False)),
          tactics=tacs,
          techniques=techs,
          tags=r.get("tags", []),
          raw_data=r,
      )
    except Exception as e:
      logger.debug(f"Direct API fetch for rule '{identifier}' failed: {e}")
      return None

  def search_rules(
      self,
      query: Optional[str] = None,
      technique: Optional[str] = None,
      tactic: Optional[str] = None,
      live_only: bool = False,
      rule_type: str = "all",
      rules: Optional[List[SecOpsRule]] = None,
  ) -> List[SecOpsRule]:
    """Search and filter rules."""
    corpus = rules if rules is not None else self.load_rules_from_cache(rule_type=rule_type)
    results = []

    q_lower = query.lower() if query else None
    t_upper = technique.upper() if technique else None
    tac_upper = tactic.upper() if tactic else None

    for r in corpus:
      if rule_type != "all":
        if rule_type == "curated" and r.rule_owner != "GOOGLE_CURATED":
          continue
        if rule_type == "custom" and r.rule_owner == "GOOGLE_CURATED":
          continue
      if live_only and not r.live_mode_enabled:
        continue
      if t_upper and t_upper not in r.techniques:
        continue
      if tac_upper and tac_upper not in r.tactics:
        continue
      if q_lower:
        match_query = (
            q_lower in r.display_name.lower()
            or q_lower in r.rule_id.lower()
            or (r.description and q_lower in r.description.lower())
            or q_lower in r.text.lower()
        )
        if not match_query:
          continue
      results.append(r)

    return results
