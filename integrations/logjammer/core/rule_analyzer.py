"""YARA-L 2.0 rule analysis and UDM-to-log-source inference engine."""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import RuleAnalysis, SecOpsRule


# Heuristic mapping between UDM event types / fields and Log Jammer playbooks
UDM_LOG_MAPPING = {
    "PROCESS_LAUNCH": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT", "CS_EDR", "AUDITD"],
    "PROCESS_TERMINATION": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT", "CS_EDR", "AUDITD"],
    "PROCESS_OPEN": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT", "CS_EDR"],
    "PROCESS_UNCATEGORIZED": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT", "CS_EDR", "AUDITD"],
    "NETWORK_CONNECTION": ["PAN_FIREWALL", "CISCO_ASA_FIREWALL", "FORTINET_FIREWALL", "AWS_VPC_FLOW", "GCP_VPC_FLOW"],
    "NETWORK_FLOW": ["AWS_VPC_FLOW", "GCP_VPC_FLOW"],
    "NETWORK_DNS": ["WINDOWS_DNS", "GCP_DNS", "CLOUDFLARE"],
    "NETWORK_HTTP": ["ZSCALER_WEBPROXY", "BLUECOAT_WEBPROXY", "CLOUDFLARE"],
    "USER_LOGIN": ["OKTA", "AZURE_AD", "AUTH_ZERO", "DUO_ACTIVITY", "WORKSPACE_ACTIVITY", "WINDOWS_SYSMON"],
    "USER_CREATION": ["AZURE_AD_AUDIT", "OKTA", "WORKSPACE_ACTIVITY", "AWS_CLOUDTRAIL"],
    "USER_CHANGE_PERMISSIONS": ["GCP_CLOUDAUDIT", "AWS_CLOUDTRAIL", "AZURE_AD_AUDIT", "OKTA"],
    "USER_RESOURCE_ACCESS": ["WORKSPACE_ACTIVITY", "OFFICE_365", "AWS_CLOUDTRAIL", "GCP_CLOUDAUDIT"],
    "FILE_CREATION": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT", "CS_EDR", "AUDITD"],
    "FILE_MODIFICATION": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT", "CS_EDR"],
    "FILE_DELETION": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT", "CS_EDR"],
    "REGISTRY_MODIFICATION": ["WINDOWS_SYSMON", "MICROSOFT_DEFENDER_ENDPOINT"],
    "EMAIL_TRANSACTION": ["OFFICE_365_MESSAGETRACE", "PROOFPOINT_MAIL", "PROOFPOINT_ON_DEMAND"],
}


class RuleAnalyzer:
  """Analyzes YARA-L 2.0 detection rules to determine required trigger conditions."""

  def __init__(self, available_log_types: Optional[List[str]] = None):
    self.available_log_types = [lt.upper() for lt in (available_log_types or [])]

  def analyze(self, rule: SecOpsRule) -> RuleAnalysis:
    """Analyze a SecOpsRule and return a structured RuleAnalysis."""
    text = rule.text or ""

    # 1. Parse meta section
    meta_info = self._parse_meta_section(text)
    tactics = list(set(rule.tactics + meta_info.get("tactics", [])))
    techniques = list(set(rule.techniques + meta_info.get("techniques", [])))

    # 2. Parse events section
    events_section = self._extract_section(text, "events")
    event_types, positive_rules, negative_rules = self._parse_events_section(events_section)

    # 3. Parse match section
    match_section = self._extract_section(text, "match")
    match_window, is_multi_event = self._parse_match_section(match_section)

    # 4. Parse condition section
    condition_section = self._extract_section(text, "condition")
    threshold_count, cond_multi = self._parse_condition_section(condition_section)
    is_multi_event = is_multi_event or cond_multi

    # 5. Extract all required UDM fields
    required_fields = sorted(list(set(list(positive_rules.keys()) + list(negative_rules.keys()))))

    # 6. Infer optimal log sources
    suggested_log_types = self._infer_log_types(
        text=text,
        event_types=event_types,
        required_fields=required_fields,
        positive_rules=positive_rules,
    )

    # Filter to available log types if provided
    if self.available_log_types:
      filtered = [lt for lt in suggested_log_types if lt in self.available_log_types]
      if filtered:
        suggested_log_types = filtered

    # 7. Generate human-readable summary
    summary = self._generate_summary(
        rule_name=rule.display_name,
        event_types=event_types,
        techniques=techniques,
        positive_rules=positive_rules,
        negative_rules=negative_rules,
        threshold_count=threshold_count,
        match_window=match_window,
        suggested_log_types=suggested_log_types,
    )

    return RuleAnalysis(
        rule_id=rule.rule_id,
        display_name=rule.display_name,
        rule_text=text,
        tactics=tactics,
        techniques=techniques,
        event_types=event_types,
        required_fields=required_fields,
        positive_constraints=positive_rules,
        negative_exclusions=negative_rules,
        suggested_log_types=suggested_log_types,
        is_multi_event=is_multi_event,
        match_window=match_window,
        threshold_count=threshold_count,
        summary=summary,
    )

  def _extract_section(self, text: str, section_name: str) -> str:
    """Extract contents of a specific section (meta, events, match, outcome, condition)."""
    pattern = rf"\b{section_name}\s*:\s*(.*?)(?=\b(?:meta|events|match|outcome|condition)\s*:|\}}\s*$)"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""

  def _parse_meta_section(self, text: str) -> Dict[str, Any]:
    """Parse key-value metadata from meta block."""
    meta_text = self._extract_section(text, "meta")
    info: Dict[str, Any] = {"tactics": [], "techniques": []}

    for line in meta_text.splitlines():
      line = line.strip()
      if not line or line.startswith("//"):
        continue
      match = re.match(r'([a-zA-Z0-9_]+)\s*=\s*"(.*?)"', line)
      if match:
        k, v = match.group(1).lower(), match.group(2).strip()
        if k in ("technique", "mitre_technique"):
          for tech in re.findall(r"T\d{4}(?:\.\d{3})?", v, re.IGNORECASE):
            info["techniques"].append(tech.upper())
        elif k in ("tactic", "mitre_tactic"):
          for tac in re.findall(r"TA\d{4}", v, re.IGNORECASE):
            info["tactics"].append(tac.upper())
        info[k] = v
    return info

  def _parse_events_section(
      self, events_text: str
  ) -> Tuple[List[str], Dict[str, List[str]], Dict[str, List[str]]]:
    """Extract event types, positive constraints, and negative exclusions."""
    event_types = set()
    positive: Dict[str, List[str]] = {}
    negative: Dict[str, List[str]] = {}

    # 1. Look for event_type assignments: $e.metadata.event_type = "..." or = /.../
    event_type_matches = re.findall(
        r"metadata\.event_type\s*=\s*[\"']([A-Z0-9_]+)[\"']", events_text, re.IGNORECASE
    )
    for et in event_type_matches:
      event_types.add(et.upper())

    # 2. re.regex(...) positive or negative
    re_regex_matches = re.findall(
        r"(!?)\s*re\.regex\s*\(\s*\$[a-zA-Z0-9_]+\.([a-zA-Z0-9_.]+)\s*,\s*([`\"/][^`\"/]+[`\"/])\s*\)",
        events_text,
    )
    for is_neg, field_path, val in re_regex_matches:
      cleaned_val = val.strip("`\"/")
      if is_neg:
        negative.setdefault(field_path, []).append(cleaned_val)
      else:
        positive.setdefault(field_path, []).append(cleaned_val)

    # 3. Extract positive field conditions: $e.field.subfield = /regex/ or = "val"
    pos_regex = re.findall(
        r"\$[a-zA-Z0-9_]+\.([a-zA-Z0-9_.]+)\s*(?:=|=(?:~)?)\s*(/[^/]+/|\"[^\"]+\"|`[^`]+`)(?:\s+nocase)?",
        events_text,
    )
    for field_path, val in pos_regex:
      if "metadata.event_type" in field_path:
        continue
      positive.setdefault(field_path, []).append(val.strip("`\"/"))

    # 4. Extract negative exclusions: $e.field.subfield != /regex/ or != "val"
    neg_regex = re.findall(
        r"\$[a-zA-Z0-9_]+\.([a-zA-Z0-9_.]+)\s*(?:!=|!(?:~)?)\s*(/[^/]+/|\"[^\"]+\"|`[^`]+`)(?:\s+nocase)?",
        events_text,
    )
    for field_path, val in neg_regex:
      negative.setdefault(field_path, []).append(val.strip("`\"/"))

    return sorted(list(event_types)), positive, negative

  def _parse_match_section(self, match_text: str) -> Tuple[Optional[str], bool]:
    """Extract match window (e.g. over 5m) and determine if multi-event."""
    if not match_text:
      return None, False

    window_match = re.search(r"over\s+([0-9]+[a-z]+)", match_text, re.IGNORECASE)
    window = window_match.group(1) if window_match else None
    return window, True

  def _parse_condition_section(self, cond_text: str) -> Tuple[int, bool]:
    """Determine event threshold and multi-event requirements from condition."""
    if not cond_text:
      return 1, False

    # Check for count thresholds, e.g. #e > 5 or #e >= 5
    threshold = 1
    is_multi = False

    gt_match = re.search(r"#[a-zA-Z0-9_]+\s*>\s*([0-9]+)", cond_text)
    if gt_match:
      threshold = int(gt_match.group(1)) + 1
      is_multi = True

    gte_match = re.search(r"#[a-zA-Z0-9_]+\s*>=\s*([0-9]+)", cond_text)
    if gte_match:
      threshold = max(threshold, int(gte_match.group(1)))
      is_multi = True

    # Check for multi-event combinations ($e1 and $e2)
    if re.search(r"\$[a-zA-Z0-9_]+\s+and\s+\$[a-zA-Z0-9_]+", cond_text, re.IGNORECASE):
      is_multi = True
      threshold = max(threshold, 2)

    return threshold, is_multi

  def _infer_log_types(
      self,
      text: str,
      event_types: List[str],
      required_fields: List[str],
      positive_rules: Dict[str, List[str]],
  ) -> List[str]:
    """Infer the best candidate log sources to trigger the rule."""
    candidates = []
    text_lower = text.lower()

    # Direct keyword indicators in rule logic or comments
    if any(k in text_lower for k in ("powershell", "cmd.exe", "rundll32", "reg.exe", "wmic", "sysmon")):
      candidates.append("WINDOWS_SYSMON")
      candidates.append("MICROSOFT_DEFENDER_ENDPOINT")
    if any(k in text_lower for k in ("aws.", "iam.amazonaws.com", "s3.amazonaws.com", "cloudtrail")):
      candidates.append("AWS_CLOUDTRAIL")
    if any(k in text_lower for k in ("workspace", "google workspace", "gsuite", "drive.google")):
      candidates.append("WORKSPACE_ACTIVITY")
    if any(k in text_lower for k in ("gcp", "cloudresourcemanager", "iam.googleapis.com")):
      candidates.append("GCP_CLOUDAUDIT")
    if any(k in text_lower for k in ("azuread", "entra", "azure_ad")):
      candidates.append("AZURE_AD")
    if any(k in text_lower for k in ("dns query", "dns_response")):
      candidates.append("WINDOWS_DNS")
      candidates.append("GCP_DNS")
    if any(k in text_lower for k in ("auditd", "/bin/bash", "/bin/sh", "linux")):
      candidates.append("AUDITD")
      candidates.append("NIX_SYSTEM")

    # Match by UDM event types
    for et in event_types:
      if et in UDM_LOG_MAPPING:
        for lt in UDM_LOG_MAPPING[et]:
          if lt not in candidates:
            candidates.append(lt)

    # Match by UDM field names
    for f in required_fields:
      if "process" in f and "WINDOWS_SYSMON" not in candidates:
        candidates.append("WINDOWS_SYSMON")
      if ("registry" in f) and "WINDOWS_SYSMON" not in candidates:
        candidates.append("WINDOWS_SYSMON")
      if "network" in f and "PAN_FIREWALL" not in candidates:
        candidates.append("PAN_FIREWALL")

    # Deduplicate while preserving priority order
    seen = set()
    deduped = []
    for c in candidates:
      if c not in seen:
        seen.add(c)
        deduped.append(c)

    return deduped or ["WINDOWS_SYSMON"]

  def _generate_summary(
      self,
      rule_name: str,
      event_types: List[str],
      techniques: List[str],
      positive_rules: Dict[str, List[str]],
      negative_rules: Dict[str, List[str]],
      threshold_count: int,
      match_window: Optional[str],
      suggested_log_types: List[str],
  ) -> str:
    """Produce a concise human-readable explanation of rule requirements."""
    lines = [f"Rule '{rule_name}' Trigger Analysis:"]
    if techniques:
      lines.append(f"- MITRE Techniques: {', '.join(techniques)}")
    if event_types:
      lines.append(f"- Required UDM Event Types: {', '.join(event_types)}")
    lines.append(f"- Recommended Log Type: {suggested_log_types[0] if suggested_log_types else 'WINDOWS_SYSMON'}")
    if threshold_count > 1:
      lines.append(f"- Event Count Threshold: At least {threshold_count} events")
    if match_window:
      lines.append(f"- Match Window: within {match_window}")

    if positive_rules:
      lines.append("- Critical Trigger Values (Must Match):")
      for field_path, vals in list(positive_rules.items())[:5]:
        lines.append(f"  * {field_path} = {' OR '.join(vals)}")

    if negative_rules:
      lines.append("- Exclusions to Avoid (Must NOT Match):")
      for field_path, vals in list(negative_rules.items())[:3]:
        lines.append(f"  * {field_path} != {' AND '.join(vals)}")

    return "\n".join(lines)
