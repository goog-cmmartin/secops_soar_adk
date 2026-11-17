"""Deterministic + ADK-Enriched Case Entity Blast Radius & Kill-Chain Timeline Workflows.

Combines Chronicle SIEM UDM precursor events, Silent (`NOT_ALERTING`) and Alerting YARA-L
detections, cross-case shared entities, packaged MITRE Enterprise ATT&CK mappings, and
Google ADK Agent 3-Tier Triage overlays into interactive visual models for SOAR widgets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import UniversalDictMixin
from engine.mitre_catalog import TECHNIQUE_REGEX, MitreCatalog
from engine.parsing import parse_timestamp
from engine.workflows.case_investigation import InvestigateCaseWorkflow
from engine.workflows.correlate_silent_detections import (
    CorrelateSilentDetectionsWorkflow,
    ParsedEntityFilter,
    _clean_case_id,
    _resolve_entity_type,
    is_noisy_entity,
)
from engine.workflows.related_cases_by_entity import RelatedCasesByEntityWorkflow

logger = logging.getLogger(__name__)

# Canonical MITRE ATT&CK Enterprise kill-chain tactic order
KILL_CHAIN_TACTIC_ORDER: List[Tuple[str, str]] = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Dev"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command & Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

# Heuristic MITRE technique inference from rule names, process command lines, and UDM event types.
# Ordered from specific adversary tradecraft (credential access, discovery, lateral movement, cloud auth)
# down to generic command interpreters (powershell, cmd.exe) so shell wrappers don't mask post-exploitation tactics.
_HEURISTIC_MITRE_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"comsvcs|minidump|lsass\.dmp|procdump|mimikatz|sekurlsa|lsass.*(?:-ma|dump|mem)", re.I), "T1003.001", "credential-access"),
    (re.compile(r"ntds\.dit|ntdsutil|vssadmin.*shadow|dcsync|drsuapi", re.I), "T1003.003", "credential-access"),
    (re.compile(r"kerberoast|asreproast|golden.?ticket|rubeus", re.I), "T1558", "credential-access"),
    (re.compile(r"password.?spray", re.I), "T1110.003", "credential-access"),
    (re.compile(r"brute.?force|credential.?stuff", re.I), "T1110", "credential-access"),
    (re.compile(r"certutil.*-decode|frombase64string|base64\s+-d", re.I), "T1140", "defense-evasion"),
    (re.compile(r"-enc|-encodedcommand|obfuscat", re.I), "T1027", "defense-evasion"),
    (re.compile(r"wevtutil\s+cl|clear-eventlog|auditpol|disable.*defender|tamper", re.I), "T1562", "defense-evasion"),
    (re.compile(r"w3wp\.exe|webshell|\.aspx|\.jsp|php-cgi|tomcat.*cmd", re.I), "T1505.003", "persistence"),
    (re.compile(r"schtasks|scheduled.?task|at\.exe|crontab", re.I), "T1053", "persistence"),
    (re.compile(r"currentversion\\run|reg\s+add.*run|userinit|winlogon", re.I), "T1547.001", "persistence"),
    (re.compile(r"useradd|net\s+user\s+.*\/add|createuser|add.*group|iam.*create", re.I), "T1136", "persistence"),
    (re.compile(r"nltest|domain.?trust|dclist|domain.?controller.?enum", re.I), "T1482", "discovery"),
    (re.compile(r"net\s+group|net\s+localgroup|domain\s+admin|group\s+discovery|get-aduser|ldapsearch|bloodhound|sharphound|account\s+discovery", re.I), "T1087", "discovery"),
    (re.compile(r"domain\s+information\s+discovery|system\s+information\s+discovery|systeminfo|uname\s+-a", re.I), "T1082", "discovery"),
    (re.compile(r"\b(?:whoami|quser|qwinsta)\b|(?:^|[;&|]\s*)id(?:\s+-[a-zA-Z]+|\s*$)", re.I), "T1033", "discovery"),
    (re.compile(r"ipconfig|ifconfig|netstat|arp\s+-a|nslookup|port.?scan", re.I), "T1016", "discovery"),
    (re.compile(r"psexec|smb|admin\$|c\$|ipc\$|winrm|wsmprovhost|rdp|mstsc|sshpass", re.I), "T1021", "lateral-movement"),
    (re.compile(r"rclone|mega\.nz|archive|7z\.exe|rar\.exe|tar\s+-cz|exfil", re.I), "T1567", "exfiltration"),
    (re.compile(r"exploit|cve-\d{4}-\d+|owa\/auth|log4j|sql.?inject|rce\b", re.I), "T1190", "initial-access"),
    (re.compile(r"phish|malicious.*attachment|macro|lnk\b", re.I), "T1566", "initial-access"),
    (
        re.compile(
            r"(?:login|sign.?in|auth).*(?:tor\b|anomalous|impossible.?travel|high.?risk|unusual)"
            r"|(?:tor\b|impossible.?travel|anomalous.*ip|high.?risk).*(?:login|sign.?in|auth)"
            r"|impossible.?travel|unusual.*vpn|valid.?account",
            re.I,
        ),
        "T1078",
        "initial-access",
    ),
    (re.compile(r"tor\b|proxy|ngrok|chisel|cobalt|beacon|c2\b|command.?and.?control", re.I), "T1090", "command-and-control"),
    (re.compile(r"ransom|encrypt|bcdedit.*recoveryenabled|vssadmin.*delete", re.I), "T1486", "impact"),
    (re.compile(r"powershell|pwsh", re.I), "T1059.001", "execution"),
    (re.compile(r"wmic\s+.*process\s+call\s+create|wmiprvse", re.I), "T1047", "execution"),
    (re.compile(r"cmd\.exe|\/bin\/sh|\/bin\/bash|wscript|cscript|mshta", re.I), "T1059", "execution"),
]

_ADK_REPORT_MARKERS = (
    "**Verdict:**",
    "Tier 1 Autonomous Triage Report",
    "# Incident Triage Report",
    "# Incident Investigation Report",
)

_THREAT_ACTOR_ID_RE = re.compile(r"^(?:UNC\d{3,5}|APT\d{1,3}|FIN\d{1,3}|DEV-\d{3,5}|TEMP\.[A-Z0-9_-]+)$", re.I)
_RULE_UUID_RE = re.compile(r"^(?:ru|ur)_[0-9a-f-]{20,}$", re.I)


def _is_threat_actor_entity(raw_type: Optional[str], identifier: str) -> bool:
    rt = (raw_type or "").strip().upper()
    if rt in ("THREATACTOR", "THREATCAMPAIGN", "CAMPAIGN", "INTRUSIONSET"):
        return True
    return bool(_THREAT_ACTOR_ID_RE.match((identifier or "").strip()))


def _human_alert_rule_info(al: Any) -> Tuple[str, str]:
    """Returns (human_rule_name, udm_query) for a SOAR CaseAlert."""
    raw_d = getattr(al, "raw", {}) or {}
    r_gen = str(raw_d.get("ruleGenerator") or "").strip()
    d_name = str(getattr(al, "display_name", "") or raw_d.get("displayName") or "").strip()
    r_name = str(getattr(al, "rule_name", "") or "").strip()
    rule_id = str(raw_d.get("sourceRuleIdentifier") or (r_name if _RULE_UUID_RE.match(r_name) else "")).strip()

    human = r_name
    if not human or _RULE_UUID_RE.match(human):
        human = r_gen or d_name or r_name or "SOAR Case Alert"

    if rule_id and _RULE_UUID_RE.match(rule_id):
        udm_q = f'security_result.rule_id = "{rule_id}"'
    else:
        escaped = human.replace('"', '\\"')
        udm_q = f'security_result.rule_name = "{escaped}"'
    return human, udm_q


def _is_private_or_internal_ip(val: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(val.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def _classify_visual_node_type(raw_type: Optional[str], identifier: str) -> str:
    """Normalizes SOAR/UDM entity types into visual graph node categories."""
    val = (identifier or "").strip()
    rt = (raw_type or "").strip().upper()

    resolved = _resolve_entity_type(raw_type, val)
    resolved_name = getattr(resolved, "name", str(resolved or "")).upper()

    if resolved_name in ("IP", "ADDRESS") or rt in ("ADDRESS", "IP", "SRC_IP", "DST_IP"):
        return "IP"
    if re.match(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$", val) or rt in (
        "FILEHASH",
        "HASH",
        "SHA256",
        "MD5",
        "SHA1",
    ):
        return "FILEHASH"
    if val.lower().startswith(("http://", "https://")) or rt in ("DESTINATIONURL", "URL", "URI"):
        return "URL"
    if val.lower().startswith("arn:aws") or rt in ("CLOUD", "CLOUDRESOURCE"):
        return "CLOUD"
    if (
        val.upper().startswith(("HKLM\\", "HKCU\\", "HKU\\", "HKCR\\", "HKEY_"))
        or re.match(r"^[a-zA-Z]:\\", val)
        or val.count("\\") >= 2
        or ("\\" in val and val.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".vbs", ".aspx", ".jsp")))
        or rt in ("PROCESS", "FILENAME", "FILE", "COMMANDLINE", "REGISTRYKEY", "REGISTRY")
    ):
        return "PROCESS"
    if "@" in val or "\\" in val or resolved_name in ("USER", "USERUNIQNAME") or rt in (
        "USER",
        "USERNAME",
        "USERUNIQNAME",
        "EMAIL",
    ):
        return "USER"
    if resolved_name in ("ASSET", "HOSTNAME", "DOMAIN") or rt in ("HOSTNAME", "HOST", "ASSET", "MACHINE", "DOMAIN"):
        return "HOST"
    # Fallback heuristics
    try:
        ipaddress.ip_address(val)
        return "IP"
    except ValueError:
        pass
    if "." in val and " " not in val and "/" not in val:
        return "HOST"
    return "HOST" if rt == "ASSET" else "PROCESS" if " " in val else "USER"


def build_entity_udm_query(identifier: str, node_type: str) -> str:
    """Constructs an accurate Chronicle UDM search query for 1-click analyst pivoting."""
    val = (identifier or "").strip()
    if not val:
        return ""
    escaped_quotes = val.replace("\\", "\\\\").replace('"', '\\"')

    if node_type == "IP":
        return (
            f'(ip = "{escaped_quotes}" OR principal.ip = "{escaped_quotes}" '
            f'OR target.ip = "{escaped_quotes}" OR src.ip = "{escaped_quotes}")'
        )
    if node_type == "HOST":
        short_host = val.split(".")[0].strip()
        if short_host and short_host.lower() != val.lower():
            esc_short = short_host.replace("\\", "\\\\").replace('"', '\\"')
            return (
                f'(principal.hostname = "{escaped_quotes}" OR target.hostname = "{escaped_quotes}" '
                f'OR principal.asset.hostname = "{escaped_quotes}" '
                f'OR principal.hostname = "{esc_short}" OR target.hostname = "{esc_short}")'
            )
        return (
            f'(principal.hostname = "{escaped_quotes}" OR target.hostname = "{escaped_quotes}" '
            f'OR principal.asset.hostname = "{escaped_quotes}")'
        )
    if node_type in ("USER", "CLOUD"):
        return (
            f'(principal.user.userid = "{escaped_quotes}" OR target.user.userid = "{escaped_quotes}" '
            f'OR principal.user.email_addresses = "{escaped_quotes}" '
            f'OR target.user.email_addresses = "{escaped_quotes}" '
            f'OR principal.user.product_object_id = "{escaped_quotes}")'
        )
    if node_type == "FILEHASH":
        h_low = escaped_quotes.lower()
        return (
            f'(target.file.sha256 = "{h_low}" OR principal.process.file.sha256 = "{h_low}" '
            f'OR target.file.md5 = "{h_low}" OR target.process.file.sha256 = "{h_low}")'
        )
    if node_type == "URL":
        return f'(target.url = "{escaped_quotes}" OR principal.url = "{escaped_quotes}")'
    if node_type == "PROCESS":
        if val.upper().startswith(("HKLM\\", "HKCU\\", "HKU\\", "HKCR\\", "HKEY_")):
            return f'target.registry.registry_key = "{escaped_quotes}" nocase'
        regex_safe = re.escape(val).replace("/", "\\/")
        return (
            f'(target.process.file.full_path = /{regex_safe}/ nocase '
            f'OR principal.process.file.full_path = /{regex_safe}/ nocase '
            f'OR target.process.command_line = /{regex_safe}/ nocase)'
        )
    return f'raw = "{escaped_quotes}"'


def resolve_mitre_metadata(*texts: Optional[str], event_type: Optional[str] = None) -> Dict[str, str]:
    """Resolves MITRE ATT&CK technique ID, name, and canonical tactic using MitreCatalog + heuristics."""
    catalog = MitreCatalog.get_instance()
    combined = " ".join(str(t) for t in texts if t).strip()

    # 1. Explicit T-code match in rule name, summary, or ADK annotation
    m_explicit = TECHNIQUE_REGEX.search(combined)
    if m_explicit:
        tid = m_explicit.group(1).upper()
        tech = catalog.get_technique(tid) or catalog.get_technique(tid.split(".")[0])
        if tech:
            tactics = tech.get("tactics") or []
            tactic_slug = str(tactics[0]).lower().replace(" ", "-") if tactics else "execution"
            tactic_obj = catalog.get_tactic(tactic_slug)
            tactic_label = tactic_obj.get("name") if tactic_obj else tactic_slug.replace("-", " ").title()
            return {
                "technique_id": tid,
                "technique_name": str(tech.get("name") or tid),
                "tactic_slug": tactic_slug,
                "tactic_name": str(tactic_label),
            }
        return {
            "technique_id": tid,
            "technique_name": tid,
            "tactic_slug": "execution",
            "tactic_name": "Execution",
        }

    # 2. Pattern heuristics against command line / rule name
    for pattern, tid, default_tactic in _HEURISTIC_MITRE_PATTERNS:
        if pattern.search(combined):
            tech = catalog.get_technique(tid) or catalog.get_technique(tid.split(".")[0])
            tactic_obj = catalog.get_tactic(default_tactic)
            tactic_label = tactic_obj.get("name") if tactic_obj else default_tactic.replace("-", " ").title()
            return {
                "technique_id": tid,
                "technique_name": str(tech.get("name") if tech else tid),
                "tactic_slug": default_tactic,
                "tactic_name": str(tactic_label),
            }

    # 3. Fallback by UDM metadata.event_type
    et = (event_type or "").strip().upper()
    if "LOGIN" in et or "AUTH" in et:
        return {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic_slug": "initial-access",
            "tactic_name": "Initial Access",
        }
    if "PROCESS" in et:
        return {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic_slug": "execution",
            "tactic_name": "Execution",
        }
    if "NETWORK_HTTP" in et or "NETWORK_DNS" in et or "NETWORK_CONNECTION" in et:
        return {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic_slug": "command-and-control",
            "tactic_name": "Command and Control",
        }
    if "FILE_" in et:
        return {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic_slug": "command-and-control",
            "tactic_name": "Command and Control",
        }
    if "REGISTRY_" in et:
        return {
            "technique_id": "T1112",
            "technique_name": "Modify Registry",
            "tactic_slug": "defense-evasion",
            "tactic_name": "Defense Evasion",
        }

    return {
        "technique_id": "",
        "technique_name": "",
        "tactic_slug": "",
        "tactic_name": "",
    }


def extract_adk_overlay(
    adk_input: Optional[Union[str, Dict[str, Any]]] = None,
    comments: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Extracts 3-Tier Triage classification, executive summary, and per-entity insights from ADK output."""
    payload: Optional[Dict[str, Any]] = None
    markdown_text = ""

    if isinstance(adk_input, dict):
        payload = adk_input.get("results") if isinstance(adk_input.get("results"), dict) else adk_input
    elif isinstance(adk_input, str) and adk_input.strip():
        cleaned = adk_input.strip()
        if not (cleaned.startswith("[") and ".JsonResult" in cleaned):
            if cleaned.startswith("{"):
                try:
                    parsed = json.loads(cleaned)
                    if isinstance(parsed, dict):
                        payload = parsed.get("results") if isinstance(parsed.get("results"), dict) else parsed
                except Exception:
                    markdown_text = cleaned
            else:
                markdown_text = cleaned

    if payload and not markdown_text:
        markdown_text = str(
            payload.get("final_response")
            or payload.get("response")
            or payload.get("analysis")
            or payload.get("output")
            or ""
        ).strip()

    # Fallback: scan Case Wall comments for most recent ADK triage report
    if not markdown_text and comments:
        for cm in comments:
            text = (
                str(cm.get("comment") or "")
                if isinstance(cm, dict)
                else str(getattr(cm, "comment", "") or "")
            ).strip()
            if not text or text.startswith("### [Automated Correlation]"):
                continue
            if any(marker in text for marker in _ADK_REPORT_MARKERS):
                markdown_text = text
                break

    if not markdown_text:
        return {
            "has_adk_analysis": False,
            "verdict": "",
            "verdict_tone": "inconclusive",
            "disposition": "",
            "confidence": "",
            "model": payload.get("model", "") if isinstance(payload, dict) else "",
            "session_id": payload.get("session_id", "") if isinstance(payload, dict) else "",
            "summary": "",
            "entity_notes": {},
            "viz_override": {},
        }

    # Check for optional structured json:adk_viz appendix
    viz_override: Dict[str, Any] = {}
    m_viz = re.search(r"```json:adk_viz\s*(\{.*?\})\s*```", markdown_text, re.S)
    if m_viz:
        try:
            viz_override = json.loads(m_viz.group(1))
        except Exception:
            viz_override = {}

    v_match = re.search(r"\*\*Verdict:\*\*\s*`?([^`|\n]+)`?", markdown_text, re.I)
    d_match = re.search(r"\*\*Disposition:\*\*\s*`?([^`|\n]+)`?", markdown_text, re.I)
    c_match = re.search(r"\*\*Confidence:\*\*\s*`?([^`|\n]+)`?", markdown_text, re.I)

    verdict = v_match.group(1).strip() if v_match else "Evaluated"
    disposition = d_match.group(1).strip() if d_match else ""
    confidence = c_match.group(1).strip().upper() if c_match else ""

    v_lower = verdict.lower()
    if "malicious" in v_lower or ("true positive" in v_lower and "benign" not in v_lower and "btp" not in v_lower):
        verdict_tone = "malicious"
    elif "benign" in v_lower or "btp" in v_lower:
        verdict_tone = "btp"
    elif "false positive" in v_lower or v_lower == "fp":
        verdict_tone = "fp"
    else:
        verdict_tone = "inconclusive"

    # Extract concise executive summary paragraph (first substantive non-heading/non-blockquote paragraph)
    summary_snippet = ""
    for line in markdown_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(">") or s.startswith("|") or s.startswith("```"):
            continue
        if "**Verdict:**" in s:
            continue
        clean_line = re.sub(r"[`*_]+", "", s).strip()
        if len(clean_line) >= 35:
            summary_snippet = clean_line[:320] + ("..." if len(clean_line) > 320 else "")
            break

    # Retain clean lines for entity context lookup
    prose_lines = [
        re.sub(r"^\s*[-*•\d.)]+\s*", "", ln.strip())
        for ln in markdown_text.splitlines()
        if ln.strip() and not ln.strip().startswith(("#", "```", "|---"))
    ]

    return {
        "has_adk_analysis": True,
        "verdict": verdict,
        "verdict_tone": verdict_tone,
        "disposition": disposition,
        "confidence": confidence,
        "model": str((payload or {}).get("model") or "Google ADK"),
        "session_id": str((payload or {}).get("session_id") or ""),
        "summary": summary_snippet,
        "_prose_lines": prose_lines[:120],
        "viz_override": viz_override if isinstance(viz_override, dict) else {},
    }


def _find_adk_insight_for_identifier(identifier: str, adk_overlay: Dict[str, Any]) -> str:
    """Finds the most informative sentence/bullet in the ADK report referencing a specific indicator."""
    if not identifier or not adk_overlay or not adk_overlay.get("has_adk_analysis"):
        return ""
    needle = identifier.strip().lower()
    if len(needle) < 3:
        return ""
    short_needle = needle.split("\\")[-1].split("/")[-1]
    for ln in adk_overlay.get("_prose_lines") or []:
        ln_low = ln.lower()
        if needle in ln_low or (len(short_needle) >= 5 and short_needle in ln_low):
            if "**verdict:**" in ln_low:
                continue
            cleaned = re.sub(r"[`*_]+", "", ln).strip()
            if len(cleaned) > 260:
                cleaned = cleaned[:257] + "..."
            return cleaned
    return ""


def _public_adk_overlay(adk_overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Strips internal parsing helper keys before JSON serialization."""
    return {
        k: v
        for k, v in (adk_overlay or {}).items()
        if not k.startswith("_") and k != "viz_override"
    }


def _extract_noun_identifiers(noun: Any) -> List[Tuple[str, str, str]]:
    """Returns list of (identifier, visual_node_type, detail_label) from a UDM principal/target summary dict."""
    if not isinstance(noun, dict):
        return []
    found: List[Tuple[str, str, str]] = []

    h = str(noun.get("hostname") or "").strip()
    if h and not is_noisy_entity(h, "HOSTNAME"):
        found.append((h, "HOST", "Endpoint / Host"))

    ips = noun.get("ip")
    ip_list = ips if isinstance(ips, list) else ([ips] if ips else [])
    for ip_val in ip_list[:3]:
        ip_s = str(ip_val or "").strip()
        if ip_s and not is_noisy_entity(ip_s, "IP"):
            sub = "Internal IP" if _is_private_or_internal_ip(ip_s) else "External IP"
            found.append((ip_s, "IP", sub))

    usr = noun.get("user")
    if isinstance(usr, dict):
        uid = str(usr.get("userid") or usr.get("userDisplayName") or "").strip()
        if not uid:
            emails = usr.get("emailAddresses") or []
            if isinstance(emails, list) and emails:
                uid = str(emails[0] or "").strip()
        if uid and not is_noisy_entity(uid, "USERUNIQNAME"):
            found.append((uid, "USER", "Identity / Account"))
    elif isinstance(usr, str) and usr.strip() and not is_noisy_entity(usr.strip(), "USERUNIQNAME"):
        found.append((usr.strip(), "USER", "Identity / Account"))

    proc = noun.get("process")
    if isinstance(proc, dict):
        cmd = str(proc.get("command_line") or proc.get("commandLine") or "").strip()
        fp = str(proc.get("fullPath") or "").strip()
        sha = str(proc.get("sha256") or "").strip()
        if cmd:
            short_cmd = cmd if len(cmd) <= 44 else cmd[:41] + "..."
            found.append((short_cmd, "PROCESS", fp or "Process Command"))
        elif fp and not is_noisy_entity(fp, "PROCESS"):
            found.append((fp, "PROCESS", "Executable Path"))
        if sha and not is_noisy_entity(sha, "SHA256"):
            found.append((sha, "FILEHASH", "SHA-256 Hash"))
    elif isinstance(proc, str) and proc.strip() and not is_noisy_entity(proc.strip(), "PROCESS"):
        p_s = proc.strip()
        short_p = p_s if len(p_s) <= 44 else p_s[:41] + "..."
        found.append((short_p, "PROCESS", "Process / Executable"))

    url_val = str(noun.get("url") or "").strip()
    if url_val and not is_noisy_entity(url_val, "DESTINATIONURL"):
        found.append((url_val, "URL", "Network URL"))

    res = noun.get("resource")
    if isinstance(res, dict):
        rname = str(res.get("name") or res.get("productObjectId") or "").strip()
        if rname and not is_noisy_entity(rname):
            found.append((rname, "CLOUD", str(res.get("resourceType") or "Cloud Resource")))

    return found


@dataclass
class EntityBlastRadiusResult(UniversalDictMixin):
    """Structured output model for the Entity Blast Radius SOAR Action & HTML Widget."""

    case_id: str
    case_title: str = ""
    case_priority: str = "UNKNOWN"
    case_status: str = "OPENED"
    case_stage: str = "Triage"
    lookback_hours: int = 48
    time_window: Dict[str, str] = field(default_factory=dict)
    secops_ui_base_url: str = ""
    adk_overlay: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, int] = field(default_factory=dict)
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    comment_id: Optional[str] = None
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KillChainTimelineResult(UniversalDictMixin):
    """Structured output model for the Kill-Chain Swimlane SOAR Action & HTML Widget."""

    case_id: str
    case_title: str = ""
    case_priority: str = "UNKNOWN"
    case_status: str = "OPENED"
    case_stage: str = "Triage"
    lookback_hours: int = 48
    time_window: Dict[str, str] = field(default_factory=dict)
    secops_ui_base_url: str = ""
    adk_overlay: Dict[str, Any] = field(default_factory=dict)
    lanes_summary: Dict[str, int] = field(default_factory=dict)
    mitre_stages: List[Dict[str, Any]] = field(default_factory=list)
    entity_lanes: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    events_truncated: bool = False
    total_events_discovered: int = 0
    comment_id: Optional[str] = None
    provenance: Dict[str, Any] = field(default_factory=dict)


class CaseAttackTelemetryCollector:
    """Collects and normalizes Case + SIEM + Cross-Case + ADK telemetry for visual workflows."""

    def __init__(self, adapter: "GoogleSecOpsAdapter"):
        self.adapter = adapter
        self.investigate_workflow = InvestigateCaseWorkflow(adapter=self.adapter)
        self.correlate_workflow = CorrelateSilentDetectionsWorkflow(adapter=self.adapter)
        self.related_cases_workflow = RelatedCasesByEntityWorkflow(adapter=self.adapter)

    def collect(
        self,
        case_id: Union[str, int],
        lookback_hours: int = 48,
        include_udm_precursors: bool = True,
        include_related_cases: bool = True,
        entity_filter: Optional[List[str]] = None,
        entity_filter_mode: str = "AUTO",
        adk_result: Optional[Union[str, Dict[str, Any]]] = None,
        cached_correlation: Optional[Dict[str, Any]] = None,
        cached_related_cases: Optional[Dict[str, Any]] = None,
        max_events: int = 400,
    ) -> Dict[str, Any]:
        clean_cid = _clean_case_id(case_id)
        investigation = self.investigate_workflow.execute(clean_cid)

        # 1. Correlation (Silent YARA-L + UDM Precursors)
        corr_dict: Dict[str, Any] = {}
        can_reuse_corr = False
        if isinstance(cached_correlation, dict) and cached_correlation.get("detections_found") is not None:
            # Reuse cached correlation if UDM precursors aren't needed OR were already collected
            already_has_udm = bool(cached_correlation.get("correlate_udm_events")) or bool(
                cached_correlation.get("events_found")
            )
            if not include_udm_precursors or already_has_udm:
                corr_dict = cached_correlation
                can_reuse_corr = True

        if not can_reuse_corr:
            try:
                corr_res = self.correlate_workflow.execute(
                    case_id=clean_cid,
                    lookback_hours=lookback_hours,
                    attach_to_case=False,
                    attach_entities=False,
                    post_wall_comment=False,
                    entity_filter=entity_filter,
                    entity_filter_mode=entity_filter_mode,
                    max_events=max_events,
                    correlate_detections=True,
                    correlate_udm_events=include_udm_precursors,
                    attach_udm_events=False,
                    extract_entities_from_events=False,
                )
                def _cget(obj: Any, k: str, default: Any = None) -> Any:
                    if isinstance(obj, dict):
                        return obj.get(k, default)
                    return getattr(obj, k, default)

                corr_dict = {
                    "detections_found": _cget(corr_res, "detections_found", []) or [],
                    "events_found": _cget(corr_res, "events_found", []) or [],
                    "entities_searched": _cget(corr_res, "entities_searched", []) or [],
                    "query_used": _cget(corr_res, "query_used", "") or "",
                    "correlate_udm_events": include_udm_precursors,
                    "raw": _cget(corr_res, "raw", {}) or {},
                }
            except Exception as exc:
                logger.warning("Correlation telemetry collection fallback for case %s: %s", clean_cid, exc)
                corr_dict = {
                    "detections_found": (cached_correlation or {}).get("detections_found", []),
                    "events_found": (cached_correlation or {}).get("events_found", []),
                    "entities_searched": (cached_correlation or {}).get("entities_searched", []),
                    "raw": {},
                }

        # 2. Cross-Case Entity Overlap
        related_list: List[Dict[str, Any]] = []
        if include_related_cases:
            if isinstance(cached_related_cases, dict) and isinstance(
                cached_related_cases.get("related_cases"), list
            ):
                related_list = cached_related_cases["related_cases"]
            else:
                try:
                    rel_res = self.related_cases_workflow.execute(
                        case_id=clean_cid,
                        lookback_days=30,
                        max_related_cases=8,
                        max_entities_to_search=15,
                        entity_filter=entity_filter,
                        entity_filter_mode=entity_filter_mode,
                        post_wall_comment=False,
                    )
                    related_list = list(getattr(rel_res, "related_cases", []) or [])
                except Exception as exc:
                    logger.warning("Related cases lookup skipped for case %s: %s", clean_cid, exc)
                    related_list = []

        # 3. ADK Agent Overlay (Explicit -> Case Wall fallback)
        comments_list = getattr(investigation, "comments", None) or []
        adk_overlay = extract_adk_overlay(adk_input=adk_result, comments=comments_list)

        # 4. Compute canonical investigation window (with dynamic post-replay lookahead)
        now_utc = datetime.now(timezone.utc)
        ref_dt: Optional[datetime] = getattr(investigation, "create_time", None)
        for al in getattr(investigation, "alerts", None) or []:
            st = getattr(al, "start_time", None)
            if st and (ref_dt is None or st < ref_dt):
                ref_dt = st
        if ref_dt is None:
            ref_dt = now_utc

        raw_tw = ((corr_dict.get("raw") or {}).get("time_window")) or {}
        start_iso = raw_tw.get("start_time") or (ref_dt - timedelta(hours=max(1, lookback_hours))).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        end_bound = max(ref_dt + timedelta(hours=2), now_utc + timedelta(minutes=15))
        end_iso = raw_tw.get("end_time") or end_bound.strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "case_id": clean_cid,
            "investigation": investigation,
            "detections_found": list(corr_dict.get("detections_found") or []),
            "events_found": list(corr_dict.get("events_found") or []),
            "related_cases": related_list,
            "adk_overlay": adk_overlay,
            "time_window": {"start_time": str(start_iso), "end_time": str(end_iso)},
            "reused_correlation": can_reuse_corr,
            "corr_dict": corr_dict,
        }


def _assign_layered_coordinates(
    nodes: List[Dict[str, Any]],
    edges: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Assigns collision-free 6-tier world coordinates with sub-column wrapping and barycenter ordering.

    Each node's rendered card footprint is ~148px wide by ~90px tall. By enforcing a minimum
    horizontal sub-column pitch of 210px (245px between semantic tiers) and a vertical row pitch
    of 116px (wrapping tiers exceeding 6 nodes into balanced sub-columns), zero node icons or
    label boxes can ever occlude one another regardless of graph density.
    """
    if not nodes:
        return

    risk_order = {"malicious": 0, "warning": 1, "info": 2, "benign": 3}
    buckets: Dict[int, List[Dict[str, Any]]] = {0: [], 1: [], 2: [], 3: [], 4: [], 5: []}

    for n in nodes:
        ntype = n.get("node_type", "HOST")
        if ntype == "CASE":
            col = 5
        elif ntype == "RULE":
            col = 4
        elif ntype in ("PROCESS", "FILEHASH"):
            col = 3
        elif ntype == "USER":
            col = 2
        elif ntype == "HOST" or (ntype == "IP" and n.get("is_internal")):
            col = 1
        else:
            col = 0
        buckets[col].append(n)

    # Initial deterministic sort inside each tier by alerting/risk priority
    for col_nodes in buckets.values():
        col_nodes.sort(
            key=lambda item: (
                0 if item.get("is_alerting") else 1,
                risk_order.get(str(item.get("risk") or "info"), 2),
                -int(item.get("hit_count") or 0),
                str(item.get("identifier") or ""),
            )
        )

    # Split dense tiers (> 6 nodes) into balanced visual sub-columns
    max_rows_per_subcol = 6
    visual_columns: List[Tuple[int, List[Dict[str, Any]]]] = []
    for tier_idx in sorted(buckets.keys()):
        t_nodes = buckets[tier_idx]
        if not t_nodes:
            continue
        num_subcols = (len(t_nodes) + max_rows_per_subcol - 1) // max_rows_per_subcol
        chunk_size = (len(t_nodes) + num_subcols - 1) // num_subcols
        for s_idx in range(0, len(t_nodes), chunk_size):
            visual_columns.append((tier_idx, t_nodes[s_idx : s_idx + chunk_size]))

    # Assign X coordinates with wider gaps between distinct semantic tiers than within wrapped sub-columns
    tier_gap = 248
    subcol_gap = 206
    col_x_coords: List[int] = []
    cur_x = 120
    prev_tier: Optional[int] = None
    for tier_idx, _ in visual_columns:
        if prev_tier is not None:
            cur_x += tier_gap if tier_idx != prev_tier else subcol_gap
        col_x_coords.append(cur_x)
        prev_tier = tier_idx

    row_pitch = 116
    center_y = 260

    def _place_column_y(c_nodes: List[Dict[str, Any]], x_coord: int) -> None:
        cnt = len(c_nodes)
        start_y = center_y - ((cnt - 1) * row_pitch) / 2.0
        for r_idx, nd in enumerate(c_nodes):
            nd["x"] = int(round(x_coord))
            nd["y"] = int(round(start_y + r_idx * row_pitch))

    for idx, (_, c_nodes) in enumerate(visual_columns):
        _place_column_y(c_nodes, col_x_coords[idx])

    # Barycenter crossing-reduction sweep using connected neighbor Y averages
    if edges:
        adj: Dict[str, List[str]] = {}
        node_lookup = {n["id"]: n for n in nodes if "id" in n}
        for ed in edges:
            u, v = ed.get("from"), ed.get("to")
            if u in node_lookup and v in node_lookup:
                adj.setdefault(u, []).append(v)
                adj.setdefault(v, []).append(u)

        for _sweep in range(2):
            for idx, (_, c_nodes) in enumerate(visual_columns):
                if len(c_nodes) <= 1:
                    continue

                def _barycenter(nd: Dict[str, Any]) -> Tuple[float, int]:
                    nbrs = [node_lookup[nid] for nid in adj.get(nd["id"], []) if nid in node_lookup]
                    if not nbrs:
                        return (float(nd.get("y", center_y)), risk_order.get(str(nd.get("risk") or "info"), 2))
                    avg_y = sum(float(nb.get("y", center_y)) for nb in nbrs) / len(nbrs)
                    return (avg_y, risk_order.get(str(nd.get("risk") or "info"), 2))

                c_nodes.sort(key=_barycenter)
                _place_column_y(c_nodes, col_x_coords[idx])
            visual_columns_rev = list(enumerate(visual_columns))[::-1]
            for idx, (_, c_nodes) in visual_columns_rev:
                if len(c_nodes) <= 1:
                    continue
                c_nodes.sort(
                    key=lambda nd: (
                        sum(float(node_lookup[nid].get("y", center_y)) for nid in adj.get(nd["id"], []) if nid in node_lookup)
                        / max(1, len([nid for nid in adj.get(nd["id"], []) if nid in node_lookup]))
                        if any(nid in node_lookup for nid in adj.get(nd["id"], []))
                        else float(nd.get("y", center_y)),
                        risk_order.get(str(nd.get("risk") or "info"), 2),
                    )
                )
                _place_column_y(c_nodes, col_x_coords[idx])


class MapEntityBlastRadiusWorkflow:
    """Constructs an interactive Entity & Detection Blast Radius graph for a SOAR Case."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.collector = CaseAttackTelemetryCollector(adapter=self.adapter)

    def execute(
        self,
        case_id: Union[str, int],
        lookback_hours: int = 48,
        include_udm_precursors: bool = True,
        include_related_cases: bool = True,
        max_nodes: int = 28,
        entity_filter: Optional[List[str]] = None,
        entity_filter_mode: str = "AUTO",
        adk_result: Optional[Union[str, Dict[str, Any]]] = None,
        cached_correlation: Optional[Dict[str, Any]] = None,
        cached_related_cases: Optional[Dict[str, Any]] = None,
        post_wall_comment: bool = False,
        secops_ui_base_url: str = "",
        collected_bundle: Optional[Dict[str, Any]] = None,
    ) -> EntityBlastRadiusResult:
        max_nodes = max(4, min(60, int(max_nodes or 28)))
        parsed_filter = ParsedEntityFilter(entity_filter=entity_filter, entity_filter_mode=entity_filter_mode)

        bundle = collected_bundle or self.collector.collect(
            case_id=case_id,
            lookback_hours=lookback_hours,
            include_udm_precursors=include_udm_precursors,
            include_related_cases=include_related_cases,
            entity_filter=entity_filter,
            entity_filter_mode=entity_filter_mode,
            adk_result=adk_result,
            cached_correlation=cached_correlation,
            cached_related_cases=cached_related_cases,
        )

        clean_cid = bundle["case_id"]
        inv = bundle["investigation"]
        detections_found: List[Dict[str, Any]] = bundle["detections_found"]
        events_found: List[Dict[str, Any]] = bundle["events_found"]
        related_cases: List[Dict[str, Any]] = bundle["related_cases"]
        adk_overlay: Dict[str, Any] = bundle["adk_overlay"]
        time_window: Dict[str, str] = bundle["time_window"]

        verdict_tone = adk_overlay.get("verdict_tone", "inconclusive")
        is_case_benign_btp = verdict_tone in ("btp", "fp")

        nodes_by_key: Dict[str, Dict[str, Any]] = {}
        edges_by_key: Dict[str, Dict[str, Any]] = {}

        def _upsert_node(
            identifier: str,
            node_type: str,
            subtitle: str = "",
            raw_type: str = "",
            risk: str = "info",
            is_suspicious: bool = False,
            is_pivot: bool = False,
            is_internal: bool = False,
            is_alerting: bool = False,
            mitre_info: Optional[Dict[str, str]] = None,
            summary_line: str = "",
            related_case_id: str = "",
            udm_override: str = "",
            bypass_cap: bool = False,
        ) -> Optional[str]:
            ident = str(identifier or "").strip()
            if not ident:
                return None
            nkey = f"{node_type}::{ident.upper()}"
            risk_rank = {"malicious": 4, "warning": 3, "benign": 2, "info": 1}

            if nkey in nodes_by_key:
                existing = nodes_by_key[nkey]
                existing["hit_count"] = existing.get("hit_count", 1) + 1
                if risk_rank.get(risk, 1) > risk_rank.get(existing.get("risk", "info"), 1):
                    existing["risk"] = risk
                if is_suspicious:
                    existing["is_suspicious"] = True
                if is_pivot:
                    existing["is_pivot"] = True
                if is_alerting:
                    existing["is_alerting"] = True
                if mitre_info and mitre_info.get("technique_id"):
                    seen_m = {m["id"] for m in existing["mitre_techniques"]}
                    if mitre_info["technique_id"] not in seen_m:
                        existing["mitre_techniques"].append(
                            {
                                "id": mitre_info["technique_id"],
                                "name": mitre_info.get("technique_name", ""),
                                "tactic": mitre_info.get("tactic_name", ""),
                            }
                        )
                if summary_line and summary_line not in existing["_summaries"]:
                    existing["_summaries"].append(summary_line)
                return existing["id"]

            if not bypass_cap and len(nodes_by_key) >= max_nodes:
                return None

            node_id = f"n_{len(nodes_by_key) + 1}"
            adk_note = _find_adk_insight_for_identifier(ident, adk_overlay)
            mitre_list = []
            if mitre_info and mitre_info.get("technique_id"):
                mitre_list.append(
                    {
                        "id": mitre_info["technique_id"],
                        "name": mitre_info.get("technique_name", ""),
                        "tactic": mitre_info.get("tactic_name", ""),
                    }
                )

            display_label = ident if len(ident) <= 28 else ident[:25] + "..."
            udm_q = udm_override if udm_override else (
                build_entity_udm_query(ident, node_type) if node_type not in ("RULE", "CASE") else ""
            )

            nodes_by_key[nkey] = {
                "id": node_id,
                "key": nkey,
                "identifier": ident,
                "label": display_label,
                "subtitle": subtitle or node_type.title(),
                "node_type": node_type,
                "raw_entity_type": raw_type or node_type,
                "risk": risk,
                "is_suspicious": is_suspicious,
                "is_pivot": is_pivot,
                "is_internal": is_internal,
                "is_alerting": is_alerting,
                "hit_count": 1,
                "silent_hits": 0,
                "alerting_hits": 0,
                "udm_hits": 0,
                "mitre_techniques": mitre_list,
                "udm_query": udm_q,
                "adk_insight": adk_note,
                "related_case_id": related_case_id,
                "_summaries": [summary_line] if summary_line else [],
                "x": 430,
                "y": 210,
            }
            return node_id

        def _find_node_by_ident(ident: str) -> Optional[Dict[str, Any]]:
            up = ident.strip().upper()
            for n in nodes_by_key.values():
                if n["identifier"].upper() == up:
                    return n
            return None

        def _add_edge(src_id: Optional[str], dst_id: Optional[str], label: str, is_hot: bool = False) -> None:
            if not src_id or not dst_id or src_id == dst_id:
                return
            ekey = f"{src_id}->{dst_id}"
            rev_key = f"{dst_id}->{src_id}"
            if ekey in edges_by_key:
                edges_by_key[ekey]["weight"] += 1
                if is_hot:
                    edges_by_key[ekey]["is_hot"] = True
                return
            if rev_key in edges_by_key:
                edges_by_key[rev_key]["weight"] += 1
                if is_hot:
                    edges_by_key[rev_key]["is_hot"] = True
                return
            edges_by_key[ekey] = {
                "from": src_id,
                "to": dst_id,
                "label": label[:26],
                "is_hot": is_hot,
                "weight": 1,
            }

        # 1. Seed Involved Case Entities (prioritizing hosts, IPs, users, processes, and suspicious/pivot indicators,
        #    while reserving node budget for Rules, Correlated Detections, UDM Precursors, and Related Cases)
        case_entity_ids: List[str] = []
        entity_seed_cap = max(6, int(max_nodes * 0.55))
        _vtype_prio = {"HOST": 0, "IP": 1, "USER": 2, "PROCESS": 3, "CLOUD": 4, "URL": 5, "FILEHASH": 6}
        candidate_case_ents: List[Tuple[Tuple[int, int], Any, str, str, str]] = []
        for ent in getattr(inv, "entities", None) or []:
            ident = str(getattr(ent, "identifier", "") or "").strip()
            raw_etype = str(getattr(ent, "entity_type", "") or "GENERICENTITY").strip()
            if not ident or is_noisy_entity(ident, raw_etype) or _is_threat_actor_entity(raw_etype, ident):
                continue
            if not parsed_filter.matches(ident, raw_etype):
                continue
            vtype = _classify_visual_node_type(raw_etype, ident)
            raw_ent_dict = getattr(ent, "raw", {}) or {}
            is_susp = bool(getattr(ent, "is_suspicious", False) or raw_ent_dict.get("isSuspicious"))
            is_piv = bool(getattr(ent, "is_pivot", False) or raw_ent_dict.get("isPivot"))
            sort_key = (0 if (is_susp or is_piv) else 1, _vtype_prio.get(vtype, 9))
            candidate_case_ents.append((sort_key, ent, ident, raw_etype, vtype))

        candidate_case_ents.sort(key=lambda item: item[0])

        for _, ent, ident, raw_etype, vtype in candidate_case_ents[:entity_seed_cap]:
            raw_ent_dict = getattr(ent, "raw", {}) or {}
            is_susp = bool(getattr(ent, "is_suspicious", False) or raw_ent_dict.get("isSuspicious"))
            is_piv = bool(getattr(ent, "is_pivot", False) or raw_ent_dict.get("isPivot"))
            is_int = bool(
                getattr(ent, "is_internal", False)
                or raw_ent_dict.get("isInternal")
                or (vtype == "IP" and _is_private_or_internal_ip(ident))
            )

            if is_case_benign_btp and not is_susp:
                base_risk = "benign"
            elif is_susp or (vtype == "IP" and not is_int and verdict_tone == "malicious"):
                base_risk = "malicious"
            elif is_piv or verdict_tone == "malicious":
                base_risk = "warning"
            else:
                base_risk = "info"

            sub = (
                "Internal IP"
                if (vtype == "IP" and is_int)
                else ("External IP" if vtype == "IP" else f"Case {vtype.title()}")
            )
            nid = _upsert_node(
                identifier=ident,
                node_type=vtype,
                subtitle=sub,
                raw_type=raw_etype,
                risk=base_risk,
                is_suspicious=is_susp,
                is_pivot=is_piv,
                is_internal=is_int,
                summary_line=f"Extracted from SOAR Case #{clean_cid} alert context.",
            )
            if nid:
                case_entity_ids.append(nid)

        # 2. Seed Alerting Case Rules & Link to Involved Entities
        alert_rule_node_ids: List[str] = []
        for al in getattr(inv, "alerts", None) or []:
            rname, al_udm_q = _human_alert_rule_info(al)
            prio = str(getattr(al, "priority", "HIGH") or "HIGH").upper()
            mitre_al = resolve_mitre_metadata(rname)
            al_risk = "warning" if is_case_benign_btp else "malicious"
            rn_id = _upsert_node(
                identifier=rname,
                node_type="RULE",
                subtitle=f"ALERTING Rule ({prio})",
                raw_type="ALERTING_RULE",
                risk=al_risk,
                is_alerting=True,
                mitre_info=mitre_al,
                summary_line=f"Primary SOAR Case Alert ({getattr(al, 'event_count', 1) or 1} event(s)).",
                udm_override=al_udm_q,
                bypass_cap=len(alert_rule_node_ids) < 4,
            )
            if rn_id:
                alert_rule_node_ids.append(rn_id)

        # 3. Correlated Silent & Alerting YARA-L Detections
        det_rule_node_ids: Set[str] = set()
        for det in detections_found[:40]:
            if not isinstance(det, dict):
                continue
            rname = str(det.get("rule_name") or "Correlated YARA-L Rule").strip()
            is_alerting = bool(det.get("is_alerting"))
            sev = str(det.get("severity") or "MEDIUM").upper()
            p_nouns = _extract_noun_identifiers(det.get("principal"))
            t_nouns = _extract_noun_identifiers(det.get("target"))
            cmd_hint = " ".join(x[0] for x in (p_nouns + t_nouns))
            mitre_det = resolve_mitre_metadata(rname, det.get("summary"), cmd_hint, event_type=det.get("event_type"))

            det_risk = "benign" if is_case_benign_btp else ("malicious" if is_alerting or sev in ("CRITICAL", "HIGH") else "warning")
            state_lbl = "ALERTING Rule" if is_alerting else "SILENT YARA-L Rule"
            escaped_rname = rname.replace('"', '\\"')
            det_node_id = _upsert_node(
                identifier=rname,
                node_type="RULE",
                subtitle=f"{state_lbl} ({sev})",
                raw_type="SILENT_RULE" if not is_alerting else "ALERTING_RULE",
                risk=det_risk,
                is_alerting=is_alerting,
                mitre_info=mitre_det,
                summary_line=str(det.get("summary") or f"Matched {state_lbl} during lookback window."),
                udm_override=f'security_result.rule_name = "{escaped_rname}"',
                bypass_cap=len(det_rule_node_ids) < 6,
            )
            if det_node_id:
                det_rule_node_ids.add(det_node_id)

            involved_nids: List[str] = []
            for ident, vtype, sub in (p_nouns + t_nouns)[:4]:
                if not parsed_filter.matches(ident, vtype):
                    continue
                is_int = vtype == "IP" and _is_private_or_internal_ip(ident)
                ent_risk = "benign" if is_case_benign_btp else ("malicious" if is_alerting else "warning")
                enid = _upsert_node(
                    identifier=ident,
                    node_type=vtype,
                    subtitle=sub,
                    risk=ent_risk,
                    is_internal=is_int,
                    mitre_info=mitre_det,
                    summary_line=f"Correlated via {state_lbl}: {rname}",
                )
                if enid:
                    involved_nids.append(enid)
                    for n_obj in nodes_by_key.values():
                        if n_obj["id"] == enid:
                            if is_alerting:
                                n_obj["alerting_hits"] += 1
                            else:
                                n_obj["silent_hits"] += 1

            # Connect principal -> target and entities -> rule
            if len(involved_nids) >= 2:
                _add_edge(
                    involved_nids[0],
                    involved_nids[1],
                    str(det.get("event_type") or "interacted").replace("_", " ").lower(),
                    is_hot=not is_case_benign_btp,
                )
            for enid in involved_nids:
                _add_edge(
                    enid,
                    det_node_id,
                    "triggered alert" if is_alerting else "matched silent rule",
                    is_hot=is_alerting and not is_case_benign_btp,
                )

        # 4. Precursor & Pivot UDM Events
        for ev in events_found[:35]:
            if not isinstance(ev, dict):
                continue
            ev_type = str(ev.get("event_type") or "UDM_EVENT").strip()
            p_nouns = _extract_noun_identifiers(ev.get("principal"))
            t_nouns = _extract_noun_identifiers(ev.get("target"))
            cmd_text = " ".join(x[0] for x in (p_nouns + t_nouns))
            mitre_ev = resolve_mitre_metadata(ev.get("description"), cmd_text, event_type=ev_type)

            p_ids: List[str] = []
            t_ids: List[str] = []
            ev_risk = "benign" if is_case_benign_btp else ("warning" if mitre_ev.get("technique_id") else "info")

            for ident, vtype, sub in p_nouns[:2]:
                if not parsed_filter.matches(ident, vtype):
                    continue
                nid = _upsert_node(
                    identifier=ident,
                    node_type=vtype,
                    subtitle=sub,
                    risk=ev_risk,
                    is_internal=(vtype == "IP" and _is_private_or_internal_ip(ident)),
                    mitre_info=mitre_ev,
                    summary_line=f"Observed as principal in UDM {ev_type}.",
                )
                if nid:
                    p_ids.append(nid)
                    for n_obj in nodes_by_key.values():
                        if n_obj["id"] == nid:
                            n_obj["udm_hits"] += 1

            for ident, vtype, sub in t_nouns[:2]:
                if not parsed_filter.matches(ident, vtype):
                    continue
                nid = _upsert_node(
                    identifier=ident,
                    node_type=vtype,
                    subtitle=sub if vtype != "PROCESS" else "Unalerted UDM Precursor",
                    risk=ev_risk,
                    is_internal=(vtype == "IP" and _is_private_or_internal_ip(ident)),
                    mitre_info=mitre_ev,
                    summary_line=f"Observed as target in UDM {ev_type}.",
                )
                if nid:
                    t_ids.append(nid)
                    for n_obj in nodes_by_key.values():
                        if n_obj["id"] == nid:
                            n_obj["udm_hits"] += 1

            edge_lbl = ev_type.replace("PROCESS_", "").replace("NETWORK_", "").replace("_", " ").lower()
            if p_ids and t_ids:
                _add_edge(p_ids[0], t_ids[0], edge_lbl, is_hot=(ev_risk == "warning" and not is_case_benign_btp))
            elif len(p_ids) >= 2:
                _add_edge(p_ids[0], p_ids[1], edge_lbl, is_hot=False)

        # 5. Related SOAR Cases Sharing Entities
        for rc in related_cases[:5]:
            if not isinstance(rc, dict):
                continue
            rc_id = str(rc.get("case_id") or "").strip()
            if not rc_id or rc_id == clean_cid:
                continue
            rc_title = str(rc.get("title") or f"Case #{rc_id}").strip()
            rc_status = "CLOSED" if rc.get("is_closed") else "OPEN"
            rc_nid = _upsert_node(
                identifier=f"Case #{rc_id}",
                node_type="CASE",
                subtitle=f"{rc_status} • {rc_title[:24]}",
                raw_type="RELATED_CASE",
                risk="warning" if rc.get("is_incident") else "info",
                related_case_id=rc_id,
                summary_line=f"Related SOAR Case #{rc_id}: {rc_title} (Priority: {rc.get('priority', 'N/A')}).",
                bypass_cap=True,
            )
            if rc_nid:
                shared_ents = rc.get("shared_entities") or []
                linked_any = False
                for se in shared_ents:
                    s_ident = str((se.get("identifier") if isinstance(se, dict) else se) or "").strip()
                    matched_node = _find_node_by_ident(s_ident)
                    if matched_node:
                        _add_edge(matched_node["id"], rc_nid, f"shared in #{rc_id}", is_hot=False)
                        linked_any = True
                if not linked_any and case_entity_ids:
                    _add_edge(case_entity_ids[0], rc_nid, f"overlap #{rc_id}", is_hot=False)

        # 6. Ensure every seeded Case Entity and Alert Rule connects so no orphans float
        connected_ids: Set[str] = set()
        for ed in edges_by_key.values():
            connected_ids.add(ed["from"])
            connected_ids.add(ed["to"])

        anchor_target = alert_rule_node_ids[0] if alert_rule_node_ids else (case_entity_ids[0] if case_entity_ids else None)
        if anchor_target:
            for cid_node in case_entity_ids:
                if cid_node not in connected_ids and cid_node != anchor_target:
                    _add_edge(
                        cid_node,
                        anchor_target,
                        "involved in alert",
                        is_hot=(verdict_tone == "malicious"),
                    )
        if case_entity_ids:
            for rn_id in alert_rule_node_ids:
                if rn_id not in connected_ids:
                    _add_edge(
                        case_entity_ids[0],
                        rn_id,
                        "triggered alert",
                        is_hot=not is_case_benign_btp,
                    )

        # Finalize node summaries, stats, and layered layout coordinates
        final_nodes: List[Dict[str, Any]] = []
        for n in nodes_by_key.values():
            summaries = n.pop("_summaries", [])
            stat_parts = []
            if n["alerting_hits"]:
                stat_parts.append(f"{n['alerting_hits']} Alerting Hit(s)")
            if n["silent_hits"]:
                stat_parts.append(f"{n['silent_hits']} Silent Rule(s)")
            if n["udm_hits"]:
                stat_parts.append(f"{n['udm_hits']} UDM Event(s)")
            if not stat_parts:
                stat_parts.append("Case Alert Indicator" if n["node_type"] not in ("RULE", "CASE") else n["subtitle"])
            n["telemetry_stats"] = " • ".join(stat_parts)
            n["summary"] = " ".join(summaries[:2]) if summaries else f"{n['node_type']} indicator in Case #{clean_cid}."
            final_nodes.append(n)

        final_edges = list(edges_by_key.values())
        _assign_layered_coordinates(final_nodes, final_edges)

        entity_nodes_cnt = sum(1 for n in final_nodes if n["node_type"] not in ("RULE", "CASE"))
        rule_nodes_cnt = sum(1 for n in final_nodes if n["node_type"] == "RULE")
        case_nodes_cnt = sum(1 for n in final_nodes if n["node_type"] == "CASE")
        high_risk_cnt = sum(1 for n in final_nodes if n["risk"] in ("malicious", "warning"))
        silent_rules_cnt = sum(1 for n in final_nodes if n["node_type"] == "RULE" and not n["is_alerting"])
        alerting_rules_cnt = sum(1 for n in final_nodes if n["node_type"] == "RULE" and n["is_alerting"])

        metrics = {
            "total_nodes": len(final_nodes),
            "entity_nodes_count": entity_nodes_cnt,
            "detection_nodes_count": rule_nodes_cnt,
            "related_case_nodes_count": case_nodes_cnt,
            "total_edges": len(final_edges),
            "elevated_nodes_count": high_risk_cnt,
            "silent_rules_count": silent_rules_cnt,
            "alerting_rules_count": alerting_rules_cnt,
        }

        comment_id = None
        if post_wall_comment and final_nodes:
            try:
                verdict_line = (
                    f"- **ADK Agent Verdict**: `{adk_overlay.get('verdict')}` ({adk_overlay.get('disposition')})\n"
                    if adk_overlay.get("has_adk_analysis")
                    else ""
                )
                wall_md = (
                    f"### [Automated Graph] Case Entity Blast Radius\n"
                    f"{verdict_line}"
                    f"- **Topology Footprint**: `{entity_nodes_cnt}` Entities, `{rule_nodes_cnt}` YARA-L Rules "
                    f"(`{silent_rules_cnt}` Silent / `{alerting_rules_cnt}` Alerting), `{case_nodes_cnt}` Related Cases, "
                    f"`{len(final_edges)}` Corroborated Edges."
                )
                c_res = self.adapter.create_case_comment(case_id=clean_cid, comment=wall_md)
                comment_id = str((c_res or {}).get("name", "")).split("/")[-1] or "posted"
            except Exception as exc:
                logger.warning("Could not post Blast Radius comment for case %s: %s", clean_cid, exc)

        prio_val = getattr(inv, "priority", "UNKNOWN")
        prio_str = prio_val.value if hasattr(prio_val, "value") else str(prio_val or "UNKNOWN")
        status_val = getattr(inv, "status", "OPENED")
        status_str = status_val.value if hasattr(status_val, "value") else str(status_val or "OPENED")

        res_obj = EntityBlastRadiusResult(
            case_id=clean_cid,
            case_title=str(getattr(inv, "display_name", "") or getattr(inv, "title", "") or f"Case #{clean_cid}"),
            case_priority=prio_str,
            case_status=status_str,
            case_stage=str(getattr(inv, "stage", "") or "Triage"),
            lookback_hours=lookback_hours,
            time_window=time_window,
            secops_ui_base_url=secops_ui_base_url,
            adk_overlay=_public_adk_overlay(adk_overlay),
            metrics=metrics,
            nodes=final_nodes,
            edges=final_edges,
            comment_id=comment_id,
            provenance={
                "workflow": "case.graph.entity_blast_radius",
                "reused_correlation": bool(bundle.get("reused_correlation")),
                "has_adk_analysis": bool(adk_overlay.get("has_adk_analysis")),
            },
        )
        res_obj._corr_export = bundle.get("corr_dict") or {}
        res_obj._related_export = {"related_cases": related_cases}
        return res_obj


class BuildKillChainTimelineWorkflow:
    """Constructs a chronological multi-lane MITRE Kill-Chain Swimlane storyboard for a SOAR Case."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.collector = CaseAttackTelemetryCollector(adapter=self.adapter)

    def execute(
        self,
        case_id: Union[str, int],
        lookback_hours: int = 48,
        include_udm_precursors: bool = True,
        max_timeline_events: int = 50,
        entity_filter: Optional[List[str]] = None,
        entity_filter_mode: str = "AUTO",
        adk_result: Optional[Union[str, Dict[str, Any]]] = None,
        cached_correlation: Optional[Dict[str, Any]] = None,
        post_wall_comment: bool = False,
        secops_ui_base_url: str = "",
        collected_bundle: Optional[Dict[str, Any]] = None,
    ) -> KillChainTimelineResult:
        max_timeline_events = max(5, min(120, int(max_timeline_events or 50)))

        bundle = collected_bundle or self.collector.collect(
            case_id=case_id,
            lookback_hours=lookback_hours,
            include_udm_precursors=include_udm_precursors,
            include_related_cases=False,
            entity_filter=entity_filter,
            entity_filter_mode=entity_filter_mode,
            adk_result=adk_result,
            cached_correlation=cached_correlation,
        )

        clean_cid = bundle["case_id"]
        inv = bundle["investigation"]
        detections_found: List[Dict[str, Any]] = bundle["detections_found"]
        events_found: List[Dict[str, Any]] = bundle["events_found"]
        adk_overlay: Dict[str, Any] = bundle["adk_overlay"]
        time_window: Dict[str, str] = bundle["time_window"]

        verdict_tone = adk_overlay.get("verdict_tone", "inconclusive")
        is_case_benign_btp = verdict_tone in ("btp", "fp")

        raw_timeline: List[Dict[str, Any]] = []
        seen_keys: Set[str] = set()

        def _norm_ts(raw_ts: Any) -> Tuple[str, str, int]:
            dt = parse_timestamp(raw_ts) if not isinstance(raw_ts, datetime) else raw_ts
            if dt is None:
                dt = getattr(inv, "create_time", None) or datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            iso_s = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            disp_s = dt.astimezone(timezone.utc).strftime("%H:%M:%S UTC")
            return iso_s, disp_s, int(dt.timestamp() * 1000)

        def _is_display_only_person_name(ident: str) -> bool:
            s = (ident or "").strip()
            return "," in s and " " in s and "@" not in s and "\\" not in s

        def _derive_entity_pivot(
            typed_nouns: List[Tuple[str, str]],
            is_aggregated_alert: bool = False,
        ) -> Tuple[str, str]:
            """Selects a clean, canonical (entity_key, entity_label) for Affected-Entity swimlane grouping."""
            users: List[Tuple[str, str]] = []
            hosts: List[Tuple[str, str]] = []
            ext_ips: List[Tuple[str, str]] = []
            int_ips: List[Tuple[str, str]] = []

            real_user_tokens = [
                ident for ident, vtype in typed_nouns if vtype == "USER" and not _is_display_only_person_name(ident)
            ]
            seen_u: Set[str] = set()
            for ident, vtype in typed_nouns:
                val = (ident or "").strip().strip('"').strip("'")
                if not val:
                    continue
                if vtype == "USER":
                    if real_user_tokens and _is_display_only_person_name(val):
                        continue
                    local = val.split("@")[0].split("\\")[-1].strip()
                    if not local or local.lower() in seen_u:
                        continue
                    seen_u.add(local.lower())
                    label_val = local if len(local) <= 22 else local[:19] + "..."
                    users.append((f"USER:{local.lower()}", f"User: {label_val}"))
                elif vtype == "HOST":
                    short_h = val.split(".")[0].strip()
                    if short_h:
                        label_val = short_h if len(short_h) <= 22 else short_h[:19] + "..."
                        hosts.append((f"HOST:{short_h.lower()}", f"Host: {label_val}"))
                elif vtype == "IP":
                    pair = (f"IP:{val.lower()}", f"IP: {val}")
                    if _is_private_or_internal_ip(val):
                        int_ips.append(pair)
                    else:
                        ext_ips.append(pair)

            if is_aggregated_alert and len(users) >= 3:
                if ext_ips:
                    return ext_ips[0]
                if hosts:
                    return hosts[0]
            if users:
                return users[0]
            if hosts:
                return hosts[0]
            if ext_ips:
                return ext_ips[0]
            if int_ips:
                return int_ips[0]
            return ("TELEMETRY:context", "System / Context")

        def _clean_display_entities(typed_nouns: List[Tuple[str, str]], limit: int = 4) -> List[str]:
            """Orders involved entities cleanly (preferring UPN/account, Host, IP over display names and raw cloud paths)."""
            has_real_user = any(vt == "USER" and not _is_display_only_person_name(i) for i, vt in typed_nouns)
            prio = {"IP": 0, "USER": 1, "HOST": 2, "PROCESS": 3, "URL": 4, "CLOUD": 5, "FILEHASH": 6}
            filtered: List[Tuple[int, str]] = []
            seen_e: Set[str] = set()
            for idx_pos, (ident, vt) in enumerate(typed_nouns):
                val = (ident or "").strip()
                if not val or val.lower() in seen_e:
                    continue
                if vt == "USER" and has_real_user and _is_display_only_person_name(val):
                    continue
                if vt == "CLOUD" and val.startswith("/tenants/"):
                    continue
                seen_e.add(val.lower())
                filtered.append((prio.get(vt, 7) * 10 + idx_pos, val))
            filtered.sort(key=lambda x: x[0])
            return [x[1] for x in filtered[:limit]]

        # 1. Precursor & Pivot UDM Events -> Lane "UDM" (coalescing repetitive identical bursts)
        udm_pattern_entries: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events_found:
            if not isinstance(ev, dict):
                continue
            ev_id = str(ev.get("event_id") or "").strip()
            dedup = f"UDM::{ev_id}" if ev_id else f"UDM::{ev.get('timestamp')}::{ev.get('event_type')}"
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)

            iso_s, disp_s, epoch_ms = _norm_ts(ev.get("timestamp"))
            ev_type = str(ev.get("event_type") or "UDM_EVENT").strip()
            p_nouns = _extract_noun_identifiers(ev.get("principal"))
            t_nouns = _extract_noun_identifiers(ev.get("target"))
            typed_nouns = [(x[0], x[1]) for x in (p_nouns + t_nouns)]
            entities_involved = _clean_display_entities(typed_nouns, limit=4) or [x[0] for x in typed_nouns[:4]]
            ent_key, ent_label = _derive_entity_pivot(typed_nouns)

            # Build readable title & command/network detail
            p_proc = ((ev.get("principal") or {}).get("process") or {}) if isinstance(ev.get("principal"), dict) else {}
            t_proc = ((ev.get("target") or {}).get("process") or {}) if isinstance(ev.get("target"), dict) else {}
            cmd_line = str(
                t_proc.get("command_line")
                or t_proc.get("commandLine")
                or p_proc.get("command_line")
                or p_proc.get("commandLine")
                or ""
            ).strip()
            host_name = str(
                ((ev.get("principal") or {}).get("hostname") if isinstance(ev.get("principal"), dict) else "")
                or ((ev.get("target") or {}).get("hostname") if isinstance(ev.get("target"), dict) else "")
                or ""
            ).strip()

            mitre_info = resolve_mitre_metadata(ev.get("description"), cmd_line, " ".join(entities_involved), event_type=ev_type)
            if cmd_line:
                short_cmd = cmd_line if len(cmd_line) <= 78 else cmd_line[:75] + "..."
                title = f"{ev_type}: {short_cmd}"
            elif entities_involved:
                title = f"{ev_type} ({' → '.join(entities_involved[:2])})"
            else:
                title = f"UDM {ev_type}"

            pattern_sig = f"{ev_type}::{title.upper()}"
            existing_burst = udm_pattern_entries.get(pattern_sig, [])
            if len(existing_burst) >= 2:
                last_rep = existing_burst[-1]
                last_rep["_burst_extra"] = last_rep.get("_burst_extra", 0) + 1
                base_title = last_rep.get("_base_title", last_rep["title"])
                last_rep["_base_title"] = base_title
                last_rep["title"] = f"{base_title} (+{last_rep['_burst_extra']} similar)"
                continue

            detail_parts = []
            if host_name:
                detail_parts.append(f"Host: {host_name}")
            if cmd_line:
                detail_parts.append(f"Command: {cmd_line[:280]}")
            elif ev.get("description"):
                detail_parts.append(str(ev.get("description"))[:240])
            if ev_id:
                detail_parts.append(f"Event ID: {ev_id}")

            adk_note = ""
            for ent_val in entities_involved:
                adk_note = _find_adk_insight_for_identifier(ent_val, adk_overlay)
                if adk_note:
                    break

            sev = "benign" if is_case_benign_btp else ("warning" if mitre_info.get("technique_id") else "info")
            udm_q = (
                build_entity_udm_query(entities_involved[0], _classify_visual_node_type("", entities_involved[0]))
                if entities_involved
                else f'metadata.event_type = "{ev_type}"'
            )

            t_slug = mitre_info.get("tactic_slug", "")
            t_lbl = mitre_info.get("tactic_name", "")
            entry_dict = {
                "timestamp": iso_s,
                "display_time": disp_s,
                "epoch_ms": epoch_ms,
                "lane": "UDM",
                "lane_label": "Precursor UDM",
                "severity": sev,
                "title": title,
                "detail": " | ".join(detail_parts) or f"Unalerted Chronicle UDM {ev_type} telemetry.",
                "mitre_id": mitre_info.get("technique_id", ""),
                "mitre_name": mitre_info.get("technique_name", ""),
                "mitre_tactic": t_lbl,
                "mitre_tactic_slug": t_slug,
                "stage_slug": t_slug or "unclassified-telemetry",
                "stage_label": t_lbl or "Telemetry Context",
                "entities": entities_involved,
                "primary_entity_key": ent_key,
                "primary_entity_label": ent_label,
                "rule_id": "",
                "event_id": ev_id,
                "udm_query": udm_q,
                "adk_annotation": adk_note,
            }
            udm_pattern_entries.setdefault(pattern_sig, []).append(entry_dict)
            raw_timeline.append(entry_dict)

        # 2. Silent & Correlated YARA-L Detections -> Lane "SILENT" or "ALERT"
        for det in detections_found:
            if not isinstance(det, dict):
                continue
            rname = str(det.get("rule_name") or "YARA-L Detection").strip()
            rid = str(det.get("rule_id") or "").strip()
            ev_id = str(det.get("event_id") or "").strip()
            is_alerting = bool(det.get("is_alerting"))
            dedup = f"DET::{rname}::{ev_id or det.get('timestamp')}"
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)

            iso_s, disp_s, epoch_ms = _norm_ts(det.get("timestamp"))
            p_nouns = _extract_noun_identifiers(det.get("principal"))
            t_nouns = _extract_noun_identifiers(det.get("target"))
            typed_nouns = [(x[0], x[1]) for x in (p_nouns + t_nouns)]
            entities_involved = _clean_display_entities(typed_nouns, limit=4) or [x[0] for x in typed_nouns[:4]]
            ent_key, ent_label = _derive_entity_pivot(typed_nouns)
            mitre_info = resolve_mitre_metadata(
                rname, det.get("summary"), " ".join(entities_involved), event_type=det.get("event_type")
            )

            lane_key = "ALERT" if is_alerting else "SILENT"
            lane_lbl = "Alerting YARA-L" if is_alerting else "Silent YARA-L"
            raw_sev = str(det.get("severity") or "MEDIUM").upper()
            if is_case_benign_btp:
                sev = "benign" if not is_alerting else "warning"
            else:
                sev = "malicious" if (is_alerting or raw_sev in ("CRITICAL", "HIGH")) else "warning"

            adk_note = _find_adk_insight_for_identifier(rname, adk_overlay)
            if not adk_note:
                for ent_val in entities_involved:
                    adk_note = _find_adk_insight_for_identifier(ent_val, adk_overlay)
                    if adk_note:
                        break

            escaped_rname = rname.replace('"', '\\"')
            detail_str = str(det.get("summary") or f"{lane_lbl} match on rule '{rname}'.")
            if rid:
                detail_str += f" (Rule ID: {rid})"
            if entities_involved:
                detail_str += f" | Entities: {', '.join(entities_involved)}"

            t_slug = mitre_info.get("tactic_slug", "")
            t_lbl = mitre_info.get("tactic_name", "")
            raw_timeline.append(
                {
                    "timestamp": iso_s,
                    "display_time": disp_s,
                    "epoch_ms": epoch_ms,
                    "lane": lane_key,
                    "lane_label": lane_lbl,
                    "severity": sev,
                    "title": f"{rname}",
                    "detail": detail_str,
                    "mitre_id": mitre_info.get("technique_id", ""),
                    "mitre_name": mitre_info.get("technique_name", ""),
                    "mitre_tactic": t_lbl,
                    "mitre_tactic_slug": t_slug,
                    "stage_slug": t_slug or "unclassified-telemetry",
                    "stage_label": t_lbl or "Telemetry Context",
                    "entities": entities_involved,
                    "primary_entity_key": ent_key,
                    "primary_entity_label": ent_label,
                    "rule_id": rid,
                    "event_id": ev_id,
                    "udm_query": f'security_result.rule_name = "{escaped_rname}"',
                    "adk_annotation": adk_note,
                }
            )

        # 3. Primary SOAR Case Alerts -> Lane "ALERT"
        all_case_ents = list(getattr(inv, "entities", None) or [])
        for al in getattr(inv, "alerts", None) or []:
            rname, al_udm_q = _human_alert_rule_info(al)
            aid = str(getattr(al, "identifier", "") or "").strip()
            dedup = f"CASE_ALERT::{aid or rname}"
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)

            iso_s, disp_s, epoch_ms = _norm_ts(getattr(al, "start_time", None) or getattr(inv, "create_time", None))
            mitre_info = resolve_mitre_metadata(rname)
            prio = str(getattr(al, "priority", "HIGH") or "HIGH").upper()
            sev = "warning" if is_case_benign_btp else "malicious"

            # Match alert-scoped entities (or fallback to case-level entities)
            matched_ents = [
                e for e in all_case_ents if aid and str((getattr(e, "raw", {}) or {}).get("alertIdentifier") or "") == aid
            ] or all_case_ents
            alert_typed_nouns: List[Tuple[str, str]] = []
            for ent_obj in matched_ents:
                e_id = str(getattr(ent_obj, "identifier", "") or "").strip()
                e_rt = str(getattr(ent_obj, "entity_type", "") or "").strip()
                if not e_id or is_noisy_entity(e_id, e_rt) or _is_threat_actor_entity(e_rt, e_id):
                    continue
                alert_typed_nouns.append((e_id, _classify_visual_node_type(e_rt, e_id)))
            alert_entities = _clean_display_entities(alert_typed_nouns, limit=4)
            al_ent_key, al_ent_label = _derive_entity_pivot(alert_typed_nouns, is_aggregated_alert=True)

            al_adk_note = _find_adk_insight_for_identifier(rname, adk_overlay)
            if not al_adk_note:
                for ent_val in alert_entities:
                    al_adk_note = _find_adk_insight_for_identifier(ent_val, adk_overlay)
                    if al_adk_note:
                        break

            detail_txt = (
                f"Case Alert #{aid} | Priority: {prio} | Vendor: {getattr(al, 'vendor', 'Google Chronicle') or 'Chronicle'} "
                f"| Event Count: {getattr(al, 'event_count', 1) or 1}"
            )
            if alert_entities:
                detail_txt += f" | Entities: {', '.join(alert_entities)}"

            t_slug = mitre_info.get("tactic_slug", "")
            t_lbl = mitre_info.get("tactic_name", "")
            raw_timeline.append(
                {
                    "timestamp": iso_s,
                    "display_time": disp_s,
                    "epoch_ms": epoch_ms,
                    "lane": "ALERT",
                    "lane_label": "Alerting YARA-L",
                    "severity": sev,
                    "title": f"SOAR Alert: {rname}",
                    "detail": detail_txt,
                    "mitre_id": mitre_info.get("technique_id", ""),
                    "mitre_name": mitre_info.get("technique_name", ""),
                    "mitre_tactic": t_lbl,
                    "mitre_tactic_slug": t_slug,
                    "stage_slug": t_slug or "initial-access",
                    "stage_label": t_lbl or "Initial Access",
                    "entities": alert_entities,
                    "primary_entity_key": al_ent_key,
                    "primary_entity_label": al_ent_label,
                    "rule_id": str((getattr(al, "raw", {}) or {}).get("sourceRuleIdentifier") or ""),
                    "event_id": aid,
                    "udm_query": al_udm_q,
                    "adk_annotation": al_adk_note,
                }
            )

        # 4. SOAR Case Creation & Google ADK Verdict Synthesis -> Lane "SOAR_ADK"
        if getattr(inv, "create_time", None):
            iso_s, disp_s, epoch_ms = _norm_ts(inv.create_time)
            raw_timeline.append(
                {
                    "timestamp": iso_s,
                    "display_time": disp_s,
                    "epoch_ms": epoch_ms,
                    "lane": "SOAR_ADK",
                    "lane_label": "SOAR & ADK",
                    "severity": "info",
                    "title": f"SOAR Case #{clean_cid} Created",
                    "detail": f"Opened in stage '{getattr(inv, 'stage', 'Triage')}' with {len(getattr(inv, 'alerts', []) or [])} alert(s).",
                    "mitre_id": "",
                    "mitre_name": "",
                    "mitre_tactic": "",
                    "mitre_tactic_slug": "",
                    "stage_slug": "soar-response",
                    "stage_label": "SOAR & ADK",
                    "entities": [],
                    "primary_entity_key": "SOAR_ADK",
                    "primary_entity_label": "SOAR & ADK",
                    "rule_id": "",
                    "event_id": clean_cid,
                    "udm_query": "",
                    "adk_annotation": "",
                }
            )

        if adk_overlay.get("has_adk_analysis"):
            # Place ADK synthesis milestone at the end of observed activity
            latest_ms = max((item["epoch_ms"] for item in raw_timeline), default=int(datetime.now(timezone.utc).timestamp() * 1000))
            synth_dt = datetime.fromtimestamp((latest_ms + 1000) / 1000.0, tz=timezone.utc)
            iso_s, disp_s, epoch_ms = _norm_ts(synth_dt)
            v_tone = adk_overlay.get("verdict_tone", "inconclusive")
            adk_sev = "malicious" if v_tone == "malicious" else ("benign" if v_tone in ("btp", "fp") else "info")
            raw_timeline.append(
                {
                    "timestamp": iso_s,
                    "display_time": disp_s,
                    "epoch_ms": epoch_ms,
                    "lane": "SOAR_ADK",
                    "lane_label": "SOAR & ADK",
                    "severity": adk_sev,
                    "title": f"ADK Agent Verdict: {adk_overlay.get('verdict')}",
                    "detail": (
                        f"Disposition: {adk_overlay.get('disposition') or 'Evaluated'} | "
                        f"Confidence: {adk_overlay.get('confidence') or 'HIGH'} | "
                        f"{adk_overlay.get('summary') or 'Autonomous triage completed.'}"
                    ),
                    "mitre_id": "",
                    "mitre_name": "",
                    "mitre_tactic": "",
                    "mitre_tactic_slug": "",
                    "stage_slug": "soar-response",
                    "stage_label": "SOAR & ADK",
                    "entities": [],
                    "primary_entity_key": "SOAR_ADK",
                    "primary_entity_label": "SOAR & ADK",
                    "rule_id": "",
                    "event_id": adk_overlay.get("session_id", ""),
                    "udm_query": "",
                    "adk_annotation": adk_overlay.get("summary", ""),
                }
            )

        # Sort chronologically ascending
        raw_timeline.sort(key=lambda x: (x["epoch_ms"], 0 if x["lane"] == "UDM" else 1))
        total_discovered = len(raw_timeline)
        truncated = total_discovered > max_timeline_events

        # Preserve diversity if capping: always keep ALERT and SOAR_ADK milestones, fill remaining with SILENT + UDM
        if truncated:
            must_keep = [e for e in raw_timeline if e["lane"] in ("ALERT", "SOAR_ADK")]
            others = [e for e in raw_timeline if e["lane"] not in ("ALERT", "SOAR_ADK")]
            remaining_slots = max(0, max_timeline_events - len(must_keep))
            selected_events = must_keep[:max_timeline_events] + others[:remaining_slots]
            selected_events.sort(key=lambda x: (x["epoch_ms"], 0 if x["lane"] == "UDM" else 1))
        else:
            selected_events = raw_timeline

        for idx, item in enumerate(selected_events, start=1):
            item.pop("_burst_extra", None)
            item.pop("_base_title", None)
            item["id"] = f"tl_{idx}"

        lanes_summary = {
            "ALL": len(selected_events),
            "UDM": sum(1 for e in selected_events if e["lane"] == "UDM"),
            "SILENT": sum(1 for e in selected_events if e["lane"] == "SILENT"),
            "ALERT": sum(1 for e in selected_events if e["lane"] == "ALERT"),
            "SOAR_ADK": sum(1 for e in selected_events if e["lane"] == "SOAR_ADK"),
        }

        tactic_counts: Dict[str, int] = {}
        tactic_techniques: Dict[str, List[str]] = {}
        for ev in selected_events:
            slug = ev.get("mitre_tactic_slug") or ""
            if slug:
                tactic_counts[slug] = tactic_counts.get(slug, 0) + 1
                tid = ev.get("mitre_id") or ""
                if tid:
                    tactic_techniques.setdefault(slug, [])
                    if tid not in tactic_techniques[slug]:
                        tactic_techniques[slug].append(tid)

        mitre_stages = [
            {
                "slug": slug,
                "label": label,
                "count": tactic_counts.get(slug, 0),
                "active": tactic_counts.get(slug, 0) > 0,
                "techniques": tactic_techniques.get(slug, []),
            }
            for slug, label in KILL_CHAIN_TACTIC_ORDER
        ]

        # Build Affected-Entity swimlane descriptors (ordered chronologically by first appearance, SOAR_ADK last)
        ent_stats: Dict[str, Dict[str, Any]] = {}
        for ev in selected_events:
            ekey = str(ev.get("primary_entity_key") or "TELEMETRY:context")
            elbl = str(ev.get("primary_entity_label") or "System / Context")
            ep = int(ev.get("epoch_ms") or 0)
            if ekey not in ent_stats:
                ent_stats[ekey] = {"key": ekey, "label": elbl, "count": 0, "first_epoch_ms": ep}
            ent_stats[ekey]["count"] += 1
            if ep < ent_stats[ekey]["first_epoch_ms"]:
                ent_stats[ekey]["first_epoch_ms"] = ep

        soar_lane_stat = ent_stats.pop("SOAR_ADK", None)
        non_soar_lanes = sorted(ent_stats.values(), key=lambda x: (-x["count"], x["first_epoch_ms"]))
        if len(non_soar_lanes) > 6:
            kept_keys = {item["key"] for item in non_soar_lanes[:5]}
            overflow_count = 0
            overflow_first = min(item["first_epoch_ms"] for item in non_soar_lanes[5:])
            for ev in selected_events:
                if ev.get("primary_entity_key") not in kept_keys and ev.get("primary_entity_key") != "SOAR_ADK":
                    ev["primary_entity_key"] = "ENTITY:other"
                    ev["primary_entity_label"] = "Other Entities"
                    overflow_count += 1
            non_soar_lanes = sorted(non_soar_lanes[:5], key=lambda x: x["first_epoch_ms"])
            non_soar_lanes.append(
                {"key": "ENTITY:other", "label": "Other Entities", "count": overflow_count, "first_epoch_ms": overflow_first}
            )
        else:
            non_soar_lanes.sort(key=lambda x: x["first_epoch_ms"])

        entity_lanes = list(non_soar_lanes)
        if soar_lane_stat:
            entity_lanes.append(soar_lane_stat)

        comment_id = None
        if post_wall_comment and selected_events:
            try:
                active_tactics = [s["label"] for s in mitre_stages if s["active"]]
                wall_md = (
                    f"### [Automated Timeline] Kill-Chain Swimlane Summary\n"
                    f"- **Events Mapped**: `{len(selected_events)}` (`{lanes_summary['UDM']}` Precursor UDM, "
                    f"`{lanes_summary['SILENT']}` Silent YARA-L, `{lanes_summary['ALERT']}` Alerting, "
                    f"`{lanes_summary['SOAR_ADK']}` SOAR/ADK)\n"
                    f"- **Observed Kill-Chain Stages**: {', '.join(active_tactics) if active_tactics else 'N/A'}"
                )
                c_res = self.adapter.create_case_comment(case_id=clean_cid, comment=wall_md)
                comment_id = str((c_res or {}).get("name", "")).split("/")[-1] or "posted"
            except Exception as exc:
                logger.warning("Could not post Kill-Chain Timeline comment for case %s: %s", clean_cid, exc)

        prio_val = getattr(inv, "priority", "UNKNOWN")
        prio_str = prio_val.value if hasattr(prio_val, "value") else str(prio_val or "UNKNOWN")
        status_val = getattr(inv, "status", "OPENED")
        status_str = status_val.value if hasattr(status_val, "value") else str(status_val or "OPENED")

        res_obj = KillChainTimelineResult(
            case_id=clean_cid,
            case_title=str(getattr(inv, "display_name", "") or getattr(inv, "title", "") or f"Case #{clean_cid}"),
            case_priority=prio_str,
            case_status=status_str,
            case_stage=str(getattr(inv, "stage", "") or "Triage"),
            lookback_hours=lookback_hours,
            time_window=time_window,
            secops_ui_base_url=secops_ui_base_url,
            adk_overlay=_public_adk_overlay(adk_overlay),
            lanes_summary=lanes_summary,
            mitre_stages=mitre_stages,
            entity_lanes=entity_lanes,
            events=selected_events,
            events_truncated=truncated,
            total_events_discovered=total_discovered,
            comment_id=comment_id,
            provenance={
                "workflow": "case.graph.kill_chain_timeline",
                "reused_correlation": bool(bundle.get("reused_correlation")),
                "has_adk_analysis": bool(adk_overlay.get("has_adk_analysis")),
            },
        )
        res_obj._corr_export = bundle.get("corr_dict") or {}
        return res_obj


# =============================================================================
# Shared SOAR Case Context & Ephemeral Pod Cache Helpers
# =============================================================================
SHARED_ATTACK_CORR_CACHE_KEY = "CASE_ATTACK_TELEMETRY_CACHE"


def read_soar_case_context_json(siemplify: Any, case_id: str, key: str) -> Optional[Dict[str, Any]]:
    """Reads a JSON dictionary from SOAR persistent Case Context DB across worker pods."""
    if not siemplify or not case_id or not key:
        return None
    raw_val = None
    try:
        if hasattr(siemplify, "get_case_context_property"):
            raw_val = siemplify.get_case_context_property(key)
        elif hasattr(siemplify, "get_context_property"):
            raw_val = siemplify.get_context_property(1, str(case_id), key)
    except Exception:
        raw_val = None
    if isinstance(raw_val, dict):
        return raw_val
    if isinstance(raw_val, str):
        cleaned = raw_val.strip()
        if cleaned.startswith("{"):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
    return None


def write_soar_case_context_json(siemplify: Any, case_id: str, key: str, data: Dict[str, Any]) -> bool:
    """Writes a JSON dictionary to SOAR persistent Case Context DB."""
    if not siemplify or not case_id or not key or not isinstance(data, dict):
        return False
    try:
        payload = json.dumps(data, default=str)
        if len(payload) > 140_000:
            return False
        if hasattr(siemplify, "set_case_context_property"):
            siemplify.set_case_context_property(key, payload)
            return True
        if hasattr(siemplify, "set_context_property"):
            siemplify.set_context_property(1, str(case_id), key, payload)
            return True
    except Exception:
        pass
    return False

