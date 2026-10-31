import ipaddress
import re
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Union

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import (
    CaseDetectionCorrelationResult,
    CaseEvidenceItem,
    EntityType,
    coerce_entity_type,
)
from engine.parsing import parse_timestamp
from engine.workflows.case_evidence import AttachCaseEvidenceWorkflow
from engine.workflows.case_investigation import InvestigateCaseWorkflow
from engine.workflows.refine_search import SearchFromEntityWorkflow
from engine.workflows.search_udm import SearchUDMWorkflow


def _clean_case_id(raw_id: Union[str, int]) -> str:
    """Extracts numeric case identifier."""
    return str(raw_id).strip().split('/')[-1]


# ---------------------------------------------------------------------------
# GUARDRAILS & SANITIZATION RULES
# ---------------------------------------------------------------------------

GENERIC_USERS = {
    "system", "nt authority\\system", "local service", "nt authority\\local service",
    "network service", "nt authority\\network service", "anonymous logon", "root",
    "nobody", "daemon", "guest", "localhost", "none", "null", "unknown", "n/a",
    "administrator", "admin", "localadmin"
}

GENERIC_BINARIES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "svchost.exe",
    "rundll32.exe", "explorer.exe", "wsmprovhost.exe", "cscript.exe", "wscript.exe",
    "msiexec.exe", "reg.exe", "taskhostw.exe", "services.exe", "lsass.exe",
    "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "taskhost.exe",
    "dllhost.exe", "wmiprvse.exe", "mshta.exe"
}

NOISY_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "127.0.0.1", "0.0.0.0", "255.255.255.255",
}


def is_noisy_ip(ip_str: str) -> bool:
    clean = ip_str.strip()
    if clean in NOISY_IPS:
        return True
    try:
        ip = ipaddress.ip_address(clean)
        return (
            ip.is_loopback or
            ip.is_multicast or
            ip.is_link_local or
            ip.is_unspecified or
            ip.is_reserved
        )
    except ValueError:
        return False


def is_noisy_entity(val: str) -> bool:
    clean = val.strip().lower()
    if not clean or len(clean) < 2:
        return True
    if clean in ("unknown", "n/a", "none", "null", "localhost"):
        return True
    if clean in GENERIC_USERS:
        return True
    for bin_name in GENERIC_BINARIES:
        if clean == bin_name or clean.endswith("\\" + bin_name) or clean.endswith("/" + bin_name):
            return True
    if is_noisy_ip(val):
        return True
    if clean.startswith("http://localhost") or clean.startswith("https://localhost"):
        return True
    if "googleapis.com/compute/v1/projects/" in clean and "/operations/" in clean:
        return True
    return False


def is_genuine_yara_l_detection(sec: Dict[str, Any], has_det_obj: bool = False) -> bool:
    """Disqualifies parser annotations (e.g. Sysmon EventID: 1) and retains genuine YARA-L detections."""
    rule_id = (sec.get("ruleId") or "").strip()
    rule_name = (sec.get("ruleName") or "").strip()
    if rule_name.lower().startswith("eventid:") or rule_name.lower().startswith("technique_id="):
        return False
    if rule_id.startswith("ru_") or rule_id.startswith("ur_"):
        return True
    if has_det_obj and rule_name and not rule_name.lower().startswith("eventid"):
        return True
    if rule_name and not rule_name.lower().startswith("eventid") and sec.get("alertState") and sec.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return True
    return False


def _resolve_entity_type(raw_type: Optional[str], raw_val: str) -> Optional[EntityType]:
    """Resolves raw entity type with fallback heuristics on the entity value."""
    if raw_type:
        try:
            return coerce_entity_type(raw_type)
        except (ValueError, TypeError):
            pass
    val_lower = raw_val.strip().lower()
    if "@" in val_lower and "." in val_lower:
        return EntityType.EMAIL
    if val_lower.startswith(("http://", "https://")):
        return EntityType.URL
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val_lower):
        return EntityType.IP
    if len(val_lower) == 64 and all(c in "0123456789abcdef" for c in val_lower):
        return EntityType.SHA256
    if len(val_lower) == 32 and all(c in "0123456789abcdef" for c in val_lower):
        return EntityType.MD5
    return None


# ---------------------------------------------------------------------------
# ENTITY FILTERING (TYPES & IDENTIFIERS, FILTER IN & FILTER OUT)
# ---------------------------------------------------------------------------

SOAR_ENTITY_TYPE_GROUPS: Dict[str, Set[str]] = {
    "DESTINATIONURL": {"DESTINATIONURL", "URL", "SOURCEURL", "TARGETURL", "REQUESTURL"},
    "URL": {"DESTINATIONURL", "URL", "SOURCEURL", "TARGETURL", "REQUESTURL"},
    "SOURCEURL": {"DESTINATIONURL", "URL", "SOURCEURL", "TARGETURL", "REQUESTURL"},
    "TARGETURL": {"DESTINATIONURL", "URL", "SOURCEURL", "TARGETURL", "REQUESTURL"},
    "REQUESTURL": {"DESTINATIONURL", "URL", "SOURCEURL", "TARGETURL", "REQUESTURL"},
    "FILENAME": {"FILENAME", "FILE", "FILEPATH", "FULLPATH"},
    "FILE": {"FILENAME", "FILE", "FILEPATH", "FULLPATH"},
    "PROCESS": {"PROCESS", "PROCESSNAME", "PROCESS_NAME", "PROCESS_ID", "PID", "COMMANDLINE", "COMMAND_LINE", "PARENTPROCESS"},
    "PROCESSNAME": {"PROCESS", "PROCESSNAME", "PROCESS_NAME", "PROCESS_ID", "PID", "COMMANDLINE", "COMMAND_LINE", "PARENTPROCESS"},
    "ADDRESS": {"ADDRESS", "IP", "IPV4", "IPV6", "IPADDRESS", "IP_ADDRESS", "SOURCEIP", "DESTINATIONIP", "SOURCEADDRESS", "DESTINATIONADDRESS", "SRC_IP", "DST_IP"},
    "IP": {"ADDRESS", "IP", "IPV4", "IPV6", "IPADDRESS", "IP_ADDRESS", "SOURCEIP", "DESTINATIONIP", "SOURCEADDRESS", "DESTINATIONADDRESS", "SRC_IP", "DST_IP"},
    "SOURCEIP": {"SOURCEIP", "SOURCEADDRESS", "SRC_IP"},
    "DESTINATIONIP": {"DESTINATIONIP", "DESTINATIONADDRESS", "DST_IP"},
    "HOSTNAME": {"HOSTNAME", "HOST", "ASSET", "DESTINATIONHOSTNAME", "SOURCEHOSTNAME", "TARGETHOSTNAME", "DEVICENAME", "COMPUTERNAME"},
    "HOST": {"HOSTNAME", "HOST", "ASSET", "DESTINATIONHOSTNAME", "SOURCEHOSTNAME", "TARGETHOSTNAME", "DEVICENAME", "COMPUTERNAME"},
    "ASSET": {"HOSTNAME", "HOST", "ASSET", "DESTINATIONHOSTNAME", "SOURCEHOSTNAME", "TARGETHOSTNAME", "DEVICENAME", "COMPUTERNAME"},
    "USERUNIQNAME": {"USERUNIQNAME", "USER", "USERNAME", "USERID", "ACCOUNT", "ACCOUNTNAME", "SOURCEUSERNAME", "DESTINATIONUSERNAME", "TARGETUSERNAME", "EMAIL", "EMAILADDRESS"},
    "USER": {"USERUNIQNAME", "USER", "USERNAME", "USERID", "ACCOUNT", "ACCOUNTNAME", "SOURCEUSERNAME", "DESTINATIONUSERNAME", "TARGETUSERNAME", "EMAIL", "EMAILADDRESS"},
    "USERNAME": {"USERUNIQNAME", "USER", "USERNAME", "USERID", "ACCOUNT", "ACCOUNTNAME", "SOURCEUSERNAME", "DESTINATIONUSERNAME", "TARGETUSERNAME", "EMAIL", "EMAILADDRESS"},
    "EMAIL": {"EMAIL", "EMAILADDRESS", "USERUNIQNAME"},
    "FILEHASH": {"FILEHASH", "HASH", "SHA256", "MD5", "SHA1"},
    "HASH": {"FILEHASH", "HASH", "SHA256", "MD5", "SHA1"},
    "SHA256": {"SHA256", "FILEHASH", "HASH"},
    "MD5": {"MD5", "FILEHASH", "HASH"},
    "SHA1": {"SHA1", "FILEHASH", "HASH"},
    "DOMAIN": {"DOMAIN", "DOMAINNAME", "DOMAIN_NAME"},
    "MAC": {"MAC", "MACADDRESS", "MAC_ADDRESS"},
    "WINDOWS_SID": {"WINDOWS_SID", "SID"},
    "RESOURCE": {"RESOURCE", "CLOUDRESOURCE"},
    "THREATACTOR": {"THREATACTOR", "THREAT_ACTOR"},
    "THREATCAMPAIGN": {"THREATCAMPAIGN", "THREAT_CAMPAIGN", "CAMPAIGN"},
    "MALWARE": {"MALWARE"},
    "THREATSIGNATURE": {"THREATSIGNATURE", "SIGNATURE"},
    "CVE": {"CVE", "VULNERABILITY"},
    "GENERIC": {"GENERIC"},
    "CUSTOM": {"CUSTOM"},
}

ALL_KNOWN_ENTITY_TYPE_TOKENS: Set[str] = set(SOAR_ENTITY_TYPE_GROUPS.keys())
for _grp in SOAR_ENTITY_TYPE_GROUPS.values():
    ALL_KNOWN_ENTITY_TYPE_TOKENS.update(_grp)


def _normalize_type_token(raw: str) -> str:
    return str(raw or "").strip().upper().replace("-", "").replace("_", "").replace(" ", "")


_NORMALIZED_TYPE_LOOKUP: Dict[str, Set[str]] = {}
for _k, _v in SOAR_ENTITY_TYPE_GROUPS.items():
    _norm_k = _normalize_type_token(_k)
    _norm_set = {_normalize_type_token(x) for x in _v} | {_k.upper()} | {x.upper() for x in _v}
    _NORMALIZED_TYPE_LOOKUP[_norm_k] = _norm_set
    _NORMALIZED_TYPE_LOOKUP[_k.upper()] = _norm_set


def is_known_entity_type_token(token: str) -> bool:
    """Returns True if token is a recognized SOAR or UDM entity type name (e.g. DESTINATIONURL, FILENAME, PROCESS)."""
    clean = str(token or "").strip()
    if clean.startswith(("-", "!", "+")):
        clean = clean[1:].strip()
    if clean.upper().startswith("TYPE:"):
        return True
    norm = _normalize_type_token(clean)
    return norm in _NORMALIZED_TYPE_LOOKUP or clean.upper() in ALL_KNOWN_ENTITY_TYPE_TOKENS


class ParsedEntityFilter:
    """Evaluates entity inclusion/exclusion rules across both Entity Types and Entity Identifiers."""

    def __init__(
        self,
        entity_filter: Optional[Union[List[str], str]] = None,
        entity_filter_mode: str = "AUTO",
    ):
        self.include_types: Set[str] = set()
        self.exclude_types: Set[str] = set()
        self.include_ids: Set[str] = set()
        self.exclude_ids: Set[str] = set()
        self.explicit_include_id_values: List[str] = []

        if not entity_filter:
            self.is_active = False
            return

        if isinstance(entity_filter, str):
            raw_tokens = [t.strip() for t in entity_filter.split(",") if t.strip()]
        else:
            raw_tokens = []
            for item in entity_filter:
                for t in str(item or "").split(","):
                    if t.strip():
                        raw_tokens.append(t.strip())

        if not raw_tokens:
            self.is_active = False
            return

        self.is_active = True
        mode_raw = str(entity_filter_mode or "AUTO").strip().upper()
        if "EXCLUDE" in mode_raw or "OUT" in mode_raw:
            default_mode = "EXCLUDE"
        elif "INCLUDE" in mode_raw or "IN" in mode_raw:
            default_mode = "INCLUDE"
        else:
            default_mode = "AUTO"

        for token in raw_tokens:
            tok = token.strip()
            if not tok:
                continue

            prefix = None
            if tok[0] in ("-", "!"):
                prefix = "EXCLUDE"
                tok = tok[1:].strip()
            elif tok[0] == "+":
                prefix = "INCLUDE"
                tok = tok[1:].strip()

            if not tok:
                continue

            force_type = False
            if tok.upper().startswith("TYPE:"):
                force_type = True
                tok = tok[5:].strip()

            norm_tok = _normalize_type_token(tok)
            is_type = force_type or (norm_tok in _NORMALIZED_TYPE_LOOKUP)

            if prefix is not None:
                effective_mode = prefix
            elif default_mode in ("EXCLUDE", "INCLUDE"):
                effective_mode = default_mode
            else:
                # AUTO mode: bare entity types (e.g. DESTINATIONURL, FILENAME, PROCESS) default to EXCLUDE,
                # while bare concrete entity identifiers (e.g. 1.2.3.4) default to INCLUDE.
                effective_mode = "EXCLUDE" if is_type else "INCLUDE"

            if is_type:
                expanded = _NORMALIZED_TYPE_LOOKUP.get(norm_tok, {norm_tok, tok.upper()})
                if effective_mode == "EXCLUDE":
                    self.exclude_types.update(expanded)
                else:
                    self.include_types.update(expanded)
            else:
                tok_upper = tok.upper()
                if effective_mode == "EXCLUDE":
                    self.exclude_ids.add(tok_upper)
                else:
                    self.include_ids.add(tok_upper)
                    self.explicit_include_id_values.append(tok)

    def matches(self, identifier: Optional[str], entity_type: Optional[str]) -> bool:
        """Returns True if the entity should be kept (included), or False if filtered out."""
        if not self.is_active:
            return True

        ident_upper = str(identifier or "").strip().upper()
        raw_etype = str(entity_type or "").strip().upper()
        norm_etype = _normalize_type_token(raw_etype)

        # Also check canonical resolved entity type if possible
        canonical_str = ""
        try:
            resolved = _resolve_entity_type(raw_etype, str(identifier or ""))
            if resolved:
                canonical_str = resolved.value.upper()
        except Exception:
            pass
        norm_canonical = _normalize_type_token(canonical_str)

        candidate_type_keys = {raw_etype, norm_etype}
        if canonical_str:
            candidate_type_keys.add(canonical_str)
            candidate_type_keys.add(norm_canonical)
        candidate_type_keys.discard("")

        # 1. Check exclusions first (Filter Out)
        if ident_upper and ident_upper in self.exclude_ids:
            return False
        if self.exclude_types and (candidate_type_keys & self.exclude_types):
            return False

        # 2. Check inclusions if any include rules were specified (Filter In)
        if self.include_ids or self.include_types:
            matched_id = bool(ident_upper and ident_upper in self.include_ids)
            matched_type = bool(self.include_types and (candidate_type_keys & self.include_types))
            return matched_id or matched_type

        return True



def _extract_event_entities(ev: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extracts high-fidelity candidate entities (IP, USER, URL, HOSTNAME) from a UDM event."""
    candidates: List[Dict[str, str]] = []
    seen: Set[str] = set()

    def _add(identifier: Optional[str], etype: str):
        if not identifier:
            return
        clean_id = str(identifier).strip()
        if is_noisy_entity(clean_id):
            return
        key = f"{clean_id.upper()}::{etype.upper()}"
        if key not in seen:
            seen.add(key)
            candidates.append({"identifier": clean_id, "type": etype})

    # 1. Principal
    p = ev.get("principal") or {}
    if isinstance(p, dict):
        for ip in p.get("ip") or []:
            _add(ip, "IP")
        p_user = p.get("user") or {}
        if isinstance(p_user, dict):
            _add(p_user.get("userid"), "USERUNIQNAME")
            _add(p_user.get("userDisplayName"), "USERUNIQNAME")
            for email in p_user.get("emailAddresses") or []:
                _add(email, "USERUNIQNAME")
        _add(p.get("hostname"), "HOSTNAME")

    # 2. Target
    t = ev.get("target") or {}
    if isinstance(t, dict):
        for ip in t.get("ip") or []:
            _add(ip, "IP")
        t_user = t.get("user") or {}
        if isinstance(t_user, dict):
            _add(t_user.get("userid"), "USERUNIQNAME")
            _add(t_user.get("userDisplayName"), "USERUNIQNAME")
            for email in t_user.get("emailAddresses") or []:
                _add(email, "USERUNIQNAME")
        _add(t.get("hostname"), "HOSTNAME")
        _add(t.get("url"), "DestinationURL")

    # 3. Source
    s = ev.get("src") or {}
    if isinstance(s, dict):
        for ip in s.get("ip") or []:
            _add(ip, "IP")
        _add(s.get("hostname"), "HOSTNAME")

    # 4. Security Result
    sec_results = ev.get("securityResult") or ev.get("security_result") or []
    for sec in sec_results:
        if isinstance(sec, dict):
            _add(sec.get("urlBackToProduct"), "DestinationURL")
            desc = sec.get("description") or ""
            import re
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", desc):
                _add(ip, "IP")

    return candidates


def _summarize_udm_event(ev: Any, is_corroborated: bool) -> Dict[str, Any]:
    """Extracts a rich, compact summary of a UDM event for LLM and SOAR consumption."""
    meta = ev.get("metadata") or {}
    p = ev.get("principal") or {}
    t = ev.get("target") or {}
    sec_results = ev.get("securityResult") or ev.get("security_result") or []
    about_list = ev.get("about") or []
    network = ev.get("network") or {}

    summary: Dict[str, Any] = {
        "event_id": meta.get("id"),
        "timestamp": meta.get("eventTimestamp"),
        "event_type": meta.get("eventType"),
        "vendor_name": meta.get("vendorName"),
        "product_name": meta.get("productName"),
        "product_event_type": meta.get("productEventType"),
        "product_log_id": meta.get("productLogId"),
        "description": meta.get("description"),
        "corroborated": is_corroborated,
    }

    def _clean_noun(noun: Any) -> Dict[str, Any]:
        if not isinstance(noun, dict):
            return {}
        out: Dict[str, Any] = {}
        if noun.get("hostname"):
            out["hostname"] = noun.get("hostname")
        if noun.get("ip"):
            out["ip"] = noun.get("ip")
        if noun.get("application"):
            out["application"] = noun.get("application")
        if noun.get("url"):
            out["url"] = noun.get("url")
        if noun.get("administrativeDomain"):
            out["domain"] = noun.get("administrativeDomain")
        usr = noun.get("user")
        if isinstance(usr, dict):
            u_info = {
                k: usr.get(k)
                for k in ("userid", "userDisplayName", "emailAddresses", "productObjectId")
                if usr.get(k)
            }
            if u_info:
                out["user"] = u_info
        grp = noun.get("group")
        if isinstance(grp, dict):
            g_info = {
                k: grp.get(k)
                for k in ("groupDisplayName", "emailAddresses", "productObjectId")
                if grp.get(k)
            }
            if g_info:
                out["group"] = g_info
        proc = noun.get("process")
        if isinstance(proc, dict):
            p_info: Dict[str, Any] = {}
            if proc.get("commandLine"):
                p_info["command_line"] = proc.get("commandLine")
            if proc.get("pid"):
                p_info["pid"] = proc.get("pid")
            f_obj = proc.get("file")
            if isinstance(f_obj, dict):
                for fk in ("fullPath", "sha256", "md5"):
                    if f_obj.get(fk):
                        p_info[fk] = f_obj.get(fk)
            if p_info:
                out["process"] = p_info
        res = noun.get("resource")
        if isinstance(res, dict):
            r_info: Dict[str, Any] = {}
            for rk in ("name", "resourceType", "resourceSubtype", "productObjectId"):
                if res.get(rk):
                    r_info[rk] = res.get(rk)
            attr = res.get("attribute")
            if isinstance(attr, dict) and attr.get("labels"):
                r_info["labels"] = attr.get("labels")
            if r_info:
                out["resource"] = r_info
        return out

    p_clean = _clean_noun(p)
    if p_clean:
        summary["principal"] = p_clean
    t_clean = _clean_noun(t)
    if t_clean:
        summary["target"] = t_clean

    if isinstance(network, dict) and network:
        net_clean = {
            k: network.get(k)
            for k in ("applicationProtocol", "direction", "ipProtocol", "sentBytes", "receivedBytes", "http", "dns")
            if network.get(k)
        }
        if net_clean:
            summary["network"] = net_clean

    if sec_results and isinstance(sec_results, list):
        sr_list = []
        for sr in sec_results[:5]:
            if not isinstance(sr, dict):
                continue
            sr_item = {
                k: sr.get(k)
                for k in (
                    "summary",
                    "description",
                    "action",
                    "severity",
                    "category",
                    "ruleName",
                    "ruleId",
                    "alertState",
                    "threatId",
                    "threatName",
                    "detectionFields",
                )
                if sr.get(k)
            }
            if sr_item:
                sr_list.append(sr_item)
        if sr_list:
            summary["security_result"] = sr_list

    if about_list and isinstance(about_list, list):
        ab_out = []
        for ab in about_list[:5]:
            if not isinstance(ab, dict):
                continue
            ab_item = {
                k: ab.get(k)
                for k in ("labels", "resource", "file", "url", "user")
                if ab.get(k)
            }
            if ab_item:
                ab_out.append(ab_item)
        if ab_out:
            summary["about"] = ab_out

    return {k: v for k, v in summary.items() if v is not None}


class CorrelateSilentDetectionsWorkflow:
    """Correlates a SOAR case's involved entities with silent (non-alerting) detections in UDM."""

    def __init__(self, adapter: Optional['GoogleSecOpsAdapter'] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.investigate_workflow = InvestigateCaseWorkflow(adapter=self.adapter)
        self.search_workflow = SearchUDMWorkflow(adapter=self.adapter)
        self.attach_workflow = AttachCaseEvidenceWorkflow(adapter=self.adapter)

    def execute(
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
        min_case_age_seconds: int = 45,
        retry_on_empty_seconds: int = 20,
    ) -> CaseDetectionCorrelationResult:
        """Executes entity correlation and attaches non-alerting detections or events to the case.

        Args:
            case_id: The SOAR Case ID or resource name.
            lookback_hours: How far back to search UDM relative to case creation/now (default: 24h).
            attach_to_case: If True, natively attaches discovered detections/events to the case.
            attach_entities: If True (and attach_to_case is True), attaches delta entities to the case alert.
            post_wall_comment: If True, adds a summary note to the Case Wall.
            entity_filter: Optional list of entity types (e.g. DESTINATIONURL, FILENAME, PROCESS) or identifiers.
            entity_filter_mode: Filter mode ('AUTO', 'EXCLUDE'/'Filter Out (Exclude)', or 'INCLUDE'/'Filter In (Include)').
            max_events: Max UDM events to fetch (default: 1000).
            correlate_detections: If True, inspects and returns rule detections (default: True).
            correlate_udm_events: If True, collects and returns non-detection raw UDM events (default: False).
            attach_udm_events: If True (and attach_to_case is True), attaches raw UDM events as EVIDENCE_TYPE_EVENT (default: False).
            extract_entities_from_events: If True, extracts candidate entities from non-detection UDM events (default: False).
            alert_vendor_filter: Only consider alerts from this vendor (default: 'Google Chronicle').
            max_entities_to_attach: Maximum number of delta entities to attach to the case alert (default: 5).
            min_case_age_seconds: Minimum case age before running correlation so asynchronous YARA-L detections
                and SOAR alert grouping settle (default: 45s).
            retry_on_empty_seconds: Wait time before retrying once if 0 detections are found on a newly created
                case (<90s old) (default: 20s).

        Returns:
            CaseDetectionCorrelationResult with findings and attachment records.
        """
        clean_case_id = _clean_case_id(case_id)
        parsed_filter = ParsedEntityFilter(entity_filter=entity_filter, entity_filter_mode=entity_filter_mode)

        # 1. Investigate case to extract entities and existing alert context
        investigation = self.investigate_workflow.execute(case_id=clean_case_id)

        # Wait for YARA-L detection indexing and SOAR alert grouping if the case was just created
        if min_case_age_seconds > 0 and investigation.created_time is not None:
            c_dt = investigation.created_time
            if c_dt.tzinfo is None:
                c_dt = c_dt.replace(tzinfo=timezone.utc)
            case_age = (datetime.now(timezone.utc) - c_dt).total_seconds()
            if 0.0 <= case_age < float(min_case_age_seconds):
                wait_s = min(float(min_case_age_seconds) - case_age, 60.0)
                time.sleep(wait_s)
                investigation = self.investigate_workflow.execute(case_id=clean_case_id)

        for attempt_idx in range(2):
            # Vendor filtering: filter alerts to only those originating from the target vendor
            target_alerts = investigation.alerts
            if alert_vendor_filter and str(alert_vendor_filter).strip():
                v_filter = str(alert_vendor_filter).strip().lower()
                target_alerts = [
                    a for a in investigation.alerts
                    if (a.vendor or "").strip().lower() == v_filter
                    or v_filter in (a.vendor or "").lower()
                    or v_filter in (a.raw.get("sourceSystemName") or "").lower()
                    or v_filter.replace(" ", "") in (a.raw.get("sourceSystemName") or "").lower()
                ]
                if not target_alerts:
                    return CaseDetectionCorrelationResult(
                        case_id=clean_case_id,
                        lookback_hours=lookback_hours,
                        entities_searched=[],
                        query_used='',
                        detections_found=[],
                        events_found=[],
                        attached_evidences=[],
                        comment_id=None,
                        provenance={
                            "workflow": "case.detection.correlate",
                            "status": "NO_MATCHING_ALERTS_FOR_VENDOR",
                            "vendor_filter": alert_vendor_filter,
                            "alerts_inspected": len(investigation.alerts),
                        },
                        raw={"status": "NO_MATCHING_ALERTS_FOR_VENDOR", "vendor_filter": alert_vendor_filter},
                    )

            existing_alert_rule_ids = {
                (a.raw.get("sourceRuleIdentifier") or a.rule_name or "").strip()
                for a in target_alerts
                if a.raw.get("sourceRuleIdentifier") or a.rule_name
            }
            existing_alert_ticket_ids: Set[str] = {
                (a.raw.get("ticketId") or "").strip().lower()
                for a in investigation.alerts
                if a.raw.get("ticketId") and str(a.raw.get("ticketId")).strip()
            }

            existing_identifiers: Set[str] = {
                e.identifier.strip().upper()
                for e in investigation.entities
                if e.identifier and str(e.identifier).strip()
            }
            primary_alert_id = None
            if target_alerts:
                primary_alert_id = target_alerts[0].name.split('/')[-1] or target_alerts[0].identifier

            # 2. Collect high-signal queryable entities and establish anchor set
            case_anchors: Set[str] = set()
            prioritized_clauses: List[Any] = []
            searched_entities: List[Dict[str, Any]] = []

            _PRIORITY_ORDER = {
                "HOSTNAME": 0,
                "ASSET": 0,
                "USER": 1,
                "EMAIL": 1,
                "IP": 2,
                "DOMAIN": 3,
                "SHA256": 4,
                "MD5": 4,
                "SHA1": 4,
                "URL": 5,
                "FILE": 6,
                "PROCESS": 7,
            }

            for ent in investigation.entities:
                val = ent.identifier.strip()
                if is_noisy_entity(val):
                    continue
                if not parsed_filter.matches(val, ent.entity_type):
                    continue

                e_type = _resolve_entity_type(ent.entity_type, val)
                if not e_type:
                    continue

                case_anchors.add(val.upper())

                try:
                    clause = SearchFromEntityWorkflow.build_entity_query(e_type, val)
                    prio = _PRIORITY_ORDER.get(e_type.value.upper(), _PRIORITY_ORDER.get(e_type.name.upper(), 8))
                    prioritized_clauses.append((prio, len(prioritized_clauses), f'({clause})'))
                    searched_entities.append({
                        'identifier': val,
                        'type': e_type.value,
                        'role': ent.role,
                    })
                except Exception:
                    pass

            # Extract threat IDs from vendor-filtered alerts (e.g. ticketId 'de_...')
            for a in target_alerts:
                tid = (a.raw.get("ticketId") or "").strip()
                if tid.startswith("de_"):
                    clean_tid = tid[3:].lower()
                    prioritized_clauses.append((9, len(prioritized_clauses), f'(security_result.threat_id = "{clean_tid}")'))
                    case_anchors.add(clean_tid.upper())
                    searched_entities.append({
                        'identifier': clean_tid,
                        'type': 'THREAT_ID',
                        'role': 'ALERT_THREAT_ID',
                    })

            if not prioritized_clauses:
                return CaseDetectionCorrelationResult(
                    case_id=clean_case_id,
                    lookback_hours=lookback_hours,
                    entities_searched=[],
                    query_used='',
                    detections_found=[],
                    events_found=[],
                    attached_evidences=[],
                    comment_id=None,
                    provenance={
                        "workflow": "case.detection.correlate",
                        "status": "NO_QUERYABLE_ANCHORS",
                    },
                    raw={'status': 'NO_QUERYABLE_ANCHORS'},
                )

            # Sort clauses so primary host/user/IP anchors always fit inside the first 10 clauses
            prioritized_clauses.sort(key=lambda item: (item[0], item[1]))
            bounded_clauses = [item[2] for item in prioritized_clauses[:10]]
            combined_query = ' OR '.join(bounded_clauses)

            # Calculate time window around case created_time or now
            ref_time = investigation.created_time or datetime.now(timezone.utc)
            if ref_time.tzinfo is None:
                ref_time = ref_time.replace(tzinfo=timezone.utc)
            start_time = (ref_time - timedelta(hours=lookback_hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
            end_time = (ref_time + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')

            from engine.domain import SearchRequest
            search_req = SearchRequest(
                query=combined_query,
                start_time=start_time,
                end_time=end_time,
                receive_limit=max_events,
                batch_size=min(max_events, 500),
            )

            stream_detections_by_id: Dict[str, Dict[str, Any]] = {}

            def _capture_stream_detections(batch_res: Any, _session: Any) -> None:
                raw_resp = getattr(batch_res, "raw_response", None)
                if not raw_resp:
                    return
                items = raw_resp if isinstance(raw_resp, list) else [raw_resp]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    op_obj = item.get("operation", item)
                    if not isinstance(op_obj, dict):
                        continue
                    ro = op_obj.get("response", op_obj) or {}
                    if not isinstance(ro, dict):
                        continue
                    det_block = ro.get("detections")
                    det_list = (
                        det_block.get("detections", [])
                        if isinstance(det_block, dict)
                        else (det_block if isinstance(det_block, list) else [])
                    )
                    for d_obj in det_list or []:
                        if not isinstance(d_obj, dict):
                            continue
                        d_id = (d_obj.get("id") or "").strip()
                        if not d_id:
                            continue
                        det_arr = d_obj.get("detection")
                        d_info = (
                            det_arr[0]
                            if isinstance(det_arr, list) and det_arr and isinstance(det_arr[0], dict)
                            else {}
                        )
                        stream_detections_by_id[d_id] = d_info

            session = self.search_workflow.execute(request=search_req, on_batch=_capture_stream_detections)

            # 3. Analyze events for genuine detections, anchor corroboration, and relevant events
            detections_found: List[Dict[str, Any]] = []
            events_found: List[Dict[str, Any]] = []
            evidence_to_attach: List[Dict[str, str]] = []
            discovered_candidates: List[Dict[str, str]] = []
            seen_evidence_ids: Set[str] = set()
            seen_det_keys: Set[str] = set()

            for ev in session.events:
                meta = ev.get('metadata') or {}
                event_id = meta.get('id')
                sec_results = ev.get('securityResult') or ev.get('security_result') or []
                detection_objs = ev.get('detections') or []

                # Check if event touches case anchors (hostname, user, IP)
                ev_anchors: Set[str] = set()
                p = ev.get("principal") or {}
                if isinstance(p, dict):
                    if p.get("hostname"): ev_anchors.add(p.get("hostname").strip().upper())
                    p_usr = p.get("user") or {}
                    if isinstance(p_usr, dict) and p_usr.get("userid"):
                        ev_anchors.add(p_usr.get("userid").strip().upper())
                    for ip in p.get("ip") or []:
                        ev_anchors.add(ip.strip().upper())
                t = ev.get("target") or {}
                if isinstance(t, dict):
                    if t.get("hostname"): ev_anchors.add(t.get("hostname").strip().upper())
                    t_usr = t.get("user") or {}
                    if isinstance(t_usr, dict) and t_usr.get("userid"):
                        ev_anchors.add(t_usr.get("userid").strip().upper())
                    for ip in t.get("ip") or []:
                        ev_anchors.add(ip.strip().upper())

                is_corroborated = bool(ev_anchors.intersection(case_anchors))
                has_genuine_detection = False

                if correlate_detections:
                    # Genuine detections from detections objects (ev["detections"])
                    for det in detection_objs:
                        det_id = (det.get('id') or '').strip()
                        if not det_id:
                            continue
                        has_genuine_detection = True
                        if det_id.lower() in existing_alert_ticket_ids:
                            continue

                        d_info = stream_detections_by_id.get(det_id, {})
                        rule_name = (
                            d_info.get('ruleName')
                            or det.get('ruleName')
                            or d_info.get('ruleId')
                            or det.get('ruleId')
                            or det_id
                        )
                        rule_id = d_info.get('ruleId') or det.get('ruleId') or ''
                        alert_state = (
                            d_info.get('alertState')
                            or det.get('alertState')
                            or 'NOT_ALERTING'
                        ).upper()
                        is_alerting = alert_state == 'ALERTING'
                        is_silent = not is_alerting

                        if is_corroborated and det_id not in seen_evidence_ids:
                            seen_evidence_ids.add(det_id)
                            evidence_to_attach.append({
                                'evidenceId': det_id,
                                'evidenceType': 'EVIDENCE_TYPE_DETECTION',
                            })

                        det_key = f"det_id::{det_id}"
                        if is_corroborated and det_key not in seen_det_keys:
                            seen_det_keys.add(det_key)
                            ev_summary = _summarize_udm_event(ev, is_corroborated)
                            detections_found.append({
                                'detection_id': det_id,
                                'rule_name': rule_name,
                                'rule_id': rule_id,
                                'alert_state': alert_state,
                                'is_alerting': is_alerting,
                                'is_silent': is_silent,
                                'event_id': event_id,
                                'timestamp': ev_summary.get('timestamp'),
                                'event_type': ev_summary.get('event_type'),
                                'product_event_type': ev_summary.get('product_event_type'),
                                'principal': ev_summary.get('principal'),
                                'target': ev_summary.get('target'),
                                'summary': (
                                    d_info.get('description')
                                    or d_info.get('summary')
                                    or ev_summary.get('description')
                                ),
                                'severity': d_info.get('severity') or det.get('severity') or 'LOW',
                                'corroborated': is_corroborated,
                            })

                    # Check securityResult entries (for inline YARA-L detections not in ev["detections"])
                    for sec in sec_results:
                        if not is_genuine_yara_l_detection(sec, has_det_obj=bool(detection_objs)):
                            continue

                        rule_name = sec.get('ruleName') or sec.get('ruleId')
                        rule_id = sec.get('ruleId') or ''
                        alert_state = (sec.get('alertState') or 'NOT_ALERTING').upper()
                        is_alerting = alert_state == 'ALERTING'
                        is_silent = not is_alerting and rule_id not in existing_alert_rule_ids

                        det_key = f"{rule_name}::{rule_id}::{event_id}"
                        if det_key in seen_det_keys:
                            continue
                        seen_det_keys.add(det_key)

                        has_genuine_detection = True
                        ev_summary = _summarize_udm_event(ev, is_corroborated)
                        detection_entry = {
                            'rule_name': rule_name,
                            'rule_id': rule_id,
                            'alert_state': alert_state,
                            'is_alerting': is_alerting,
                            'is_silent': is_silent,
                            'event_id': event_id,
                            'timestamp': ev_summary.get('timestamp'),
                            'event_type': ev_summary.get('event_type'),
                            'product_event_type': ev_summary.get('product_event_type'),
                            'principal': ev_summary.get('principal'),
                            'target': ev_summary.get('target'),
                            'summary': sec.get('summary'),
                            'severity': sec.get('severity'),
                            'corroborated': is_corroborated,
                        }
                        detections_found.append(detection_entry)

                        # Only attach to case if corroborated with anchor
                        if is_corroborated and not is_alerting and attach_udm_events:
                            if event_id and event_id not in seen_evidence_ids:
                                seen_evidence_ids.add(event_id)
                                evidence_to_attach.append({
                                    'evidenceId': event_id,
                                    'evidenceType': 'EVIDENCE_TYPE_EVENT',
                                })

                    # Extract entities only from genuine, corroborated detections
                    if has_genuine_detection and is_corroborated:
                        for cand in _extract_event_entities(ev):
                            if not parsed_filter.matches(cand.get('identifier'), cand.get('type')):
                                continue
                            cid_upper = cand['identifier'].strip().upper()
                            if cid_upper not in existing_identifiers and cid_upper not in case_anchors:
                                discovered_candidates.append(cand)

                if not has_genuine_detection:
                    if correlate_udm_events and event_id:
                        events_found.append(_summarize_udm_event(ev, is_corroborated))
                        if attach_udm_events and is_corroborated and event_id not in seen_evidence_ids:
                            seen_evidence_ids.add(event_id)
                            evidence_to_attach.append({
                                'evidenceId': event_id,
                                'evidenceType': 'EVIDENCE_TYPE_EVENT',
                            })
                    if extract_entities_from_events and is_corroborated:
                        for cand in _extract_event_entities(ev):
                            if not parsed_filter.matches(cand.get('identifier'), cand.get('type')):
                                continue
                            cid_upper = cand['identifier'].strip().upper()
                            if cid_upper not in existing_identifiers and cid_upper not in case_anchors:
                                discovered_candidates.append(cand)

            # If this is the first pass, 0 detections were found, and the case is still <90s old,
            # wait briefly and retry once to catch delayed YARA-L detection indexing.
            if (
                attempt_idx == 0
                and correlate_detections
                and not detections_found
                and retry_on_empty_seconds > 0
                and investigation.created_time is not None
            ):
                c_dt = investigation.created_time
                if c_dt.tzinfo is None:
                    c_dt = c_dt.replace(tzinfo=timezone.utc)
                if 0.0 <= (datetime.now(timezone.utc) - c_dt).total_seconds() < 90.0:
                    time.sleep(min(float(retry_on_empty_seconds), 30.0))
                    investigation = self.investigate_workflow.execute(case_id=clean_case_id)
                    continue
            break

        # 4. Attach evidence and delta entities if requested
        attached_items: List[CaseEvidenceItem] = []
        if attach_to_case and evidence_to_attach:
            # Batch attach (up to 50 items per call)
            attach_res = self.attach_workflow.execute(
                case_id=clean_case_id,
                evidence_items=evidence_to_attach[:50],
            )
            attached_items = attach_res.evidence_items

        attached_entities: List[Dict[str, Any]] = []
        if attach_to_case and attach_entities and primary_alert_id and discovered_candidates:
            seen_cand_keys: Set[str] = set()
            for cand in discovered_candidates:
                if len(attached_entities) >= max_entities_to_attach:
                    break
                cid = cand['identifier'].strip()
                ctype = cand['type'].strip()
                ckey = f"{cid.upper()}::{ctype.upper()}"
                if ckey in seen_cand_keys or cid.upper() in existing_identifiers or cid.upper() in case_anchors:
                    continue
                seen_cand_keys.add(ckey)
                try:
                    res = self.adapter.add_case_alert_entity(
                        case_id=clean_case_id,
                        case_alert_id=primary_alert_id,
                        identifier=cid,
                        entity_type=ctype,
                    )
                    attached_entities.append({
                        'identifier': cid,
                        'type': ctype,
                        'entity_id': res.get('id'),
                        'status': 'ATTACHED',
                    })
                    existing_identifiers.add(cid.upper())
                except Exception as e:
                    attached_entities.append({
                        'identifier': cid,
                        'type': ctype,
                        'error': str(e),
                        'status': 'FAILED',
                    })

        # 5. Post summary comment to Case Wall if requested
        comment_id: Optional[str] = None
        if post_wall_comment and (detections_found or events_found or attached_items or attached_entities):
            comment_lines = [
                f'### [Automated Correlation] Silent Detections & Evidence',
                f'- **Lookback Window**: {lookback_hours} hours ({start_time} to {end_time})',
                f'- **Entities Searched**: {len(searched_entities)}',
                f'- **Total Detections Found**: {len(detections_found)}',
                f'- **UDM Events Correlated**: {len(events_found)}',
                f'- **Evidence Items Attached**: {len(attached_items)}',
                f'- **New Entities Attached to Case**: {len(attached_entities)}',
            ]
            if detections_found:
                comment_lines.append("\n**Discovered Detections:**")
                for d in detections_found[:5]:
                    rule_label = d.get("rule_name") or "Unknown Rule"
                    state_label = d.get("alert_state") or "SILENT"
                    sev_label = d.get("severity") or "N/A"
                    comment_lines.append(f"- `{rule_label}` (State: {state_label}, Severity: {sev_label})")
            if events_found:
                comment_lines.append(f"\n**Discovered UDM Events ({len(events_found)} total):**")
                for ev_item in events_found[:5]:
                    ev_type = ev_item.get("event_type") or "UNKNOWN"
                    comment_lines.append(f"- `{ev_item.get('event_id')}` (Type: {ev_type})")
            if attached_entities:
                comment_lines.append("\n**Newly Attached Entities:**")
                for ae in attached_entities[:5]:
                    status_suffix = f" (ID: {ae.get('entity_id')})" if ae.get('status') == 'ATTACHED' else f" (Failed: {ae.get('error')})"
                    comment_lines.append(f"- `{ae['identifier']}` ({ae['type']}){status_suffix}")
            comment_text = "\n".join(comment_lines)
            try:
                comment_res = self.adapter.create_case_comment(case_id=clean_case_id, comment=comment_text)
                comment_id = comment_res.get('name', '').split('/')[-1] or 'created'
            except Exception:
                pass

        return CaseDetectionCorrelationResult(
            case_id=clean_case_id,
            lookback_hours=lookback_hours,
            entities_searched=searched_entities,
            query_used=combined_query,
            detections_found=detections_found,
            events_found=events_found,
            attached_evidences=attached_items,
            attached_entities=attached_entities,
            comment_id=comment_id,
            provenance={
                "workflow": "case.detection.correlate",
                "lookback_hours": lookback_hours,
                "entities_count": len(searched_entities),
                "detections_count": len(detections_found),
                "events_count": len(events_found),
                "attached_count": len(attached_items),
                "attached_entities_count": len(attached_entities),
                "correlate_detections": correlate_detections,
                "correlate_udm_events": correlate_udm_events,
                "attach_udm_events": attach_udm_events,
            },
            raw={
                'events_scanned': len(session.events),
                'total_evidence_candidates': len(evidence_to_attach),
                'total_delta_entity_candidates': len(discovered_candidates),
                'time_window': {
                    'start_time': start_time,
                    'end_time': end_time,
                },
                'case_alerts': [
                    {
                        'alert_id': a.identifier,
                        'display_name': a.rule_name or a.raw.get('displayName'),
                        'rule_id': a.raw.get('sourceRuleIdentifier'),
                        'ticket_id': a.raw.get('ticketId'),
                        'vendor': a.vendor,
                    }
                    for a in target_alerts
                ],
            },
        )

