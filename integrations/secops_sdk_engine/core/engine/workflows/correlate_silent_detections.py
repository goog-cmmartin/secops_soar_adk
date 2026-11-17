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
    LifecycleState,
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
    # Windows built-in & service identities
    "system", "nt authority\\system", "local service", "nt authority\\local service",
    "network service", "nt authority\\network service", "anonymous logon",
    "nt authority\\anonymous logon", "nt authority\\authenticated users",
    "nt authority\\everyone", "nt authority\\iusr", "iusr", "everyone",
    "authenticated users", "builtin\\administrators", "builtin\\users",
    "builtin\\guests", "defaultaccount", "wdagutilityaccount", "krbtgt",
    "dwm-1", "dwm-2", "dwm-3", "umfd-0", "umfd-1", "umfd-2", "umfd-3",
    # Default OS, cloud image & service identities
    "root", "nobody", "daemon", "guest", "localhost", "none", "null", "unknown",
    "n/a", "administrator", "admin", "localadmin", "ec2-user", "ubuntu", "centos",
    "debian", "fedora", "rhel", "ec2-instance-connect", "ssm-user", "cloud-user",
    "azureuser", "gcp-user", "bitnami", "vagrant", "ansible", "opc", "www-data",
    "apache", "nginx", "postgres", "mysql", "redis", "mongodb", "sshd", "_apt",
    "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
    "backup", "list", "irc", "gnats", "systemd-network", "systemd-resolve",
    "systemd-timesync", "messagebus", "tss", "uuidd", "tcpdump", "ntp", "chrony",
    "postfix", "dovecot",
    # Generic / localized built-in admin & placeholder names seen in telemetry
    "user", "users", "adm", "administrateur", "administratör", "administrador",
    "amministratore", "super user", "superuser", "test", "testuser", "operator",
    "service", "default",
}

GENERIC_USER_DOMAIN_PREFIXES = (
    "nt authority\\",
    "builtin\\",
    "window manager\\",
    "font driver host\\",
    "nt service\\",
)

# Well-known universal Windows SIDs (Null S-1-0-*, World S-1-1-*, Local S-1-2-*,
# Creator S-1-3-*, Non-unique S-1-4-*, NT Authority S-1-5-1..20, Built-in S-1-5-32-*,
# Auth S-1-5-64-*, NT Service S-1-5-80-*, VM S-1-5-83-*, DWM S-1-5-90-*, UMFD S-1-5-96-*,
# AppContainer S-1-15-*, Mandatory Integrity S-1-16-*, Asserted Identity S-1-18-*)
# plus domain SIDs ending in well-known default RIDs (500=Admin, 501=Guest, 502=krbtgt,
# 503=DefaultAccount, 504=WDAGUtilityAccount, 512..527/553/571/572 built-in domain groups).
_WELL_KNOWN_SID_RE = re.compile(
    r"^s-1-(?:"
    r"[0-4](?:-\d+)*|"
    r"5-(?:[1-9]|1\d|20|32-\d+|64-\d+|80(?:-\d+)*|83(?:-\d+)*|90(?:-\d+)*|96(?:-\d+)*)|"
    r"5-5-\d+-\d+|"
    r"5-21-[\d-]+-(?:500|501|502|503|504|512|513|514|515|516|517|518|519|520|521|522|525|526|527|553|571|572)|"
    r"15(?:-\d+)+|"
    r"16-\d+|"
    r"18-\d+"
    r")$",
    re.IGNORECASE,
)

GENERIC_BINARIES = {
    # Core Windows OS & system processes
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "conhost.exe",
    "svchost.exe", "rundll32.exe", "explorer.exe", "wsmprovhost.exe", "cscript.exe",
    "wscript.exe", "msiexec.exe", "reg.exe", "taskhostw.exe", "services.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "taskhost.exe", "dllhost.exe", "wmiprvse.exe", "mshta.exe", "wmic.exe",
    "vssvc.exe", "vssadmin.exe", "sppsvc.exe", "spoolsv.exe", "audiodg.exe",
    "dwm.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
    "backgroundtaskhost.exe", "dllhst3g.exe", "werfault.exe", "wermgr.exe",
    "trustedinstaller.exe", "tiworker.exe", "mobsync.exe", "searchindexer.exe",
    "wuauclt.exe", "usoclient.exe", "mpcmdrun.exe", "msmpeng.exe", "nissrv.exe",
    "securityhealthservice.exe", "notepad.exe", "calc.exe",
    # Built-in Windows discovery / admin / LOLBin utilities
    "net.exe", "net1.exe", "whoami.exe", "nltest.exe", "ipconfig.exe", "ping.exe",
    "tracert.exe", "nslookup.exe", "arp.exe", "route.exe", "netstat.exe",
    "schtasks.exe", "sc.exe", "tasklist.exe", "taskkill.exe", "find.exe",
    "findstr.exe", "where.exe", "systeminfo.exe", "hostname.exe", "quser.exe",
    "qwinsta.exe", "query.exe", "icacls.exe", "cacls.exe", "takeown.exe",
    "attrib.exe", "xcopy.exe", "robocopy.exe", "curl.exe", "certutil.exe",
    "bitsadmin.exe", "wevtutil.exe", "bcdedit.exe",
    "fltmc.exe", "gpupdate.exe", "gpresult.exe", "klist.exe",
    "logman.exe", "makecab.exe", "expand.exe", "tar.exe", "winget.exe",
    # Common Linux / macOS system shells, utilities & EDR/browser binaries
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "sudo", "su", "ls", "cat",
    "grep", "awk", "sed", "ps", "top", "kill", "chmod", "chown", "cp", "mv", "rm",
    "mkdir", "touch", "uname", "id", "env", "systemctl", "journalctl", "service",
    "cron", "crond", "sshd", "systemd", "init", "launchd", "apt", "apt-get",
    "dpkg", "yum", "dnf", "rpm", "gzip", "wget", "curl", "ssh", "scp", "sftp",
    "sshpass", "rsync", "nc", "netcat", "socat", "python", "python3", "perl",
    "ruby", "java", "node", "git", "docker", "kubectl", "chrome.exe", "msedge.exe",
    "firefox.exe", "csfalconservice.exe", "csfalconcontainer.exe", "falcon-sensor",
}

GENERIC_BINARY_PATH_SUBSTRINGS = (
    "/opt/crowdstrike/falcon-sensor",
    "\\program files\\crowdstrike\\",
    "\\windows\\system32\\wbem\\",
)

# Known SHA256 hashes of standard Windows OS system binaries (wmiprvse.exe, cmd.exe, vssadmin.exe, lsass.exe)
# as well as empty-file / well-known placeholder hashes that appear across unrelated hosts.
KNOWN_GENERIC_BINARY_HASHES = {
    "b5c78bef3883e3099f7ef844da1446db29107e5c0223b97f29e7fafab5527f15",  # wmiprvse.exe
    "bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527",  # cmd.exe
    "d7577fb88cca3169c7931dc0d8ec9a444227dc14f6c71d6d39d86a0c5cad1976",  # vssadmin.exe
    "7d91e2704409593c233031b8f7a3c22cc12d653d92f85c5c77233403ee7cb0b4",  # lsass.exe
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file SHA-256
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",  # empty file SHA-512 prefix
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # SHA-256("password")
    "a1b2c3d498fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # synthetic placeholder hash
    "b3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b851",  # synthetic placeholder hash
    "c3d4e5f698fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b857",  # synthetic placeholder hash
    "e2b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b899",  # synthetic placeholder hash
    "b4f98124801e9a38f3224b7a3a921d78291048f0291471018294a02918291823",  # synthetic placeholder hash
    "d41d8cd98f00b204e9800998ecf8427e",  # empty file MD5
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # empty file SHA-1
}

NOISY_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "127.0.0.1", "0.0.0.0", "255.255.255.255",
}

GENERIC_METADATA_VALUES = {
    "unknown", "n/a", "none", "null", "localhost", "true", "false",
    "outcome", "match", "beacon", "chronicle", "google chronicle", "home",
    "sensitive customer data", "remote_host_contacted_info",
    "windows powershell ise host", "consolehost", "serverremotehost", "default host",
}

NOISY_CONSOLE_URL_PREFIXES = (
    "http://localhost",
    "https://localhost",
    "https://console.aws.amazon.com/",
    "https://app.wiz.io/",
    "https://portal.azure.com/",
    "https://console.cloud.google.com/",
    "https://security.microsoft.com/",
)

_HEX_MASK_RE = re.compile(r"^0x[0-9a-f]{1,16}$", re.IGNORECASE)
_ISO_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}", re.IGNORECASE)
_BARE_NUMERIC_RE = re.compile(r"^\d+$")

_HOSTNAME_TYPE_TOKENS = {
    "HOSTNAME", "HOST", "ASSET", "DESTINATIONHOSTNAME", "SOURCEHOSTNAME",
    "TARGETHOSTNAME", "DEVICENAME", "COMPUTERNAME",
}
_USER_TYPE_TOKENS = {
    "USERUNIQNAME", "USER", "USERNAME", "USERID", "ACCOUNT", "ACCOUNTNAME",
    "SOURCEUSERNAME", "DESTINATIONUSERNAME", "TARGETUSERNAME", "WINDOWS_SID", "SID",
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


def is_noisy_entity(val: str, entity_type: Optional[str] = None) -> bool:
    clean = str(val or "").strip().lower()
    if not clean or len(clean) < 2:
        return True
    if clean in GENERIC_METADATA_VALUES:
        return True
    if clean in GENERIC_USERS:
        return True
    if clean.startswith(GENERIC_USER_DOMAIN_PREFIXES):
        return True
    if "\\" in clean and clean.split("\\")[-1] in GENERIC_USERS:
        return True
    if _WELL_KNOWN_SID_RE.match(clean):
        return True
    if _BARE_NUMERIC_RE.match(clean):
        # Bare integers (e.g. PIDs 652, 4572 mapped as PROCESS entities) are never valid cross-host anchors
        return True
    if _HEX_MASK_RE.match(clean):
        # Hex access bitmasks (e.g. 0x1010, 0x1fffff mapped as DEPLOYMENT)
        return True
    if _ISO_TIMESTAMP_RE.match(clean):
        # Raw timestamps mapped as DEPLOYMENT or generic entities
        return True
    if clean.startswith("arn:aws:iam::aws:policy/"):
        # Built-in AWS-managed IAM policy ARNs shared across all AWS accounts
        return True
    if clean.endswith("@wiz.io"):
        # Vendor detection rule author emails mapped into alert entities
        return True
    if clean in KNOWN_GENERIC_BINARY_HASHES:
        return True
    for bin_name in GENERIC_BINARIES:
        if clean == bin_name or clean.endswith("\\" + bin_name) or clean.endswith("/" + bin_name):
            return True
    for path_sub in GENERIC_BINARY_PATH_SUBSTRINGS:
        if path_sub in clean:
            return True
    if is_noisy_ip(val):
        return True
    if clean.startswith(NOISY_CONSOLE_URL_PREFIXES):
        return True
    if "googleapis.com/compute/v1/projects/" in clean and "/operations/" in clean:
        return True

    if entity_type:
        etype_norm = str(entity_type).strip().upper().replace("-", "").replace("_", "").replace(" ", "")
        etype_raw = str(entity_type).strip().upper()
        if etype_raw in _HOSTNAME_TYPE_TOKENS or etype_norm in _HOSTNAME_TYPE_TOKENS:
            # Hostnames cannot contain spaces (e.g. "Windows PowerShell ISE Host") or '@' email addresses
            if " " in clean or "@" in clean or "\\" in clean or "/" in clean:
                return True
        if etype_raw in _USER_TYPE_TOKENS or etype_norm in _USER_TYPE_TOKENS:
            # Machine accounts ending in '$' (e.g. WIN-SERVER$) should not correlate as user accounts
            if clean.endswith("$"):
                return True

    return False


def _normalize_user_root(val: str) -> str:
    """Extracts a canonical lowercase user root token across email, domain\\user, and display name formats."""
    clean = str(val or "").strip().lower()
    if not clean:
        return ""
    if "@" in clean:
        clean = clean.split("@")[0]
    if "\\" in clean:
        clean = clean.split("\\")[-1]
    return re.sub(r"[^a-z0-9]+", ".", clean).strip(".")


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
    """Resolves raw entity type with unambiguous value heuristics first, then raw_type fallback."""
    val_lower = raw_val.strip().lower()
    if val_lower.startswith(("http://", "https://")):
        return EntityType.URL
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val_lower):
        return EntityType.IP
    if "@" in val_lower and "." in val_lower:
        return EntityType.EMAIL
    if len(val_lower) == 64 and all(c in "0123456789abcdef" for c in val_lower):
        return EntityType.SHA256
    if len(val_lower) == 32 and all(c in "0123456789abcdef" for c in val_lower):
        return EntityType.MD5
    if raw_type:
        try:
            return coerce_entity_type(raw_type)
        except (ValueError, TypeError):
            pass
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
        if is_noisy_entity(clean_id, etype):
            return
        key = f"{clean_id.upper()}::{etype.upper()}"
        if key not in seen:
            seen.add(key)
            candidates.append({"identifier": clean_id, "type": etype})

    def _extract_from_process(proc: Any):
        if not isinstance(proc, dict):
            return
        cmd = str(proc.get("commandLine") or "")
        if cmd:
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", cmd):
                _add(ip, "IP")
            for url in re.findall(r"https?://[^\s\"'<>|;&]+", cmd):
                _add(url.rstrip(".,;)"), "DestinationURL")
        f_obj = proc.get("file")
        if isinstance(f_obj, dict):
            f_path = f_obj.get("fullPath")
            if not f_path or not is_noisy_entity(str(f_path), "FILENAME"):
                _add(f_obj.get("sha256"), "FILEHASH")
                _add(f_obj.get("md5"), "FILEHASH")
                _add(f_path, "FILENAME")
        parent = proc.get("parentProcess")
        if isinstance(parent, dict):
            p_cmd = str(parent.get("commandLine") or "")
            if p_cmd:
                for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", p_cmd):
                    _add(ip, "IP")
                for url in re.findall(r"https?://[^\s\"'<>|;&]+", p_cmd):
                    _add(url.rstrip(".,;)"), "DestinationURL")
            pf_obj = parent.get("file")
            if isinstance(pf_obj, dict):
                pf_path = pf_obj.get("fullPath")
                if not pf_path or not is_noisy_entity(str(pf_path), "FILENAME"):
                    _add(pf_obj.get("sha256"), "FILEHASH")
                    _add(pf_obj.get("md5"), "FILEHASH")
                    _add(pf_path, "FILENAME")

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
        _extract_from_process(p.get("process"))

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
        _extract_from_process(t.get("process"))
        tf_obj = t.get("file")
        if isinstance(tf_obj, dict):
            tf_path = tf_obj.get("fullPath")
            if not tf_path or not is_noisy_entity(str(tf_path), "FILENAME"):
                _add(tf_obj.get("sha256"), "FILEHASH")
                _add(tf_obj.get("md5"), "FILEHASH")
                _add(tf_path, "FILENAME")

    # 3. Source
    s = ev.get("src") or {}
    if isinstance(s, dict):
        for ip in s.get("ip") or []:
            _add(ip, "IP")
        s_user = s.get("user") or {}
        if isinstance(s_user, dict):
            _add(s_user.get("userid"), "USERUNIQNAME")
            _add(s_user.get("userDisplayName"), "USERUNIQNAME")
            for email in s_user.get("emailAddresses") or []:
                _add(email, "USERUNIQNAME")
        _add(s.get("hostname"), "HOSTNAME")

    # 4. Security Result
    sec_results = ev.get("securityResult") or ev.get("security_result") or []
    for sec in sec_results:
        if isinstance(sec, dict):
            _add(sec.get("urlBackToProduct"), "DestinationURL")
            desc = sec.get("description") or ""
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
        lookback_hours: int = 48,
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
            lookback_hours: How far back to search UDM relative to case creation/now (default: 48h).
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

        # 1. Wait for YARA-L detection indexing and SOAR alert grouping if the case was just created,
        # checking case creation time before running full investigation so we don't double-fetch alerts/entities.
        if min_case_age_seconds > 0:
            try:
                pre_case = self.adapter.get_case(clean_case_id)
                pre_dt = parse_timestamp(pre_case.get("createTime")) if isinstance(pre_case, dict) else None
                if pre_dt is not None:
                    if pre_dt.tzinfo is None:
                        pre_dt = pre_dt.replace(tzinfo=timezone.utc)
                    case_age = (datetime.now(timezone.utc) - pre_dt).total_seconds()
                    if 0.0 <= case_age < float(min_case_age_seconds):
                        wait_s = min(float(min_case_age_seconds) - case_age, 60.0)
                        time.sleep(wait_s)
            except Exception:
                pass

        # Investigate case to extract entities and existing alert context (single pass)
        investigation = self.investigate_workflow.execute(case_id=clean_case_id)

        # If the case was enriched by a LogJammer multi-log simulation, automatically correlate
        # corroborated UDM events and extract entities from them so PAM/Firewall/EDR pivot events
        # are never missed even if the caller left those flags at their defaults.
        raw_case_dict = (
            getattr(investigation, "raw_case", None)
            if isinstance(getattr(investigation, "raw_case", None), dict)
            else (
                getattr(investigation, "raw", None)
                if isinstance(getattr(investigation, "raw", None), dict)
                else {}
            )
        )
        case_raw_tags = raw_case_dict.get("tags") or []
        case_tag_names = {
            str(t.get("displayName") or t.get("tag") if isinstance(t, dict) else t).strip()
            for t in case_raw_tags
            if t
        }
        if "LogJammer:Simulated" in case_tag_names:
            correlate_udm_events = True
            extract_entities_from_events = True

        for attempt_idx in range(2):
            # Vendor filtering: filter alerts to only those originating from the target vendor
            target_alerts = investigation.alerts
            if (
                alert_vendor_filter
                and str(alert_vendor_filter).strip()
                and str(alert_vendor_filter).strip().upper() not in ("ALL", "*", "ANY")
            ):
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
            existing_user_roots: Set[str] = set()
            prioritized_clauses: List[Any] = []
            searched_entities: List[Dict[str, Any]] = []
            seen_query_clauses: Set[str] = set()
            seen_query_user_roots: Set[str] = set()

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

            prev_was_generic_binary = False
            prev_alert_id: Optional[str] = None

            for ent in investigation.entities:
                val = ent.identifier.strip()
                ent_raw = ent.raw if isinstance(getattr(ent, "raw", None), dict) else {}
                alert_id = str(ent_raw.get("alertIdentifier") or "GLOBAL").strip()
                if alert_id != prev_alert_id:
                    prev_was_generic_binary = False
                    prev_alert_id = alert_id

                val_lower = val.lower()
                is_gen_bin = any(
                    val_lower == b or val_lower.endswith("\\" + b) or val_lower.endswith("/" + b)
                    for b in GENERIC_BINARIES
                ) or any(sub in val_lower for sub in GENERIC_BINARY_PATH_SUBSTRINGS)
                if is_gen_bin:
                    prev_was_generic_binary = True
                    continue

                if is_noisy_entity(val, ent.entity_type):
                    prev_was_generic_binary = False
                    continue
                if not parsed_filter.matches(val, ent.entity_type):
                    continue

                e_type = _resolve_entity_type(ent.entity_type, val)
                if not e_type:
                    prev_was_generic_binary = False
                    continue

                # If this entity is a file hash immediately following a generic Windows OS binary
                # (e.g. cmd.exe, wmic.exe, wmiprvse.exe, vssvc.exe), do not use it as a UDM anchor/query
                if e_type in (EntityType.SHA256, EntityType.MD5, EntityType.SHA1) and prev_was_generic_binary:
                    continue
                if e_type not in (EntityType.SHA256, EntityType.MD5, EntityType.SHA1):
                    prev_was_generic_binary = False

                case_anchors.add(val.upper())
                local_user_part = ""
                if e_type in (EntityType.USER, EntityType.EMAIL):
                    uroot = _normalize_user_root(val)
                    if uroot:
                        existing_user_roots.add(uroot)
                    if "@" in val:
                        cand_local = val.split("@")[0].strip()
                        if len(cand_local) >= 3 and not is_noisy_entity(cand_local, "USERUNIQNAME"):
                            local_user_part = cand_local.lower()
                            case_anchors.add(cand_local.upper())

                try:
                    clause = SearchFromEntityWorkflow.build_entity_query(e_type, val)
                    if ent.entity_type:
                        try:
                            raw_coerced = coerce_entity_type(ent.entity_type)
                            if raw_coerced and raw_coerced != e_type:
                                alt_clause = SearchFromEntityWorkflow.build_entity_query(raw_coerced, val)
                                if alt_clause and alt_clause != clause:
                                    clause = f"{clause} OR {alt_clause}"
                        except Exception:
                            pass
                    if local_user_part:
                        try:
                            short_user_clause = SearchFromEntityWorkflow.build_entity_query(
                                EntityType.USER, local_user_part
                            )
                            if short_user_clause and short_user_clause not in clause:
                                clause = f"{clause} OR {short_user_clause}"
                        except Exception:
                            pass
                    base_bucket = e_type.value.upper()
                    prio = _PRIORITY_ORDER.get(base_bucket, _PRIORITY_ORDER.get(e_type.name.upper(), 8))

                    # Deprioritize redundant user display-name/domain aliases so they don't starve IP/HASH/URL clauses
                    if e_type in (EntityType.USER, EntityType.EMAIL):
                        uroot = _normalize_user_root(val)
                        if " " in val:
                            prio = 6
                        elif uroot and uroot in seen_query_user_roots:
                            prio = 5
                        if uroot:
                            seen_query_user_roots.add(uroot)

                    wrapped_clause = f'({clause})'
                    if wrapped_clause not in seen_query_clauses:
                        seen_query_clauses.add(wrapped_clause)
                        prioritized_clauses.append((prio, len(prioritized_clauses), wrapped_clause, alert_id, base_bucket))
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
                a_ident = str(a.identifier or a.raw.get("alertIdentifier") or "GLOBAL").strip()
                if tid.startswith("de_"):
                    clean_tid = tid[3:].lower()
                    escaped_tid = clean_tid.replace("\\", "\\\\").replace('"', '\\"')
                    t_clause = f'(security_result.threat_id = "{escaped_tid}")'
                    if t_clause not in seen_query_clauses:
                        seen_query_clauses.add(t_clause)
                        prioritized_clauses.append((9, len(prioritized_clauses), t_clause, a_ident, "THREAT_ID"))
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

            # Multi-alert & entity-type diverse clause selection (up to 15 clauses):
            # Pass 1: Guarantee up to 3 top-priority clauses for each grouped alert on the case
            # Pass 2: Fill remaining slots up to MAX_QUERY_CLAUSES with bucket diversity
            MAX_QUERY_CLAUSES = 15
            prioritized_clauses.sort(key=lambda item: (item[0], item[1]))
            selected_clause_indices: Set[int] = set()
            bounded_clauses: List[str] = []
            bucket_counts: Dict[str, int] = {}

            clauses_by_alert: Dict[str, List[Any]] = {}
            for item in prioritized_clauses:
                clauses_by_alert.setdefault(item[3], []).append(item)

            for _aid, a_items in clauses_by_alert.items():
                taken_for_alert = 0
                for item in a_items:
                    if len(bounded_clauses) >= MAX_QUERY_CLAUSES or taken_for_alert >= 3:
                        break
                    if item[1] not in selected_clause_indices:
                        selected_clause_indices.add(item[1])
                        bounded_clauses.append(item[2])
                        b_key = "USER" if item[4] in ("USER", "EMAIL") else ("HASH" if item[4] in ("SHA256", "MD5", "SHA1") else item[4])
                        bucket_counts[b_key] = bucket_counts.get(b_key, 0) + 1
                        taken_for_alert += 1

            # Pass 2a: Fill remaining slots while capping any single entity bucket at 4 clauses
            for item in prioritized_clauses:
                if len(bounded_clauses) >= MAX_QUERY_CLAUSES:
                    break
                if item[1] in selected_clause_indices:
                    continue
                b_key = "USER" if item[4] in ("USER", "EMAIL") else ("HASH" if item[4] in ("SHA256", "MD5", "SHA1") else item[4])
                if bucket_counts.get(b_key, 0) >= 4:
                    continue
                selected_clause_indices.add(item[1])
                bounded_clauses.append(item[2])
                bucket_counts[b_key] = bucket_counts.get(b_key, 0) + 1

            # Pass 2b: Fill any remaining capacity up to MAX_QUERY_CLAUSES in priority order
            for item in prioritized_clauses:
                if len(bounded_clauses) >= MAX_QUERY_CLAUSES:
                    break
                if item[1] not in selected_clause_indices:
                    selected_clause_indices.add(item[1])
                    bounded_clauses.append(item[2])

            combined_query = f"({' OR '.join(bounded_clauses)}) AND metadata.event_type != \"ENTITY_RISK_CHANGE\""

            # Calculate time window around case created_time or now
            now_utc = datetime.now(timezone.utc)
            ref_time = investigation.created_time or now_utc
            if ref_time.tzinfo is None:
                ref_time = ref_time.replace(tzinfo=timezone.utc)
            start_time = (ref_time - timedelta(hours=lookback_hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
            end_dt = max(ref_time + timedelta(hours=2), now_utc + timedelta(minutes=15))
            end_time = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

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
            if getattr(session, "lifecycle", None) == LifecycleState.FAILED:
                session.raise_for_failure()

            # 3. Analyze events for genuine detections, anchor corroboration, and relevant events
            detections_found: List[Dict[str, Any]] = []
            events_found: List[Dict[str, Any]] = []
            evidence_to_attach: List[Dict[str, str]] = []
            det_evidence_by_rule: Dict[str, List[Any]] = {}
            event_evidence_items: List[Dict[str, str]] = []
            discovered_candidates: List[Dict[str, str]] = []
            seen_evidence_ids: Set[str] = set()
            seen_det_keys: Set[str] = set()

            for ev in session.events:
                meta = ev.get('metadata') or {}
                event_id = meta.get('id')
                event_ts = str(meta.get('eventTimestamp') or '')
                event_type_upper = (meta.get('eventType') or meta.get('event_type') or '').strip().upper()
                sec_results = ev.get('securityResult') or ev.get('security_result') or []
                detection_objs = ev.get('detections') or []

                # Extract non-noisy event entities once and build comprehensive ev_anchors set
                # (hostname, userid, displayName, email, IP, non-generic SHA256/MD5/fullPath, URL, threatId)
                ev_candidates = _extract_event_entities(ev)
                ev_anchors: Set[str] = {
                    c["identifier"].strip().upper()
                    for c in ev_candidates
                    if c.get("identifier") and str(c.get("identifier")).strip()
                }
                for noun_key in ("principal", "target", "src"):
                    noun_obj = ev.get(noun_key) or {}
                    if not isinstance(noun_obj, dict):
                        continue
                    h_val = str(noun_obj.get("hostname") or "").strip()
                    if h_val and not is_noisy_entity(h_val, "HOSTNAME"):
                        ev_anchors.add(h_val.upper())
                    u_val = str(noun_obj.get("url") or "").strip()
                    if u_val and not is_noisy_entity(u_val, "DestinationURL"):
                        ev_anchors.add(u_val.upper())
                    n_usr = noun_obj.get("user") or {}
                    if isinstance(n_usr, dict):
                        for uk in ("userid", "userDisplayName"):
                            usr_val = str(n_usr.get(uk) or "").strip()
                            if usr_val and not is_noisy_entity(usr_val, "USERUNIQNAME"):
                                ev_anchors.add(usr_val.upper())
                        for em in n_usr.get("emailAddresses") or []:
                            em_val = str(em or "").strip()
                            if em_val and not is_noisy_entity(em_val, "USERUNIQNAME"):
                                ev_anchors.add(em_val.upper())
                    for ip in noun_obj.get("ip") or []:
                        ip_val = str(ip or "").strip()
                        if ip_val and not is_noisy_entity(ip_val, "IP"):
                            ev_anchors.add(ip_val.upper())
                for sec in sec_results:
                    if isinstance(sec, dict) and sec.get("threatId"):
                        tid_val = str(sec.get("threatId")).strip()
                        ev_anchors.add(tid_val.upper())
                        if tid_val.lower().startswith("de_"):
                            ev_anchors.add(tid_val[3:].upper())

                is_corroborated = bool(ev_anchors.intersection(case_anchors))
                has_any_detection = False
                has_silent_detection = False
                is_existing_case_alert_event = False

                if correlate_detections:
                    # Genuine detections from detections objects (ev["detections"])
                    for det in detection_objs:
                        det_id = (det.get('id') or '').strip()
                        if not det_id:
                            continue
                        has_any_detection = True
                        if det_id.lower() in existing_alert_ticket_ids:
                            is_existing_case_alert_event = True
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
                        if not is_silent:
                            continue

                        has_silent_detection = True

                        if is_corroborated and det_id not in seen_evidence_ids:
                            seen_evidence_ids.add(det_id)
                            det_evidence_by_rule.setdefault(str(rule_name), []).append((
                                event_ts,
                                {
                                    'evidenceId': det_id,
                                    'evidenceType': 'EVIDENCE_TYPE_DETECTION',
                                },
                            ))

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
                    for sec in (sec_results if not detection_objs and not is_existing_case_alert_event else []):
                        if not is_genuine_yara_l_detection(sec, has_det_obj=bool(detection_objs)):
                            continue

                        has_any_detection = True
                        rule_name = sec.get('ruleName') or sec.get('ruleId')
                        rule_id = sec.get('ruleId') or ''
                        if rule_id and rule_id in existing_alert_rule_ids:
                            is_existing_case_alert_event = True
                            continue
                        alert_state = (sec.get('alertState') or 'NOT_ALERTING').upper()
                        is_alerting = alert_state == 'ALERTING'
                        is_silent = not is_alerting and rule_id not in existing_alert_rule_ids
                        if not is_silent:
                            continue

                        det_key = f"{rule_name}::{rule_id}::{event_id}"
                        if det_key in seen_det_keys:
                            continue
                        seen_det_keys.add(det_key)

                        has_silent_detection = True
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
                                event_evidence_items.append({
                                    'evidenceId': event_id,
                                    'evidenceType': 'EVIDENCE_TYPE_EVENT',
                                })

                    # Extract entities only from genuine, corroborated silent detections
                    if has_silent_detection and is_corroborated:
                        for cand in ev_candidates:
                            if not parsed_filter.matches(cand.get('identifier'), cand.get('type')):
                                continue
                            cid_upper = cand['identifier'].strip().upper()
                            if cid_upper not in existing_identifiers and cid_upper not in case_anchors:
                                discovered_candidates.append(cand)

                if not has_silent_detection and not is_existing_case_alert_event and event_type_upper != 'ENTITY_RISK_CHANGE':
                    if correlate_udm_events and event_id and is_corroborated:
                        events_found.append(_summarize_udm_event(ev, is_corroborated))
                        if attach_udm_events and is_corroborated and event_id not in seen_evidence_ids:
                            seen_evidence_ids.add(event_id)
                            event_evidence_items.append({
                                'evidenceId': event_id,
                                'evidenceType': 'EVIDENCE_TYPE_EVENT',
                            })
                    if extract_entities_from_events and is_corroborated:
                        for cand in ev_candidates:
                            if not parsed_filter.matches(cand.get('identifier'), cand.get('type')):
                                continue
                            cid_upper = cand['identifier'].strip().upper()
                            if cid_upper not in existing_identifiers and cid_upper not in case_anchors:
                                discovered_candidates.append(cand)

            # Interleave detection evidence round-robin across rules (newest timestamp first within each rule)
            # so replayed detections from a single rule cannot crowd out other silent detection rules in [:50].
            sorted_rule_queues: List[List[Dict[str, str]]] = []
            for _rname, r_items in det_evidence_by_rule.items():
                r_items_sorted = sorted(r_items, key=lambda x: x[0], reverse=True)
                sorted_rule_queues.append([x[1] for x in r_items_sorted])
            max_queue_len = max((len(q) for q in sorted_rule_queues), default=0)
            for idx_in_q in range(max_queue_len):
                for q in sorted_rule_queues:
                    if idx_in_q < len(q):
                        evidence_to_attach.append(q[idx_in_q])
            evidence_to_attach.extend(event_evidence_items)

            # Deduplicate and rank discovered delta entity candidates so high-signal pivots
            # (new HOSTNAME, external IP, genuinely new USER, internal IP, FILEHASH/URL) rank ahead of
            # redundant display-name/domain aliases of already-known case users.
            cand_freq: Dict[str, int] = {}
            unique_candidates: List[Dict[str, str]] = []
            for cand in discovered_candidates:
                cid = cand['identifier'].strip()
                ctype = cand['type'].strip()
                ckey = f"{cid.upper()}::{ctype.upper()}"
                if cid.upper() in existing_identifiers or cid.upper() in case_anchors:
                    continue
                if ckey not in cand_freq:
                    cand_freq[ckey] = 0
                    unique_candidates.append(cand)
                cand_freq[ckey] += 1

            def _rank_delta_candidate(item_with_idx: Any) -> Any:
                idx_pos, cand_obj = item_with_idx
                cid = cand_obj['identifier'].strip()
                ctype = cand_obj['type'].strip().upper()
                ckey = f"{cid.upper()}::{ctype}"
                freq = cand_freq.get(ckey, 1)
                if ctype == "HOSTNAME":
                    tier = 0
                elif ctype == "IP":
                    try:
                        ip_obj = ipaddress.ip_address(cid)
                        tier = 3 if ip_obj.is_private else 1
                    except ValueError:
                        tier = 3
                elif ctype == "USERUNIQNAME":
                    uroot = _normalize_user_root(cid)
                    is_known_root = bool(uroot and uroot in existing_user_roots)
                    has_space = " " in cid
                    if not is_known_root and not has_space:
                        tier = 2
                    elif not is_known_root and has_space:
                        tier = 6
                    else:
                        tier = 7
                elif ctype in ("FILEHASH", "DESTINATIONURL"):
                    tier = 4
                elif ctype == "FILENAME":
                    tier = 5
                else:
                    tier = 6
                return (tier, -freq, idx_pos)

            discovered_candidates = [
                c for _, c in sorted(enumerate(unique_candidates), key=_rank_delta_candidate)
            ]

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
            attached_user_roots: Set[str] = set(existing_user_roots)
            deferred_user_aliases: List[Dict[str, str]] = []

            for cand in discovered_candidates:
                if len(attached_entities) >= max_entities_to_attach:
                    break
                cid = cand['identifier'].strip()
                ctype = cand['type'].strip()
                ckey = f"{cid.upper()}::{ctype.upper()}"
                if ckey in seen_cand_keys or cid.upper() in existing_identifiers or cid.upper() in case_anchors:
                    continue
                if ctype.upper() == "USERUNIQNAME":
                    uroot = _normalize_user_root(cid)
                    if uroot and uroot in attached_user_roots:
                        deferred_user_aliases.append(cand)
                        continue
                    if uroot:
                        attached_user_roots.add(uroot)
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

            # If slots remain after all distinct entity roots were considered, fill with deferred aliases
            for cand in deferred_user_aliases:
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

        # Inspect prior correlation comments on Case Wall for delta tracking & comment deduplication
        prior_detections_count: Optional[int] = None
        has_identical_prior_comment = False
        for cm in (getattr(investigation, "comments", None) or []):
            cm_text = str(getattr(cm, "comment", "") or "")
            if "### [Automated Correlation] Silent Detections & Evidence" in cm_text:
                m_det = re.search(r"-\s*\*\*Total Detections Found\*\*:\s*(\d+)", cm_text)
                if m_det:
                    det_cnt = int(m_det.group(1))
                    if prior_detections_count is None or det_cnt > prior_detections_count:
                        prior_detections_count = det_cnt
                    if det_cnt == len(detections_found) and len(attached_entities) == 0:
                        has_identical_prior_comment = True

        delta_detections_count = (
            max(0, len(detections_found) - prior_detections_count)
            if prior_detections_count is not None
            else 0
        )
        recommended_detection_tags: List[str] = []
        if detections_found:
            recommended_detection_tags.append("SilentDetections:Found")
        if delta_detections_count > 0 or len(attached_entities) > 0:
            recommended_detection_tags.append("SilentDetections:DeltaAdded")

        # 5. Post summary comment to Case Wall if requested (deduplicated against identical prior comments)
        comment_id: Optional[str] = None
        comment_error: Optional[str] = None
        if (
            post_wall_comment
            and not has_identical_prior_comment
            and (detections_found or events_found or attached_items or attached_entities)
        ):
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
                grouped_rules: Dict[Any, int] = {}
                for d in detections_found:
                    r_key = (
                        d.get("rule_name") or "Unknown Rule",
                        d.get("alert_state") or "SILENT",
                        d.get("severity") or "N/A",
                    )
                    grouped_rules[r_key] = grouped_rules.get(r_key, 0) + 1
                for (rule_label, state_label, sev_label), r_count in list(grouped_rules.items())[:10]:
                    count_suffix = f" — {r_count}x" if r_count > 1 else ""
                    comment_lines.append(
                        f"- `{rule_label}` (State: {state_label}, Severity: {sev_label}){count_suffix}"
                    )
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
            except Exception as exc:
                comment_error = f"{type(exc).__name__}: {exc}"

        provenance_meta: Dict[str, Any] = {
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
        }
        raw_meta: Dict[str, Any] = {
            'events_scanned': len(session.events),
            'total_evidence_candidates': len(evidence_to_attach),
            'total_delta_entity_candidates': len(discovered_candidates),
            'prior_detections_count': prior_detections_count,
            'delta_detections_count': delta_detections_count,
            'recommended_detection_tags': recommended_detection_tags,
            'duplicate_comment_skipped': has_identical_prior_comment,
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
        }
        if comment_error:
            provenance_meta["comment_error"] = comment_error
            raw_meta["comment_error"] = comment_error

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
            provenance=provenance_meta,
            raw=raw_meta,
        )

