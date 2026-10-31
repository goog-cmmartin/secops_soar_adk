"""Automatic indicator detection and UDM / Graph / IoC query mapping.

Parses untyped strings (IPs, hashes, emails, hostnames, URLs, MACs, domains, usernames)
and returns structured query fragments for UDM Event Search, UDM Entity Graph Search,
and Enterprise IoC Intelligence searches.

When the caller already knows the type (e.g. a SOAR involved-entity carries an
``entity_type``), pass it via ``hint`` to bypass the ambiguous regex heuristics.
The regex fallback remains for genuinely untyped input.
"""

from dataclasses import dataclass
from enum import Enum
import ipaddress
import re
from typing import Callable, Dict, Optional, Union

from engine.domain import EntityType, coerce_entity_type


def _escape_udm_literal(val: str) -> str:
    """Escapes backslashes and double quotes for UDM double-quoted string literals."""
    return val.replace("\\", "\\\\").replace('"', '\\"')


class EntityCategory(str, Enum):
    FILE = "FILE"
    ASSET = "ASSET"
    USER = "USER"
    DOMAIN_NAME = "DOMAIN_NAME"
    NETWORK = "NETWORK"
    RESOURCE = "RESOURCE"
    URL = "URL"
    OTHER = "OTHER"


@dataclass(frozen=True)
class DetectedEntity:
    """Represents a detected indicator and its canonical search representations.

    ``graph_field`` is the primary UDM Entity Graph field. Some entity types are
    inherently ambiguous in the graph schema (e.g. a SOAR ``USERUNIQNAME`` may be a
    ``userid`` *or* an ``email_addresses`` value; a ``DOMAIN`` may live under
    ``domain.name`` *or* ``hostname``). For those, ``graph_fields`` holds every field
    that should be OR'd together and ``graph_query`` is the composed OR expression.
    For single-field entities ``graph_fields == (graph_field,)``.
    """

    raw_value: str
    entity_type: EntityType
    category: EntityCategory
    graph_field: str
    graph_query: str
    event_query: str
    ioc_value_type: Optional[str] = None
    graph_fields: tuple = ()

    def __post_init__(self):
        # Guarantee graph_fields is always populated and the primary is first.
        if not self.graph_fields:
            object.__setattr__(self, "graph_fields", (self.graph_field,))


# ---------------------------------------------------------------------------
# Per-type builders. Each accepts the already-stripped raw value and returns a
# fully-formed DetectedEntity. These are the single source of truth for how a
# given EntityType maps to graph/event/IoC queries; both the regex heuristics
# and the hint dispatch reuse them.
# ---------------------------------------------------------------------------

def _build_ip(val: str) -> DetectedEntity:
    ev = _escape_udm_literal(val)
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.IP,
        category=EntityCategory.ASSET,
        graph_field="graph.entity.ip",
        graph_query=f'graph.entity.ip = "{ev}"',
        event_query=f'principal.ip = "{ev}" OR target.ip = "{ev}" OR src.ip = "{ev}"',
        # FieldAndValue.ValueType has no plain IP value; IP_ADDRESS is rejected
        # with HTTP 400. ASSET_IP_ADDRESS is the documented IP enum and is
        # accepted by legacySearchEnterpriseWideIoCs and summarizeEntity
        # (verified live 2026-10-10).
        ioc_value_type="ASSET_IP_ADDRESS",
    )


def _build_md5(val: str) -> DetectedEntity:
    v = _escape_udm_literal(val.lower())
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.MD5,
        category=EntityCategory.FILE,
        graph_field="graph.entity.file.md5",
        graph_query=f'graph.entity.file.md5 = "{v}"',
        event_query=f'target.file.md5 = "{v}" OR principal.process.file.md5 = "{v}"',
        ioc_value_type="HASH_MD5",
    )


def _build_sha1(val: str) -> DetectedEntity:
    v = _escape_udm_literal(val.lower())
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.SHA1,
        category=EntityCategory.FILE,
        graph_field="graph.entity.file.sha1",
        graph_query=f'graph.entity.file.sha1 = "{v}"',
        event_query=f'target.file.sha1 = "{v}" OR principal.process.file.sha1 = "{v}"',
        ioc_value_type="HASH_SHA1",
    )


def _build_sha256(val: str) -> DetectedEntity:
    v = _escape_udm_literal(val.lower())
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.SHA256,
        category=EntityCategory.FILE,
        graph_field="graph.entity.file.sha256",
        graph_query=f'graph.entity.file.sha256 = "{v}"',
        event_query=f'target.file.sha256 = "{v}" OR principal.process.file.sha256 = "{v}"',
        ioc_value_type="HASH_SHA256",
    )


def _build_mac(val: str) -> DetectedEntity:
    v = _escape_udm_literal(val.lower())
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.MAC,
        category=EntityCategory.ASSET,
        graph_field="graph.entity.mac",
        graph_query=f'graph.entity.mac = "{v}"',
        event_query=f'principal.mac = "{v}" OR target.mac = "{v}" OR src.mac = "{v}"',
        ioc_value_type="MAC_ADDRESS",
    )


def _build_email(val: str) -> DetectedEntity:
    v = _escape_udm_literal(val.lower())
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.EMAIL,
        category=EntityCategory.USER,
        graph_field="graph.entity.user.email_addresses",
        graph_query=f'graph.entity.user.email_addresses = "{v}" nocase',
        event_query=f'principal.user.email_addresses = "{v}" OR target.user.email_addresses = "{v}"',
        ioc_value_type="EMAIL_ADDRESS",
    )


def _build_url(val: str) -> DetectedEntity:
    ev = _escape_udm_literal(val)
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.URL,
        category=EntityCategory.URL,
        graph_field="graph.entity.url",
        graph_query=f'graph.entity.url = "{ev}"',
        event_query=f'target.url = "{ev}" OR network.http.referral_url = "{ev}"',
        ioc_value_type="URL",
    )


def _build_sid(val: str) -> DetectedEntity:
    ev = _escape_udm_literal(val)
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.WINDOWS_SID,
        category=EntityCategory.USER,
        graph_field="graph.entity.user.windows_sid",
        graph_query=f'graph.entity.user.windows_sid = "{ev}"',
        event_query=f'principal.user.windows_sid = "{ev}" OR target.user.windows_sid = "{ev}"',
        ioc_value_type=None,
    )


def _build_resource(val: str) -> DetectedEntity:
    ev = _escape_udm_literal(val)
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.RESOURCE,
        category=EntityCategory.RESOURCE,
        graph_field="graph.entity.resource.name",
        graph_query=f'graph.entity.resource.name = "{ev}"',
        event_query=f'target.resource.name = "{ev}"',
        ioc_value_type=None,
    )


def _build_domain(val: str) -> DetectedEntity:
    v = _escape_udm_literal(val.lower())
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.DOMAIN,
        category=EntityCategory.DOMAIN_NAME,
        graph_field="graph.entity.domain.name",
        graph_query=f'graph.entity.domain.name = "{v}"',
        event_query=f'network.dns.questions.name = "{v}" OR target.hostname = "{v}"',
        ioc_value_type="DOMAIN_NAME",
    )


def _build_hostname(val: str) -> DetectedEntity:
    ev = _escape_udm_literal(val)
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.HOSTNAME,
        category=EntityCategory.ASSET,
        graph_field="graph.entity.hostname",
        graph_query=f'graph.entity.hostname = "{ev}" nocase',
        event_query=f'principal.hostname = "{ev}" nocase OR target.hostname = "{ev}" nocase',
        ioc_value_type="HOSTNAME",
    )


def _build_user(val: str) -> DetectedEntity:
    ev = _escape_udm_literal(val)
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.USER,
        category=EntityCategory.USER,
        graph_field="graph.entity.user.userid",
        graph_query=f'graph.entity.user.userid = "{ev}" nocase',
        event_query=f'principal.user.userid = "{ev}" nocase OR target.user.userid = "{ev}" nocase',
        ioc_value_type="USER_ID",
    )


def _build_file_name(val: str) -> DetectedEntity:
    """A file *name*/path (not a hash). Routes to file.full_path, not userid."""
    ev = _escape_udm_literal(val)
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.FILE,
        category=EntityCategory.FILE,
        graph_field="graph.entity.file.full_path",
        graph_query=f'graph.entity.file.full_path = "{ev}" nocase',
        event_query=(
            f'target.file.full_path = "{ev}" nocase '
            f'OR principal.process.file.full_path = "{ev}" nocase'
        ),
        ioc_value_type=None,
    )


def _compose_graph_or(pairs, nocase: bool = False) -> str:
    """Compose an OR expression across multiple graph fields.

    ``pairs`` is an iterable of ``(field, value)``. Each clause is rendered as
    ``field = "value"`` with an optional trailing ``nocase``. Values are escaped
    for UDM string literals.
    """
    suffix = " nocase" if nocase else ""
    return " OR ".join(
        f'{field} = "{_escape_udm_literal(value)}"{suffix}' for field, value in pairs
    )


def _build_user_or_email(val: str) -> DetectedEntity:
    """SOAR USERUNIQNAME: identity may be a bare userid OR an email address.

    Emits an OR across both graph fields so the search matches whichever the
    graph actually stored. Values are lower-cased for the email clause; userid
    matching is case-insensitive via ``nocase``.
    """
    v = val.lower()
    ev = _escape_udm_literal(val)
    ev_lower = _escape_udm_literal(v)
    fields = ("graph.entity.user.userid", "graph.entity.user.email_addresses")
    graph_query = _compose_graph_or(
        ((fields[0], val), (fields[1], v)), nocase=True
    )
    event_query = (
        f'principal.user.userid = "{ev}" nocase '
        f'OR target.user.userid = "{ev}" nocase '
        f'OR principal.user.email_addresses = "{ev_lower}" '
        f'OR target.user.email_addresses = "{ev_lower}"'
    )
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.USER,
        category=EntityCategory.USER,
        graph_field=fields[0],
        graph_fields=fields,
        graph_query=graph_query,
        event_query=event_query,
        ioc_value_type="USER_ID",
    )


def _build_domain_or_hostname(val: str) -> DetectedEntity:
    """SOAR DOMAIN: value may be a registered domain OR an asset hostname.

    Emits an OR across ``domain.name`` and ``hostname`` (both case-insensitive).
    """
    v = val.lower()
    ev = _escape_udm_literal(val)
    ev_lower = _escape_udm_literal(v)
    fields = ("graph.entity.domain.name", "graph.entity.hostname")
    graph_query = _compose_graph_or(((fields[0], v), (fields[1], val)), nocase=True)
    event_query = (
        f'network.dns.questions.name = "{ev_lower}" nocase '
        f'OR target.hostname = "{ev}" nocase '
        f'OR principal.hostname = "{ev}" nocase'
    )
    return DetectedEntity(
        raw_value=val,
        entity_type=EntityType.DOMAIN,
        category=EntityCategory.DOMAIN_NAME,
        graph_field=fields[0],
        graph_fields=fields,
        graph_query=graph_query,
        event_query=event_query,
        ioc_value_type="DOMAIN_NAME",
    )


# Map an EntityType to its builder. Used by the hint dispatch.
_BUILDERS: Dict[EntityType, Callable[[str], DetectedEntity]] = {
    EntityType.IP: _build_ip,
    EntityType.MD5: _build_md5,
    EntityType.SHA1: _build_sha1,
    EntityType.SHA256: _build_sha256,
    EntityType.MAC: _build_mac,
    EntityType.EMAIL: _build_email,
    EntityType.URL: _build_url,
    EntityType.WINDOWS_SID: _build_sid,
    EntityType.RESOURCE: _build_resource,
    EntityType.DOMAIN: _build_domain,
    EntityType.HOSTNAME: _build_hostname,
    EntityType.USER: _build_user,
}
# FILE builder is registered separately only if the domain enum exposes it.
if hasattr(EntityType, "FILE"):
    _BUILDERS[EntityType.FILE] = _build_file_name


# ---------------------------------------------------------------------------
# SOAR involved-entity type -> our EntityType. SOAR types are free-form-ish
# strings; normalise to upper-case and strip separators for matching.
# For file hashes, the concrete hash algorithm is resolved by length at runtime.
# ---------------------------------------------------------------------------
_SOAR_TYPE_MAP: Dict[str, EntityType] = {
    "ADDRESS": EntityType.IP,
    "IP": EntityType.IP,
    "IPV4": EntityType.IP,
    "IPV6": EntityType.IP,
    "IPADDRESS": EntityType.IP,
    "HOSTNAME": EntityType.HOSTNAME,
    "HOST": EntityType.HOSTNAME,
    "MACADDRESS": EntityType.MAC,
    "MAC": EntityType.MAC,
    "USER": EntityType.USER,
    "USERUNIQNAME": EntityType.USER,
    "USERNAME": EntityType.USER,
    "USERID": EntityType.USER,
    "EMAIL": EntityType.EMAIL,
    "EMAILADDRESS": EntityType.EMAIL,
    "DESTINATIONURL": EntityType.URL,
    "URL": EntityType.URL,
    "DOMAIN": EntityType.DOMAIN,
    "DOMAINNAME": EntityType.DOMAIN,
    "WINDOWSSID": EntityType.WINDOWS_SID,
    "SID": EntityType.WINDOWS_SID,
    "SHA256": EntityType.SHA256,
    "MD5": EntityType.MD5,
    "SHA1": EntityType.SHA1,
    "RESOURCE": EntityType.RESOURCE,
    "EMAILSUBJECT": EntityType.USER,  # subjects aren't graph indicators; best-effort
    "CVE": EntityType.RESOURCE,
}
if hasattr(EntityType, "FILE"):
    _SOAR_TYPE_MAP["FILENAME"] = EntityType.FILE
    _SOAR_TYPE_MAP["FILE"] = EntityType.FILE
    _SOAR_TYPE_MAP["PROCESS"] = EntityType.FILE  # process name -> file path family


# SOAR types whose graph representation is genuinely ambiguous and must be
# searched as an OR across multiple fields. These take precedence over the
# single-field EntityType builders when the caller supplies the SOAR hint.
# (The plain regex fallback still uses the narrow single-field builders, since
# it can already tell an email from a userid and a domain from a hostname.)
_SOAR_MULTI: Dict[str, Callable[[str], DetectedEntity]] = {
    "USERUNIQNAME": _build_user_or_email,
    "DOMAIN": _build_domain_or_hostname,
}


def _normalise_hint(hint: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", hint.upper())


def _resolve_hash(val: str) -> Optional[DetectedEntity]:
    """Return the correct hash entity for a hex string, by length; else None."""
    if re.fullmatch(r"[a-fA-F0-9]{32}", val):
        return _build_md5(val)
    if re.fullmatch(r"[a-fA-F0-9]{40}", val):
        return _build_sha1(val)
    if re.fullmatch(r"[a-fA-F0-9]{64}", val):
        return _build_sha256(val)
    return None


# Common file extensions that strongly imply a file name/path rather than a
# hostname or username. Kept deliberately small and high-signal.
_FILE_EXT_RE = re.compile(
    r"\.(exe|dll|sys|bat|cmd|ps1|vbs|js|jar|msi|scr|"
    r"doc|docx|xls|xlsx|ppt|pptx|pdf|rtf|"
    r"zip|rar|7z|gz|tar|"
    r"sh|py|php|dmg|apk|bin|dat|tmp|log)$",
    re.IGNORECASE,
)

# A domain must have a plausible alphabetic TLD (>= 2 letters). This prevents
# things like "WRK-01.local"? -> .local is allowed; but "foo.123" is not a domain.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

# Hostname signal: contains a dash or a trailing '$' (machine account) or is a
# recognised host-ish token. A *bare* short alphanumeric token is treated as a
# username instead (see fallback), because that is the far more common case for
# untyped identifiers in case data.
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\$?$")


def _looks_like_hostname(val: str) -> bool:
    """Heuristic: a single-label token that reads like a host, not a person.

    Signals: presence of a hyphen (WRK-01, WIN-DESKTOP), a trailing '$'
    (Windows machine account), or an embedded digit run typical of asset tags.
    """
    if not _HOSTNAME_RE.fullmatch(val):
        return False
    if val.endswith("$"):
        return True
    if "-" in val:
        return True
    # e.g. "SERVER01", "HOST12" -> letters followed by digits reads host-ish.
    if re.fullmatch(r"[a-zA-Z]{2,}\d{1,}", val):
        return True
    return False


def _detect_by_regex(val: str) -> DetectedEntity:
    """Heuristic detection for genuinely untyped strings.

    Ordered most-specific -> least-specific. The final catch-all is USER (not
    HOSTNAME): a bare token with no host-like signal is far more likely to be a
    username in case data. HOSTNAME is only chosen on a positive host signal.
    """
    # 1. IP Address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(val)
        return _build_ip(val)
    except ValueError:
        pass

    # 2. File Hashes (MD5: 32, SHA1: 40, SHA256: 64)
    hashed = _resolve_hash(val)
    if hashed is not None:
        return hashed

    # 3. MAC Address (colon/hyphen sextet or Cisco dot-triplet)
    if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", val) or re.fullmatch(
        r"([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}", val
    ):
        return _build_mac(val)

    # 4. Email Address
    if re.fullmatch(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", val):
        return _build_email(val)

    # 5. URL / Web Resource (http, https, ftp, file schemes)
    if re.match(r"^(https?|ftp|file)://", val, re.IGNORECASE):
        return _build_url(val)

    # 6. Windows Security Identifier (SID)
    if re.fullmatch(r"S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-\d{3,5}", val, re.IGNORECASE):
        return _build_sid(val)

    # 7. Cloud Resource Name
    if val.startswith("//") or val.startswith("projects/"):
        return _build_resource(val)

    # 8. Unambiguous file *paths*: UNC (\\\\host\\share), drive path (C:\\..), or POSIX path.
    #    A lone interior backslash (DOMAIN\\user credential form) is NOT a path and
    #    is deliberately left to fall through to the USER fallback.
    if val.startswith("\\\\") or re.match(r"^[a-zA-Z]:[\\/]", val) or val.startswith("/"):
        return _build_file_name(val)

    # 9. Single-label file name (exactly one dot) whose suffix is a known file
    #    extension -- e.g. "invoice.pdf", "payload.exe". Resolved before the
    #    domain check because "name.ext" is far more likely a file than a domain
    #    when the extension is a recognised non-TLD file type. Multi-dot names
    #    (e.g. "host.acme.com") fall through to the domain check below.
    if val.count(".") == 1 and _FILE_EXT_RE.search(val):
        return _build_file_name(val)

    # 10. Domain Name (FQDN with alphabetic TLD) -- e.g. "evil-domain.com",
    #     "host.acme.com".
    if _DOMAIN_RE.fullmatch(val):
        return _build_domain(val)

    # 11. Remaining known-extension file names (multi-dot, non-domain).
    if _FILE_EXT_RE.search(val):
        return _build_file_name(val)

    # 12. Hostname / Asset Name -- only on a positive host signal.
    if _looks_like_hostname(val):
        return _build_hostname(val)

    # 13. Fallback: User ID / Username (the most common untyped identifier).
    return _build_user(val)


def detect_entity(value: str, hint: Optional[Union[EntityType, str]] = None) -> DetectedEntity:
    """Detects indicator type from a string and produces canonical graph & event queries.

    Args:
        value: String identifier (e.g. IP, file hash, email, hostname, domain, username).
        hint: Optional known type. Accepts either our own ``EntityType`` values or
            SOAR involved-entity type strings (e.g. ``"FILEHASH"``, ``"PHONENUMBER"``,
            ``"USERUNIQNAME"``). When the hint maps to a concrete builder it takes
            precedence over the regex heuristics. Unknown/unmappable hints fall back
            to regex detection.

    Returns:
        DetectedEntity containing the typed entity, graph query, event query, and IoC valueType.
    """
    val = value.strip()
    if not val:
        raise ValueError("Cannot detect entity type from an empty string.")

    if hint is not None:
        if isinstance(hint, EntityType):
            builder = _BUILDERS.get(hint)
            if builder is not None:
                return builder(val)
        elif str(hint).strip():
            norm = _normalise_hint(str(hint))

            # File hashes: SOAR only says "FILEHASH"; pick MD5/SHA1/SHA256 by length.
            if norm in ("FILEHASH", "HASH"):
                hashed = _resolve_hash(val)
                if hashed is not None:
                    return hashed
                return _detect_by_regex(val)

            multi = _SOAR_MULTI.get(norm)
            if multi is not None:
                return multi(val)

            mapped = _SOAR_TYPE_MAP.get(norm)
            if mapped is None:
                try:
                    mapped = coerce_entity_type(hint)
                except (ValueError, TypeError):
                    mapped = None

            if mapped is not None:
                builder = _BUILDERS.get(mapped)
                if builder is not None:
                    return builder(val)
            # Unknown hint (e.g. PHONENUMBER with no graph field) -> regex fallback.

    return _detect_by_regex(val)
