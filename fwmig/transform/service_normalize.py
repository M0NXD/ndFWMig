"""
Service object-group normalisation.

Cisco ASA/FWSM/FTD `object-group service` blocks can carry *inline* members:

    object-group service webports tcp
     port-object eq 80
     port-object range 8000 8080
    object-group service mixed
     service-object tcp destination eq 443
     service-object udp destination eq 53
     group-object webports

The ASA parser stores these as internal IR tokens on the group's member list:
`proto:tcp`, `port:eq 80`, `tcp destination eq 443`, `group:webports`, … The ASA
generator understands those tokens and round-trips them losslessly, but
zone-based generators (PAN-OS, FortiGate) reference group members purely by
*name*, so emitting the raw tokens produces garbage like
`<member>port:eq 80</member>`.

`normalize_service_groups` rewrites such groups into clean name references,
synthesising standalone `ServiceObject`s for every inline definition so the
zone-based generators have real objects to point at. It is a no-op for groups
that already contain only named references (the typical PAN/FortiGate source
case).
"""

from __future__ import annotations

import copy
import re
from typing import List, Optional, Tuple

from ..models.common import FirewallConfig, ServiceObject
from ..parsers.cisco_asa import _parse_port_spec, _port_str


def _safe(name: str) -> str:
    """Sanitise a synthesised object name to a portable character set."""
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", name)


def _protos_for(proto: Optional[str]) -> List[str]:
    """Expand a group/service protocol into concrete single protocols.

    Port-objects require a protocol; ASA allows the group-level qualifier to be
    `tcp`, `udp` or `tcp-udp`. `tcp-udp` has no single-object representation on
    PAN-OS, so it expands to two objects.
    """
    if not proto:
        return ["tcp"]
    p = proto.lower()
    if p in ("tcp-udp", "tcpudp"):
        return ["tcp", "udp"]
    return [p]


def _ports_from_spec(spec: str) -> Optional[str]:
    """Convert a port-object spec ('eq 80', 'range 1024 2048', 'lt 1024') to an
    IR port string ('80', '1024-2048', '1-1023'). Returns None if unparseable."""
    tokens = spec.split()
    if not tokens:
        return None
    port, _ = _parse_port_spec(tokens, 0)
    return port


def _parse_service_object(spec: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Parse an inline `service-object` body.

    Examples:
        'tcp destination eq 80'        -> ('tcp', None, '80')
        'udp source eq 53'             -> ('udp', '53', None)
        'tcp source eq 1024 destination eq 80' -> ('tcp', '1024', '80')
        'icmp'                         -> ('icmp', None, None)

    Returns (protocol, src_port, dst_port).
    """
    tokens = spec.split()
    proto = tokens[0].lower() if tokens else "ip"
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    i = 1
    while i < len(tokens):
        kw = tokens[i].lower()
        if kw == "source":
            src_port, i = _parse_port_spec(tokens, i + 1)
        elif kw == "destination":
            dst_port, i = _parse_port_spec(tokens, i + 1)
        else:
            i += 1
    return proto, src_port, dst_port


def normalize_service_groups(cfg: FirewallConfig) -> Tuple[FirewallConfig, List[str]]:
    """Return a deep-copied config whose service object-groups reference only
    named service objects, plus a list of migration warnings.

    Inline port-objects and service-objects are materialised as new
    `ServiceObject`s (appended to ``cfg.service_objects``) and the group members
    are replaced with the synthesised names.
    """
    cfg = copy.deepcopy(cfg)
    warnings: List[str] = []

    # Name space we must avoid colliding with when synthesising objects.
    used_names = {s.name for s in cfg.service_objects}
    used_names |= {g.name for g in cfg.object_groups}

    # Pre-existing service object/group names. A member matching one of these is
    # a reference (even if it looks like a bare protocol token), not an inline
    # definition to synthesise.
    known_refs = frozenset(used_names)

    def _unique(base: str) -> str:
        base = _safe(base) or "svc"
        name = base
        n = 2
        while name in used_names:
            name = f"{base}_{n}"
            n += 1
        used_names.add(name)
        return name

    synthesised: List[ServiceObject] = []

    for grp in cfg.object_groups:
        if grp.group_type != "service":
            continue

        group_proto: Optional[str] = None
        cleaned: List[str] = []
        inline_count = 0

        for member in grp.members:
            # Group-level protocol qualifier (consumed, not a real member).
            if member.startswith("proto:"):
                group_proto = member[6:]
                continue

            # Nested service-group reference.
            if member.startswith("group:"):
                cleaned.append(member[6:])
                continue

            # Port-object: inherits the group protocol.
            if member.startswith("port:"):
                spec = member[5:]
                dst_port = _ports_from_spec(spec)
                for proto in _protos_for(group_proto):
                    label = dst_port or "any"
                    obj = ServiceObject(
                        name=_unique(f"{grp.name}_{proto}_{label}"),
                        protocol=proto,
                        dst_port=dst_port,
                        description=f"Auto-generated from {grp.name} port-object '{spec}'",
                    )
                    synthesised.append(obj)
                    cleaned.append(obj.name)
                inline_count += 1
                continue

            # `service-object object NAME` -> a plain named reference.
            if member.lower().startswith("object "):
                cleaned.append(member.split(None, 1)[1])
                continue

            # A member that names an existing service object/group is a
            # reference, not an inline definition (guards against a service
            # legitimately named e.g. "tcp").
            if member in known_refs:
                cleaned.append(member)
                continue

            # Inline `service-object <proto> [source ...] [destination ...]`.
            # Heuristic: a member carrying a protocol keyword and/or port
            # operators rather than a bare name.
            tokens = member.split()
            looks_inline = len(tokens) > 1 or (
                tokens and tokens[0].lower() in (
                    "tcp", "udp", "tcp-udp", "icmp", "icmp6", "ip",
                    "esp", "ah", "gre", "sctp",
                )
            )
            if looks_inline:
                base_proto, src_port, dst_port = _parse_service_object(member)
                for proto in _protos_for(base_proto):
                    label = dst_port or src_port or "any"
                    obj = ServiceObject(
                        name=_unique(f"{grp.name}_{proto}_{label}"),
                        protocol=proto,
                        src_port=src_port,
                        dst_port=dst_port,
                        description=f"Auto-generated from {grp.name} service-object '{member}'",
                    )
                    synthesised.append(obj)
                    cleaned.append(obj.name)
                inline_count += 1
                continue

            # Already a clean named reference.
            cleaned.append(member)

        # Always write back the cleaned members: even when nothing was
        # synthesised, this strips internal prefixes (e.g. 'group:X', 'object X')
        # so zone-based generators emit bare name references.
        grp.members = cleaned
        if inline_count:
            warnings.append(
                f"Service group '{grp.name}': {inline_count} inline member(s) "
                f"expanded into synthesised service object(s) - review generated "
                f"object names/ports."
            )

    cfg.service_objects.extend(synthesised)
    return cfg, warnings


# Protocols whose ACE service tokens carry (or imply) ports and so can be
# represented as a standalone ServiceObject on zone-based targets.
_PORTED_PROTOS = frozenset({"tcp", "udp", "sctp", "tcp-udp", "tcpudp"})
# Service tokens that already denote "all services" — left untouched.
_ANY_SERVICE = frozenset({"any", "ANY", "ALL", "all", "application-default"})


def _parse_combined_service_token(tok: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Split a Cisco combined ACE service token into (proto, src_port, dst_port).

    Tokens are produced by the ASA ACL parser, e.g.
        'tcp:dst:443'              -> ('tcp', None, '443')
        'tcp:src:1024:dst:80'      -> ('tcp', '1024', '80')
        'udp:dst:8000-8080'        -> ('udp', None, '8000-8080')
        'tcp'                      -> ('tcp', None, None)   (bare protocol)
    """
    parts = tok.split(":")
    proto: Optional[str] = None
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    idx = 0
    if parts and parts[0].lower() not in ("src", "dst"):
        proto = parts[0].lower()
        idx = 1
    while idx < len(parts) - 1:
        direction = parts[idx].lower()
        if direction == "src":
            src_port = parts[idx + 1]
        elif direction == "dst":
            dst_port = parts[idx + 1]
        idx += 2
    return proto, src_port, dst_port


def normalize_inline_services(cfg: FirewallConfig) -> Tuple[FirewallConfig, List[str]]:
    """Materialise inline ACE service tokens into named ServiceObjects.

    Cisco ACLs embed ports directly in the rule (``permit tcp any any eq 443``),
    which the parser stores as a combined token like ``tcp:dst:443`` on
    ``AccessRule.service``. Zone-based generators (PAN-OS, FortiGate) can only
    reference services by *name*, so without this they drop the port and widen
    the rule to all services. This rewrites every ported-protocol token into a
    synthesised ServiceObject and replaces it with that object's name; identical
    specs are de-duplicated so one object is reused. Bare non-ported protocols
    (icmp/ip/esp/…) and plain name references are left for the generator to map.
    """
    cfg = copy.deepcopy(cfg)
    warnings: List[str] = []

    used_names = {s.name for s in cfg.service_objects}
    used_names |= {g.name for g in cfg.object_groups}
    known_refs = frozenset(used_names)

    def _unique(base: str) -> str:
        base = _safe(base) or "svc"
        name = base
        n = 2
        while name in used_names:
            name = f"{base}_{n}"
            n += 1
        used_names.add(name)
        return name

    by_spec: dict = {}            # (proto, src, dst) -> [names]
    synthesised: List[ServiceObject] = []

    def _ensure(proto: str, src: Optional[str], dst: Optional[str]) -> List[str]:
        key = (proto, src, dst)
        if key in by_spec:
            return by_spec[key]
        names: List[str] = []
        for p in _protos_for(proto):
            label = dst or src or "all"
            obj = ServiceObject(
                name=_unique(f"svc_{p}_{label}"),
                protocol=p,
                src_port=src,
                dst_port=dst,
                description="Auto-generated from inline ACL service",
            )
            synthesised.append(obj)
            names.append(obj.name)
        by_spec[key] = names
        return names

    count = 0
    for rule in cfg.access_rules:
        if not rule.service:
            continue
        new_tokens: List[str] = []
        for tok in rule.service:
            # Keep "any"/named-reference tokens (a bare name with no port info).
            if tok in _ANY_SERVICE or (":" not in tok and tok in known_refs):
                new_tokens.append(tok)
                continue
            proto, src, dst = _parse_combined_service_token(tok)
            if proto in _PORTED_PROTOS:
                new_tokens.extend(_ensure(proto, src, dst))
                count += 1
            else:
                # Bare icmp/ip/esp/… or an unknown name — leave for the generator.
                new_tokens.append(tok)
        rule.service = new_tokens

    cfg.service_objects.extend(synthesised)
    if count:
        warnings.append(
            f"{count} inline ACL service reference(s) expanded into synthesised "
            "service object(s) — review generated object names/ports."
        )
    return cfg, warnings
