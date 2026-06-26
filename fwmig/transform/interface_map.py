"""
Interface- and zone-name refactoring across platforms.

Interface identifiers differ between firewall platforms:
  - Cisco ASA/FWSM/FTD : rules/NAT/access-group/routes reference the logical
                         'nameif' (e.g. "outside", "inside", "dmz").
  - FortiGate          : policies reference an interface name (e.g. "port1") OR
                         a zone name ('config system zone' groups interfaces).
  - Palo Alto PAN-OS   : security rules reference zone names (e.g. "trust"),
                         and a zone groups one or more layer3 interfaces.

Zones and interfaces have a cardinality mismatch: one zone may contain several
interfaces. Migrating a zone-based source (FortiGate/PAN) to an interface-based
target (Cisco ASA) therefore has to *resolve* each zone to interface(s):

  - A target name may be a comma-separated list ("inside1,inside2") meaning the
    source zone expands to multiple target interfaces. Rule zone references are
    flattened to that list; ACL bindings are duplicated, one per member; routes
    bind to the first member (a static route can't span interfaces) with a
    warning.
  - Because Cisco ACLs bind to an interface rather than carrying a zone, an
    ingress 'access-group' binding is synthesised from each rule's source zone
    when the target is Cisco and the source had none.

This module collects the source config's interface/zone identities, suggests
target names per the destination platform's convention, and applies a
user-editable mapping across the whole config prior to generation.
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass, field
from typing import Dict, List

from ..models.common import FirewallConfig, Platform, Interface, AclBinding


CISCO_TARGETS = frozenset({Platform.CISCO_ASA, Platform.CISCO_FWSM, Platform.CISCO_FTD})


@dataclass
class IfaceIdentity:
    """One rule-facing interface/zone identity in a source config."""
    key: str                                   # the rule-facing name
    physical: str = ""                         # physical interface name, if any
    logical: str = ""                          # nameif / zone label, if any
    kind: str = "interface"                    # "interface" | "zone"
    members: List[str] = field(default_factory=list)   # member keys (zones only)


def source_key(platform: Platform, iface: Interface) -> str:
    """Return the rule-facing interface identifier for `iface` on its source platform."""
    if platform == Platform.FORTIGATE:
        return iface.name or iface.nameif or iface.zone or ""
    if platform == Platform.PALO_ALTO:
        return iface.zone or iface.name or iface.nameif or ""
    # Cisco ASA / FWSM / FTD
    return iface.nameif or iface.name or ""


def _split(val: str) -> List[str]:
    """Split a comma-separated interface/zone field into meaningful tokens."""
    if not val:
        return []
    return [t.strip() for t in val.split(",") if t.strip() and t.strip().lower() != "any"]


def _referenced_names(cfg: FirewallConfig) -> List[str]:
    """Every interface/zone name referenced by rules, NAT, bindings or routes."""
    names: List[str] = []
    for r in cfg.access_rules:
        names += _split(r.src_zone) + _split(r.dst_zone)
    for n in cfg.nat_rules:
        names += _split(n.src_interface or "") + _split(n.dst_interface or "")
    for b in cfg.acl_bindings:
        if b.interface:
            names.append(b.interface)
    for rt in cfg.routes:
        if rt.interface:
            names.append(rt.interface)
    return names


def collect_interface_names(cfg: FirewallConfig) -> List[IfaceIdentity]:
    """
    Ordered, de-duplicated list of interface/zone identities in the source config.

    Order: identities defined by an Interface object first, then zones (with
    their member interfaces), then identities only referenced by rules/NAT/etc.
    """
    seen: Dict[str, IfaceIdentity] = {}
    order: List[str] = []

    for iface in cfg.interfaces:
        key = source_key(cfg.platform, iface)
        if not key or key in seen:
            continue
        seen[key] = IfaceIdentity(
            key=key,
            physical=iface.name or "",
            logical=iface.nameif or iface.zone or "",
        )
        order.append(key)

    for zone in cfg.zones:
        if not zone.name:
            continue
        if zone.name in seen:
            # An interface and a zone share a name — promote it to a zone.
            ident = seen[zone.name]
            ident.kind = "zone"
            ident.members = list(zone.interfaces)
            continue
        seen[zone.name] = IfaceIdentity(
            key=zone.name,
            logical="zone",
            kind="zone",
            members=list(zone.interfaces),
        )
        order.append(zone.name)

    for ref in _referenced_names(cfg):
        if ref and ref not in seen:
            seen[ref] = IfaceIdentity(key=ref)
            order.append(ref)

    return [seen[k] for k in order]


def suggest_target_names(
    identities: List[IfaceIdentity], target: Platform
) -> Dict[str, str]:
    """
    Suggest a target name for each source identity, following the destination
    platform's naming convention:

      - FortiGate target : interfaces get sequential 'portN' names; zones keep
        their name (FortiOS has zones).
      - PAN-OS target    : keep the name (an interface becomes a same-named zone;
        a source zone migrates as-is).
      - Cisco target     : keep the name. A zone defaults to a single nameif of
        the same name; the user can expand it to a comma-separated list of member
        interfaces (see apply_interface_mapping) when the zone spans several.
    """
    mapping: Dict[str, str] = {}
    if target == Platform.FORTIGATE:
        port = 1
        for idn in identities:
            if idn.kind == "zone":
                mapping[idn.key] = idn.key
            else:
                mapping[idn.key] = f"port{port}"
                port += 1
    else:
        for idn in identities:
            mapping[idn.key] = idn.key
    return mapping


def apply_interface_mapping(
    cfg: FirewallConfig, mapping: Dict[str, str], target: Platform
) -> FirewallConfig:
    """
    Return a deep copy of `cfg` with interface/zone identifiers renamed per
    `mapping`. A mapping value may be a comma-separated list, meaning the source
    identity (typically a zone) expands to several target interfaces.

    Applied to every rule-facing reference (rule zones, NAT interfaces, ACL
    bindings, routes), to zone definitions, and to the Interface objects using
    the field the `target` generator emits as the interface identifier:
      - FortiGate target -> Interface.name
      - PAN-OS target    -> Interface.zone
      - Cisco target     -> Interface.nameif (physical Interface.name preserved)

    The original `cfg` is not mutated.
    """
    if not mapping:
        return cfg

    cfg = copy.deepcopy(cfg)
    cisco = target in CISCO_TARGETS

    def expand(name: str) -> List[str]:
        """Mapped target tokens for a single source name (may be several)."""
        val = mapping.get(name, name)
        toks = [t.strip() for t in val.split(",") if t.strip()]
        return toks or [val]

    def mp_one(name: str) -> str:
        """Mapped target for a field that can only hold one value (take first)."""
        return expand(name)[0]

    def mp_csv(val: str) -> str:
        """Map every token in a comma-separated field, flattening expansions."""
        if not val:
            return val
        out: List[str] = []
        for tok in val.split(","):
            t = tok.strip()
            if not t:
                continue
            if t.lower() == "any":
                out.append(t)
            else:
                out.extend(expand(t))
        return ",".join(out)

    # Cisco ACLs bind to interfaces, not zones. When migrating a zone-based
    # source to a Cisco target with no explicit bindings, synthesise an ingress
    # 'access-group' from each rule's source zone before renaming, so the zone's
    # mapping/expansion flows through to the binding(s).
    if cisco and not cfg.acl_bindings:
        seen_bind = set()
        for r in cfg.access_rules:
            if not r.src_zone:
                continue
            acl = r.acl_name or "MIGRATED_ACL"
            for tok in _split(r.src_zone):
                if (acl, tok) not in seen_bind:
                    seen_bind.add((acl, tok))
                    cfg.acl_bindings.append(
                        AclBinding(acl_name=acl, interface=tok, direction="in")
                    )

    # Rule-facing zone references
    for r in cfg.access_rules:
        if cisco:
            # The zone intent is now carried by the synthesised ACL binding;
            # Cisco extended ACEs don't encode zones.
            r.src_zone = None
            r.dst_zone = None
        else:
            if r.src_zone:
                r.src_zone = mp_csv(r.src_zone)
            if r.dst_zone:
                r.dst_zone = mp_csv(r.dst_zone)

    # NAT interfaces
    for n in cfg.nat_rules:
        if n.src_interface:
            n.src_interface = mp_csv(n.src_interface)
        if n.dst_interface:
            n.dst_interface = mp_csv(n.dst_interface)

    # ACL bindings — duplicate per member when a zone expands to several interfaces
    new_bindings: List[AclBinding] = []
    for b in cfg.acl_bindings:
        if b.interface:
            for tgt in expand(b.interface):
                new_bindings.append(dataclasses.replace(b, interface=tgt))
        else:
            new_bindings.append(b)
    cfg.acl_bindings = new_bindings

    # Routes — a static route binds to one interface; use the first member
    for rt in cfg.routes:
        if rt.interface:
            targets = expand(rt.interface)
            original = rt.interface
            rt.interface = targets[0]
            if len(targets) > 1:
                cfg.parse_warnings.append(
                    f"Route to {rt.network}/{rt.mask} referenced '{original}', which "
                    f"maps to multiple interfaces {targets}; bound to first "
                    f"('{targets[0]}') — review the others manually."
                )

    # Zone definitions — rename the zone and its members
    for z in cfg.zones:
        members: List[str] = []
        for m in z.interfaces:
            members.extend(expand(m))
        z.interfaces = members
        if z.name:
            z.name = mp_one(z.name)

    # Interface objects — rename the field the target generator emits
    for iface in cfg.interfaces:
        key = source_key(cfg.platform, iface)
        if key not in mapping:
            continue
        new = mp_one(key)
        if target == Platform.FORTIGATE:
            iface.name = new
        elif target == Platform.PALO_ALTO:
            iface.zone = new
        else:  # Cisco target — keep physical name, rename logical nameif
            iface.nameif = new

    return cfg
