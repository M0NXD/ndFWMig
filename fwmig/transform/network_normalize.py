"""
Inline address-literal materialisation.

Cisco ACLs and network object-groups embed raw addresses directly:

    access-list IN extended permit ip 10.0.0.0/24 host 192.168.1.5
    object-group network SERVERS
     network-object host 10.1.1.10
     network-object 10.1.2.0 255.255.255.0

The ASA parser keeps these as literal values on ``AccessRule.src_address`` /
``dst_address`` and on ``ObjectGroup.members`` (``host:10.1.1.10``, ``10.1.2.0/24``).
The ASA generator emits them natively, but zone-based targets (PAN-OS, FortiGate)
can only reference address objects by *name* — emitting a bare CIDR there yields
an invalid reference to a non-existent object.

``materialize_address_literals`` rewrites every inline address literal (in rule
src/dst lists and in network object-group members) into a synthesised
``NetworkObject`` and replaces the literal with that object's name. Identical
literals are de-duplicated so one object is reused. Plain name references,
``any``/``all``, ``interface:`` and PAN-OS ``dag:`` members are left untouched.
"""

from __future__ import annotations

import copy
import re
from typing import List, Set, Tuple

from ..models.common import FirewallConfig, NetworkObject, ObjectType
from ..util.netaddr import mask_to_prefix


_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", name)


def _is_v6(value: str) -> bool:
    return ":" in value


def _canon(value: str) -> str:
    """Canonical comparison form for an address value.

    Collapses the equivalent spellings of the same network so an inline literal
    can be matched against an already-defined object: 'addr mask' -> 'addr/plen',
    'addr/plen' kept as-is, bare host kept as-is.
    """
    value = value.strip()
    if " " in value:                      # "10.1.2.0 255.255.255.0"
        addr, mask = value.split(None, 1)
        if ":" not in addr and mask.count(".") == 3:
            return f"{addr}/{mask_to_prefix(mask)}"
    return value


def _canon_keys(obj: NetworkObject) -> Set[str]:
    """Every canonical key an existing object can satisfy as a literal target."""
    if obj.obj_type == ObjectType.HOST:
        v = obj.value.strip()
        return {v, f"{v}/32"}             # a /32 literal and a bare host are the same
    if obj.obj_type == ObjectType.NETWORK:
        return {_canon(obj.value)}
    return set()


def _is_literal(tok: str) -> bool:
    """True if `tok` is a raw address literal rather than a name reference."""
    if not tok or tok in ("any", "any4", "any6", "all"):
        return False
    if tok.startswith("interface:"):
        return False
    if _IPV4_RE.match(tok):
        return True
    return _is_v6(tok)


def materialize_address_literals(cfg: FirewallConfig) -> Tuple[FirewallConfig, List[str]]:
    """Return a deep-copied config with inline address literals replaced by
    references to synthesised NetworkObjects, plus migration warnings."""
    cfg = copy.deepcopy(cfg)
    warnings: List[str] = []

    used_names = {o.name for o in cfg.network_objects}
    used_names |= {g.name for g in cfg.object_groups}

    def _unique(base: str) -> str:
        base = _safe(base) or "net"
        name = base
        n = 2
        while name in used_names:
            name = f"{base}_{n}"
            n += 1
        used_names.add(name)
        return name

    # Canonical-value -> object name, seeded with the already-defined objects so
    # a literal that matches an existing object reuses it instead of synthesising
    # a redundant 'net_*' copy.
    by_canon: dict = {}
    for o in cfg.network_objects:
        for k in _canon_keys(o):
            by_canon.setdefault(k, o.name)

    synthesised: List[NetworkObject] = []

    def _ensure(value: str) -> str:
        key = _canon(value)
        existing = by_canon.get(key)
        if existing is not None:
            return existing
        obj_type = ObjectType.NETWORK if "/" in value else ObjectType.HOST
        obj = NetworkObject(
            name=_unique(f"net_{value}"),
            obj_type=obj_type,
            value=value,
            description="Auto-generated from inline address literal",
        )
        synthesised.append(obj)
        # Register every canonical spelling so later literals (and a bare host vs
        # /32 form) reuse this new object too.
        for k in _canon_keys(obj):
            by_canon.setdefault(k, obj.name)
        return obj.name

    count = 0

    # Network object-group members.
    for grp in cfg.object_groups:
        if grp.group_type != "network":
            continue
        new_members: List[str] = []
        for m in grp.members:
            if m.startswith("group:"):
                new_members.append(m[6:])           # nested group -> bare name
            elif m.startswith("dag:"):
                new_members.append(m)               # PAN-OS dynamic filter — leave
            elif m.startswith("host:"):
                new_members.append(_ensure(m[5:])); count += 1
            elif _is_literal(m):
                new_members.append(_ensure(m)); count += 1
            else:
                new_members.append(m)               # already a name reference
        grp.members = new_members

    # Rule source / destination address literals.
    for rule in cfg.access_rules:
        for attr in ("src_address", "dst_address"):
            values = getattr(rule, attr)
            if not values:
                continue
            out: List[str] = []
            for a in values:
                if a.startswith("host:"):
                    out.append(_ensure(a[5:])); count += 1
                elif _is_literal(a):
                    out.append(_ensure(a)); count += 1
                else:
                    out.append(a)
            setattr(rule, attr, out)

    cfg.network_objects.extend(synthesised)
    if count:
        warnings.append(
            f"{count} inline address literal(s) rewritten to named address "
            f"objects ({len(synthesised)} newly synthesised, the rest reusing "
            "existing/shared objects) — review generated object names."
        )
    return cfg, warnings
