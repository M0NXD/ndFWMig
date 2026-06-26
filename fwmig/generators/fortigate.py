"""Generate FortiGate FortiOS configurations."""

from __future__ import annotations
from typing import List, Dict
from .base import BaseGenerator
from ..models.common import (
    FirewallConfig, NetworkObject, ServiceObject, ObjectGroup,
    AccessRule, NATRule, Interface, Route, ObjectType, NATType,
)
from ..transform import (
    normalize_service_groups, normalize_inline_services, materialize_address_literals,
)


class FortiGateGenerator(BaseGenerator):
    # Bare protocol tokens (no port) map to FortiOS built-in service objects.
    _PROTO_SVC = {
        "tcp": "ALL_TCP", "udp": "ALL_UDP", "sctp": "ALL_SCTP",
        "icmp": "ALL_ICMP", "icmp6": "ALL_ICMP6", "ip": "ALL",
        "gre": "GRE", "esp": "ESP", "ah": "AH", "ospf": "OSPF",
    }

    def generate(self, cfg: FirewallConfig) -> str:
        self._warnings.clear()
        # Zone-based targets reference objects by name only, so expand every
        # Cisco-style inline construct (service-group members, inline ACE ports,
        # inline address literals) into real, named objects first.
        cfg, w1 = normalize_service_groups(cfg)
        cfg, w2 = normalize_inline_services(cfg)
        cfg, w3 = materialize_address_literals(cfg)
        self._warnings.extend(w1 + w2 + w3)
        blocks: List[str] = []

        blocks.append(f"# Generated for FortiGate FortiOS {self.version}")
        blocks.append(f"# Source: {cfg.platform.value} {cfg.version}")

        # Version-specific header notes
        if self.version == "8.0":
            blocks.append("# NOTE: FortiOS 8.0 - IKE DH group defaults changed to group 20/21.")
            blocks.append("# NOTE: FortiOS 8.0 - 'config system sdwan' is the SD-WAN block (not virtual-wan-link).")
            blocks.append("# NOTE: FortiOS 8.0 - CASB and AI Fabric features require additional licensing.")
        elif self.version == "7.6":
            blocks.append("# NOTE: FortiOS 7.6 - 'set casb-profile' and 'set ztna-device-ownership' available in policy.")
            self._warn("FortiOS 7.6: CASB profile and ZTNA device ownership fields not emitted - configure manually if needed.")
        blocks.append("")

        # Hostname
        if cfg.hostname:
            blocks.append("config system global")
            blocks.append(f'    set hostname "{cfg.hostname}"')
            blocks.append("end")
            blocks.append("")

        # Interfaces
        if cfg.interfaces:
            blocks.append("config system interface")
            for iface in cfg.interfaces:
                blocks.extend(self._gen_interface(iface))
            blocks.append("end")
            blocks.append("")

        # Zones (group interfaces)
        zones = [z for z in cfg.zones if z.name]
        if zones:
            blocks.append("config system zone")
            for zone in zones:
                blocks.append(f'    edit "{zone.name}"')
                if zone.interfaces:
                    members = " ".join(f'"{m}"' for m in zone.interfaces)
                    blocks.append(f'        set interface {members}')
                blocks.append("    next")
            blocks.append("end")
            blocks.append("")

        # IPv6 is configured in separate FortiOS blocks (address6 / addrgrp6 /
        # static6 / srcaddr6). Work out which objects/groups are IPv6 up front.
        v6_obj_names = {o.name for o in cfg.network_objects if self._is_ipv6(o.value)}

        def _group_is_v6(g: ObjectGroup) -> bool:
            return any(self._is_ipv6(m) or m in v6_obj_names for m in g.members)

        net_groups = [g for g in cfg.object_groups if g.group_type == "network"]
        v6_grp_names = {g.name for g in net_groups if _group_is_v6(g)}
        v6_refs = v6_obj_names | v6_grp_names

        # Static routes (split IPv4 / IPv6)
        v4_routes = [r for r in cfg.routes if not self._is_ipv6(r.network)]
        v6_routes = [r for r in cfg.routes if self._is_ipv6(r.network)]
        if v4_routes:
            blocks.append("config router static")
            for i, route in enumerate(v4_routes, 1):
                blocks.extend(self._gen_route(i, route))
            blocks.append("end")
            blocks.append("")
        if v6_routes:
            blocks.append("config router static6")
            for i, route in enumerate(v6_routes, 1):
                blocks.extend(self._gen_route(i, route))
            blocks.append("end")
            blocks.append("")

        # Firewall addresses (split IPv4 / IPv6)
        v4_objs = [o for o in cfg.network_objects if not self._is_ipv6(o.value)]
        v6_objs = [o for o in cfg.network_objects if self._is_ipv6(o.value)]
        if v4_objs:
            blocks.append("config firewall address")
            for obj in v4_objs:
                blocks.extend(self._gen_address(obj))
            blocks.append("end")
            blocks.append("")
        if v6_objs:
            blocks.append("config firewall address6")
            for obj in v6_objs:
                blocks.extend(self._gen_address6(obj))
            blocks.append("end")
            blocks.append("")

        # Address groups (split IPv4 / IPv6)
        v4_groups = [g for g in net_groups if g.name not in v6_grp_names]
        v6_groups = [g for g in net_groups if g.name in v6_grp_names]
        if v4_groups:
            blocks.append("config firewall addrgrp")
            for grp in v4_groups:
                blocks.extend(self._gen_addrgrp(grp))
            blocks.append("end")
            blocks.append("")
        if v6_groups:
            blocks.append("config firewall addrgrp6")
            for grp in v6_groups:
                blocks.extend(self._gen_addrgrp(grp))
            blocks.append("end")
            blocks.append("")

        # Service custom
        if cfg.service_objects:
            blocks.append("config firewall service custom")
            for svc in cfg.service_objects:
                blocks.extend(self._gen_service(svc))
            blocks.append("end")
            blocks.append("")

        # Service groups
        svc_groups = [g for g in cfg.object_groups if g.group_type == "service"]
        if svc_groups:
            blocks.append("config firewall service group")
            for grp in svc_groups:
                blocks.extend(self._gen_service_group(grp))
            blocks.append("end")
            blocks.append("")

        # Policies
        if cfg.access_rules:
            blocks.append("config firewall policy")
            for i, rule in enumerate(cfg.access_rules, 1):
                blocks.extend(self._gen_policy(i, rule, cfg, v6_refs))
            blocks.append("end")
            blocks.append("")

        # VIPs (DNAT)
        static_nats = [n for n in cfg.nat_rules if n.nat_type == NATType.STATIC and n.translated_dst]
        if static_nats:
            blocks.append("config firewall vip")
            for rule in static_nats:
                blocks.extend(self._gen_vip(rule))
            blocks.append("end")
            blocks.append("")

        # IP Pools (PAT/SNAT). Interface PAT (translate to the egress interface
        # address) has no ippool in FortiOS — it is enabled per-policy via
        # 'set nat enable', so exclude those and warn instead of emitting a
        # bogus 'set startip interface'.
        def _is_iface_pat(n: NATRule) -> bool:
            ts = (n.translated_src or "").lower()
            return ts == "interface" or ts.startswith("interface:")

        pat_nats = [n for n in cfg.nat_rules
                    if n.nat_type in (NATType.PAT, NATType.DYNAMIC)
                    and n.translated_src and not _is_iface_pat(n)]
        iface_pat = [n for n in cfg.nat_rules
                     if n.nat_type == NATType.PAT and _is_iface_pat(n)]
        if iface_pat:
            self._warn(
                f"{len(iface_pat)} interface-PAT rule(s) (dynamic source to egress "
                "interface) — enable 'set nat enable' on the matching FortiGate "
                "policy; no ippool emitted."
            )
        if pat_nats:
            blocks.append("config firewall ippool")
            for rule in pat_nats:
                blocks.extend(self._gen_ippool(rule))
            blocks.append("end")
            blocks.append("")

        # Migration warnings
        for w in cfg.parse_warnings + self._warnings:
            blocks.append(f"# WARNING: {w}")

        return "\n".join(blocks)

    # ------------------------------------------------------------------ INTERFACE
    def _gen_interface(self, iface: Interface) -> List[str]:
        lines = [f'    edit "{iface.name}"']
        if iface.nameif or iface.description:
            alias = iface.nameif or iface.description
            lines.append(f'        set alias "{alias}"')
        if iface.ip_address:
            mask = iface.subnet_mask or (
                self._prefix_to_mask(iface.prefix_len) if iface.prefix_len else "255.255.255.0"
            )
            lines.append(f'        set ip {iface.ip_address} {mask}')
        if iface.description:
            lines.append(f'        set description "{iface.description}"')
        lines.append(f'        set status {"up" if iface.enabled else "down"}')
        if iface.vlan:
            lines.append(f'        set vlanid {iface.vlan}')
        if iface.mtu:
            lines.append(f'        set mtu {iface.mtu}')
        lines.append("    next")
        return lines

    # ------------------------------------------------------------------ ROUTE
    def _gen_route(self, idx: int, route: Route) -> List[str]:
        mask = route.mask
        if "." in mask:
            plen = self._mask_to_prefix(mask)
            subnet = f"{route.network}/{plen}"
        else:
            subnet = f"{route.network}/{mask}"

        lines = [f"    edit {idx}"]
        lines.append(f'        set dst {subnet}')
        lines.append(f'        set gateway {route.next_hop}')
        if route.interface:
            lines.append(f'        set device "{route.interface}"')
        lines.append(f'        set distance {route.metric}')
        if route.description:
            lines.append(f'        set comment "{route.description}"')
        lines.append("    next")
        return lines

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """True if an IR address/network value is IPv6.

        Strips IR token prefixes that themselves contain a colon
        ('host:', 'group:', 'dag:', 'interface:') so they aren't mistaken for
        the colons in an IPv6 literal.
        """
        if not value:
            return False
        for pfx in ("host:", "group:", "dag:", "interface:"):
            if value.startswith(pfx):
                value = value[len(pfx):]
                break
        return ":" in value

    # ------------------------------------------------------------------ ADDRESS (IPv4)
    def _gen_address(self, obj: NetworkObject) -> List[str]:
        lines = [f'    edit "{obj.name}"']
        if obj.description:
            lines.append(f'        set comment "{obj.description}"')
        if obj.obj_type == ObjectType.HOST:
            mask = self._prefix_to_mask(32)
            lines.append(f'        set type ipmask')
            lines.append(f'        set subnet {obj.value} {mask}')
        elif obj.obj_type == ObjectType.NETWORK:
            val = obj.value
            if "/" in val:
                addr, plen = val.split("/", 1)
                mask = self._prefix_to_mask(int(plen))
                val = f"{addr} {mask}"
            lines.append(f'        set type ipmask')
            lines.append(f'        set subnet {val}')
        elif obj.obj_type == ObjectType.RANGE:
            rng = obj.value.replace("-", " ", 1)
            parts = rng.split()
            lines.append(f'        set type iprange')
            if len(parts) >= 2:
                lines.append(f'        set start-ip {parts[0]}')
                lines.append(f'        set end-ip {parts[1]}')
        elif obj.obj_type == ObjectType.FQDN:
            lines.append(f'        set type fqdn')
            lines.append(f'        set fqdn "{obj.value}"')
        lines.append("    next")
        return lines

    # ------------------------------------------------------------------ ADDRESS (IPv6)
    def _gen_address6(self, obj: NetworkObject) -> List[str]:
        """Emit an IPv6 object for the 'config firewall address6' block."""
        lines = [f'    edit "{obj.name}"']
        if obj.description:
            lines.append(f'        set comment "{obj.description}"')
        if obj.obj_type == ObjectType.RANGE:
            rng = obj.value.replace("-", " ", 1)
            parts = rng.split()
            lines.append(f'        set type iprange')
            if len(parts) >= 2:
                lines.append(f'        set start-ip {parts[0]}')
                lines.append(f'        set end-ip {parts[1]}')
        elif obj.obj_type == ObjectType.FQDN:
            lines.append(f'        set type fqdn')
            lines.append(f'        set fqdn "{obj.value}"')
        else:
            # HOST or NETWORK - address6 uses CIDR prefix notation via 'set ip6'.
            val = obj.value if "/" in obj.value else f"{obj.value}/128"
            lines.append(f'        set type ipprefix')
            lines.append(f'        set ip6 {val}')
        lines.append("    next")
        return lines

    # ------------------------------------------------------------------ ADDRGRP
    def _gen_addrgrp(self, grp: ObjectGroup) -> List[str]:
        lines = [f'    edit "{grp.name}"']
        if grp.description:
            lines.append(f'        set comment "{grp.description}"')
        clean = [m.removeprefix("host:").removeprefix("group:").removeprefix("dag:")
                 for m in grp.members]
        member_str = " ".join(f'"{m}"' for m in clean)
        lines.append(f'        set member {member_str}')
        lines.append("    next")
        return lines

    # ------------------------------------------------------------------ SERVICE
    def _gen_service(self, svc: ServiceObject) -> List[str]:
        lines = [f'    edit "{svc.name}"']
        if svc.description:
            lines.append(f'        set comment "{svc.description}"')
        proto_map = {"tcp": "TCP", "udp": "UDP", "sctp": "SCTP",
                     "icmp": "ICMP", "icmp6": "ICMP6", "ip": "IP"}
        proto = proto_map.get(svc.protocol.lower(), "TCP")
        lines.append(f'        set protocol {proto}')
        if svc.protocol.lower() in ("tcp", "udp", "sctp"):
            dst = svc.dst_port or "1-65535"
            key = f"{svc.protocol.lower()}-portrange"
            # Only append the ':src' half when a source port is actually set;
            # FortiOS treats a bare range as 'any source port'.
            if svc.src_port:
                lines.append(f'        set {key} {dst}:{svc.src_port}')
            else:
                lines.append(f'        set {key} {dst}')
        elif svc.protocol.lower() in ("icmp", "icmp6") and svc.icmp_type is not None:
            lines.append(f'        set icmptype {svc.icmp_type}')
            if svc.icmp_code is not None:
                lines.append(f'        set icmpcode {svc.icmp_code}')
        lines.append("    next")
        return lines

    # ------------------------------------------------------------------ SERVICE GROUP
    def _gen_service_group(self, grp: ObjectGroup) -> List[str]:
        lines = [f'    edit "{grp.name}"']
        member_str = " ".join(f'"{m}"' for m in grp.members)
        lines.append(f'        set member {member_str}')
        lines.append("    next")
        return lines

    # ------------------------------------------------------------------ POLICY
    def _gen_policy(self, idx: int, rule: AccessRule, cfg: FirewallConfig,
                    v6_refs: frozenset = frozenset()) -> List[str]:
        lines = [f"    edit {idx}"]
        lines.append(f'        set name "{rule.name}"')

        src_iface, dst_iface = self._policy_interfaces(rule, cfg)

        def _intf_tokens(val: str) -> str:
            # A value may be a comma-separated list when a zone expanded to
            # several interfaces; FortiOS wants each as its own quoted token.
            parts = [p.strip() for p in val.split(",") if p.strip()] or [val]
            return " ".join(f'"{p}"' for p in parts)

        lines.append(f'        set srcintf {_intf_tokens(src_iface)}')
        lines.append(f'        set dstintf {_intf_tokens(dst_iface)}')

        def _members_str(addrs: List[str]) -> str:
            if not addrs or addrs in (["any"], ["all"]):
                return '"all"'
            return " ".join(f'"{a}"' for a in addrs)

        def _is_v6(a: str) -> bool:
            return self._is_ipv6(a) or a in v6_refs

        # FortiOS keeps IPv4 and IPv6 members in separate policy fields
        # (srcaddr/srcaddr6, dstaddr/dstaddr6).
        def _emit(field: str, addrs: List[str]) -> None:
            v4 = [a for a in addrs if not _is_v6(a)]
            v6 = [a for a in addrs if _is_v6(a)]
            # Emit the IPv4 field when there are v4 members, or when the rule has
            # no addresses at all (-> "all"); skip it for IPv6-only rules.
            if v4 or not v6:
                lines.append(f'        set {field} {_members_str(v4)}')
            if v6:
                lines.append(f'        set {field}6 {_members_str(v6)}')
                self._warn(
                    f"Rule '{rule.name}': IPv6 members routed to '{field}6' "
                    f"({', '.join(v6)}) - review IPv4/IPv6 policy split."
                )

        _emit("srcaddr", rule.src_address)
        _emit("dstaddr", rule.dst_address)

        action = "accept" if rule.action == "permit" else "deny"
        lines.append(f'        set action {action}')

        # Services. Inline ports were already materialised into named service
        # objects by normalize_inline_services; what remains is names, "any",
        # bare protocols (-> FortiOS built-ins), or an unresolved combined token.
        svcs = rule.service if rule.service else ["ALL"]
        clean_svcs = []
        for s in svcs:
            if s in ("any", "ANY", "ALL", "all"):
                clean_svcs.append("ALL")
            elif s.lower() in self._PROTO_SVC:
                clean_svcs.append(self._PROTO_SVC[s.lower()])
            elif ":" in s:
                self._warn(
                    f"Rule '{rule.name}': inline service '{s}' could not be resolved; "
                    "defaulted to ALL — verify manually."
                )
                clean_svcs.append("ALL")
            else:
                clean_svcs.append(s)
        lines.append(f'        set service {" ".join(f"{chr(34)}{s}{chr(34)}" for s in clean_svcs)}')

        lines.append(f'        set logtraffic {"all" if rule.logging else "disable"}')
        if not rule.enabled:
            lines.append('        set status disable')
        if rule.description:
            lines.append(f'        set comments "{rule.description}"')
        lines.append("    next")
        return lines

    @staticmethod
    def _policy_interfaces(rule: AccessRule, cfg: FirewallConfig) -> tuple:
        """
        Resolve (srcintf, dstintf) for a policy.

        Zone-based sources already carry src_zone/dst_zone. For Cisco sources the
        ACL->interface relationship lives in cfg.acl_bindings: an 'in' binding makes
        the bound interface the ingress (srcintf); 'out' makes it the egress (dstintf).
        """
        src = rule.src_zone
        dst = rule.dst_zone
        if not src and not dst and rule.acl_name:
            for b in cfg.acl_bindings:
                if b.acl_name == rule.acl_name and b.interface:
                    if b.direction == "in":
                        src = b.interface
                    elif b.direction == "out":
                        dst = b.interface
                    break
        return src or "any", dst or "any"

    # ------------------------------------------------------------------ VIP
    def _gen_vip(self, rule: NATRule) -> List[str]:
        lines = [f'    edit "{rule.name}"']
        if rule.description:
            lines.append(f'        set comment "{rule.description}"')
        iface = rule.dst_interface or "any"
        lines.append(f'        set extintf "{iface}"')
        if rule.original_dst:
            lines.append(f'        set extip {rule.original_dst}')
        if rule.translated_dst:
            lines.append(f'        set mappedip "{rule.translated_dst}"')
        if rule.original_service:
            lines.append(f'        set extport {rule.original_service}')
        if rule.translated_service:
            lines.append(f'        set mappedport {rule.translated_service}')
        lines.append("    next")
        return lines

    # ------------------------------------------------------------------ IPPOOL
    def _gen_ippool(self, rule: NATRule) -> List[str]:
        lines = [f'    edit "{rule.name}"']
        if rule.description:
            lines.append(f'        set comments "{rule.description}"')
        pool_type = "overload" if rule.nat_type == NATType.PAT else "one-to-one"
        lines.append(f'        set type {pool_type}')
        if rule.translated_src:
            rng = rule.translated_src
            if "-" in rng:
                start, end = rng.split("-", 1)
            else:
                start = end = rng
            lines.append(f'        set startip {start}')
            lines.append(f'        set endip {end}')
        lines.append("    next")
        return lines
