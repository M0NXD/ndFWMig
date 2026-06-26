"""Generate Cisco ASA configurations."""

from __future__ import annotations
import re as _re
from typing import List, Optional
from .base import BaseGenerator
from ..util.netaddr import prefix_to_mask
from ..models.common import (
    FirewallConfig, NetworkObject, ServiceObject, ObjectGroup,
    AccessRule, NATRule, Interface, Route, ObjectType, NATType,
)

OLD_NAT_VERSIONS = {"7.x", "8.0", "8.1", "8.2"}

_IP_RE = _re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _addr_token(addr: str, net_grp_names: frozenset = frozenset()) -> str:
    """Convert an address to ASA ACL token(s)."""
    if addr in ("any", "any4", "any6", ""):
        return "any"
    if addr.startswith("host:"):
        return f"host {addr[5:]}"
    if addr.startswith("group:"):
        return f"object-group {addr[6:]}"
    if addr.startswith("interface:"):
        return f"interface {addr[10:]}"
    # IPv6 uses prefix (CIDR) notation in ASA ACLs, not a dotted mask.
    if ":" in addr:
        return addr if "/" in addr else f"host {addr}"
    if "/" in addr:
        network, plen = addr.split("/", 1)
        try:
            plen_int = int(plen)
        except ValueError:
            return f"{network} {plen}"
        return f"{network} {prefix_to_mask(plen_int)}"
    # Bare dotted-decimal IP (host) or "addr mask" pair
    if _IP_RE.match(addr):
        return f"host {addr}"
    if " " in addr:
        # "network mask" already in dotted-decimal form
        return addr
    # Named reference: an object-group if it matches a known network group,
    # otherwise a network object.
    if addr in net_grp_names:
        return f"object-group {addr}"
    return f"object {addr}"


class CiscoASAGenerator(BaseGenerator):
    OLD_NAT_VERSIONS = OLD_NAT_VERSIONS

    def __init__(self, version: str) -> None:
        super().__init__(version)
        self._old_nat = version in self.OLD_NAT_VERSIONS

    @staticmethod
    def _port_clause(port: str) -> str:
        """Render an IR port string as an ASA operator clause (leading space).

        '80' -> ' eq 80'; '8000-8080' -> ' range 8000 8080'; '!80' -> ' neq 80'.
        """
        if not port:
            return ""
        if port.startswith("!"):
            return f" neq {port[1:]}"
        if "-" in port:
            return f" range {port.replace('-', ' ', 1)}"
        return f" eq {port}"

    def generate(self, cfg: FirewallConfig) -> str:
        self._warnings.clear()
        lines: List[str] = []

        lines.append(f"! Generated for Cisco ASA {self.version}")
        lines.append(f"! Source: {cfg.platform.value} {cfg.version}")
        if cfg.hostname:
            lines.append(f"hostname {cfg.hostname}")
        if cfg.domain_name:
            lines.append(f"domain-name {cfg.domain_name}")
        lines.append("")

        # Interfaces
        for iface in cfg.interfaces:
            lines.extend(self._gen_interface(iface))
            lines.append("")

        # Network objects
        for obj in cfg.network_objects:
            lines.extend(self._gen_network_object(obj))

        # Service objects
        for svc in cfg.service_objects:
            lines.extend(self._gen_service_object(svc))

        # Object groups
        for grp in cfg.object_groups:
            lines.extend(self._gen_object_group(grp))

        # Access rules (grouped by ACL name)
        lines.extend(self._gen_acls(cfg))

        # NAT rules
        lines.extend(self._gen_nat(cfg))

        # Access-group bindings (apply ACLs to interfaces / globally)
        lines.extend(self._gen_acl_bindings(cfg))

        # Routes
        for route in cfg.routes:
            lines.append(self._gen_route(route))

        # Migration warnings as comments
        for w in cfg.parse_warnings + self._warnings:
            lines.append(f"! WARNING: {w}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ INTERFACE
    def _gen_interface(self, iface: Interface) -> List[str]:
        lines = [f"interface {iface.name}"]
        if iface.nameif:
            lines.append(f" nameif {iface.nameif}")
        if iface.security_level is not None:
            lines.append(f" security-level {iface.security_level}")
        if iface.ip_address:
            mask = iface.subnet_mask or (
                self._prefix_to_mask(iface.prefix_len) if iface.prefix_len else "255.255.255.0"
            )
            lines.append(f" ip address {iface.ip_address} {mask}")
        if iface.description:
            lines.append(f" description {iface.description}")
        if iface.vlan:
            lines.append(f" vlan {iface.vlan}")
        lines.append(" no shutdown" if iface.enabled else " shutdown")
        return lines

    # ------------------------------------------------------------------ NETWORK OBJECT
    def _gen_network_object(self, obj: NetworkObject) -> List[str]:
        lines = [f"object network {obj.name}"]
        if obj.description:
            lines.append(f" description {obj.description}")
        if obj.obj_type == ObjectType.HOST:
            lines.append(f" host {obj.value}")
        elif obj.obj_type == ObjectType.NETWORK:
            if ":" in obj.value:
                # IPv6 networks use CIDR notation directly (no dotted mask).
                lines.append(f" subnet {obj.value}")
            elif "/" in obj.value:
                addr, plen = obj.value.split("/", 1)
                mask = self._prefix_to_mask(int(plen))
                lines.append(f" subnet {addr} {mask}")
            elif " " in obj.value:
                lines.append(f" subnet {obj.value}")
            else:
                lines.append(f" host {obj.value}")
        elif obj.obj_type == ObjectType.RANGE:
            val = obj.value.replace("-", " ", 1) if "-" in obj.value else obj.value
            lines.append(f" range {val}")
        elif obj.obj_type == ObjectType.FQDN:
            lines.append(f" fqdn {obj.value}")
        return lines

    # ------------------------------------------------------------------ SERVICE OBJECT
    def _gen_service_object(self, svc: ServiceObject) -> List[str]:
        lines = [f"object service {svc.name}"]
        if svc.description:
            lines.append(f" description {svc.description}")
        parts = [f" service {svc.protocol}"]
        if svc.src_port:
            parts.append(f" source eq {svc.src_port}")
        if svc.dst_port:
            if "-" in svc.dst_port:
                lo, hi = svc.dst_port.split("-", 1)
                parts.append(f" destination range {lo} {hi}")
            else:
                parts.append(f" destination eq {svc.dst_port}")
        lines.append("".join(parts))
        return lines

    # ------------------------------------------------------------------ OBJECT-GROUP
    def _gen_object_group(self, grp: ObjectGroup) -> List[str]:
        if grp.group_type == "network":
            lines = [f"object-group network {grp.name}"]
            if grp.description:
                lines.append(f" description {grp.description}")
            for m in grp.members:
                if m.startswith("host:"):
                    lines.append(f" network-object host {m[5:]}")
                elif m.startswith("group:"):
                    lines.append(f" group-object {m[6:]}")
                elif ":" in m:
                    # IPv6 network-object uses CIDR notation directly.
                    lines.append(f" network-object {m}")
                elif "/" in m:
                    addr, plen = m.split("/", 1)
                    mask = self._prefix_to_mask(int(plen))
                    lines.append(f" network-object {addr} {mask}")
                else:
                    lines.append(f" network-object object {m}")
        elif grp.group_type == "service":
            # Detect protocol from first member if any
            proto = ""
            if grp.members and grp.members[0].startswith("proto:"):
                proto = " " + grp.members[0][6:]
                members = grp.members[1:]
            else:
                members = grp.members
            lines = [f"object-group service {grp.name}{proto}"]
            if grp.description:
                lines.append(f" description {grp.description}")
            for m in members:
                if m.startswith("group:"):
                    lines.append(f" group-object {m[6:]}")
                elif m.startswith("port:"):
                    lines.append(f" port-object {m[5:]}")
                else:
                    lines.append(f" service-object {m}")
        elif grp.group_type == "protocol":
            lines = [f"object-group protocol {grp.name}"]
            if grp.description:
                lines.append(f" description {grp.description}")
            for m in grp.members:
                lines.append(f" protocol-object {m}")
        elif grp.group_type == "icmp-type":
            lines = [f"object-group icmp-type {grp.name}"]
            if grp.description:
                lines.append(f" description {grp.description}")
            for m in grp.members:
                lines.append(f" icmp-object {m}")
        else:
            lines = [f"! Unsupported group type: {grp.group_type} for {grp.name}"]
        return lines

    # ------------------------------------------------------------------ ACLs
    def _gen_acls(self, cfg: FirewallConfig) -> List[str]:
        lines = []
        # Group rules by ACL name; unnamed rules go to DEFAULT_ACL
        acl_map: dict = {}
        for rule in cfg.access_rules:
            acl = rule.acl_name or "MIGRATED_ACL"
            acl_map.setdefault(acl, []).append(rule)

        # Build lookup sets for service / address resolution
        svc_obj_names  = {s.name for s in cfg.service_objects}
        svc_grp_names  = {g.name for g in cfg.object_groups if g.group_type == "service"}
        net_grp_names  = frozenset(g.name for g in cfg.object_groups if g.group_type == "network")

        for acl_name, rules in acl_map.items():
            for rule in rules:
                if rule.description:
                    lines.append(f"access-list {acl_name} remark {rule.description}")
                block = self._gen_ace(acl_name, rule, svc_obj_names, svc_grp_names, cfg, net_grp_names)
                if block:
                    lines.extend(block.splitlines())
        return lines

    def _gen_ace(self, acl_name: str, rule: AccessRule,
                 svc_obj_names: set, svc_grp_names: set,
                 cfg: FirewallConfig,
                 net_grp_names: frozenset = frozenset()) -> str:
        action = "permit" if rule.action == "permit" else "deny"
        inactive = "" if rule.enabled else " inactive"

        # Protocol
        proto = rule.protocol if rule.protocol not in ("any", "ip") else "ip"
        # For Palo Alto / FortiGate rules that use zones, warn
        if rule.src_zone or rule.dst_zone:
            self._warn(
                f"Rule '{rule.name}' uses zones (src={rule.src_zone}, dst={rule.dst_zone}) "
                "which don't map directly to ASA extended ACLs."
            )

        # Multi-address: expand to one ACE per srcxdst combination (up to 4 each)
        src_addrs = rule.src_address[:4] if rule.src_address else ["any"]
        dst_addrs = rule.dst_address[:4] if rule.dst_address else ["any"]
        if len(rule.src_address) > 4:
            self._warn(f"Rule '{rule.name}': {len(rule.src_address)} source addresses - only first 4 emitted.")
        if len(rule.dst_address) > 4:
            self._warn(f"Rule '{rule.name}': {len(rule.dst_address)} dest addresses - only first 4 emitted.")

        # Port / service - split into src_port_str and dst_port_str
        # Token format from parsers: "proto:src:PORT", "proto:dst:PORT", or "proto:src:P:dst:Q"
        src_port_str = ""
        dst_port_str = ""
        if rule.service and rule.service != ["any"]:
            svc = rule.service[0]
            if ":" in svc:
                parts = svc.split(":")
                proto_part = parts[0] if parts[0] else proto
                if proto_part not in ("ip", "any"):
                    proto = proto_part
                # Walk pairs: parts[1]="src"|"dst", parts[2]=port, parts[3]="src"|"dst", parts[4]=port ...
                idx = 1
                while idx < len(parts) - 1:
                    direction = parts[idx]
                    port = parts[idx + 1]
                    idx += 2
                    port_tok = self._port_clause(port)
                    if direction == "src":
                        src_port_str = port_tok
                    elif direction == "dst":
                        dst_port_str = port_tok
            else:
                # Plain service name - resolve to proto/port if possible
                if svc not in ("any", "ANY", "ALL", "ip"):
                    if svc in svc_grp_names:
                        dst_port_str = f" object-group {svc}"
                    elif svc in svc_obj_names:
                        # Look up the service object and inline its proto/port
                        svc_def = next((s for s in cfg.service_objects if s.name == svc), None)
                        if svc_def:
                            if svc_def.protocol not in ("ip", "any"):
                                proto = svc_def.protocol
                            if svc_def.src_port:
                                src_port_str = self._port_clause(svc_def.src_port)
                            if svc_def.dst_port:
                                dst_port_str = self._port_clause(svc_def.dst_port)
                        else:
                            dst_port_str = f" object {svc}"
                    else:
                        # Unknown - emit as object reference with a warning
                        self._warn(f"Rule '{rule.name}': service '{svc}' not found in objects/groups - "
                                   "emitted as 'object-group'; verify manually.")
                        dst_port_str = f" object-group {svc}"

        log_str = " log" if rule.logging else ""

        # Emit one ACE per srcxdst pair
        lines = []
        for src_addr in src_addrs:
            src = _addr_token(src_addr, net_grp_names)
            for dst_addr in dst_addrs:
                dst = _addr_token(dst_addr, net_grp_names)
                lines.append(
                    f"access-list {acl_name} extended {action} {proto} "
                    f"{src}{src_port_str} {dst}{dst_port_str}{log_str}{inactive}"
                )
        return "\n".join(lines)

    # ------------------------------------------------------------------ ACL BINDINGS
    def _gen_acl_bindings(self, cfg: FirewallConfig) -> List[str]:
        """Emit 'access-group' lines binding ACLs to interfaces / globally."""
        if not cfg.acl_bindings:
            return []
        lines = ["", "! Access-group bindings"]
        for b in cfg.acl_bindings:
            if b.direction == "global" or not b.interface:
                lines.append(f"access-group {b.acl_name} global")
            else:
                lines.append(
                    f"access-group {b.acl_name} {b.direction} interface {b.interface}"
                )
        return lines

    # ------------------------------------------------------------------ NAT
    def _gen_nat(self, cfg: FirewallConfig) -> List[str]:
        lines: List[str] = []
        if not cfg.nat_rules:
            return lines

        lines.append("")
        lines.append("! NAT Rules")

        for i, rule in enumerate(cfg.nat_rules):
            if self._old_nat:
                lines.extend(self._gen_nat_old(rule, i))
            else:
                lines.extend(self._gen_nat_new(rule, i))
        return lines

    def _gen_nat_new(self, rule: NATRule, idx: int) -> List[str]:
        src_if = rule.src_interface or "any"
        dst_if = rule.dst_interface or "any"
        nat_type = "static" if rule.nat_type == NATType.STATIC else "dynamic"

        orig_src  = self._nat_addr_token(rule.original_src)
        trans_src = self._nat_addr_token(rule.translated_src)

        line = f"nat ({src_if},{dst_if}) source {nat_type} {orig_src} {trans_src}"

        if rule.original_dst and rule.translated_dst:
            line += (f" destination static "
                     f"{self._nat_addr_token(rule.original_dst)} "
                     f"{self._nat_addr_token(rule.translated_dst)}")
        if rule.original_service and rule.translated_service:
            line += f" service {rule.original_service} {rule.translated_service}"

        lines = [line]
        if rule.description:
            lines.append(f"! {rule.description}")
        return lines

    @staticmethod
    def _nat_addr_token(addr: Optional[str]) -> str:
        """Return correct ASA token for a NAT address field.
        Named objects need the 'object' keyword; IPs and 'any'/'interface' do not.
        """
        if not addr or addr.lower() in ("any", "interface", "pat-pool"):
            return addr or "any"
        # If it looks like an IP or CIDR leave it bare; otherwise it's an object name
        if _re.match(r"^[\d\./:]+$", addr):
            return addr
        if addr.startswith("interface:"):
            return "interface"
        return f"object {addr}"

    @staticmethod
    def _split_cidr(addr: Optional[str], default_mask: str) -> tuple:
        """Split an IR address that may be 'net/prefix' into (addr, dotted_mask).
        A bare address (no prefix) keeps `default_mask`."""
        if addr and "/" in addr and ":" not in addr:
            net, plen = addr.split("/", 1)
            try:
                return net, CiscoASAGenerator._prefix_to_mask(int(plen))
            except ValueError:
                return addr, default_mask
        return addr, default_mask

    def _gen_nat_old(self, rule: NATRule, idx: int) -> List[str]:
        if rule.nat_type == NATType.STATIC:
            src = rule.src_interface or "inside"
            dst = rule.dst_interface or "outside"
            g_net, _ = self._split_cidr(rule.translated_src, "255.255.255.255")
            l_net, l_mask = self._split_cidr(rule.original_src, "255.255.255.255")
            return [f"static ({src},{dst}) {g_net or 'any'} "
                    f"{l_net or 'any'} netmask {l_mask}"]
        else:
            src = rule.src_interface or "inside"
            dst = rule.dst_interface or "outside"
            net, mask = self._split_cidr(rule.original_src, "0.0.0.0")
            # Use a stable per-rule id so the matching 'global' pairs correctly.
            nat_id = idx + 1
            lines = [f"nat ({src}) {nat_id} {net or '0.0.0.0'} {mask}"]
            # Emit the paired global pool so the dynamic translation is complete.
            if rule.translated_src:
                lines.append(f"global ({dst}) {nat_id} {rule.translated_src}")
            return lines

    # ------------------------------------------------------------------ ROUTE
    def _gen_route(self, route: Route) -> str:
        iface = route.interface or "outside"
        return f"route {iface} {route.network} {route.mask} {route.next_hop} {route.metric}"
