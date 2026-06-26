"""Generate Palo Alto PAN-OS configurations as `set` CLI commands.

Output is the configuration-mode `set` syntax (what admins paste after
`configure`), not the running-config XML. Multi-value fields use PAN-OS bracket
list syntax: `[ a b c ]`. A single-vsys (vsys1) context is assumed.
"""

from __future__ import annotations
from typing import List
from .base import BaseGenerator
from ..models.common import (
    FirewallConfig, NetworkObject, ServiceObject, ObjectGroup,
    AccessRule, NATRule, Interface, Route, ObjectType, NATType,
)
from ..transform import (
    normalize_service_groups, normalize_inline_services, materialize_address_literals,
)


def _q(val: str) -> str:
    """Quote a token if it is empty or contains whitespace (PAN-OS CLI rule)."""
    s = "" if val is None else str(val)
    if s == "" or any(c.isspace() for c in s):
        return f'"{s}"'
    return s


def _mv(values: List[str], default: str = "any") -> str:
    """Render a member field: bare token for one value, '[ ... ]' for several."""
    vals = [v for v in (values or []) if v != ""] or [default]
    if len(vals) == 1:
        return _q(vals[0])
    return "[ " + " ".join(_q(v) for v in vals) + " ]"


class PaloAltoGenerator(BaseGenerator):
    # Security-rule path prefix
    _SEC = "set rulebase security rules"
    _NAT = "set rulebase nat rules"

    def generate(self, cfg: FirewallConfig) -> str:
        self._warnings.clear()
        # PAN-OS rules reference objects by name only, so expand every Cisco-style
        # inline construct (service-group members, inline ACE ports, inline address
        # literals) into real, named objects before emitting set commands.
        cfg, w1 = normalize_service_groups(cfg)
        cfg, w2 = normalize_inline_services(cfg)
        cfg, w3 = materialize_address_literals(cfg)
        self._warnings.extend(w1 + w2 + w3)

        lines: List[str] = []

        # Hostname
        lines.append(f"set deviceconfig system hostname {_q(cfg.hostname or 'migrated-fw')}")

        # Address objects
        for obj in cfg.network_objects:
            lines.extend(self._gen_address(obj))

        # Address groups
        for grp in (g for g in cfg.object_groups if g.group_type == "network"):
            lines.extend(self._gen_address_group(grp))

        # Service objects
        for svc in cfg.service_objects:
            lines.extend(self._gen_service(svc))

        # Service groups
        for grp in (g for g in cfg.object_groups if g.group_type == "service"):
            lines.extend(self._gen_service_group(grp))

        # Zones (group layer3 interfaces) — carried over from a zone-based source
        for zone in (z for z in cfg.zones if z.name):
            if zone.interfaces:
                lines.append(
                    f"set zone {_q(zone.name)} network layer3 {_mv(zone.interfaces)}"
                )
            else:
                lines.append(f"set zone {_q(zone.name)} network layer3")

        # Security rules
        for rule in cfg.access_rules:
            lines.extend(self._gen_security_rule(rule, cfg))

        # NAT rules
        for rule in cfg.nat_rules:
            lines.extend(self._gen_nat_rule(rule))

        # Interfaces
        for iface in cfg.interfaces:
            lines.extend(self._gen_interface(iface))

        # Static routes
        for route in cfg.routes:
            lines.extend(self._gen_route(route))

        # Migration warnings (parse-time risks + this generation's warnings)
        for w in cfg.parse_warnings + self._warnings:
            lines.append(f"# WARNING: {w}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ ADDRESS
    def _gen_address(self, obj: NetworkObject) -> List[str]:
        base = f"set address {_q(obj.name)}"
        lines: List[str] = []
        if obj.obj_type == ObjectType.HOST:
            # IPv6 hosts are /128, not /32.
            host_plen = "128" if ":" in obj.value else "32"
            lines.append(f"{base} ip-netmask {obj.value}/{host_plen}")
        elif obj.obj_type == ObjectType.NETWORK:
            val = obj.value
            if " " in val:
                addr, mask = val.split(None, 1)
                val = f"{addr}/{self._mask_to_prefix(mask)}"
            lines.append(f"{base} ip-netmask {val}")
        elif obj.obj_type == ObjectType.RANGE:
            val = obj.value.replace(" ", "-", 1) if " " in obj.value else obj.value
            lines.append(f"{base} ip-range {val}")
        elif obj.obj_type == ObjectType.FQDN:
            lines.append(f"{base} fqdn {_q(obj.value)}")
        if obj.description:
            lines.append(f"{base} description {_q(obj.description)}")
        return lines

    # ------------------------------------------------------------------ ADDRESS GROUP
    def _gen_address_group(self, grp: ObjectGroup) -> List[str]:
        base = f"set address-group {_q(grp.name)}"
        members = [
            m.removeprefix("host:").removeprefix("group:")
            for m in grp.members if not m.startswith("dag:")
        ]
        lines = [f"{base} static {_mv(members, default='')}"] if members else []
        if grp.description:
            lines.append(f"{base} description {_q(grp.description)}")
        return lines

    # ------------------------------------------------------------------ SERVICE
    def _gen_service(self, svc: ServiceObject) -> List[str]:
        base = f"set service {_q(svc.name)}"
        # PAN-OS service objects only model tcp/udp/sctp. ICMP/IP and other
        # protocols are matched via App-ID applications, not service objects, so
        # there is no faithful service representation — warn and skip rather than
        # mislabel the object as tcp (which would silently match all TCP traffic).
        if svc.protocol not in ("tcp", "udp", "sctp"):
            self._warn(
                f"Service '{svc.name}': protocol '{svc.protocol}' has no PAN-OS "
                "service representation (use an App-ID application instead); "
                "object not emitted — rules referencing it need manual review."
            )
            return []
        pan_proto = svc.protocol
        # PAN-OS requires a destination port on tcp/udp/sctp service objects;
        # an all-ports service (no dst_port) becomes the full 1-65535 range.
        lines = [f"{base} protocol {pan_proto} port {svc.dst_port or '1-65535'}"]
        if svc.src_port:
            lines.append(f"{base} protocol {pan_proto} source-port {svc.src_port}")
        if svc.description:
            lines.append(f"{base} description {_q(svc.description)}")
        return lines

    # ------------------------------------------------------------------ SERVICE GROUP
    def _gen_service_group(self, grp: ObjectGroup) -> List[str]:
        if not grp.members:
            self._warn(f"Service group '{grp.name}' has no members; not emitted.")
            return []
        return [f"set service-group {_q(grp.name)} members {_mv(grp.members)}"]

    # ------------------------------------------------------------------ SECURITY RULE
    def _gen_security_rule(self, rule: AccessRule, cfg: FirewallConfig) -> List[str]:
        base = f"{self._SEC} {_q(rule.name)}"
        lines: List[str] = []

        src_z, dst_z = self._rule_zones(rule, cfg)
        src_zones = src_z.split(",") if src_z else ["any"]
        dst_zones = dst_z.split(",") if dst_z else ["any"]

        lines.append(f"{base} from {_mv(src_zones)}")
        lines.append(f"{base} to {_mv(dst_zones)}")
        lines.append(f"{base} source {_mv(rule.src_address)}")
        lines.append(f"{base} destination {_mv(rule.dst_address)}")

        if rule.src_negated:
            lines.append(f"{base} negate-source yes")
        if rule.dst_negated:
            lines.append(f"{base} negate-destination yes")

        lines.append(f"{base} application {_mv(rule.application)}")

        # Normalise Cisco-style service tokens
        clean_svcs = []
        for s in (rule.service or ["application-default"]):
            if s in ("any", "ANY", "ALL"):
                clean_svcs.append("any")
            elif ":" in s:
                clean_svcs.append(s.split(":")[0] or "any")
            else:
                clean_svcs.append(s)
        lines.append(f"{base} service {_mv(clean_svcs)}")

        lines.append(f"{base} action {'allow' if rule.action == 'permit' else 'deny'}")
        lines.append(f"{base} log-end {'yes' if rule.logging else 'no'}")
        if rule.log_start:
            lines.append(f"{base} log-start yes")
        if not rule.enabled:
            lines.append(f"{base} disabled yes")
        if rule.description:
            lines.append(f"{base} description {_q(rule.description)}")
        return lines

    @staticmethod
    def _rule_zones(rule: AccessRule, cfg: FirewallConfig) -> tuple:
        """
        Resolve (from_zone, to_zone) for a security rule.

        Zone-based sources already carry src_zone/dst_zone. For Cisco sources the
        zone is derived from the ACL->interface binding: an 'in' binding makes the
        bound interface the source zone (from); 'out' makes it the destination (to).
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
        return src, dst

    # ------------------------------------------------------------------ NAT RULE
    def _gen_nat_rule(self, rule: NATRule) -> List[str]:
        base = f"{self._NAT} {_q(rule.name)}"
        lines: List[str] = []

        src_zones = rule.src_interface.split(",") if rule.src_interface else ["any"]
        dst_zones = rule.dst_interface.split(",") if rule.dst_interface else ["any"]
        lines.append(f"{base} from {_mv(src_zones)}")
        lines.append(f"{base} to {_mv(dst_zones)}")

        orig_src = rule.original_src.split(",") if rule.original_src else ["any"]
        orig_dst = rule.original_dst.split(",") if rule.original_dst else ["any"]
        lines.append(f"{base} source {_mv(orig_src)}")
        lines.append(f"{base} destination {_mv(orig_dst)}")
        lines.append(f"{base} service {_q(rule.original_service) if rule.original_service else 'any'}")

        if rule.translated_src:
            st = f"{base} source-translation"
            if rule.nat_type == NATType.STATIC:
                lines.append(f"{st} static-ip translated-address {rule.translated_src}")
                if rule.bidirectional:
                    lines.append(f"{st} static-ip bi-directional yes")
            elif rule.nat_type == NATType.PAT:
                # Interface PAT (translate to the egress interface address) is
                # stored either as 'interface:<name>' (PAN-OS source) or as a bare
                # 'interface' (ASA/FTD source). Both must use PAN-OS
                # 'interface-address', never 'translated-address' (which would name
                # a non-existent address object called "interface").
                if rule.translated_src.lower() == "interface":
                    lines.append(f"{st} dynamic-ip-and-port interface-address")
                elif rule.translated_src.startswith("interface:"):
                    iface_name = rule.translated_src[10:]
                    lines.append(f"{st} dynamic-ip-and-port interface-address interface {_q(iface_name)}")
                else:
                    addrs = [a.strip() for a in rule.translated_src.split(",")]
                    lines.append(f"{st} dynamic-ip-and-port translated-address {_mv(addrs, default='')}")
            else:
                addrs = [a.strip() for a in rule.translated_src.split(",")]
                lines.append(f"{st} dynamic-ip translated-address {_mv(addrs, default='')}")

        if rule.translated_dst:
            dt = f"{base} destination-translation"
            lines.append(f"{dt} translated-address {rule.translated_dst}")
            if rule.translated_service:
                lines.append(f"{dt} translated-port {rule.translated_service}")

        if rule.description:
            lines.append(f"{base} description {_q(rule.description)}")
        return lines

    # ------------------------------------------------------------------ INTERFACE
    def _gen_interface(self, iface: Interface) -> List[str]:
        base = f"set network interface ethernet {_q(iface.name)}"
        lines: List[str] = []
        if iface.ip_address:
            plen = iface.prefix_len or (
                self._mask_to_prefix(iface.subnet_mask) if iface.subnet_mask else 24
            )
            lines.append(f"{base} layer3 ip {iface.ip_address}/{plen}")
        if iface.description:
            lines.append(f"{base} comment {_q(iface.description)}")
        return lines

    # ------------------------------------------------------------------ ROUTE
    def _gen_route(self, route: Route) -> List[str]:
        plen = self._mask_to_prefix(route.mask) if "." in route.mask else int(route.mask)
        base = (
            f"set network virtual-router default routing-table ip "
            f"static-route {_q(route.network + '/' + str(plen))}"
        )
        lines = [
            f"{base} destination {route.network}/{plen}",
            f"{base} nexthop ip-address {route.next_hop}",
        ]
        if route.interface:
            lines.append(f"{base} interface {_q(route.interface)}")
        lines.append(f"{base} metric {route.metric}")
        return lines
