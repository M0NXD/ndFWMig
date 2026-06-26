"""
Palo Alto PAN-OS parser.

Input format: XML exported via 'show config running' or 'export configuration'.
Handles vsys1 (default) and multi-vsys configs.

Version matrix handled:
  8.0 / 8.1 — standard XML schema
  9.0 / 9.1 — added Security Profile Groups in policy
  10.0+     — added Enhanced Application Logging, UUID on rules
  11.0+     — added SCTP app-id, AI-powered features (policy hints — not CLI-visible)
"""

from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Optional, List

from .base import BaseParser
from ..models.common import (
    FirewallConfig, NetworkObject, ServiceObject, ObjectGroup,
    AccessRule, NATRule, Interface, Route, Zone,
    Platform, ObjectType, NATType,
)


def _text(el: Optional[ET.Element], path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    return (found.text or default) if found is not None else default


def _members(el: Optional[ET.Element], path: str) -> List[str]:
    """Return list of <member> text values under path."""
    if el is None:
        return []
    return [m.text or "" for m in el.findall(f"{path}/member") if m.text]


class PaloAltoParser(BaseParser):
    """Parse PAN-OS XML configuration."""

    def parse(self, text: str) -> FirewallConfig:
        cfg = FirewallConfig(platform=Platform.PALO_ALTO, version=self.version)
        cfg.raw_lines = text.splitlines()

        # Support both full XML and snippet starting with <config>
        stripped = text.strip()
        if not stripped.startswith("<?xml") and not stripped.startswith("<config"):
            # Try wrapping
            stripped = f"<config>{stripped}</config>"

        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as e:
            self._error(cfg, f"XML parse error: {e}")
            return cfg

        device_el = self._find_device(root)

        # Hostname
        cfg.hostname = _text(device_el, "deviceconfig/system/hostname") if device_el else ""

        # Interfaces / routes (from network section)
        net_el = root.find(".//network") if root.tag != "network" else root
        if net_el is not None:
            self._parse_interfaces(net_el, cfg)
            self._parse_routes(net_el, cfg)

        # Find ALL vsys entries and merge them
        vsys_list = self._find_all_vsys(root)
        if not vsys_list:
            self._warn(cfg, "No vsys found in config - nothing to parse.")
            return cfg
        if len(vsys_list) > 1:
            names = [el.get("name", "?") for el in vsys_list]
            self._warn(cfg, f"Multi-vsys config ({', '.join(names)}) - all vsys merged into one output. "
                            "Review zone/interface references for conflicts.")

        for vsys_el in vsys_list:
            self._parse_zones(vsys_el, cfg)
            self._parse_address_objects(vsys_el, cfg)
            self._parse_address_groups(vsys_el, cfg)
            self._parse_service_objects(vsys_el, cfg)
            self._parse_service_groups(vsys_el, cfg)
            # NB: an ElementTree element with no children is falsy, so a plain
            # `find(...) or vsys_el` would wrongly discard an empty <rulebase>.
            rulebase = vsys_el.find("rulebase")
            if rulebase is None:
                rulebase = vsys_el
            self._parse_security_rules(rulebase, cfg)
            self._parse_nat_rules(rulebase, cfg)

        return cfg

    # ------------------------------------------------------------------ navigation
    @staticmethod
    def _find_all_vsys(root: ET.Element) -> List[ET.Element]:
        """Return all vsys entry elements, in document order."""
        for path in (
            ".//devices/entry/vsys/entry",
            ".//vsys/entry",
        ):
            els = root.findall(path)
            if els:
                return els
        # Single-vsys or snippet export — check for bare vsys entry by name attr
        by_name = root.findall(".//entry[@name]")
        for el in by_name:
            if el.find("address") is not None or el.find("rulebase") is not None:
                return [el]
        # Root itself looks like vsys content
        if root.find("address") is not None or root.find("rulebase") is not None:
            return [root]
        return []

    @staticmethod
    def _find_device(root: ET.Element) -> Optional[ET.Element]:
        for path in (".//devices/entry", ".//device"):
            el = root.find(path)
            if el is not None:
                return el
        return None

    # ------------------------------------------------------------------ INTERFACES
    def _parse_interfaces(self, net_el: ET.Element, cfg: FirewallConfig) -> None:
        for iface_section in net_el.findall("interface"):
            for category in iface_section:
                for entry in category.findall("entry"):
                    name = entry.get("name", "")
                    iface = Interface(name=name)
                    iface.description = _text(entry, "comment")

                    layer3 = entry.find("layer3")
                    if layer3 is not None:
                        ip_el = layer3.find("ip/entry")
                        if ip_el is not None:
                            cidr = ip_el.get("name", "")
                            if "/" in cidr:
                                addr, plen = cidr.split("/", 1)
                                iface.ip_address = addr
                                iface.prefix_len = int(plen)
                        # NB: 'interface-management-profile' is NOT the logical name
                        # (zones live in a separate <zone> section), so don't map it
                        # onto nameif — that produced misleading interface labels.

                    link_state = _text(entry, "link-state")
                    iface.enabled = (link_state.lower() != "down")
                    cfg.interfaces.append(iface)

    # ------------------------------------------------------------------ ZONES
    def _parse_zones(self, vsys_el: ET.Element, cfg: FirewallConfig) -> None:
        """Parse the <zone> section: each zone lists its layer3 member interfaces."""
        zone_section = vsys_el.find("zone")
        if zone_section is None:
            return
        for entry in zone_section.findall("entry"):
            name = entry.get("name", "")
            if not name:
                continue
            # Members can sit under network/layer3, network/layer2, or network/tap.
            members: List[str] = []
            net_el = entry.find("network")
            if net_el is not None:
                for kind in ("layer3", "layer2", "virtual-wire", "tap"):
                    members += _members(net_el, kind)
            cfg.zones.append(Zone(name=name, interfaces=members))
            # Reflect zone membership onto the matching interfaces.
            for iface in cfg.interfaces:
                if iface.name in members:
                    iface.zone = name

    # ------------------------------------------------------------------ ROUTES
    def _parse_routes(self, net_el: ET.Element, cfg: FirewallConfig) -> None:
        for vr in net_el.findall(".//virtual-router/entry"):
            for route in vr.findall("routing-table/ip/static-route/entry"):
                dest = _text(route, "destination")
                nexthop_el = route.find("nexthop")
                nexthop = ""
                if nexthop_el is not None:
                    for child in nexthop_el:
                        nexthop = child.text or ""
                        break
                network, mask = dest, "0.0.0.0"
                if "/" in dest:
                    network, plen = dest.split("/", 1)
                    # Keep IPv6 prefix length as-is; only IPv4 gets a dotted mask.
                    mask = plen if ":" in network else self._prefix_to_mask(int(plen))
                cfg.routes.append(Route(
                    network=network,
                    mask=mask,
                    next_hop=nexthop,
                    interface=_text(route, "interface"),
                    metric=int(_text(route, "metric", "1") or "1"),
                    is_default=(dest in ("0.0.0.0/0", "default")),
                ))

    # ------------------------------------------------------------------ ADDRESS OBJECTS
    def _parse_address_objects(self, vsys: ET.Element, cfg: FirewallConfig) -> None:
        for entry in vsys.findall("address/entry"):
            name = entry.get("name", "")
            obj = NetworkObject(name=name)
            obj.description = _text(entry, "description")
            obj.tags = _members(entry, "tag")

            if entry.find("ip-netmask") is not None:
                val = _text(entry, "ip-netmask")
                if "/32" in val or ("/" not in val and "." in val):
                    obj.obj_type = ObjectType.HOST
                    obj.value = val.split("/")[0]
                else:
                    obj.obj_type = ObjectType.NETWORK
                    obj.value = val
            elif entry.find("ip-range") is not None:
                obj.obj_type = ObjectType.RANGE
                obj.value = _text(entry, "ip-range")
            elif entry.find("fqdn") is not None:
                obj.obj_type = ObjectType.FQDN
                obj.value = _text(entry, "fqdn")
            else:
                obj.obj_type = ObjectType.HOST
                obj.value = name

            cfg.network_objects.append(obj)

    # ------------------------------------------------------------------ ADDRESS GROUPS
    def _parse_address_groups(self, vsys: ET.Element, cfg: FirewallConfig) -> None:
        for entry in vsys.findall("address-group/entry"):
            grp = ObjectGroup(
                name=entry.get("name", ""),
                group_type="network",
                members=_members(entry, "static"),
                description=_text(entry, "description"),
                tags=_members(entry, "tag"),
            )
            # Dynamic address groups (DAGs)
            dag = entry.find("dynamic/filter")
            if dag is not None and dag.text:
                grp.members.append(f"dag:{dag.text}")
            cfg.object_groups.append(grp)

    # ------------------------------------------------------------------ SERVICE OBJECTS
    def _parse_service_objects(self, vsys: ET.Element, cfg: FirewallConfig) -> None:
        for entry in vsys.findall("service/entry"):
            name = entry.get("name", "")
            proto_el = entry.find("protocol")
            if proto_el is None:
                continue
            for proto_name in ("tcp", "udp", "sctp"):
                p = proto_el.find(proto_name)
                if p is not None:
                    svc = ServiceObject(
                        name=name,
                        protocol=proto_name,
                        src_port=_text(p, "source-port") or None,
                        dst_port=_text(p, "port") or None,
                        description=_text(entry, "description"),
                    )
                    cfg.service_objects.append(svc)

    # ------------------------------------------------------------------ SERVICE GROUPS
    def _parse_service_groups(self, vsys: ET.Element, cfg: FirewallConfig) -> None:
        for entry in vsys.findall("service-group/entry"):
            grp = ObjectGroup(
                name=entry.get("name", ""),
                group_type="service",
                members=_members(entry, "members"),
                description=_text(entry, "description"),
                tags=_members(entry, "tag"),
            )
            cfg.object_groups.append(grp)

    # ------------------------------------------------------------------ SECURITY RULES
    def _parse_security_rules(self, vsys: ET.Element, cfg: FirewallConfig) -> None:
        seq = 1
        for entry in vsys.findall("security/rules/entry"):
            name = entry.get("name", f"rule_{seq}")
            action = _text(entry, "action", "allow").lower()
            # Normalize: PAN-OS 'allow'→'permit', 'deny'→'deny', 'drop'→'deny'
            if action == "allow":
                action = "permit"
            elif action in ("deny", "drop", "reset-both", "reset-client", "reset-server"):
                action = "deny"

            rule = AccessRule(
                name=name,
                action=action,
                protocol="any",
                src_zone=",".join(_members(entry, "from")),
                dst_zone=",".join(_members(entry, "to")),
                src_address=_members(entry, "source"),
                dst_address=_members(entry, "destination"),
                src_negated=_text(entry, "source-negate", "no").lower() == "yes",
                dst_negated=_text(entry, "destination-negate", "no").lower() == "yes",
                service=_members(entry, "service"),
                application=_members(entry, "application"),
                logging=_text(entry, "log-end", "yes").lower() == "yes",
                log_start=_text(entry, "log-start", "no").lower() == "yes",
                enabled=_text(entry, "disabled", "no").lower() != "yes",
                description=_text(entry, "description"),
                tags=_members(entry, "tag"),
                sequence=seq,
            )
            cfg.access_rules.append(rule)
            seq += 1

    # ------------------------------------------------------------------ NAT RULES
    def _parse_nat_rules(self, vsys: ET.Element, cfg: FirewallConfig) -> None:
        for i, entry in enumerate(vsys.findall("nat/rules/entry")):
            name = entry.get("name", f"nat_{i+1}")
            nat_type = NATType.STATIC

            src_trans = entry.find("source-translation")
            dst_trans = entry.find("destination-translation")

            trans_src, orig_src_svc, trans_src_svc = None, None, None
            trans_dst, trans_dst_port = None, None

            if src_trans is not None:
                if src_trans.find("static-ip") is not None:
                    nat_type = NATType.STATIC
                    trans_src = _text(src_trans, "static-ip/translated-address")
                elif src_trans.find("dynamic-ip-and-port") is not None:
                    nat_type = NATType.PAT
                    pool = src_trans.find("dynamic-ip-and-port/translated-address")
                    if pool is not None:
                        trans_src = ",".join(_members(pool, "."))
                    iface_el = src_trans.find("dynamic-ip-and-port/interface-address")
                    if iface_el is not None:
                        # The interface name is a child element, not an attribute.
                        trans_src = f"interface:{_text(iface_el, 'interface')}"
                elif src_trans.find("dynamic-ip") is not None:
                    nat_type = NATType.DYNAMIC
                    trans_src = ",".join(_members(src_trans, "dynamic-ip/translated-address"))

            if dst_trans is not None:
                trans_dst = _text(dst_trans, "translated-address")
                trans_dst_port = _text(dst_trans, "translated-port") or None

            rule = NATRule(
                name=name,
                nat_type=nat_type,
                src_interface=",".join(_members(entry, "from")),
                dst_interface=",".join(_members(entry, "to")),
                original_src=",".join(_members(entry, "source")),
                translated_src=trans_src,
                original_dst=",".join(_members(entry, "destination")),
                translated_dst=trans_dst,
                original_service=_text(entry, "service"),
                translated_service=trans_dst_port,
                description=_text(entry, "description"),
                tags=_members(entry, "tag"),
                order=i + 1,
            )
            cfg.nat_rules.append(rule)
