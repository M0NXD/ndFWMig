"""
FortiGate FortiOS parser.

Input format: FortiGate configuration file (flat text with config/edit/next/end blocks).

Version matrix:
  5.x — uses 'config firewall policy' with srcaddr/dstaddr, older NAT
  6.0 / 6.2 — mostly same; added central SNAT/DNAT tables
  6.4     — central-nat mode improvements, SD-WAN
  7.0+    — 'config firewall policy' largely unchanged; added ztna-tags
  7.2/7.4 — policy blocks include 'set ztna-status', 'set casb-profile'

Key config blocks parsed:
  config system global          → hostname
  config system interface       → interfaces
  config router static          → routes
  config firewall address       → network objects
  config firewall addrgrp       → network groups
  config firewall service custom → service objects
  config firewall service group  → service groups
  config firewall policy         → access rules (IPv4)
  config firewall policy6        → access rules (IPv6)
  config firewall ippool         → NAT pools (PAT)
  config firewall vip            → DNAT/virtual IPs
  config firewall nat            → SNAT (central NAT, 6.0+)
  config central-snat-map        → central SNAT (6.0+)
"""

from __future__ import annotations
import re
from typing import Optional, List, Dict, Tuple, Any

from .base import BaseParser
from ..models.common import (
    FirewallConfig, NetworkObject, ServiceObject, ObjectGroup,
    AccessRule, NATRule, Interface, Route, Zone,
    Platform, ObjectType, NATType,
)


# ---------------------------------------------------------------------------
# Block parser helper
# ---------------------------------------------------------------------------

def _parse_blocks(lines: List[str]) -> List[Dict[str, Any]]:
    """
    Parse FortiGate hierarchical config into a list of block dicts.
    Each block: { 'type': 'config'|'edit', 'key': str, 'entries': [...], 'sets': {key: val} }
    """
    stack: List[Dict] = []
    blocks: List[Dict] = []
    current: Optional[Dict] = None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.lower().startswith("config "):
            key = stripped[7:].strip()
            new_block: Dict[str, Any] = {"type": "config", "key": key, "entries": [], "sets": {}}
            if current is not None:
                # Nested config block — attach to current entry, do NOT add to top-level list
                current["entries"].append(new_block)
                stack.append(current)
            else:
                # Top-level config block
                blocks.append(new_block)
            current = new_block

        elif stripped.lower().startswith("edit "):
            key = stripped[5:].strip().strip('"')
            entry: Dict[str, Any] = {"type": "edit", "key": key, "entries": [], "sets": {}}
            if current is not None:
                current["entries"].append(entry)
                stack.append(current)
            current = entry

        elif stripped.lower().startswith("set "):
            rest = stripped[4:].strip()
            m = re.match(r'(\S+)\s*(.*)', rest)
            if m and current is not None:
                k = m.group(1)
                raw_v = m.group(2).strip()
                # Multi-value quoted: set member "A" "B" "C"  →  store as-is for split_members
                # Single-quoted or bare: strip outer quotes if single value
                if raw_v.startswith('"') and raw_v.count('"') == 2:
                    raw_v = raw_v.strip('"')
                current["sets"][k] = raw_v

        elif stripped.lower() == "next":
            if stack:
                current = stack.pop()

        elif stripped.lower() == "end":
            if stack:
                current = stack.pop()
            else:
                current = None

    return blocks


def _find_block(blocks: List[Dict], key: str) -> Optional[Dict]:
    key_lower = key.lower()
    for b in blocks:
        if b.get("key", "").lower() == key_lower:
            return b
    return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class FortiGateParser(BaseParser):
    """Parse FortiOS configuration files."""

    def parse(self, text: str) -> FirewallConfig:
        cfg = FirewallConfig(platform=Platform.FORTIGATE, version=self.version)
        cfg.raw_lines = text.splitlines()

        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        blocks = _parse_blocks(lines)

        # System global (hostname)
        sys_global = _find_block(blocks, "system global")
        if sys_global:
            cfg.hostname = sys_global["sets"].get("hostname", "")

        # Interfaces
        sys_iface = _find_block(blocks, "system interface")
        if sys_iface:
            for entry in sys_iface.get("entries", []):
                cfg.interfaces.append(self._parse_interface(entry))

        # Zones (group interfaces) — 'config system zone'
        sys_zone = _find_block(blocks, "system zone")
        if sys_zone:
            for entry in sys_zone.get("entries", []):
                zone = self._parse_zone(entry)
                if zone:
                    cfg.zones.append(zone)
                    # Reflect membership back onto the member interfaces so the
                    # zone is visible from either direction.
                    for iface in cfg.interfaces:
                        if iface.name in zone.interfaces:
                            iface.zone = zone.name

        # Static routes
        router_static = _find_block(blocks, "router static")
        if router_static:
            for entry in router_static.get("entries", []):
                r = self._parse_route(entry)
                if r:
                    cfg.routes.append(r)

        # Firewall addresses
        fw_addr = _find_block(blocks, "firewall address")
        if fw_addr:
            for entry in fw_addr.get("entries", []):
                obj = self._parse_fw_address(entry)
                if obj:
                    cfg.network_objects.append(obj)

        # Firewall address groups
        fw_addrgrp = _find_block(blocks, "firewall addrgrp")
        if fw_addrgrp:
            for entry in fw_addrgrp.get("entries", []):
                grp = self._parse_addrgrp(entry)
                if grp:
                    cfg.object_groups.append(grp)

        # Service custom
        svc_custom = _find_block(blocks, "firewall service custom")
        if svc_custom:
            for entry in svc_custom.get("entries", []):
                svc = self._parse_service_custom(entry)
                if svc:
                    cfg.service_objects.append(svc)

        # Service group
        svc_group = _find_block(blocks, "firewall service group")
        if svc_group:
            for entry in svc_group.get("entries", []):
                grp = self._parse_service_group(entry)
                if grp:
                    cfg.object_groups.append(grp)

        # Policies (IPv4)
        fw_policy = _find_block(blocks, "firewall policy")
        if fw_policy:
            for entry in fw_policy.get("entries", []):
                rule = self._parse_policy(entry)
                if rule:
                    cfg.access_rules.append(rule)

        # Policies (IPv6) — same structure
        fw_policy6 = _find_block(blocks, "firewall policy6")
        if fw_policy6:
            for entry in fw_policy6.get("entries", []):
                rule = self._parse_policy(entry)
                if rule:
                    rule.name = f"ipv6_{rule.name}"
                    rule.protocol = "ipv6"
                    cfg.access_rules.append(rule)

        # Virtual IPs (DNAT)
        fw_vip = _find_block(blocks, "firewall vip")
        if fw_vip:
            for entry in fw_vip.get("entries", []):
                nat = self._parse_vip(entry, len(cfg.nat_rules))
                if nat:
                    cfg.nat_rules.append(nat)

        # IP pools (PAT / dynamic NAT)
        fw_ippool = _find_block(blocks, "firewall ippool")
        if fw_ippool:
            for entry in fw_ippool.get("entries", []):
                nat = self._parse_ippool(entry, len(cfg.nat_rules))
                if nat:
                    cfg.nat_rules.append(nat)

        # Central SNAT (FortiOS 6.0+)
        central_snat = _find_block(blocks, "firewall central-snat-map") or \
                       _find_block(blocks, "central-snat-map")
        if central_snat:
            for entry in central_snat.get("entries", []):
                nat = self._parse_central_snat(entry, len(cfg.nat_rules))
                if nat:
                    cfg.nat_rules.append(nat)

        return cfg

    # ------------------------------------------------------------------ INTERFACE
    @staticmethod
    def _parse_interface(entry: Dict) -> Interface:
        sets = entry.get("sets", {})
        name = entry.get("key", "")
        iface = Interface(name=name)
        iface.description = sets.get("description", sets.get("alias", ""))
        iface.nameif = sets.get("alias", "")
        iface.zone = sets.get("zone", "")

        ip_str = sets.get("ip", "")
        if ip_str and " " in ip_str:
            parts = ip_str.split()
            iface.ip_address = parts[0]
            iface.subnet_mask = parts[1]
        elif "/" in ip_str:
            addr, plen = ip_str.split("/", 1)
            iface.ip_address = addr
            iface.prefix_len = int(plen)

        status = sets.get("status", "up")
        iface.enabled = (status.lower() == "up")

        vlanid = sets.get("vlanid", "")
        if vlanid.isdigit():
            iface.vlan = int(vlanid)

        mtu = sets.get("mtu", "")
        if mtu.isdigit():
            iface.mtu = int(mtu)

        return iface

    # ------------------------------------------------------------------ ZONE
    @staticmethod
    def _parse_zone(entry: Dict) -> Optional[Zone]:
        name = entry.get("key", "")
        if not name:
            return None
        sets = entry.get("sets", {})
        # 'set interface "port1" "port2"' — multi-value quoted list.
        members_str = sets.get("interface", "")
        found = re.findall(r'"([^"]*)"|\b(\S+)\b', members_str)
        members = [a or b for a, b in found if (a or b)]
        return Zone(
            name=name,
            interfaces=members,
            description=sets.get("description", ""),
        )

    # ------------------------------------------------------------------ ROUTE
    @staticmethod
    def _parse_route(entry: Dict) -> Optional[Route]:
        sets = entry.get("sets", {})
        dst = sets.get("dst", "")
        if not dst:
            return None
        gw = sets.get("gateway", "0.0.0.0")
        dev = sets.get("device", "").strip('"')

        network, mask = "0.0.0.0", "0.0.0.0"
        if " " in dst:
            # Format: "0.0.0.0 0.0.0.0"
            parts = dst.split(None, 1)
            network, mask = parts[0], parts[1]
        elif "/" in dst:
            network, plen = dst.split("/", 1)
            # Keep IPv6 prefix length as-is; only IPv4 gets a dotted mask.
            mask = plen if ":" in network else FortiGateParser._prefix_to_mask(int(plen))
        else:
            network = dst

        return Route(
            network=network,
            mask=mask,
            next_hop=gw,
            interface=dev,
            metric=int(sets.get("distance", "10")),
            is_default=(network in ("0.0.0.0", "default")),
            description=sets.get("comment", ""),
        )

    # ------------------------------------------------------------------ FIREWALL ADDRESS
    @staticmethod
    def _parse_fw_address(entry: Dict) -> Optional[NetworkObject]:
        name = entry.get("key", "")
        if not name:
            return None
        sets = entry.get("sets", {})
        obj = NetworkObject(name=name, description=sets.get("comment", ""))

        fw_type = sets.get("type", "ipmask").lower()
        if fw_type in ("ipmask", ""):
            subnet = sets.get("subnet", "")
            if subnet:
                if " " in subnet:
                    addr, mask = subnet.split(None, 1)
                    obj.value = f"{addr} {mask}"
                    prefix = sum(bin(int(o)).count("1") for o in mask.split("."))
                    if prefix == 32:
                        obj.obj_type = ObjectType.HOST
                        obj.value = addr
                    else:
                        obj.obj_type = ObjectType.NETWORK
                else:
                    obj.value = subnet
                    obj.obj_type = ObjectType.HOST
        elif fw_type == "iprange":
            start = sets.get("start-ip", "")
            end = sets.get("end-ip", "")
            obj.obj_type = ObjectType.RANGE
            obj.value = f"{start}-{end}"
        elif fw_type == "fqdn":
            obj.obj_type = ObjectType.FQDN
            obj.value = sets.get("fqdn", name)
        elif fw_type == "wildcard":
            obj.obj_type = ObjectType.NETWORK
            obj.value = sets.get("wildcard", "")
        else:
            obj.obj_type = ObjectType.HOST
            obj.value = name

        return obj

    # ------------------------------------------------------------------ ADDR GROUP
    @staticmethod
    def _parse_addrgrp(entry: Dict) -> Optional[ObjectGroup]:
        name = entry.get("key", "")
        if not name:
            return None
        sets = entry.get("sets", {})
        members_str = sets.get("member", "")
        found = re.findall(r'"([^"]*)"|\b(\S+)\b', members_str)
        members = [a or b for a, b in found if (a or b)]
        return ObjectGroup(
            name=name,
            group_type="network",
            members=members,
            description=sets.get("comment", ""),
        )

    # ------------------------------------------------------------------ SERVICE CUSTOM
    @staticmethod
    def _parse_service_custom(entry: Dict) -> Optional[ServiceObject]:
        name = entry.get("key", "")
        if not name:
            return None
        sets = entry.get("sets", {})
        proto_num = sets.get("protocol", "TCP").upper()
        proto_map = {"TCP": "tcp", "UDP": "udp", "SCTP": "sctp", "ICMP": "icmp",
                     "ICMP6": "icmp6", "IP": "ip", "6": "tcp", "17": "udp", "1": "icmp"}
        proto = proto_map.get(proto_num, proto_num.lower())

        src_port = sets.get("tcp-portrange", sets.get("udp-portrange", ""))
        # FortiGate format: "dst_port:src_port" or just "dst_port"
        dst_p, src_p = None, None
        if src_port:
            parts = src_port.split(":")
            dst_p = parts[0] if parts[0] else None
            src_p = parts[1] if len(parts) > 1 and parts[1] else None

        # ICMP/ICMP6 services carry a type (and optional code) rather than ports.
        icmp_type = sets.get("icmptype", "")
        icmp_code = sets.get("icmpcode", "")

        return ServiceObject(
            name=name,
            protocol=proto,
            src_port=src_p,
            dst_port=dst_p,
            icmp_type=int(icmp_type) if icmp_type.isdigit() else None,
            icmp_code=int(icmp_code) if icmp_code.isdigit() else None,
            description=sets.get("comment", ""),
        )

    # ------------------------------------------------------------------ SERVICE GROUP
    @staticmethod
    def _parse_service_group(entry: Dict) -> Optional[ObjectGroup]:
        name = entry.get("key", "")
        if not name:
            return None
        sets = entry.get("sets", {})
        members_str = sets.get("member", "")
        found = re.findall(r'"([^"]*)"|\b(\S+)\b', members_str)
        members = [a or b for a, b in found if (a or b)]
        return ObjectGroup(
            name=name,
            group_type="service",
            members=members,
            description=sets.get("comment", ""),
        )

    # FortiOS 7.6+ / 8.0 policy fields we recognise but don't map
    _FOS_EXTRA_FIELDS = frozenset({
        "ztna-status", "ztna-ems-tag", "ztna-device-ownership",
        "casb-profile", "file-filter-profile", "video-filter-profile",
        "emailfilter-profile", "dlp-profile",
    })

    # ------------------------------------------------------------------ POLICY
    @staticmethod
    def _parse_policy(entry: Dict) -> Optional[AccessRule]:
        seq_id = entry.get("key", "")
        sets = entry.get("sets", {})

        action_raw = sets.get("action", "accept").lower()
        action = "permit" if action_raw == "accept" else "deny"

        # FortiGate multi-value format: "addr1" "addr2" or bare addr
        def split_members(val: str) -> List[str]:
            found = re.findall(r'"([^"]*)"|\b(\S+)\b', val)
            return [a or b for a, b in found if (a or b)]

        src_addrs = split_members(sets.get("srcaddr", "all"))
        dst_addrs = split_members(sets.get("dstaddr", "all"))
        services  = split_members(sets.get("service", "ALL"))

        src_iface = sets.get("srcintf", "")
        dst_iface = sets.get("dstintf", "")

        log = sets.get("logtraffic", "disable").lower() != "disable"

        enabled_raw = sets.get("status", "enable").lower()
        enabled = enabled_raw == "enable"

        name = sets.get("name", f"policy_{seq_id}")
        if not name:
            name = f"policy_{seq_id}"

        return AccessRule(
            name=name,
            action=action,
            protocol="ip",
            src_zone=src_iface,
            dst_zone=dst_iface,
            src_address=src_addrs if src_addrs else ["all"],
            dst_address=dst_addrs if dst_addrs else ["all"],
            service=services if services else ["ALL"],
            logging=log,
            enabled=enabled,
            description=sets.get("comments", ""),
            sequence=int(seq_id) if seq_id.isdigit() else 0,
        )

    # ------------------------------------------------------------------ VIP (DNAT)
    @staticmethod
    def _parse_vip(entry: Dict, idx: int) -> Optional[NATRule]:
        name = entry.get("key", f"vip_{idx}")
        sets = entry.get("sets", {})
        extip = sets.get("extip", "")
        mappedip = sets.get("mappedip", "")
        extport = sets.get("extport", "")
        mappedport = sets.get("mappedport", "")
        iface = sets.get("extintf", "any")

        if not extip and not mappedip:
            return None

        return NATRule(
            name=name,
            nat_type=NATType.STATIC,
            dst_interface=iface,
            original_dst=extip,
            translated_dst=mappedip,
            original_service=extport or None,
            translated_service=mappedport or None,
            description=sets.get("comment", ""),
            order=idx,
        )

    # ------------------------------------------------------------------ IPPOOL (SNAT/PAT)
    @staticmethod
    def _parse_ippool(entry: Dict, idx: int) -> Optional[NATRule]:
        name = entry.get("key", f"ippool_{idx}")
        sets = entry.get("sets", {})
        pool_type = sets.get("type", "overload").lower()
        nat_type = NATType.PAT if pool_type == "overload" else NATType.DYNAMIC
        startip = sets.get("startip", "")
        endip = sets.get("endip", "")
        if not startip:
            return None
        trans_src = startip if not endip or startip == endip else f"{startip}-{endip}"
        return NATRule(
            name=name,
            nat_type=nat_type,
            translated_src=trans_src,
            description=sets.get("comments", ""),
            order=idx,
        )

    # ------------------------------------------------------------------ CENTRAL SNAT
    @staticmethod
    def _parse_central_snat(entry: Dict, idx: int) -> Optional[NATRule]:
        sets = entry.get("sets", {})
        src_addr = sets.get("srcaddr", "")
        dst_addr = sets.get("dstaddr", "")
        nat_ippool = sets.get("nat-ippool", "")
        src_iface = sets.get("srcintf", "")
        dst_iface = sets.get("dstintf", "")

        return NATRule(
            name=f"central_snat_{entry.get('key', idx)}",
            nat_type=NATType.PAT if nat_ippool else NATType.DYNAMIC,
            src_interface=src_iface,
            dst_interface=dst_iface,
            original_src=src_addr or None,
            original_dst=dst_addr or None,
            translated_src=nat_ippool or None,
            order=idx,
        )
