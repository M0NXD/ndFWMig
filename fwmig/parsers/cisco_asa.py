"""
Cisco ASA parser.

Version matrix handled:
  7.x / 8.0-8.2   — old NAT (global / nat / static commands)
  8.3+             — new object NAT + twice NAT
  9.x              — same as 8.3+ with additions (object-group-security, etc.)
"""

from __future__ import annotations
import re
from typing import Optional, List, Tuple

from .base import BaseParser
from ..models.common import (
    FirewallConfig, NetworkObject, ServiceObject, ObjectGroup,
    AccessRule, AclBinding, NATRule, Interface, Route,
    Platform, ObjectType, NATType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _port_str(tok: str) -> str:
    """Normalise port token — handles named ports."""
    NAMED = {
        "www": "80", "http": "80", "https": "443", "ftp": "21",
        "ftp-data": "20", "telnet": "23", "ssh": "22", "smtp": "25",
        "pop3": "110", "imap4": "143", "dns": "53", "domain": "53",
        "ntp": "123", "snmp": "161", "bgp": "179", "ldap": "389",
        "sqlnet": "1521", "ms-sql": "1433", "netbios-ssn": "139",
        "netbios-ns": "137", "netbios-dgm": "138",
        "aol": "5190", "rtsp": "554", "sip": "5060", "h323": "1720",
        "kerberos": "88", "radius": "1645", "tacacs": "49",
        "talk": "517", "uucp": "540", "lotusnotes": "1352",
        "pptp": "1723", "citrix-ica": "1494", "msrpc": "135",
    }
    return NAMED.get(tok.lower(), tok)


def _parse_port_spec(tokens: List[str], idx: int) -> Tuple[Optional[str], int]:
    """
    Parse optional port specifier starting at tokens[idx].
    Returns (port_string, new_idx).
    port_string examples: "80", "1024-65535", "!80"
    """
    if idx >= len(tokens):
        return None, idx
    op = tokens[idx].lower()
    if op == "eq" and idx + 1 < len(tokens):
        return _port_str(tokens[idx + 1]), idx + 2
    if op == "range" and idx + 2 < len(tokens):
        return f"{_port_str(tokens[idx+1])}-{_port_str(tokens[idx+2])}", idx + 3
    if op in ("lt", "gt", "neq") and idx + 1 < len(tokens):
        port = _port_str(tokens[idx + 1])
        if op == "lt":
            port = f"1-{int(port)-1}" if port.isdigit() else port
        elif op == "gt":
            port = f"{int(port)+1}-65535" if port.isdigit() else port
        elif op == "neq":
            port = f"!{port}"
        return port, idx + 2
    return None, idx


def _parse_addr_spec(tokens: List[str], idx: int) -> Tuple[str, Optional[str], int]:
    """
    Parse an address specifier in an access-list line.
    Returns (address_str, mask_str_or_None, new_idx).
    Handles: any | any4 | any6 | host <ip> | <ip> <wildcard> | object <name> | object-group <name>
    """
    if idx >= len(tokens):
        return "any", None, idx
    tok = tokens[idx].lower()
    if tok in ("any", "any4", "any6"):
        return "any", None, idx + 1
    if tok == "host" and idx + 1 < len(tokens):
        return tokens[idx + 1], None, idx + 2
    if tok in ("object", "object-group") and idx + 1 < len(tokens):
        return tokens[idx + 1], None, idx + 2
    if tok == "interface" and idx + 1 < len(tokens):
        return f"interface:{tokens[idx+1]}", None, idx + 2
    # ip + wildcard
    if idx + 1 < len(tokens):
        return tokens[idx], tokens[idx + 1], idx + 2
    return tokens[idx], None, idx + 1


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class CiscoASAParser(BaseParser):
    """Parse Cisco ASA CLI configurations."""

    # Versions that use old-style NAT (global / nat / static)
    OLD_NAT_VERSIONS = {"7.x", "8.0", "8.1", "8.2"}

    def __init__(self, version: str) -> None:
        super().__init__(version)
        self._old_nat = version in self.OLD_NAT_VERSIONS or version.startswith("7")

    # ------------------------------------------------------------------
    def parse(self, text: str) -> FirewallConfig:
        cfg = FirewallConfig(platform=Platform.CISCO_ASA, version=self.version)
        cfg.raw_lines = text.splitlines()

        lines = self._clean_lines(text)
        i = 0
        pending_remarks: list[str] = []   # remarks appear BEFORE their ACE in ASA configs
        # Old-style NAT: 'nat (if) <id> ...' lines pair with 'global (if) <id> <pool>'
        # lines by id. Collect both, then link after the full pass (order-independent).
        old_nat_by_id: dict[str, list[NATRule]] = {}
        global_pools: dict[str, tuple[str, str]] = {}
        while i < len(lines):
            line = lines[i]
            low = line.lower()

            if low.startswith("hostname "):
                cfg.hostname = line.split(None, 1)[1]
                i += 1

            elif low.startswith("domain-name "):
                cfg.domain_name = line.split(None, 1)[1]
                i += 1

            elif low.startswith("interface "):
                iface, consumed = self._parse_interface(lines, i)
                cfg.interfaces.append(iface)
                i += consumed

            elif low.startswith("object network "):
                obj, consumed, inline_nat = self._parse_object_network(lines, i)
                # Re-entering 'object network X' edits the existing object (this is
                # how inline Auto-NAT is attached), so merge rather than duplicate.
                existing = next((o for o in cfg.network_objects if o.name == obj.name), None)
                if existing is not None:
                    if obj.value:
                        existing.obj_type = obj.obj_type
                        existing.value = obj.value
                    if obj.description:
                        existing.description = obj.description
                else:
                    cfg.network_objects.append(obj)
                if inline_nat:
                    cfg.nat_rules.append(inline_nat)
                i += consumed

            elif low.startswith("object service "):
                obj, consumed = self._parse_object_service(lines, i)
                cfg.service_objects.append(obj)
                i += consumed

            elif low.startswith("object-group network "):
                grp, consumed = self._parse_og_network(lines, i)
                cfg.object_groups.append(grp)
                i += consumed

            elif low.startswith("object-group service "):
                grp, consumed = self._parse_og_service(lines, i)
                cfg.object_groups.append(grp)
                i += consumed

            elif low.startswith("object-group protocol "):
                grp, consumed = self._parse_og_protocol(lines, i)
                cfg.object_groups.append(grp)
                i += consumed

            elif low.startswith("object-group icmp-type "):
                grp, consumed = self._parse_og_icmp(lines, i)
                cfg.object_groups.append(grp)
                i += consumed

            elif re.match(r"access-list\s+\S+\s+extended\s", low):
                rule = self._parse_acl_line(line, cfg)
                if rule:
                    if pending_remarks:
                        rule.description = "; ".join(pending_remarks)
                        pending_remarks.clear()
                    cfg.access_rules.append(rule)
                i += 1

            elif re.match(r"access-list\s+\S+\s+remark\s", low):
                # Buffer remark — will be attached to the *next* ACE parsed
                parts = line.split(None, 3)
                remark = parts[3] if len(parts) > 3 else ""
                pending_remarks.append(remark)
                i += 1

            # New-style NAT (8.3+)
            elif not self._old_nat and re.match(r"nat\s+\(", low):
                nat, consumed = self._parse_nat_new(lines, i)
                if nat:
                    cfg.nat_rules.append(nat)
                i += consumed

            # Old-style NAT
            elif self._old_nat and low.startswith("nat ("):
                nat, nat_id = self._parse_nat_old(line, len(cfg.nat_rules))
                if nat:
                    cfg.nat_rules.append(nat)
                    if nat_id is not None:
                        old_nat_by_id.setdefault(nat_id, []).append(nat)
                i += 1

            elif self._old_nat and low.startswith("static ("):
                nat = self._parse_static_old(line, len(cfg.nat_rules))
                if nat:
                    cfg.nat_rules.append(nat)
                i += 1

            elif self._old_nat and low.startswith("global ("):
                # global (iface) <id> {<ip>|<start>-<end>|interface}
                gm = re.match(r"global\s+\(([^)]+)\)\s+(\d+)\s+(\S+)(?:\s+(\S+))?",
                              line, re.IGNORECASE)
                if gm:
                    pool = gm.group(3)
                    if gm.group(4) and gm.group(4).lower() != "netmask":
                        pool = f"{pool}-{gm.group(4)}"
                    global_pools[gm.group(2)] = (gm.group(1), pool)
                cfg.metadata.setdefault("global_commands", []).append(line)
                i += 1

            elif low.startswith("access-group "):
                self._parse_access_group(line, cfg)
                i += 1

            elif low.startswith("route "):
                route = self._parse_route(line)
                if route:
                    cfg.routes.append(route)
                i += 1

            else:
                self._unparsed(cfg, line)
                i += 1

        # Link old-style 'global' pools to their 'nat' rules by id so the dynamic
        # translation (pool address / interface PAT) isn't lost.
        for nat_id, (g_iface, pool) in global_pools.items():
            for nat in old_nat_by_id.get(nat_id, []):
                nat.dst_interface = g_iface
                nat.translated_src = pool
                if pool.lower() == "interface":
                    nat.nat_type = NATType.PAT

        return cfg

    # ------------------------------------------------------------------ INTERFACE
    def _parse_interface(self, lines: List[str], start: int) -> Tuple[Interface, int]:
        header = lines[start]
        name = header.split(None, 1)[1] if " " in header else "unknown"
        iface = Interface(name=name)
        i = start + 1
        while i < len(lines):
            line = lines[i]
            low = line.lower().strip()
            # Any new top-level keyword ends the interface block
            if re.match(r"^(interface|object|access-list|nat|route|hostname|domain-name"
                        r"|object-group|aaa|crypto|policy-map|class-map|ip local pool"
                        r"|username|enable|banner|boot)\s", low):
                break
            if low.startswith("nameif "):
                iface.nameif = line.split(None, 1)[1]
            elif low.startswith("ip address "):
                parts = line.split()
                if len(parts) >= 4:
                    iface.ip_address = parts[2]
                    iface.subnet_mask = parts[3]
            elif low.startswith("security-level "):
                try:
                    iface.security_level = int(line.split()[1])
                except ValueError:
                    pass
            elif low.startswith("description "):
                iface.description = line.split(None, 1)[1]
            elif low == "shutdown":
                iface.enabled = False
            elif low == "no shutdown":
                iface.enabled = True
            elif low.startswith("vlan "):
                try:
                    iface.vlan = int(line.split()[1])
                except ValueError:
                    pass
            i += 1
        return iface, i - start

    # ------------------------------------------------------------------ OBJECT NETWORK
    def _parse_object_network(
        self, lines: List[str], start: int
    ) -> Tuple[NetworkObject, int, Optional[NATRule]]:
        name = lines[start].split(None, 2)[2]
        obj = NetworkObject(name=name)
        inline_nat: Optional[NATRule] = None
        i = start + 1
        while i < len(lines):
            line = lines[i]
            low = line.lower()
            if re.match(r"^(object|object-group|access-list|route|interface|hostname)\s", low):
                break
            if low.startswith("host "):
                obj.obj_type = ObjectType.HOST
                obj.value = line.split()[1]
            elif low.startswith("subnet "):
                obj.obj_type = ObjectType.NETWORK
                parts = line.split()
                obj.value = f"{parts[1]} {parts[2]}" if len(parts) >= 3 else parts[1]
            elif low.startswith("range "):
                obj.obj_type = ObjectType.RANGE
                parts = line.split()
                obj.value = f"{parts[1]}-{parts[2]}" if len(parts) >= 3 else parts[1]
            elif low.startswith("fqdn "):
                obj.obj_type = ObjectType.FQDN
                parts = line.split()
                obj.value = parts[-1]
            elif low.startswith("description "):
                obj.description = line.split(None, 1)[1]
            elif low.startswith("nat ") and not self._old_nat:
                # Inline Auto NAT (Object NAT) has 'static'|'dynamic' right after the parens:
                #   nat (src,dst) dynamic interface | dynamic <obj> | static <ip> [service ...]
                # A top-level twice (manual) NAT has 'source'/'destination' instead and must
                # NOT be consumed here — break so the main loop parses it.
                kw_m = re.match(r"nat\s+\([^)]*\)\s+(\w+)", line, re.IGNORECASE)
                kw = kw_m.group(1).lower() if kw_m else ""
                if kw in ("static", "dynamic"):
                    inline_nat = self._parse_object_nat(line, name)
                else:
                    break
            i += 1
        return obj, i - start, inline_nat

    def _parse_object_nat(self, line: str, obj_name: str) -> Optional[NATRule]:
        """
        Parse inline 'nat' sub-command inside an 'object network' block.
        nat (src_iface,dst_iface) {static|dynamic} ...
        """
        m = re.match(r"nat\s+\(([^,)]+),([^)]+)\)\s+(\w+)\s*(.*)", line, re.IGNORECASE)
        if not m:
            return None
        src_if = m.group(1).strip()
        dst_if = m.group(2).strip()
        nat_kw = m.group(3).lower()
        rest   = m.group(4).strip()

        rest_tokens = rest.split()
        trans_addr = rest_tokens[0] if rest_tokens else "interface"

        if nat_kw == "dynamic":
            nat_type = NATType.PAT if trans_addr.lower() in ("interface", "pat-pool") else NATType.DYNAMIC
        else:
            nat_type = NATType.STATIC

        # Static PAT: nat (dmz,outside) static <ip> service tcp <real> <mapped>
        # ASA emits the real service as "<proto> <real_port>" and the mapped side
        # as just the mapped port, so the generator can write "service tcp 443 8443".
        orig_svc, trans_svc = None, None
        if "service" in rest.lower() and len(rest_tokens) >= 4:
            svc_idx = next((j for j, t in enumerate(rest_tokens) if t.lower() == "service"), -1)
            if svc_idx != -1 and svc_idx + 3 < len(rest_tokens):
                orig_svc  = f"{rest_tokens[svc_idx+1]} {rest_tokens[svc_idx+2]}"
                trans_svc = rest_tokens[svc_idx+3]

        return NATRule(
            name=f"obj_nat_{obj_name}",
            nat_type=nat_type,
            src_interface=src_if,
            dst_interface=dst_if,
            original_src=obj_name,
            translated_src=trans_addr,
            original_service=orig_svc,
            translated_service=trans_svc,
        )

    # ------------------------------------------------------------------ OBJECT SERVICE
    def _parse_object_service(self, lines: List[str], start: int) -> Tuple[ServiceObject, int]:
        name = lines[start].split(None, 2)[2]
        svc = ServiceObject(name=name)
        i = start + 1
        while i < len(lines):
            line = lines[i]
            low = line.lower()
            if re.match(r"^(object|object-group|access-list|nat|route|interface|hostname)\s", low):
                break
            if low.startswith("service "):
                # Index off the lower-cased tokens so mixed-case keywords
                # ('Source'/'Destination') can't raise ValueError; port values
                # are case-insensitive so parsing them from `lparts` is safe.
                parts = line.split()
                lparts = low.split()
                if len(parts) >= 2:
                    svc.protocol = parts[1]
                if "source" in lparts:
                    idx = lparts.index("source")
                    svc.src_port, _ = _parse_port_spec(lparts, idx + 1)
                if "destination" in lparts:
                    idx = lparts.index("destination")
                    svc.dst_port, _ = _parse_port_spec(lparts, idx + 1)
                if "eq" in lparts and "destination" not in lparts and "source" not in lparts:
                    eq_idx = lparts.index("eq")
                    svc.dst_port = _port_str(lparts[eq_idx + 1]) if eq_idx + 1 < len(lparts) else None
            elif low.startswith("description "):
                svc.description = line.split(None, 1)[1]
            i += 1
        return svc, i - start

    # ------------------------------------------------------------------ OBJECT-GROUP NETWORK
    def _parse_og_network(self, lines: List[str], start: int) -> Tuple[ObjectGroup, int]:
        name = lines[start].split(None, 2)[2]
        grp = ObjectGroup(name=name, group_type="network")
        i = start + 1
        while i < len(lines):
            line = lines[i]
            low = line.lower()
            if re.match(r"^(object|object-group|access-list|nat|route|interface|hostname)\s", low):
                break
            if low.startswith("network-object host "):
                grp.members.append(f"host:{line.split()[2]}")
            elif low.startswith("network-object object "):
                grp.members.append(line.split()[2])
            elif low.startswith("network-object "):
                parts = line.split()
                if len(parts) >= 3:
                    grp.members.append(f"{parts[1]}/{self._mask_to_prefix(parts[2])}")
                else:
                    grp.members.append(parts[1])
            elif low.startswith("group-object "):
                grp.members.append(f"group:{line.split()[1]}")
            elif low.startswith("description "):
                grp.description = line.split(None, 1)[1]
            i += 1
        return grp, i - start

    # ------------------------------------------------------------------ OBJECT-GROUP SERVICE
    def _parse_og_service(self, lines: List[str], start: int) -> Tuple[ObjectGroup, int]:
        parts = lines[start].split()
        name = parts[2]
        proto = parts[3] if len(parts) > 3 else ""
        grp = ObjectGroup(name=name, group_type="service")
        if proto:
            grp.members.append(f"proto:{proto}")
        i = start + 1
        while i < len(lines):
            line = lines[i]
            low = line.lower()
            if re.match(r"^(object|object-group|access-list|nat|route|interface|hostname)\s", low):
                break
            if low.startswith("service-object "):
                grp.members.append(line.split(None, 1)[1])
            elif low.startswith("port-object "):
                grp.members.append(f"port:{line.split(None,1)[1]}")
            elif low.startswith("group-object "):
                grp.members.append(f"group:{line.split()[1]}")
            elif low.startswith("description "):
                grp.description = line.split(None, 1)[1]
            i += 1
        return grp, i - start

    # ------------------------------------------------------------------ OBJECT-GROUP PROTOCOL
    def _parse_og_protocol(self, lines: List[str], start: int) -> Tuple[ObjectGroup, int]:
        name = lines[start].split(None, 2)[2]
        grp = ObjectGroup(name=name, group_type="protocol")
        i = start + 1
        while i < len(lines):
            line = lines[i]
            low = line.lower()
            if re.match(r"^(object|object-group|access-list|nat|route|interface|hostname)\s", low):
                break
            if low.startswith("protocol-object "):
                grp.members.append(line.split()[1])
            elif low.startswith("description "):
                grp.description = line.split(None, 1)[1]
            i += 1
        return grp, i - start

    # ------------------------------------------------------------------ OBJECT-GROUP ICMP
    def _parse_og_icmp(self, lines: List[str], start: int) -> Tuple[ObjectGroup, int]:
        name = lines[start].split(None, 2)[2]
        grp = ObjectGroup(name=name, group_type="icmp-type")
        i = start + 1
        while i < len(lines):
            line = lines[i]
            low = line.lower()
            if re.match(r"^(object|object-group|access-list|nat|route|interface|hostname)\s", low):
                break
            if low.startswith("icmp-object "):
                grp.members.append(line.split()[1])
            elif low.startswith("description "):
                grp.description = line.split(None, 1)[1]
            i += 1
        return grp, i - start

    # ------------------------------------------------------------------ ACL
    def _parse_acl_line(self, line: str, cfg: FirewallConfig) -> Optional[AccessRule]:
        """
        access-list <name> extended {permit|deny} <proto>
            <src_addr> [src_port] <dst_addr> [dst_port] [log [level]]
        """
        tokens = line.split()
        if len(tokens) < 6:
            self._warn(cfg, f"Short ACL line: {line}")
            return None

        acl_name = tokens[1]
        # tokens[2] == 'extended'
        action = tokens[3].lower()
        proto = tokens[4].lower()

        idx = 5
        src_addr, src_mask, idx = _parse_addr_spec(tokens, idx)
        src_port: Optional[str] = None
        dst_port: Optional[str] = None

        if proto in ("tcp", "udp", "tcp-udp", "sctp"):
            src_port, idx = _parse_port_spec(tokens, idx)

        dst_addr, dst_mask, idx = _parse_addr_spec(tokens, idx)

        if proto in ("tcp", "udp", "tcp-udp", "sctp"):
            dst_port, idx = _parse_port_spec(tokens, idx)

        log = False
        log_level = "informational"
        while idx < len(tokens):
            tok = tokens[idx].lower()
            if tok == "log":
                log = True
                if idx + 1 < len(tokens) and tokens[idx + 1].lower() not in ("disable", "default", "inactive"):
                    log_level = tokens[idx + 1]
            elif tok == "inactive":
                action = "inactive"
            idx += 1

        # Build service string
        svc_parts = []
        if proto not in ("ip", "any"):
            svc_parts.append(proto)
        if src_port:
            svc_parts.append(f"src:{src_port}")
        if dst_port:
            svc_parts.append(f"dst:{dst_port}")
        service = [":".join(svc_parts)] if svc_parts else ["any"]

        def _combined(addr: str, mask: Optional[str]) -> str:
            if not mask:
                return addr
            # ASA *extended* ACLs use standard subnet masks (255.255.255.0 = /24),
            # NOT IOS-style wildcard masks. The prefix length is the popcount of
            # the mask: a 255.255.255.255 mask is a /32 host, 0.0.0.0 is "any".
            try:
                octets = [int(o) for o in mask.split(".")]
                prefix = sum(bin(o).count("1") for o in octets)
                if prefix >= 32:
                    # Exact host match — store as bare IP; _addr_token → "host <ip>"
                    return addr
                if prefix <= 0:
                    return "any"
                return f"{addr}/{prefix}"
            except (ValueError, AttributeError):
                return f"{addr} {mask}"

        rule_name = f"{acl_name}_{len([r for r in cfg.access_rules if r.acl_name == acl_name]) + 1}"
        rule = AccessRule(
            name=rule_name,
            action=action if action != "inactive" else "deny",
            protocol=proto,
            src_address=[_combined(src_addr, src_mask)],
            dst_address=[_combined(dst_addr, dst_mask)],
            service=service,
            logging=log,
            log_level=log_level,
            enabled=(action != "inactive"),
            acl_name=acl_name,
            sequence=len([r for r in cfg.access_rules if r.acl_name == acl_name]) + 1,
        )
        return rule

    # ------------------------------------------------------------------ ACCESS-GROUP
    def _parse_access_group(self, line: str, cfg: FirewallConfig) -> None:
        """
        access-group <acl> in  interface <nameif>
        access-group <acl> out interface <nameif>
        access-group <acl> global                    (FTD / ASA 9.x)
        """
        parts = line.split()
        if len(parts) < 3:
            self._warn(cfg, f"Short access-group line: {line}")
            return
        acl = parts[1]
        direction = parts[2].lower()
        if direction == "global":
            cfg.acl_bindings.append(
                AclBinding(acl_name=acl, interface=None, direction="global")
            )
        elif direction in ("in", "out") and len(parts) >= 5 and parts[3].lower() == "interface":
            cfg.acl_bindings.append(
                AclBinding(acl_name=acl, interface=parts[4], direction=direction)
            )
        else:
            self._warn(cfg, f"Unrecognised access-group syntax: {line}")

    # ------------------------------------------------------------------ NAT (8.3+)
    def _parse_nat_new(self, lines: List[str], start: int) -> Tuple[Optional[NATRule], int]:
        """
        nat (src_iface,dst_iface) [after-auto|1-2147483647] source {static|dynamic} ...
        Multi-line: continuation with 'destination ...' on next line(s).
        """
        line = lines[start]
        # Consume continuation lines (destination, service, etc.)
        full = line
        i = start + 1
        while i < len(lines) and lines[i].strip().startswith(("destination ", "service ", "description ")):
            full += " " + lines[i].strip()
            i += 1

        # Parse interfaces
        m = re.match(r"nat\s+\(([^,)]+),([^)]+)\)", full, re.IGNORECASE)
        if not m:
            return None, i - start

        src_iface = m.group(1).strip()
        dst_iface = m.group(2).strip()

        tokens = full.split()
        nat_idx = next((j for j, t in enumerate(tokens) if t.lower() == "source"), -1)
        if nat_idx == -1:
            return None, i - start

        nat_type_str = tokens[nat_idx + 1].lower() if nat_idx + 1 < len(tokens) else "static"
        nat_type = NATType.STATIC if nat_type_str == "static" else NATType.DYNAMIC

        # original_src is next after nat_type
        orig_src, trans_src = None, None
        orig_dst, trans_dst = None, None
        orig_svc, trans_svc = None, None

        idx2 = nat_idx + 2
        if idx2 < len(tokens):
            orig_src = tokens[idx2]
        if idx2 + 1 < len(tokens):
            trans_src = tokens[idx2 + 1]

        dest_idx = next((j for j, t in enumerate(tokens) if t.lower() == "destination"), -1)
        if dest_idx != -1:
            dest_type = tokens[dest_idx + 1].lower() if dest_idx + 1 < len(tokens) else "static"
            if dest_idx + 2 < len(tokens):
                orig_dst = tokens[dest_idx + 2]
            if dest_idx + 3 < len(tokens):
                trans_dst = tokens[dest_idx + 3]

        svc_idx = next((j for j, t in enumerate(tokens) if t.lower() == "service"), -1)
        if svc_idx != -1:
            if svc_idx + 1 < len(tokens):
                orig_svc = tokens[svc_idx + 1]
            if svc_idx + 2 < len(tokens):
                trans_svc = tokens[svc_idx + 2]

        # Detect PAT
        if trans_src and trans_src.lower() in ("interface", "pat-pool"):
            nat_type = NATType.PAT

        rule = NATRule(
            name=f"nat_{start}",
            nat_type=nat_type,
            src_interface=src_iface,
            dst_interface=dst_iface,
            original_src=orig_src,
            translated_src=trans_src,
            original_dst=orig_dst,
            translated_dst=trans_dst,
            original_service=orig_svc,
            translated_service=trans_svc,
        )
        return rule, i - start

    # ------------------------------------------------------------------ OLD NAT
    def _addr_with_mask(self, addr: str, mask: Optional[str]) -> str:
        """Combine an address and a subnet mask into CIDR form.

        Host masks (/32) and a missing mask collapse to the bare address so the
        common host case stays clean; networks keep their prefix so the mask
        survives the round-trip.
        """
        if not mask:
            return addr
        prefix = self._mask_to_prefix(mask)
        if prefix >= 32:
            return addr
        return f"{addr}/{prefix}"

    def _parse_nat_old(self, line: str, idx: int) -> Tuple[Optional[NATRule], Optional[str]]:
        """nat (inside) 1 10.0.0.0 255.255.255.0 -> (rule, nat_id)"""
        m = re.match(r"nat\s+\(([^)]+)\)\s+(\d+)\s+(\S+)(?:\s+(\S+))?", line, re.IGNORECASE)
        if not m:
            return None, None
        rule = NATRule(
            name=f"old_nat_{idx}",
            nat_type=NATType.DYNAMIC,
            src_interface=m.group(1),
            original_src=self._addr_with_mask(m.group(3), m.group(4)),
        )
        return rule, m.group(2)

    def _parse_static_old(self, line: str, idx: int) -> Optional[NATRule]:
        """static (inside,outside) 198.51.100.1 10.0.0.1 netmask 255.255.255.255"""
        m = re.match(
            r"static\s+\(([^,)]+),([^)]+)\)\s+(\S+)\s+(\S+)(?:\s+netmask\s+(\S+))?",
            line, re.IGNORECASE,
        )
        if not m:
            return None
        mask = m.group(5)
        return NATRule(
            name=f"old_static_{idx}",
            nat_type=NATType.STATIC,
            src_interface=m.group(1),
            dst_interface=m.group(2),
            translated_src=self._addr_with_mask(m.group(3), mask),
            original_src=self._addr_with_mask(m.group(4), mask),
        )

    # ------------------------------------------------------------------ ROUTE
    def _parse_route(self, line: str) -> Optional[Route]:
        """route <iface> <network> <mask> <nexthop> [metric]"""
        parts = line.split()
        if len(parts) < 5:
            return None
        return Route(
            interface=parts[1],
            network=parts[2],
            mask=parts[3],
            next_hop=parts[4],
            metric=int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 1,
            is_default=(parts[2] == "0.0.0.0"),
        )
