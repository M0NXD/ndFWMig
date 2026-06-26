"""
Intermediate Representation (IR) — platform-agnostic firewall config model.
All parsers produce this; all generators consume it.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


class Platform(str, Enum):
    CISCO_ASA   = "Cisco ASA"
    CISCO_FWSM  = "Cisco FWSM"
    CISCO_FTD   = "Cisco FTD"
    PALO_ALTO   = "Palo Alto PAN-OS"
    FORTIGATE   = "FortiGate FortiOS"


# Version sets for each platform — ordered newest-first for display
PLATFORM_VERSIONS: Dict[Platform, List[str]] = {
    # ASA: 9.24 is the current latest (as of mid-2026); Cisco is sunsetting ASA toward FTD
    Platform.CISCO_ASA:  ["9.24", "9.23", "9.22", "9.21", "9.20",
                           "9.19", "9.18", "9.16", "9.14", "9.12", "9.8", "9.6",
                           "9.4", "9.2", "9.1", "9.0", "8.6", "8.4",
                           "8.3", "8.2", "8.0", "7.x"],
    Platform.CISCO_FWSM: ["4.1", "4.0", "3.2", "3.1", "3.0", "2.3"],
    # FTD: 10.0 released Dec 2025 (new major version, 66-month lifecycle);
    #       7.7 released 2025; 7.6 current recommended (7.6.4); 7.4 LTS
    Platform.CISCO_FTD:  ["10.0", "7.7", "7.6", "7.4", "7.2", "7.0", "6.7", "6.6", "6.4", "6.2", "6.0"],
    # PAN-OS: 12.1 released May 2026; 11.2 released May 2024
    Platform.PALO_ALTO:  ["12.1", "11.2", "11.1", "11.0", "10.2", "10.1", "10.0",
                           "9.1", "9.0", "8.1", "8.0"],
    # FortiOS: 8.0 released March 2026 (AI Fabric, quantum-safe);
    #          7.6 active maintenance branch (7.6.5 current as of mid-2026)
    Platform.FORTIGATE:  ["8.0", "7.6", "7.4", "7.2", "7.0", "6.4", "6.2", "6.0",
                           "5.6", "5.4", "5.2", "5.0"],
}

# Notes on what changed in newer versions (used by GUI tooltips / warnings)
VERSION_NOTES: Dict[str, str] = {
    # Cisco ASA
    "ASA:9.24": "ASA 9.24 — Current latest release. NAT/ACL/object syntax unchanged from 9.20.",
    "ASA:9.23": (
        "ASA 9.23 — Old SSH stack deprecated; Cisco SSH stack is now the only supported stack. "
        "NAT/ACL/object syntax unchanged."
    ),
    "ASA:9.22": (
        "ASA 9.22 — Firepower 2100 dropped (last supported by 9.20). "
        "NAT/ACL/object syntax unchanged."
    ),
    "ASA:9.21": "ASA 9.21 — Maintenance release. NAT/ACL/object syntax unchanged.",
    "ASA:9.20": "ASA 9.20 — Last version to support Firepower 2100. NAT/ACL/object syntax unchanged.",
    "ASA:9.19": (
        "ASA 9.19 — End-of-Sale Nov 2025. Cisco sunsetting ASA; recommend migrating to FTD. "
        "CLI syntax unchanged from 9.18."
    ),
    "ASA:9.18": "ASA 9.18 — End-of-Sale Nov 2025. Same syntax as 9.16.",
    # Cisco FTD
    "FTD:10.0": (
        "FTD 10.0 (Dec 2025) — New major version with 66-month support lifecycle. "
        "Key additions: FTD Model Migration Wizard (hardware platform migration), "
        "Dynamic Firewall (user trust scores), Enhanced EVE, SnortML. "
        "LINA/ASA CLI syntax is UNCHANGED from 7.x — all new features are FMC-managed."
    ),
    "FTD:7.7": (
        "FTD 7.7 — Enhanced SNORT 3 rules, TLS fingerprint inspection. "
        "LINA/ASA CLI syntax unchanged; FMC API additions."
    ),
    "FTD:7.6": (
        "FTD 7.6 — Current recommended release (7.6.4). "
        "Encrypted visibility engine, SD-WAN policy enhancements. "
        "LINA CLI syntax unchanged from 7.4."
    ),
    "FTD:7.4": "FTD 7.4 — LTS branch; Secure Firewall 4200 series support.",
    # PAN-OS
    "PAN-OS:12.1": "PAN-OS 12.1 (May 2026) — AI-Ops enhancements, same XML policy schema as 11.x",
    "PAN-OS:11.2": "PAN-OS 11.2 (May 2024) — Enhanced SCTP App-ID, same XML schema as 11.x",
    "PAN-OS:11.1": "PAN-OS 11.1 (Nov 2023) — Zone-based enhanced protection, same schema as 11.0",
    "PAN-OS:10.2": "PAN-OS 10.2 — Advanced DNS security, same schema as 10.x",
    "PAN-OS:9.1":  "PAN-OS 9.1 — Added ip-wildcard address type",
    # FortiOS
    "FortiOS:8.0": (
        "FortiOS 8.0 (Mar 2026) — AI Fabric agents, quantum-safe VPN defaults. "
        "Firewall policy CLI structure unchanged from 7.x. "
        "New: 'config system sdwan' replaces 'config system virtual-wan-link' (already done in 7.0). "
        "IKE DH group defaults changed (phase1/2 now group 20/21)."
    ),
    "FortiOS:7.6": (
        "FortiOS 7.6 — ZTNA full integration, CASB profiles in policy, "
        "SD-WAN application steering improvements. "
        "Policy: new 'set casb-profile' and 'set ztna-device-ownership' fields."
    ),
    "FortiOS:7.4": "FortiOS 7.4 — SD-WAN enhancements, ZTNA tags in policy",
    "FortiOS:7.2": "FortiOS 7.2 — ZTNA access proxy, inline CASB",
    "FortiOS:7.0": "FortiOS 7.0 — SD-WAN renamed from virtual-wan-link, ZTNA introduced",
}


class ObjectType(str, Enum):
    HOST    = "host"
    NETWORK = "network"
    RANGE   = "range"
    FQDN    = "fqdn"
    ANY     = "any"


class ServiceProtocol(str, Enum):
    TCP   = "tcp"
    UDP   = "udp"
    ICMP  = "icmp"
    ICMP6 = "icmp6"
    IP    = "ip"
    ESP   = "esp"
    AH    = "ah"
    GRE   = "gre"
    SCTP  = "sctp"


class NATType(str, Enum):
    STATIC       = "static"
    DYNAMIC      = "dynamic"
    PAT          = "pat"
    DYNAMIC_PAT  = "dynamic-pat"
    IDENTITY     = "identity"


@dataclass
class NetworkObject:
    name: str
    obj_type: ObjectType = ObjectType.HOST
    # For host: single IP; for network: CIDR or "addr mask"; for range: "start end"
    value: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def to_cidr(self) -> str:
        """Best-effort CIDR representation."""
        if self.obj_type == ObjectType.HOST:
            return f"{self.value}/32"
        if self.obj_type == ObjectType.NETWORK and " " in self.value:
            from ..util.netaddr import mask_to_prefix
            addr, mask = self.value.split(None, 1)
            return f"{addr}/{mask_to_prefix(mask)}"
        return self.value


@dataclass
class ServiceObject:
    name: str
    protocol: str = "tcp"
    src_port: Optional[str] = None   # "80" | "1024-65535" | None
    dst_port: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class ObjectGroup:
    name: str
    group_type: str = "network"      # 'network' | 'service' | 'protocol' | 'icmp-type' | 'application'
    members: List[str] = field(default_factory=list)  # names of objects or inline values
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class AccessRule:
    # Unique name/id within the config (may be auto-generated for unnamed ACEs)
    name: str
    action: str = "permit"           # 'permit' | 'deny'
    protocol: str = "ip"

    # Zone-based (Palo Alto / FTD / FortiGate)
    src_zone: Optional[str] = None
    dst_zone: Optional[str] = None

    # Address refs — names of objects/groups or "any" / inline CIDR
    src_address: List[str] = field(default_factory=list)
    dst_address: List[str] = field(default_factory=list)
    src_negated: bool = False
    dst_negated: bool = False

    # Service refs — names of service objects/groups or "any"
    service: List[str] = field(default_factory=list)
    application: List[str] = field(default_factory=list)   # Palo Alto app-id

    # Logging
    logging: bool = False
    log_level: str = "informational"
    log_start: bool = False

    enabled: bool = True
    description: str = ""
    tags: List[str] = field(default_factory=list)

    # Source tracking
    acl_name: Optional[str] = None   # Cisco ACL name this ACE belongs to
    sequence: Optional[int] = None   # line number within the ACL


@dataclass
class AclBinding:
    """
    Binds an ACL (by name) to an interface and direction.

    On Cisco this is the 'access-group' command:
        access-group <acl> in  interface <nameif>   -> direction='in',  interface=<nameif>
        access-group <acl> out interface <nameif>   -> direction='out', interface=<nameif>
        access-group <acl> global                    -> direction='global', interface=None

    Zone-based platforms (PAN-OS / FortiGate) express the same intent per-rule via
    src_zone/dst_zone, so generators for those targets translate a binding into the
    rule's ingress (in) or egress (out) interface.
    """
    acl_name: str
    interface: Optional[str] = None   # nameif / zone; None means "global"
    direction: str = "in"             # 'in' | 'out' | 'global'


@dataclass
class NATRule:
    name: str
    nat_type: NATType = NATType.STATIC
    order: int = 0

    # Interfaces / zones
    src_interface: Optional[str] = None
    dst_interface: Optional[str] = None

    # Original traffic
    original_src: Optional[str] = None    # object/group name or inline addr
    original_dst: Optional[str] = None
    original_service: Optional[str] = None

    # Translated traffic
    translated_src: Optional[str] = None
    translated_dst: Optional[str] = None
    translated_service: Optional[str] = None

    bidirectional: bool = False
    no_proxy_arp: bool = False
    route_lookup: bool = False
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class Interface:
    name: str                            # physical name, e.g. "GigabitEthernet0/0"
    nameif: Optional[str] = None         # logical name, e.g. "outside"
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    prefix_len: Optional[int] = None
    security_level: Optional[int] = None
    description: str = ""
    enabled: bool = True
    vlan: Optional[int] = None
    zone: Optional[str] = None           # Palo Alto / FortiGate zone
    mtu: Optional[int] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class Zone:
    """
    A security zone that groups one or more interfaces.

    Used by zone-based platforms:
      - FortiGate : 'config system zone' (members are interface names, e.g. port1)
      - PAN-OS    : <zone> section (members are layer3 interface names)

    Interface-based platforms (Cisco ASA/FWSM/FTD) have no zone construct; when a
    target is interface-based, a zone is resolved to its member interfaces by the
    interface-mapping transform (see fwmig/transform/interface_map.py).
    """
    name: str
    interfaces: List[str] = field(default_factory=list)   # member interface identifiers
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class Route:
    network: str
    mask: str                            # dotted-decimal or prefix len as str
    next_hop: str
    interface: Optional[str] = None
    metric: int = 1
    is_default: bool = False
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class FirewallConfig:
    """Top-level container produced by every parser."""
    platform: Platform
    version: str                         # version string as selected by user

    hostname: str = ""
    domain_name: str = ""

    interfaces: List[Interface]     = field(default_factory=list)
    zones: List[Zone]               = field(default_factory=list)
    network_objects: List[NetworkObject]  = field(default_factory=list)
    service_objects: List[ServiceObject]  = field(default_factory=list)
    object_groups: List[ObjectGroup]      = field(default_factory=list)
    access_rules: List[AccessRule]        = field(default_factory=list)
    acl_bindings: List[AclBinding]        = field(default_factory=list)
    nat_rules: List[NATRule]             = field(default_factory=list)
    routes: List[Route]                  = field(default_factory=list)

    # Raw lines for display / fallback
    raw_lines: List[str] = field(default_factory=list)

    # Parser diagnostics
    parse_warnings: List[str] = field(default_factory=list)
    parse_errors: List[str]   = field(default_factory=list)
    unparsed_lines: List[str] = field(default_factory=list)

    # Any extra platform-specific metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
