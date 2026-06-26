"""Generate Cisco FTD configurations (ASA 9.x+ CLI / LINA syntax)."""

from __future__ import annotations
from typing import List
from .cisco_asa import CiscoASAGenerator
from ..models.common import FirewallConfig, Platform


class CiscoFTDGenerator(CiscoASAGenerator):
    def __init__(self, version: str) -> None:
        super().__init__(version)
        self._old_nat = False  # FTD always new-style NAT

    def generate(self, cfg: FirewallConfig) -> str:
        text = super().generate(cfg)
        lines = text.splitlines()
        lines[0] = f"! Generated for Cisco FTD {self.version} (LINA/FlexConfig)"
        lines[1] = f"! Source: {cfg.platform.value} {cfg.version}"

        out = [lines[0], lines[1], ""]
        # FTD doesn't allow direct interface IP via CLI - must go through FMC
        # so we wrap interface config in a FlexConfig hint
        in_iface = False
        for line in lines[2:]:
            if line.startswith("interface "):
                in_iface = True
                out.append("! NOTE: FTD interface config is managed via FMC - below is for reference only")
            if in_iface and line == "":
                in_iface = False
            out.append(line)

        # Access-group assignments. When the source carried explicit bindings
        # (cfg.acl_bindings), the base ASA generator already emitted them above.
        # Otherwise fall back to a global binding per ACL (FTD's default model).
        if not cfg.acl_bindings:
            acl_names = []
            for rule in cfg.access_rules:
                if rule.acl_name and rule.acl_name not in acl_names:
                    acl_names.append(rule.acl_name)
            if acl_names:
                out.append("")
                out.append("! Access-group assignments (apply ACLs to interfaces or globally)")
                for acl in acl_names:
                    out.append(f"access-group {acl} global")

        # Version-specific notes
        if self.version == "10.0":
            out.append("")
            out.append("! FTD 10.0 (Dec 2025): New major version - 66-month software lifecycle.")
            out.append("! LINA CLI syntax is identical to 7.x; all new features are FMC-managed:")
            out.append("!   - FTD Model Migration Wizard (hardware platform migration)")
            out.append("!   - Dynamic Firewall (user trust scores via FMC)")
            out.append("!   - Enhanced Encrypted Visibility Engine (EVE) + SnortML")
            out.append("!   - Requires FMC 10.0 for full feature support")
        elif self.version in ("7.6", "7.7"):
            out.append("")
            out.append(f"! FTD {self.version}: Manage via FMC {self.version}.x or FDM.")
            out.append("! Encrypted Visibility Engine and TLS fingerprinting configured in FMC - not in LINA CLI.")
        if self.version == "7.7":
            out.append("! FTD 7.7: Enhanced SNORT 3 rule tuning available via FMC - not in LINA config.")

        return "\n".join(out)
