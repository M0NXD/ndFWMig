"""
Cisco FWSM parser.

FWSM is largely ASA-like but predates ASA 8.3 NAT changes and has
some differences in object-group handling and ACL syntax.

Version matrix:
  2.3 — very limited object-group support
  3.x — object-groups, ACLs mostly like ASA 7.x
  4.x — closer to ASA 8.2; still old-NAT only
"""

from __future__ import annotations
from .cisco_asa import CiscoASAParser
from ..models.common import FirewallConfig, Platform


class CiscoFWSMParser(CiscoASAParser):
    """
    FWSM reuses the ASA parser with old-NAT enforced and a few overrides.
    FWSM never got the 8.3+ NAT syntax.
    """

    def __init__(self, version: str) -> None:
        super().__init__(version)
        # FWSM always uses old NAT syntax regardless of version
        self._old_nat = True

    def parse(self, text: str) -> FirewallConfig:
        cfg = super().parse(text)
        cfg.platform = Platform.CISCO_FWSM
        cfg.version = self.version

        # FWSM-specific fixups
        self._fixup_fwsm(cfg)
        return cfg

    @staticmethod
    def _fixup_fwsm(cfg: FirewallConfig) -> None:
        """
        FWSM differences vs ASA:
        - 'fixup protocol' commands instead of 'inspect' (version 2.x/3.x)
        - No support for 'object network' (only object-group)
        - Slight ACL syntax differences (same tokens, different ordering sometimes)
        We flag anything that looks like FTD/ASA 9.x feature usage.
        """
        for rule in cfg.access_rules:
            if "object-group-security" in (rule.description or ""):
                cfg.parse_warnings.append(
                    f"Rule '{rule.name}' uses object-group-security - not supported in FWSM."
                )
