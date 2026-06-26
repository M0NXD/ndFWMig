"""
Cisco FTD parser.

FTD CLI (LINA) is almost identical to ASA 9.x for most features.
FTD 6.x+ adds:
  - 'access-group' with 'global' keyword
  - Prefilter policies (not in CLI)
  - 'object network' / 'object service' unchanged
  - Some additional inspection commands
  - FlexConfig wrapper blocks (begin/end markers)
FTD 7.x adds:
  - snort3 references in show output
  - 'policy-map' AVC changes
  - Dynamic NAT / PAT pool enhancements

We reuse the ASA 9.x parser and post-process FTD-specific constructs.
"""

from __future__ import annotations
from .cisco_asa import CiscoASAParser
from ..models.common import FirewallConfig, Platform


class CiscoFTDParser(CiscoASAParser):
    """FTD inherits ASA parsing; always uses new-style NAT."""

    def __init__(self, version: str) -> None:
        super().__init__(version)
        self._old_nat = False   # FTD always 8.3+ NAT

    def parse(self, text: str) -> FirewallConfig:
        # Strip FlexConfig wrappers before passing to ASA parser
        clean_text = self._strip_flexconfig(text)
        cfg = super().parse(clean_text)
        cfg.platform = Platform.CISCO_FTD
        cfg.version = self.version
        # 'access-group ... global' and 'access-group ... in/out interface ...' are
        # both handled by the shared ASA parse loop (-> cfg.acl_bindings).
        return cfg

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _strip_flexconfig(text: str) -> str:
        """Remove FlexConfig begin/end markers."""
        lines = []
        in_flex = False
        for line in text.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("flexconfig ") or stripped == "flexconfig":
                in_flex = True
                continue
            if in_flex and stripped == "end":
                in_flex = False
                continue
            if not in_flex:
                lines.append(line)
        return "\n".join(lines)
