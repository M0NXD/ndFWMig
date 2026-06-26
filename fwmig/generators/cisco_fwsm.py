"""Generate Cisco FWSM configurations (always old-NAT syntax)."""

from __future__ import annotations
from .cisco_asa import CiscoASAGenerator
from ..models.common import FirewallConfig, Platform


class CiscoFWSMGenerator(CiscoASAGenerator):
    def __init__(self, version: str) -> None:
        super().__init__(version)
        self._old_nat = True   # FWSM never got new NAT

    def generate(self, cfg: FirewallConfig) -> str:
        text = super().generate(cfg)
        # Replace header comment
        lines = text.splitlines()
        lines[0] = f"! Generated for Cisco FWSM {self.version}"
        lines[1] = f"! Source: {cfg.platform.value} {cfg.version}"

        # FWSM does not support 'object network/service' - comment out the whole
        # block (header + indented sub-commands), not just the header line.
        out = []
        in_object = False
        for line in lines:
            if line.startswith("object network ") or line.startswith("object service "):
                in_object = True
                out.append("! FWSM does not support object definitions - manual conversion needed")
                out.append(f"! {line}")
                self._warn(f"FWSM does not support 'object network/service' - convert manually: {line}")
                continue
            if in_object:
                # Continuation lines are indented; a non-indented (non-empty) line ends the block.
                if line[:1].isspace():
                    out.append(f"! {line.strip()}")
                    continue
                in_object = False
            out.append(line)
        return "\n".join(out)
