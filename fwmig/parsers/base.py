"""Base parser interface."""

from __future__ import annotations
from abc import ABC, abstractmethod
from ..models.common import FirewallConfig
from ..util import netaddr


class BaseParser(ABC):
    def __init__(self, version: str) -> None:
        self.version = version

    @abstractmethod
    def parse(self, text: str) -> FirewallConfig:
        """Parse raw config text and return a FirewallConfig."""

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _warn(cfg: FirewallConfig, msg: str) -> None:
        cfg.parse_warnings.append(msg)

    @staticmethod
    def _error(cfg: FirewallConfig, msg: str) -> None:
        cfg.parse_errors.append(msg)

    @staticmethod
    def _unparsed(cfg: FirewallConfig, line: str) -> None:
        cfg.unparsed_lines.append(line)

    @staticmethod
    def _clean_lines(text: str) -> list[str]:
        """Strip blank lines and Cisco comment/banner lines, returning stripped lines.

        Cisco configs use '!' as a comment/section-divider and config dumps begin
        with ': ...' header lines ('# Saved', ': Serial Number:'). Dropping both
        keeps them out of the unparsed-line diagnostics.
        """
        lines = []
        for raw in text.splitlines():
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped.startswith("!") or stripped.startswith(":"):
                continue
            lines.append(stripped)
        return lines

    # Thin wrappers over fwmig.util.netaddr (kept for the many self._… call sites).
    _mask_to_prefix = staticmethod(netaddr.mask_to_prefix)
    _prefix_to_mask = staticmethod(netaddr.prefix_to_mask)
    _wildcard_to_mask = staticmethod(netaddr.wildcard_to_mask)

    def _version_gte(self, target: str) -> bool:
        """Return True if self.version >= target, comparing component-by-component.

        Uses tuple comparison so that e.g. 9.12 > 9.8 (which a naive float
        comparison would get wrong). Non-numeric components are treated as 0.
        """
        def _tuple(v: str) -> tuple:
            out = []
            for part in v.replace("+", "").replace("x", "0").split("."):
                try:
                    out.append(int(part))
                except ValueError:
                    out.append(0)
            return tuple(out)

        try:
            sv, tv = _tuple(self.version), _tuple(target)
            # Pad to equal length so comparison is well-defined (9.0 vs 9.0.1)
            length = max(len(sv), len(tv))
            sv += (0,) * (length - len(sv))
            tv += (0,) * (length - len(tv))
            return sv >= tv
        except Exception:
            return True
