"""Base generator interface."""

from __future__ import annotations
from abc import ABC, abstractmethod
from ..models.common import FirewallConfig
from ..util import netaddr


class BaseGenerator(ABC):
    def __init__(self, version: str) -> None:
        self.version = version
        self._warnings: list[str] = []

    @abstractmethod
    def generate(self, cfg: FirewallConfig) -> str:
        """Generate target platform config text from a FirewallConfig."""

    @property
    def warnings(self) -> list[str]:
        return self._warnings

    def _warn(self, msg: str) -> None:
        self._warnings.append(msg)

    # Thin wrappers over fwmig.util.netaddr (kept for the many self._… call sites).
    _mask_to_prefix = staticmethod(netaddr.mask_to_prefix)
    _prefix_to_mask = staticmethod(netaddr.prefix_to_mask)
