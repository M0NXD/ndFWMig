"""IPv4 mask / prefix conversion helpers, shared by parsers and generators."""

from __future__ import annotations


def mask_to_prefix(mask: str) -> int:
    """Dotted-decimal subnet mask -> prefix length (popcount). Defaults to 32."""
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except Exception:
        return 32


def prefix_to_mask(prefix: int) -> str:
    """IPv4 prefix length -> dotted-decimal mask.

    Clamped to 0..32 so an out-of-range prefix (e.g. an IPv6 /64 reaching an
    IPv4 code path) degrades instead of raising 'negative shift count'.
    """
    prefix = max(0, min(32, prefix))
    mask = (0xFFFFFFFF >> (32 - prefix)) << (32 - prefix)
    return ".".join(str((mask >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def wildcard_to_mask(wildcard: str) -> str:
    """Cisco IOS wildcard mask -> subnet mask (255 - octet per byte)."""
    try:
        parts = [255 - int(o) for o in wildcard.split(".")]
        return ".".join(str(p) for p in parts)
    except Exception:
        return "255.255.255.255"
