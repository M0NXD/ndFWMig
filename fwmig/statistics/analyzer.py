"""Configuration statistics and migration complexity analysis."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from ..models.common import FirewallConfig, AccessRule, NATType


@dataclass
class ConfigStats:
    # Counts
    interface_count: int = 0
    network_object_count: int = 0
    service_object_count: int = 0
    object_group_count: int = 0
    network_group_count: int = 0
    service_group_count: int = 0
    acl_count: int = 0              # distinct ACL names
    rule_count: int = 0             # total ACEs / security rules
    permit_count: int = 0
    deny_count: int = 0
    disabled_rule_count: int = 0
    nat_rule_count: int = 0
    static_nat_count: int = 0
    dynamic_nat_count: int = 0
    pat_count: int = 0
    route_count: int = 0
    default_route_count: int = 0

    # Quality metrics
    logged_rule_count: int = 0
    unlogged_rule_count: int = 0
    logging_coverage_pct: float = 0.0
    any_any_rule_count: int = 0     # rules with any src and any dst
    unnamed_rule_count: int = 0
    duplicate_rule_count: int = 0
    shadowed_rule_count: int = 0

    # Complexity
    unique_protocols: List[str] = field(default_factory=list)
    unique_acl_names: List[str] = field(default_factory=list)
    complexity_score: int = 0       # 0-100
    # Rule density: how many rules per ACL / zone-pair
    rules_per_acl: Dict[str, int] = field(default_factory=dict)
    largest_acl: str = ""
    largest_acl_size: int = 0

    # Migration issues
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    migration_risks: List[Tuple[str, str]] = field(default_factory=list)  # (rule_name, risk)

    # Protocol breakdown
    protocol_breakdown: Dict[str, int] = field(default_factory=dict)
    # Zone/interface usage
    zone_usage: Dict[str, int] = field(default_factory=dict)
    # Object type breakdown
    object_type_breakdown: Dict[str, int] = field(default_factory=dict)


class ConfigAnalyzer:
    """Analyse a FirewallConfig and produce ConfigStats."""

    def analyse(self, cfg: FirewallConfig) -> ConfigStats:
        stats = ConfigStats()
        stats.warnings = list(cfg.parse_warnings)
        stats.errors = list(cfg.parse_errors)

        # Interfaces
        stats.interface_count = len(cfg.interfaces)

        # Objects
        stats.network_object_count = len(cfg.network_objects)
        stats.service_object_count = len(cfg.service_objects)
        stats.object_group_count   = len(cfg.object_groups)
        stats.network_group_count  = sum(1 for g in cfg.object_groups if g.group_type == "network")
        stats.service_group_count  = sum(1 for g in cfg.object_groups if g.group_type == "service")

        # Object type breakdown
        for obj in cfg.network_objects:
            key = obj.obj_type.value
            stats.object_type_breakdown[key] = stats.object_type_breakdown.get(key, 0) + 1

        # Routes
        stats.route_count = len(cfg.routes)
        stats.default_route_count = sum(1 for r in cfg.routes if r.is_default)

        # NAT
        stats.nat_rule_count  = len(cfg.nat_rules)
        stats.static_nat_count  = sum(1 for n in cfg.nat_rules if n.nat_type == NATType.STATIC)
        stats.dynamic_nat_count = sum(1 for n in cfg.nat_rules if n.nat_type == NATType.DYNAMIC)
        stats.pat_count         = sum(1 for n in cfg.nat_rules if n.nat_type == NATType.PAT)

        # Access rules
        acl_names: set = set()
        protocols: set = set()
        seen_sigs: set = set()
        permit_sigs: list = []

        stats.rule_count = len(cfg.access_rules)
        for rule in cfg.access_rules:
            if rule.acl_name:
                acl_names.add(rule.acl_name)

            if rule.action == "permit":
                stats.permit_count += 1
            else:
                stats.deny_count += 1

            if not rule.enabled:
                stats.disabled_rule_count += 1

            if rule.logging:
                stats.logged_rule_count += 1

            # any/any detection
            src_any = any(a in ("any", "any4", "any6", "all", "") for a in rule.src_address) or not rule.src_address
            dst_any = any(a in ("any", "any4", "any6", "all", "") for a in rule.dst_address) or not rule.dst_address
            if src_any and dst_any and rule.protocol in ("ip", "any", ""):
                stats.any_any_rule_count += 1
                if rule.action == "permit":
                    stats.migration_risks.append((rule.name, "permit any-any rule — security risk"))

            # Unnamed rules
            if not rule.description and rule.name.startswith(("_", "rule_", "policy_")):
                stats.unnamed_rule_count += 1

            # Duplicate detection (same zones+src+dst+service+action).
            # Zones are part of the key so rules in different zone pairs aren't
            # mistaken for duplicates (they have None zones on Cisco, so this is
            # a no-op there).
            sig = (
                rule.src_zone,
                rule.dst_zone,
                tuple(sorted(rule.src_address)),
                tuple(sorted(rule.dst_address)),
                tuple(sorted(rule.service)),
                rule.protocol,
                rule.action,
            )
            if sig in seen_sigs:
                stats.duplicate_rule_count += 1
                stats.migration_risks.append((rule.name, "potential duplicate rule"))
            seen_sigs.add(sig)

            protocols.add(rule.protocol)

            # Protocol breakdown
            stats.protocol_breakdown[rule.protocol] = \
                stats.protocol_breakdown.get(rule.protocol, 0) + 1

            # Zone usage
            for zone in filter(None, [rule.src_zone, rule.dst_zone]):
                for z in zone.split(","):
                    z = z.strip()
                    if z:
                        stats.zone_usage[z] = stats.zone_usage.get(z, 0) + 1

        stats.unique_acl_names = sorted(acl_names)
        stats.acl_count = len(acl_names) or 1
        stats.unique_protocols = sorted(protocols)

        # Logging coverage
        stats.unlogged_rule_count = stats.rule_count - stats.logged_rule_count
        stats.logging_coverage_pct = (
            round(stats.logged_rule_count / stats.rule_count * 100, 1)
            if stats.rule_count else 0.0
        )

        # Rules per ACL / zone-pair
        for rule in cfg.access_rules:
            key = rule.acl_name or (
                f"{rule.src_zone or '?'}->{rule.dst_zone or '?'}"
                if (rule.src_zone or rule.dst_zone) else "__default__"
            )
            stats.rules_per_acl[key] = stats.rules_per_acl.get(key, 0) + 1
        if stats.rules_per_acl:
            stats.largest_acl = max(stats.rules_per_acl, key=lambda k: stats.rules_per_acl[k])
            stats.largest_acl_size = stats.rules_per_acl[stats.largest_acl]

        # Shadowing detection (improved — permit-over-permit and permit-over-deny)
        self._detect_shadowing(cfg.access_rules, stats)

        # Complexity score (0-100)
        stats.complexity_score = self._complexity_score(cfg, stats)

        # Platform-specific risk warnings
        self._platform_risks(cfg, stats)

        return stats

    # ------------------------------------------------------------------ shadowing
    @staticmethod
    def _detect_shadowing(rules: List[AccessRule], stats: ConfigStats) -> None:
        """
        Shadowing detection:
        1. Any rule following a permit any-any in the same ACL/policy set is shadowed.
        2. A permit rule that is an exact duplicate of an earlier permit is redundant.
        """
        # Group rules the way they are actually evaluated: a Cisco ACL, or — for
        # zone-based platforms — a single zone pair. Without the zone-pair key,
        # an any-any permit in one zone pair would wrongly "shadow" rules in
        # every other zone pair.
        acl_rules: Dict[str, List[AccessRule]] = {}
        for rule in rules:
            key = rule.acl_name or (
                f"{rule.src_zone or '?'}->{rule.dst_zone or '?'}"
                if (rule.src_zone or rule.dst_zone) else "__default__"
            )
            acl_rules.setdefault(key, []).append(rule)

        for acl, ruleset in acl_rules.items():
            found_any_any_permit = False
            earlier_permit_sigs: set = set()
            for rule in ruleset:
                src_any = not rule.src_address or all(a in ("any", "any4", "any6", "all") for a in rule.src_address)
                dst_any = not rule.dst_address or all(a in ("any", "any4", "any6", "all") for a in rule.dst_address)
                svc_any = not rule.service or rule.service == ["any"]
                proto_any = rule.protocol in ("ip", "any", "")

                if found_any_any_permit:
                    stats.shadowed_rule_count += 1
                    stats.migration_risks.append(
                        (rule.name, f"shadowed by earlier permit any-any in ACL/policy '{acl}'")
                    )

                elif rule.action == "permit":
                    # Permit-over-permit: exact same match criteria (redundant)
                    sig = (
                        frozenset(rule.src_address),
                        frozenset(rule.dst_address),
                        frozenset(rule.service),
                        rule.protocol,
                    )
                    if sig in earlier_permit_sigs:
                        stats.shadowed_rule_count += 1
                        stats.migration_risks.append(
                            (rule.name, f"redundant permit — identical earlier permit exists in '{acl}'")
                        )
                    else:
                        earlier_permit_sigs.add(sig)

                if src_any and dst_any and svc_any and proto_any and rule.action == "permit":
                    found_any_any_permit = True

    # ------------------------------------------------------------------ complexity
    @staticmethod
    def _complexity_score(cfg: FirewallConfig, stats: ConfigStats) -> int:
        score = 0
        # Rule count (0-30)
        score += min(30, stats.rule_count // 10)
        # NAT complexity (0-20)
        score += min(20, stats.nat_rule_count * 2)
        # Object/group complexity (0-20); nested groups add extra weight
        group_names = {g.name for g in cfg.object_groups}
        nesting_bonus = sum(
            1 for g in cfg.object_groups
            if any(m in group_names for m in g.members)
        )
        score += min(20, (stats.network_object_count + stats.object_group_count + nesting_bonus * 2) // 5)
        # Parse errors (0-15)
        score += min(15, len(stats.errors) * 5)
        # Migration risks (0-10)
        score += min(10, len(stats.migration_risks))
        # Unlogged rules (0-5) — indicates poor hygiene
        if stats.rule_count:
            unlogged_pct = stats.unlogged_rule_count / stats.rule_count
            score += round(unlogged_pct * 5)
        return min(100, score)

    # ------------------------------------------------------------------ platform risks
    @staticmethod
    def _platform_risks(cfg: FirewallConfig, stats: ConfigStats) -> None:
        from ..models.common import Platform
        if cfg.platform == Platform.PALO_ALTO:
            for rule in cfg.access_rules:
                if rule.application and rule.application != ["any"]:
                    stats.migration_risks.append(
                        (rule.name,
                         f"Uses App-ID [{', '.join(rule.application)}] — no direct mapping to ACL-based platforms")
                    )
        if cfg.platform in (Platform.CISCO_ASA, Platform.CISCO_FWSM, Platform.CISCO_FTD):
            # Warn about zone-less rules when targeting zone-based platforms
            for rule in cfg.access_rules:
                if not rule.src_zone and not rule.dst_zone:
                    # Only warn once
                    stats.warnings.append(
                        "Source config uses interface-bound ACLs with no explicit zones — "
                        "manual zone assignment required for zone-based target platforms."
                    )
                    break
