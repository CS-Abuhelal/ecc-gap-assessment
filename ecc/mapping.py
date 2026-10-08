"""Match CIS checks to ECC controls with the rules in mapping.yaml."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from ecc.models import CisCheck, CisPolicy, FactName, Mapping, Rule


def cis_parts(cis: str) -> tuple[str, ...]:
    return tuple(cis.split("."))


def rule_for(cis: str, rules: Iterable[Rule]) -> Rule | None:
    """The rule whose CIS id is the longest whole-part prefix of `cis`."""
    target = cis_parts(cis)
    best: Rule | None = None
    for rule in rules:
        prefix = cis_parts(rule.cis)
        if target[: len(prefix)] != prefix:
            continue
        if best is None or len(prefix) > len(cis_parts(best.cis)):
            best = rule
    return best


def controls_for(check: CisCheck, mapping: Mapping) -> tuple[str, ...]:
    rule = rule_for(check.cis, mapping.rules)
    return rule.ecc if rule is not None else ()


def checks_by_control(policy: CisPolicy, mapping: Mapping) -> dict[str, list[CisCheck]]:
    found: dict[str, list[CisCheck]] = {}
    for check in policy.checks:
        for control_id in controls_for(check, mapping):
            found.setdefault(control_id, []).append(check)
    return found


def facts_by_control(mapping: Mapping) -> dict[str, list[FactName]]:
    found: dict[str, list[FactName]] = {}
    for link in mapping.facts:
        for control_id in link.ecc:
            found.setdefault(control_id, []).append(link.fact)
    return found


def unmapped_checks(policy: CisPolicy, mapping: Mapping) -> list[CisCheck]:
    return [check for check in policy.checks if rule_for(check.cis, mapping.rules) is None]


def unused_rules(policy: CisPolicy, mapping: Mapping) -> list[Rule]:
    """Rules that are never the winning rule for any check (dead or shadowed)."""
    winners = set()
    for check in policy.checks:
        rule = rule_for(check.cis, mapping.rules)
        if rule is not None:
            winners.add(rule.cis)
    return [rule for rule in mapping.rules if rule.cis not in winners]


def duplicate_rules(mapping: Mapping) -> list[str]:
    counts = Counter(rule.cis for rule in mapping.rules)
    return sorted(cis for cis, count in counts.items() if count > 1)
