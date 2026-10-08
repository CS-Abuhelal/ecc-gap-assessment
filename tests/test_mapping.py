from ecc.mapping import (
    checks_by_control,
    controls_for,
    duplicate_rules,
    facts_by_control,
    rule_for,
    unmapped_checks,
    unused_rules,
)
from ecc.models import CisCheck, CisPolicy, Mapping, Rule


def rule(cis: str, *ecc: str) -> Rule:
    return Rule(cis=cis, ecc=ecc or ("2-3-2",), why="Test rule.")


RULES = (rule("1", "2-2-3"), rule("1.1", "2-2-1"), rule("1.10", "2-5-3"), rule("17", "2-12-3"))


def test_the_longest_matching_rule_wins():
    assert rule_for("1.1.3", RULES).cis == "1.1"
    assert rule_for("1.2.1", RULES).cis == "1"


def test_matching_uses_whole_parts():
    assert rule_for("1.10.1", RULES).cis == "1.10"
    assert rule_for("11.1", RULES) is None


def test_a_full_cis_id_targets_one_check():
    rules = (*RULES, rule("1.1.3", "2-12-3"))
    assert rule_for("1.1.3", rules).cis == "1.1.3"
    assert rule_for("1.1.4", rules).cis == "1.1"


def test_checks_are_grouped_by_control(dataset):
    found = checks_by_control(dataset.policy, dataset.mapping)
    assert [check.id for check in found["2-2-3"]] == [26000, 26001]
    assert [check.id for check in found["2-12-3"]] == [26139, 26140]
    assert unmapped_checks(dataset.policy, dataset.mapping) == []


def test_controls_for_returns_the_rule_targets(dataset):
    assert controls_for(dataset.policy.checks[0], dataset.mapping) == ("2-2-3",)


def test_unmapped_checks_unused_and_duplicate_rules():
    policy = CisPolicy(
        policy={"id": "p", "name": "P"},
        checks=[CisCheck(id=1, cis="1.1.1", title="a"), CisCheck(id=2, cis="5.1", title="b")],
    )
    mapping = Mapping(rules=[rule("1"), rule("1.1"), rule("1.1"), rule("9")])
    assert [check.id for check in unmapped_checks(policy, mapping)] == [2]
    assert [r.cis for r in unused_rules(policy, mapping)] == ["1", "9"]
    assert duplicate_rules(mapping) == ["1.1"]


def test_facts_are_grouped_by_control(dataset):
    assert facts_by_control(dataset.mapping) == {"2-12-3": ["log_retention"]}
