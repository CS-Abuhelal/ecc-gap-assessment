from pathlib import Path

from ecc.load import load_catalog, load_model
from ecc.mapping import controls_for, duplicate_rules, unmapped_checks, unused_rules
from ecc.models import CisPolicy, Mapping

DATA = Path(__file__).resolve().parents[1] / "data"


def load() -> tuple[CisPolicy, Mapping]:
    policy = load_model(CisPolicy, DATA / "cis_checks.yaml")
    return policy, load_model(Mapping, DATA / "mapping.yaml")


def test_every_check_has_a_rule():
    policy, mapping = load()
    assert unmapped_checks(policy, mapping) == []


def test_every_rule_is_used_and_unique():
    policy, mapping = load()
    assert unused_rules(policy, mapping) == []
    assert duplicate_rules(mapping) == []


def test_every_target_is_a_real_control():
    _, mapping = load()
    known = {control.id for control in load_catalog(DATA / "catalog.yaml")}
    targets = {target for rule in mapping.rules for target in rule.ecc}
    targets |= {target for link in mapping.facts for target in link.ecc}
    assert targets <= known


def test_every_rule_explains_itself():
    _, mapping = load()
    assert all(len(rule.why) >= 20 for rule in mapping.rules)


def test_spot_checks():
    policy, mapping = load()
    checks = {check.id: check for check in policy.checks}
    assert controls_for(checks[26005], mapping) == ("2-2-3",)  # 1.2.1 lockout duration
    assert controls_for(checks[26138], mapping) == ("2-5-3", "2-12-3")  # 9.3.9 firewall log
    assert controls_for(checks[26139], mapping) == ("2-12-3",)  # 17.1.1 audit credentials
    assert controls_for(checks[26281], mapping) == ("2-3-2",)  # 18.9.33.6.1 standby network
    assert controls_for(checks[26285], mapping) == ("2-2-3",)  # 18.9.33.6.5 wake password
    assert controls_for(checks[26286], mapping) == ("2-2-3",)  # 18.9.33.6.6 wake password
    assert controls_for(checks[26294], mapping) == ("2-3-3",)  # 18.9.51.1.1 NTP client
    assert controls_for(checks[26403], mapping) == ("2-3-3",)  # 18.10.42.17 Defender AV
    assert controls_for(checks[26474], mapping) == ("2-3-3",)  # 18.10.92.2.1 auto updates
