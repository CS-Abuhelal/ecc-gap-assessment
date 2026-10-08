from pathlib import Path

import pytest

POLICIES = Path(__file__).resolve().parents[1] / "docs" / "policies"
EXPECTED = {
    "cybersecurity-policy.md": ["1-3-1", "1-3-3", "1-3-4", "1-9-4", "2-3-1"],
    "roles-and-responsibilities.md": ["1-2-1", "1-2-3", "1-4-1", "1-4-2"],
    "risk-management-method.md": ["1-5-1", "1-5-2", "1-5-3", "1-5-4"],
    "access-control-policy.md": ["2-2-1", "2-2-2", "2-2-3", "2-2-4"],
    "vulnerability-management-policy.md": ["2-10-1", "2-10-2", "2-10-3", "2-10-4"],
    "logging-and-monitoring-policy.md": ["2-12-1", "2-12-2", "2-12-3", "2-12-4"],
}
HEADER = ("Rimal Byte (fictional)", "Approved by", "5 October 2026", "October 2027")


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_policy_has_its_header_and_controls(name):
    text = (POLICIES / name).read_text(encoding="utf-8")
    for required in HEADER:
        assert required in text, f"{name} lacks {required!r}"
    for control in EXPECTED[name]:
        assert control in text, f"{name} does not cite ECC {control}"
    words = len(text.split())
    assert 400 <= words <= 900, f"{name} has {words} words"


def test_the_risk_method_matches_the_code():
    text = (POLICIES / "risk-management-method.md").read_text(encoding="utf-8")
    for band in ("1-4", "5-9", "10-16", "20-25", "Low", "Medium", "High", "Critical"):
        assert band in text


def test_the_vulnerability_deadlines_are_stated():
    text = (POLICIES / "vulnerability-management-policy.md").read_text(encoding="utf-8")
    for deadline in ("7 days", "30 days", "90 days"):
        assert deadline in text
