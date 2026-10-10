import copy
from pathlib import Path

import pytest

from tests.fixtures import FIXES
from tools.check_fixes import DEFAULT_FIXES, main, problems
from tools.gen_cis_checks import DEFAULT_POLICY

ROOT = Path(__file__).resolve().parents[1]

POLICY = {
    "checks": [
        {
            "id": 26000,
            "rules": [
                r'c:powershell secedit /export /cfg $env:TEMP\secpol.cfg; Get-Content '
                r'$env:TEMP\secpol.cfg | Select-String "PasswordHistorySize"; Remove-Item '
                r'$env:TEMP\secpol.cfg -> n:PasswordHistorySize = (\d+) compare >= 24'
            ],
        },
        {
            "id": 26004,
            "rules": [
                r"r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SAM"
                r" -> RelaxMinimumPasswordLengthLimits",
                r"r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SAM"
                r" -> RelaxMinimumPasswordLengthLimits -> 1",
            ],
        },
        {
            "id": 26139,
            "rules": [
                r'c:auditpol.exe /get /subcategory:"Credential Validation" -> r:Success and Failure'
            ],
        },
    ]
}


def fixes_with(change=None):
    fixes = copy.deepcopy(FIXES)
    fixes["fixes"][0]["checks"] = [26000, 26004]
    if change:
        change(fixes["fixes"])
    return fixes


def test_matching_values_pass():
    assert problems(POLICY, fixes_with()) == []


@pytest.mark.parametrize(
    ("change", "check"),
    [
        (lambda fixes: fixes[0]["items"][0].update(value=5), 26000),
        (lambda fixes: fixes[0]["items"][1].update(value=0), 26004),
        (lambda fixes: fixes[1]["items"][0].update(require="success"), 26139),
        (lambda fixes: fixes[1]["items"][0].update(subcategory="Logon"), 26139),
    ],
)
def test_a_wrong_value_is_caught(change, check):
    found = problems(POLICY, fixes_with(change))
    assert len(found) == 1
    assert f"no item satisfies check {check}" in found[0]


def test_an_unknown_check_is_caught():
    found = problems(POLICY, fixes_with(lambda fixes: fixes[1]["checks"].append(99999)))
    assert found == ["F02: check 99999 is not in the policy"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"condition": "any"}, "its condition is 'any'"),
        (
            {"rules": [r'not c:auditpol.exe /get /subcategory:"Credential Validation" -> r:No'
                       r" Auditing"]},
            "it has a rule this script does not read",
        ),
    ],
)
def test_checks_it_cannot_read_are_reported_not_passed(change, reason):
    policy = copy.deepcopy(POLICY)
    policy["checks"][2].update(change)
    found = problems(policy, fixes_with())
    assert len(found) == 1
    assert found[0].startswith(f"F02: check 26139 cannot be verified: {reason}")


LOG_SIZE = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"


@pytest.mark.parametrize(("value", "ok"), [(196608, True), (200000, True), (32768, False)])
def test_registry_numbers_are_compared(value, ok):
    item = {
        "kind": "registry",
        "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
        "name": "MaxSize",
        "type": "DWord",
        "value": value,
    }
    fix = {"id": "F04", "title": "t", "why": "w", "effect": "e", "checks": [26376], "items": [item]}
    rule = f"r:{LOG_SIZE} -> MaxSize -> n:^(\\d+) compare >= 196608"
    policy = {"checks": [{"id": 26376, "condition": "all", "rules": [rule]}]}
    assert (problems(policy, {"fixes": [fix]}) == []) is ok


@pytest.mark.skipif(not DEFAULT_POLICY.is_file(), reason="needs the Wazuh agent's SCA policy")
def test_the_real_fixes_match_the_installed_wazuh_policy(capsys):
    assert main(["check_fixes", str(DEFAULT_POLICY), str(ROOT / DEFAULT_FIXES)]) == 0
    assert "0 problem(s) in 12 fixes covering 57 checks." in capsys.readouterr().out
