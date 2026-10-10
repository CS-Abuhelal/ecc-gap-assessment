"""Check every value in remediation/fixes.json against the Wazuh SCA rules of its checks.

Each value rule of each targeted check (a registry value, an auditpol result or a secedit
number) must be satisfied by one of the fix's items. Run it where the Wazuh agent is installed:

    python -m tools.check_fixes [policy.yml] [fixes.json]
"""

from __future__ import annotations

import json
import operator
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from tools.gen_cis_checks import DEFAULT_POLICY

DEFAULT_FIXES = Path("remediation/fixes.json")
COMPARE: dict[str, Callable[[int, int], bool]] = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
    "==": operator.eq,
}
# The secedit export key that each 'net accounts' option sets.
SECEDIT = {
    "uniquepw": "PasswordHistorySize",
    "minpwage": "MinimumPasswordAge",
    "minpwlen": "MinimumPasswordLength",
    "lockoutduration": "LockoutDuration",
    "lockoutthreshold": "LockoutBadCount",
    "lockoutwindow": "ResetLockoutCount",
}
AUDIT_RESULT = {"Success and Failure": "both", "Success": "success", "Failure": "failure"}
REGISTRY_RULE = re.compile(r"r:(.+?) -> (\S+) -> (.+)$")
NUMBER = re.compile(r"n:\^?\(\\d\+\) compare (>=|<=|>|<|==) (\d+)$")
AUDIT_RULE = re.compile(r'/subcategory:"([^"]+)" -> r:(.+)$')
SECEDIT_RULE = re.compile(r"n:(\w+) = \(\\d\+\) compare (>=|<=|>|<|==) (\d+)$")


def is_value_rule(rule: str) -> bool:
    """Rules that test a value; the others only test that a key or value exists."""
    return rule.startswith("c:") or rule.count(" -> ") >= 2


def registry_path(item_path: str) -> str:
    return item_path.replace("HKLM:\\", "HKEY_LOCAL_MACHINE\\", 1).lower()


def satisfies(item: dict[str, Any], rule: str) -> bool:
    kind = item["kind"]
    if kind == "registry":
        match = REGISTRY_RULE.match(rule)
        if not match or match[1].lower() != registry_path(item["path"]):
            return False
        if match[2] != item["name"]:
            return False
        expected, value = match[3], str(item["value"])
        number = NUMBER.match(expected)
        if number:
            return value.isdigit() and COMPARE[number[1]](int(value), int(number[2]))
        if expected.startswith("r:"):
            return re.search(expected[2:], value) is not None
        return value == expected
    if kind == "audit":
        match = AUDIT_RULE.search(rule)
        if not match or match[1] != item["subcategory"] or match[2] not in AUDIT_RESULT:
            return False
        return item["require"] in (AUDIT_RESULT[match[2]], "both")
    if kind == "account":
        match = SECEDIT_RULE.search(rule)
        if not match or match[1] != SECEDIT[item["option"]]:
            return False
        return COMPARE[match[2]](int(item["value"]), int(match[3]))
    return False


def problems(policy: dict[str, Any], fixes: dict[str, Any]) -> list[str]:
    rules = {int(check["id"]): check["rules"] for check in policy["checks"]}
    found: list[str] = []
    for fix in fixes["fixes"]:
        for check in fix["checks"]:
            if check not in rules:
                found.append(f"{fix['id']}: check {check} is not in the policy")
                continue
            for rule in filter(is_value_rule, rules[check]):
                if not any(satisfies(item, rule) for item in fix["items"]):
                    found.append(f"{fix['id']}: no item satisfies check {check}: {rule}")
    return found


def main(argv: list[str]) -> int:
    policy_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_POLICY
    fixes_path = Path(argv[2]) if len(argv) > 2 else DEFAULT_FIXES
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    fixes = json.loads(fixes_path.read_text(encoding="utf-8"))
    found = problems(policy, fixes)
    for line in found:
        print(line)
    checks = sum(len(fix["checks"]) for fix in fixes["fixes"])
    print(f"{len(found)} problem(s) in {len(fixes['fixes'])} fixes covering {checks} checks.")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
