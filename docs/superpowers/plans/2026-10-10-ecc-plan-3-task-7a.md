# ECC Gap Assessment, Plan 3 Task 7a: Honest Before/After Presentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the before/after outputs exact for a reader. They should:
- mark an optional fix that was not applied;
- use wording that is true whether or not the report compares two snapshots;
- state their denominators;
- list CIS checks that changed outside the fixes;
- back the claim "every fix value matches its Wazuh rule" with a committed script and tests;
- close the small content items from the plan 3 final review.

**Context:** This is the code part of plan 3 Task 7 (`docs/superpowers/plans/2026-10-09-ecc-plan-3-remediation.md`). The after snapshot was committed on 10 October 2026: 176 of 473 checks pass, and F08 (account lockout) was left out on purpose. The narrative, README and licence come after this task.

**Tech Stack:** As in plan 3.

Every code block below was applied to a copy of the repository at b568925 and verified: 313 tests pass, ruff is clean, `check` passes, and `python -m tools.check_fixes` reports 0 problems against the Wazuh policy installed on WS-01.

## Global Constraints

The global constraints of plan 3 apply unchanged. See `.git/sdd/p3-global-constraints.md` or the plan 3 document.

---

### Task 7a: Optional fixes, wording, denominators, changes outside the fixes, fix checker, content

**Files:**
- Create: `tools/check_fixes.py`, `tests/test_check_fixes.py`.
- Modify:
  - `ecc/models.py`, `ecc/remediation.py`, `ecc/validate.py`, `ecc/html.py`, `ecc/excel.py`, `ecc/templates/report.html.j2`;
  - `data/risks.yaml`, `data/applicability.yaml`, `docs/company-profile.md`, three policies in `docs/policies/`;
  - `tests/fixtures.py`, `tests/test_remediation.py`, `tests/test_validate.py`, `tests/test_html.py`, `tests/test_excel.py`, `tests/test_real_data.py`.

**Interfaces produced:**
- `ReportText.optional_fixes_applied: tuple[str, ...]`, which defaults to empty.
- `FixResult.applied: bool | None`. It is None when there is no earlier snapshot; otherwise it is True for every required fix, and for each optional fix listed in `optional_fixes_applied`.
- `CheckChange(check, before, after)` and `other_changes(dataset, before, after)` in `ecc/remediation.py`.
- The report context gains `other_changes`.
- The workbook's Remediation sheet gains a "Checks" count column and "Yes, applied" / "Yes, not applied" labels.
- `tools/check_fixes.py` provides `problems(policy, fixes) -> list[str]` and `main(argv)`.
- Validation adds two rules: `optional_fixes_applied` may only name optional fixes, and a later snapshot may not pass an optional fix's checks unless that fix is listed.

- [ ] **Step 1: Write the failing tests**

In `tests/fixtures.py`, replace:

```python
    "limitations": ["All data here is made up."],
```

with:

```python
    "limitations": ["All data here is made up."],
    "optional_fixes_applied": ["F02"],
```

Append to the end of `tests/test_remediation.py`:

```python


def test_an_optional_fix_counts_as_applied_only_when_listed(dataset, baseline, after):
    first, second = fix_results(dataset, after, baseline)
    assert (first.applied, second.applied) == (True, True)
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    unlisted = fix_results(dataclasses.replace(dataset, report=report), after, baseline)
    assert [row.applied for row in unlisted] == [True, False]
    assert [row.applied for row in fix_results(dataset, baseline)] == [True, True]


def test_changes_outside_the_fixes_are_listed(dataset, baseline, after):
    assert other_changes(dataset, baseline, after) == ()
    results = [
        check.model_copy(update={"result": "failed"}) if check.id == 26001 else check
        for check in after.checks
    ]
    changed = other_changes(dataset, baseline, after.model_copy(update={"checks": tuple(results)}))
    assert [(c.check.id, c.before, c.after) for c in changed] == [(26001, "passed", "failed")]


def test_checks_of_a_fix_left_out_count_as_outside_the_fixes(dataset, baseline, after):
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    unlisted = dataclasses.replace(dataset, report=report)
    assert [c.check.id for c in other_changes(unlisted, baseline, after)] == [26139]
```

In `tests/test_remediation.py`, replace:

```python
import pytest
```

with:

```python
import dataclasses

import pytest
```

In `tests/test_remediation.py`, replace:

```python
from ecc.remediation import fix_results
```

with:

```python
from ecc.remediation import fix_results, other_changes
```

Append to the end of `tests/test_validate.py`:

```python


def test_optional_fixes_must_be_listed_when_applied(root):
    rewrite(root, "report.yaml", {**REPORT, "optional_fixes_applied": ["F01"]})
    found = problems(root)
    assert "report.yaml: optional_fixes_applied names fixes that are not optional (1): F01" in found
    expected = (
        "report.yaml: optional fixes passing in snapshot 'after' "
        "but missing from optional_fixes_applied (1): F02"
    )
    assert expected in found
```

In `tests/test_validate.py`, replace:

```python
    MAPPING,
    RISKS,
```

with:

```python
    MAPPING,
    REPORT,
    RISKS,
```

In `tests/test_html.py`, replace:

```python
    assert "<b>2 of 2 targeted checks pass</b> (was 0)." in html
```

with:

```python
    assert "<b>2 of 2 targeted checks pass</b> (was 0)." in html
    assert "snapshots. Each row counts" in html
    assert "No CIS check outside the fixes changed" in html
```

In `tests/test_html.py`, replace:

```python
def test_a_single_snapshot_report_shows_the_planned_fixes(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "2 reversible fixes are planned in remediation/fixes.json" in html
```

with:

```python
def test_a_single_snapshot_report_lists_the_fixes(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "2 reversible fixes are listed in remediation/fixes.json" in html
```

Append to the end of `tests/test_html.py`:

```python


def test_an_optional_fix_left_out_is_marked_and_not_counted(dataset, baseline, after):
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, after), assess(changed, baseline))
    assert "except the optional F02, which was left out" in html
    assert "<b>1 of 1 targeted checks pass</b> (was 0)." in html
    assert '<td>2-12-3</td><td class="nowrap">Not applied</td>' in html


def test_a_single_snapshot_report_also_marks_a_fix_left_out(dataset, baseline):
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, baseline))
    assert "the optional F02 is left out" in html
    assert "<b>0 of 1 targeted checks pass</b>." in html
    assert '<td>2-12-3</td><td class="nowrap">Not applied</td>' in html


def test_checks_changed_outside_the_fixes_are_listed(dataset, baseline, after):
    results = tuple(
        check.model_copy(update={"result": "failed"}) if check.id == 26001 else check
        for check in after.checks
    )
    later = after.model_copy(update={"checks": results})
    html = render_html(dataset, assess(dataset, later), assess(dataset, baseline))
    assert "No applied fix targets these checks" in html
    assert "<td>26001</td><td>1.1.2</td>" in html
    assert "<td>passed</td><td>failed</td>" in html
```

In `tests/test_excel.py`, replace:

```python
    header = ["CIS checks", "ECC controls", "baseline passing", "after passing"]
    assert values(sheet, 1)[5:] == header
    assert values(sheet, 2)[0] == "F01"
    assert values(sheet, 3)[4:] == ["Yes", "26139", "2-12-3", 0, 1]
```

with:

```python
    header = ["CIS checks", "Number of checks", "ECC controls", "baseline passing", "after passing"]
    assert values(sheet, 1)[5:] == header
    assert values(sheet, 2)[0] == "F01"
    assert values(sheet, 3)[4:] == ["Yes, applied", "26139", 1, "2-12-3", 0, 1]
```

Append to the end of `tests/test_excel.py`:

```python


def test_a_fix_left_out_shows_as_not_applied(tmp_path, dataset, baseline, after):
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    changed = dataclasses.replace(dataset, report=report)
    sheet = workbook(tmp_path, changed, after, baseline)["Remediation"]
    assert values(sheet, 3)[4:] == ["Yes, not applied", "26139", 1, "2-12-3"] + ["Not applied"] * 2
```

In `tests/test_excel.py`, replace:

```python
from openpyxl import load_workbook
```

with:

```python
import dataclasses

from openpyxl import load_workbook
```

In `tests/test_real_data.py`, replace:

```python
    dataset, snapshots, assessment = baseline_assessment()
```

with:

```python
    dataset, _, assessment = baseline_assessment()
```

Create `tests/test_check_fixes.py`:

```python
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
```

Run: `.venv/Scripts/python -m pytest -q`
Expected: collection errors and failures, because `other_changes`, `optional_fixes_applied` and `tools.check_fixes` do not exist yet.

- [ ] **Step 2: Implement**

In `ecc/models.py`, replace:

```python
    key_findings: tuple[Paragraph, ...] = ()
    limitations: tuple[Paragraph, ...] = ()
```

with:

```python
    key_findings: tuple[Paragraph, ...] = ()
    limitations: tuple[Paragraph, ...] = ()
    # Optional fixes in remediation/fixes.json that were applied; the rest count as not applied.
    optional_fixes_applied: tuple[Annotated[str, Field(pattern=FIX_PATTERN)], ...] = ()
```

In `ecc/remediation.py`, replace:

```python
from ecc.models import Fix, Snapshot


@dataclass(frozen=True)
class FixResult:
    fix: Fix
    controls: tuple[str, ...]
    before: int | None
    after: int
```

with:

```python
from ecc.models import CisCheck, Fix, Snapshot


@dataclass(frozen=True)
class FixResult:
    """A fix with its ECC controls and passing checks.

    `applied` is False only for an optional fix missing from report.yaml's optional_fixes_applied.
    """

    fix: Fix
    controls: tuple[str, ...]
    before: int | None
    after: int
    applied: bool


@dataclass(frozen=True)
class CheckChange:
    check: CisCheck
    before: str
    after: str
```

In `ecc/remediation.py`, replace:

```python
    by_id = {check.id: check for check in dataset.policy.checks}
    rows: list[FixResult] = []
```

with:

```python
    by_id = {check.id: check for check in dataset.policy.checks}
    chosen = set(dataset.report.optional_fixes_applied)
    rows: list[FixResult] = []
```

In `ecc/remediation.py`, replace:

```python
                before=passing(before, fix.checks) if before is not None else None,
                after=passing(after, fix.checks),
            )
        )
    return tuple(rows)
```

with:

```python
                before=passing(before, fix.checks) if before is not None else None,
                after=passing(after, fix.checks),
                applied=not fix.optional or fix.id in chosen,
            )
        )
    return tuple(rows)


def other_changes(dataset: Dataset, before: Snapshot, after: Snapshot) -> tuple[CheckChange, ...]:
    """CIS checks that no applied fix targets but whose result changed between two snapshots."""
    chosen = set(dataset.report.optional_fixes_applied)
    targeted = {
        check
        for fix in dataset.fixes.fixes
        if not fix.optional or fix.id in chosen
        for check in fix.checks
    }
    old = {check.id: check.result for check in before.checks}
    new = {check.id: check.result for check in after.checks}
    return tuple(
        CheckChange(check, old[check.id], new[check.id])
        for check in dataset.policy.checks
        if check.id not in targeted
        and check.id in old
        and check.id in new
        and old[check.id] != new[check.id]
    )
```

In `ecc/validate.py`, replace:

```python
    if snapshots:
        first = snapshots[0]
        failed = {check.id for check in first.checks if check.result == "failed"}
        report(
            f"fixes.json: checks that were not failing in snapshot '{first.label}'",
            [str(c) for c in sorted((set(fixed) & check_ids) - failed)],
        )
```

with:

```python
    chosen = dataset.report.optional_fixes_applied
    optional = {fix.id for fix in fixes if fix.optional}
    report(
        "report.yaml: optional_fixes_applied names fixes that are not optional",
        sorted(set(chosen) - optional),
    )
    if snapshots:
        first = snapshots[0]
        failed = {check.id for check in first.checks if check.result == "failed"}
        report(
            f"fixes.json: checks that were not failing in snapshot '{first.label}'",
            [str(c) for c in sorted((set(fixed) & check_ids) - failed)],
        )
        skipped = [fix for fix in fixes if fix.optional and fix.id not in chosen]
        for snapshot in snapshots[1:]:
            results = {check.id: check.result for check in snapshot.checks}
            report(
                f"report.yaml: optional fixes passing in snapshot '{snapshot.label}' "
                "but missing from optional_fixes_applied",
                sorted(
                    {
                        fix.id
                        for fix in skipped
                        for check in fix.checks
                        if check in failed and results.get(check) == "passed"
                    }
                ),
            )
```

In `ecc/html.py`, replace:

```python
from ecc.remediation import fix_results
```

with:

```python
from ecc.remediation import fix_results, other_changes
```

In `ecc/html.py`, replace:

```python
        "fixes": fix_results(
            dataset, after.snapshot, before.snapshot if before is not None else None
        ),
```

with:

```python
        "fixes": fix_results(
            dataset, after.snapshot, before.snapshot if before is not None else None
        ),
        "other_changes": (
            other_changes(dataset, before.snapshot, after.snapshot) if before is not None else ()
        ),
```

In `ecc/templates/report.html.j2`, replace:

```html
<p class="note">A control is Implemented only when every one of its checks passes, so it can gain many passing checks and keep its rating.</p>
{% endif %}
{% endif %}
```

with:

```html
<p class="note">A control is Implemented only when every one of its checks passes, so it can gain many passing checks and keep its rating. Checks that were not applicable or not scanned are left out of these counts.</p>
{% endif %}
<h3>CIS checks that changed outside the fixes</h3>
{% if other_changes %}
<p class="note">No applied fix targets these checks, so something else on the PC changed them, for example a Windows update.</p>
<div class="table-wrap"><table>
<thead><tr><th>Check</th><th>CIS</th><th>Title</th><th>{{ before_snapshot.label }}</th><th>{{ snapshot.label }}</th></tr></thead>
<tbody>
{% for c in other_changes %}
<tr><td>{{ c.check.id }}</td><td>{{ c.check.cis }}</td><td>{{ c.check.title }}</td><td>{{ c.before }}</td><td>{{ c.after }}</td></tr>
{% endfor %}
</tbody></table></div>
{% else %}
<p class="note">No CIS check outside the fixes changed, so the fixes account for every change in the checks.</p>
{% endif %}
{% endif %}
```

In `ecc/templates/report.html.j2`, replace:

```html
{% if before_snapshot %}
<p class="note">The fixes in remediation/fixes.json were applied with remediation/apply.ps1 between the &ldquo;{{ before_snapshot.label }}&rdquo; and &ldquo;{{ snapshot.label }}&rdquo; snapshots (an optional fix only when chosen). Each row counts the fix's own CIS checks that pass.</p>
{% else %}
<p class="note">{{ fixes|length }} reversible fixes are planned in remediation/fixes.json. remediation/apply.ps1 applies them after saving the old values, and remediation/undo.ps1 restores them. Each row counts the fix's own CIS checks that pass now.</p>
{% endif %}
<p><b>{{ fixes|sum(attribute="after") }} of {{ fixes|map(attribute="fix.checks")|map("length")|sum }} targeted checks pass</b>{% if before_snapshot %} (was {{ fixes|sum(attribute="before") }}){% endif %}.</p>
```

with:

```html
{% set left_out = fixes|rejectattr("applied")|map(attribute="fix.id")|list %}
{% set counted = fixes|selectattr("applied")|list %}
{% if before_snapshot %}
<p class="note">The fixes in remediation/fixes.json were applied with remediation/apply.ps1 between the &ldquo;{{ before_snapshot.label }}&rdquo; and &ldquo;{{ snapshot.label }}&rdquo; snapshots{% if left_out %}, except the optional {{ left_out|join(", ") }}, which {{ "was" if left_out|length == 1 else "were" }} left out{% endif %}. Each row counts the fix's own CIS checks that pass, out of all the checks it targets.</p>
{% else %}
<p class="note">{{ fixes|length }} reversible fixes are listed in remediation/fixes.json{% if left_out %}; the optional {{ left_out|join(", ") }} {{ "is" if left_out|length == 1 else "are" }} left out{% endif %}. remediation/apply.ps1 applies them after saving the old values (an optional fix only when chosen), and remediation/undo.ps1 restores them. Each row counts the fix's own CIS checks that pass in this snapshot, out of all the checks it targets.</p>
{% endif %}
<p><b>{{ counted|sum(attribute="after") }} of {{ counted|map(attribute="fix.checks")|map("length")|sum }} targeted checks pass</b>{% if before_snapshot %} (was {{ counted|sum(attribute="before") }}){% endif %}.</p>
```

In `ecc/templates/report.html.j2`, replace:

```html
<td class="nowrap">{% if row.before is not none %}{{ row.before }} &rarr; {% endif %}{{ row.after }} of {{ row.fix.checks|length }}</td></tr>
```

with:

```html
<td class="nowrap">{% if row.applied is false %}Not applied{% else %}{% if row.before is not none %}{{ row.before }} &rarr; {% endif %}{{ row.after }} of {{ row.fix.checks|length }}{% endif %}</td></tr>
```

In `ecc/excel.py`, replace:

```python
    rows = fix_results(dataset, after.snapshot, before.snapshot if before is not None else None)
    header = ["Fix", "Change", "Why", "What changes on the PC", "Optional", "CIS checks"]
    header.append("ECC controls")
    if before is not None:
        header.append(f"{before.snapshot.label} passing")
    header.append(f"{after.snapshot.label} passing")
```

with:

```python
    rows = fix_results(dataset, after.snapshot, before.snapshot if before is not None else None)
    header = ["Fix", "Change", "Why", "What changes on the PC", "Optional", "CIS checks"]
    header += ["Number of checks", "ECC controls"]
    if before is not None:
        header.append(f"{before.snapshot.label} passing")
    header.append(f"{after.snapshot.label} passing")
```

In `ecc/excel.py`, replace:

```python
                "Yes" if row.fix.optional else "No",
                ", ".join(str(check) for check in row.fix.checks),
                ", ".join(row.controls),
                *([row.before] if before is not None else []),
                row.after,
            ]
            for row in rows
        ],
        [6, 36, 48, 48, 9, 30, 18, 12, 12],
```

with:

```python
                optional_label(row),
                ", ".join(str(check) for check in row.fix.checks),
                len(row.fix.checks),
                ", ".join(row.controls),
                *passing_cells(row, before is not None),
            ]
            for row in rows
        ],
        [6, 36, 48, 48, 16, 30, 10, 18, 12, 12],
```

In `ecc/excel.py`, replace:

```python
def write_remediation(
```

with:

```python
def optional_label(row: FixResult) -> str:
    if not row.fix.optional:
        return "No"
    return "Yes, applied" if row.applied else "Yes, not applied"


def passing_cells(row: FixResult, comparing: bool) -> list[int | str | None]:
    """The passing counts, or 'Not applied' for an optional fix that was left out."""
    if not row.applied:
        return ["Not applied"] * (2 if comparing else 1)
    return [row.before, row.after] if comparing else [row.after]


def write_remediation(
```

In `ecc/excel.py`, replace:

```python
from ecc.remediation import fix_results
```

with:

```python
from ecc.remediation import FixResult, fix_results
```

In `docs/policies/access-control-policy.md`, replace:

```markdown
| ECC-2:2024 controls | 1-9-5, 2-2-1,
```

with:

```markdown
| ECC-2:2024 controls | 1-3-4, 1-9-5, 2-2-1,
```

In `docs/policies/logging-and-monitoring-policy.md`, replace:

```markdown
| ECC-2:2024 controls | 2-12-1,
```

with:

```markdown
| ECC-2:2024 controls | 1-3-4, 2-12-1,
```

In `docs/policies/vulnerability-management-policy.md`, replace:

```markdown
| ECC-2:2024 controls | 2-10-1,
```

with:

```markdown
| ECC-2:2024 controls | 1-3-4, 2-10-1,
```

In `data/risks.yaml`, replace:

```yaml
      October 2027, so a change in the business before then could leave a document out of date
      for a few months.
```

with:

```yaml
      October 2027, so a change in the business before then could leave a document out of date
      until the first review.
```

In `data/applicability.yaml`, replace:

```yaml
      Byte's systems; its cloud service (Microsoft 365) is assessed under 4-2.
```

with:

```yaml
      Byte's systems; Rimal Byte's cloud service (Microsoft 365) is assessed under 4-2.
```

In `docs/company-profile.md`, replace:

```markdown
  provider's and web host's terms cover none of these.
```

with:

```markdown
  provider's and web host's terms cover none of these. The internet provider also applies its
  router's firmware updates when the IT Manager asks, as part of that standard service.
```

In `ecc/templates/report.html.j2`, replace:

```html
and a requirement that is neither documented nor carried out is Not implemented.
```

with:

```html
and a requirement that is neither approved nor carried out is Not implemented.
```

Create `tools/check_fixes.py`:

```python
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


def unverifiable(check: dict[str, Any]) -> str | None:
    """Why this script cannot judge a check, or None. Only 'all' checks of plain rules are read."""
    condition = check.get("condition", "all")
    if condition != "all":
        return f"its condition is '{condition}'"
    for rule in check["rules"]:
        if not rule.startswith(("r:", "c:")):
            return f"it has a rule this script does not read: {rule}"
    return None


def problems(policy: dict[str, Any], fixes: dict[str, Any]) -> list[str]:
    checks = {int(check["id"]): check for check in policy["checks"]}
    found: list[str] = []
    for fix in fixes["fixes"]:
        for check in fix["checks"]:
            if check not in checks:
                found.append(f"{fix['id']}: check {check} is not in the policy")
                continue
            reason = unverifiable(checks[check])
            if reason:
                found.append(f"{fix['id']}: check {check} cannot be verified: {reason}")
                continue
            for rule in filter(is_value_rule, checks[check]["rules"]):
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
```

- [ ] **Step 3: Verify and commit**

Run:
- `.venv/Scripts/python -m pytest -q -W error`: `313 passed`. On WS-01 this includes the real Wazuh policy check; elsewhere that one test is skipped.
- `.venv/Scripts/python -m ruff check .`
- `.venv/Scripts/python -m ecc check`: `OK: 108 controls, 482 checks, 2 snapshot(s).`
- `.venv/Scripts/python -m tools.check_fixes`: `0 problem(s) in 12 fixes covering 57 checks.`

```bash
git add ecc/models.py ecc/remediation.py ecc/validate.py ecc/html.py ecc/templates/report.html.j2 ecc/excel.py docs/policies/access-control-policy.md docs/policies/logging-and-monitoring-policy.md docs/policies/vulnerability-management-policy.md data/risks.yaml data/applicability.yaml docs/company-profile.md tools/check_fixes.py tests/fixtures.py tests/test_remediation.py tests/test_validate.py tests/test_html.py tests/test_excel.py tests/test_real_data.py tests/test_check_fixes.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Mark unapplied optional fixes, list changes outside the fixes, and commit the fix checker"
```
