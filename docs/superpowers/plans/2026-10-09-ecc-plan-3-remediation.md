# ECC Gap Assessment, Plan 3: Remediation, Before/After and Publishing

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 57 failed CIS checks on WS-01 with reversible scripts that Ahmed reviews and runs himself, measure the result in an "after" snapshot, show the before/after in the workbook and report, and publish the project.

**Architecture:** `remediation/fixes.json` lists 12 fixes. Each fix names the failed checks it targets and the exact settings it changes. The Python side reads the same file: it validates it, works out per-fix results, and shows them in a Remediation sheet and report section. A PowerShell module (`remediation/Remediation.psm1`) reads, changes and restores the settings. `apply.ps1` and `undo.ps1` are thin scripts around it. Ahmed runs them on WS-01, and CI applies and undoes them on a throwaway Windows runner. Once the after snapshot exists, the narrative, README and licence are finished and the repository is published, after Ahmed confirms.

**Tech Stack:** As before (Python 3.11+, pydantic, PyYAML, openpyxl, Jinja2, pytest, ruff 0.16.4), plus Windows PowerShell 5.1 (registry provider, `auditpol`, `net accounts`) and GitHub Actions (Ubuntu and Windows runners, Pages).

**Sources:**
- The Wazuh SCA policy `cis_win11_enterprise.yml`. A script checked every value in `fixes.json` against the rule of the check it targets, and also confirmed that a deliberately wrong value is caught.
- Microsoft's advanced audit subcategory GUIDs.
- Spec section 8, and spec section 15 (added with this plan): `docs/superpowers/specs/2026-10-08-ecc-gap-assessment-design.md`.

Every code block and data file below was applied to a copy of the repository and verified before this plan was written:
- Test counts after each task: Task 1 260, Task 2 286, Task 3 291, Task 4 293.
- ruff is clean and `check` passes after every task.
- A read-only dry run of the real fix list on WS-01 showed all 57 settings with their current and new values.
- A simulated after snapshot gives:
  - 176 of 473 checks passing without the optional F08, or 179 with it;
  - 26.5% compliance, or 27.0% if the five high-severity vulnerabilities are also patched.

## Global Constraints

- Work in the repository root `ecc-gap-assessment/`; run everything through `.venv/Scripts/python`.
- Lint with `ruff==0.16.4`, rules `E, F, I, UP, B`, line length 100; `ruff check .` must print `All checks passed!` before every commit.
- Privacy: never write the Windows user name, the computer name, any `C:\Users\...` path or the Wazuh agent's real name into a committed file. Tests use made-up names only (`DESKTOP-TEST1`).
- Claude never changes system settings and never handles the Wazuh password. Ahmed runs `apply.ps1`, `undo.ps1` and `collect` himself. Tests touch only throwaway keys under `HKCU:\Software\ecc-remediation-test-*`.
- Fixes may use only three kinds of change:
  - registry values under `HKLM:\SOFTWARE\Policies`, `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`, `...\Control\Lsa` and `...\Control\SAM`;
  - advanced audit subcategories, where auditing is added and never removed;
  - local account policy set with `net accounts`.
- Every fix must be reversible, need no restart, and not change how Ahmed signs in.
- PowerShell files use Windows PowerShell 5.1 syntax and ASCII characters only.
- Copy code and data exactly as given; they were verified against the real baseline.
- Commit with `git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "..."`. Do not push, add a remote or create a GitHub repository; Task 8 does that only after Ahmed confirms.

## File Structure

| File | Responsibility |
|---|---|
| `remediation/fixes.json` | The 12 fixes: the checks each targets, the settings it changes, why, and what Ahmed will notice |
| `ecc/models.py` | `RegistryItem`, `AuditItem`, `AccountItem`, `Fix`, `FixList` (allowlisted registry paths); `long_date` |
| `ecc/load.py` | `Dataset.fixes`, read from `remediation/fixes.json` with `load_json_model` |
| `ecc/validate.py` | Fix ids used twice, unknown or repeated checks, checks that were not failing in the first snapshot |
| `ecc/remediation.py` | `fix_results`: per fix, its ECC controls and how many of its checks pass before and after |
| `ecc/assess.py` | `check_progress`: passing checks per control in two snapshots |
| `ecc/excel.py`, `ecc/html.py`, `ecc/templates/report.html.j2` | Remediation sheet and section, checks-per-control table, long dates, page title |
| `remediation/Remediation.psm1` | Read, change, back up, restore and verify settings |
| `remediation/apply.ps1`, `remediation/undo.ps1` | What Ahmed runs; `-WhatIf` and a confirmation prompt; backups in `remediation/backups/` (git-ignored) |
| `tests/test_remediation.py`, `tests/test_remediation_scripts.py` | Python side; PowerShell module through Windows PowerShell against HKCU test keys |
| `.github/workflows/ci.yml`, `.github/workflows/pages.yml` | Ubuntu lint, tests and build; Windows apply-and-undo round trip; Pages build and deploy |

---

### Task 1: Fix list, models, loading and validation

**Files:** Create `remediation/fixes.json`, `ecc/remediation.py`, `tests/test_remediation.py`; modify `ecc/models.py`, `ecc/load.py`, `ecc/validate.py`, `tests/fixtures.py`, `tests/test_validate.py`, `tests/test_real_data.py`.

**Interfaces produced:**
- In `ecc/models.py`:
  - `RegistryItem(kind="registry", path, name, type: "DWord" | "String", value)`
  - `AuditItem(kind="audit", guid, subcategory, require: "success" | "failure" | "both")`
  - `AccountItem(kind="account", option, value)`
  - `Fix(id, title, why, effect, optional=False, checks, items)` and `FixList(fixes)`
- `Dataset.fixes: FixList`, and `load_json_model(model, path)` in `ecc/load.py`.
- In `ecc/remediation.py`: `FixResult(fix, controls, before, after)`, `control_key(control_id)`, `passing(snapshot, checks)`, and `fix_results(dataset, after, before=None)`.
- Test fixtures `FIXES` and `write_fixes(root, content)`.

- [ ] **Step 1: Write the failing tests and fixtures**

In `tests/fixtures.py`, replace:

```python
DATA_FILES = {
```

with:

```python
FIXES = {
    "fixes": [
        {
            "id": "F01",
            "title": "Remember old passwords",
            "why": "Stops people reusing a recent password.",
            "effect": "Nothing until the next password change.",
            "checks": [26000],
            "items": [
                {"kind": "account", "option": "uniquepw", "value": 24},
                {
                    "kind": "registry",
                    "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SAM",
                    "name": "RelaxMinimumPasswordLengthLimits",
                    "type": "DWord",
                    "value": 1,
                },
            ],
        },
        {
            "id": "F02",
            "title": "Audit sign-ins",
            "why": "Records failed sign-ins.",
            "effect": "More Security events.",
            "optional": True,
            "checks": [26139],
            "items": [
                {
                    "kind": "audit",
                    "guid": "{0CCE923F-69AE-11D9-BED3-505054503030}",
                    "subcategory": "Credential Validation",
                    "require": "both",
                }
            ],
        },
    ]
}

DATA_FILES = {
```

In `tests/fixtures.py`, replace:

```python
def write_root(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    for name, content in DATA_FILES.items():
        rewrite(root, name, content)
```

with:

```python
def write_fixes(root: Path, content: object) -> None:
    path = root / "remediation" / "fixes.json"
    path.write_text(json.dumps(content, indent=2), encoding="utf-8")


def write_root(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    for name, content in DATA_FILES.items():
        rewrite(root, name, content)
    (root / "remediation").mkdir()
    write_fixes(root, FIXES)
```

In `tests/test_validate.py`, replace:

```python
    EVIDENCE,
    MAPPING,
```

with:

```python
    EVIDENCE,
    FIXES,
    MAPPING,
```

In `tests/test_validate.py`, replace:

```python
    SAMA_MAPPING,
    rewrite,
)
```

with:

```python
    SAMA_MAPPING,
    rewrite,
    write_fixes,
)
```

Append to the end of `tests/test_validate.py`:

```python


def test_fixes_must_name_known_checks_once(root):
    first, second = FIXES["fixes"]
    fixes = [first, {**second, "id": "F01", "checks": [26000, 99999]}]
    write_fixes(root, {"fixes": fixes})
    found = problems(root)
    assert "fixes.json: fix ids used twice (1): F01" in found
    assert "fixes.json: unknown CIS checks (1): 99999" in found
    assert "fixes.json: checks listed in two fixes (1): 26000" in found


def test_fixes_must_target_checks_that_failed_first(root):
    first, second = FIXES["fixes"]
    write_fixes(root, {"fixes": [first, {**second, "checks": [26001, 26139, 26140]}]})
    expected = "fixes.json: checks that were not failing in snapshot 'baseline' (2): 26001, 26140"
    assert expected in problems(root)
```

Create `tests/test_remediation.py`:

```python
import pytest

from ecc.load import DataError, load_dataset
from ecc.models import FixList
from ecc.remediation import fix_results
from tests.fixtures import FIXES, write_fixes


def test_the_fixes_are_loaded(dataset):
    first, second = dataset.fixes.fixes
    assert (first.id, first.optional, second.optional) == ("F01", False, True)
    assert [item.kind for item in first.items] == ["account", "registry"]


def test_each_fix_reports_its_controls_and_passing_checks(dataset, baseline, after):
    first, second = fix_results(dataset, after, baseline)
    assert (first.fix.id, first.controls, first.before, first.after) == ("F01", ("2-2-3",), 0, 1)
    assert (second.controls, second.before, second.after) == (("2-12-3",), 0, 1)


def test_without_an_earlier_snapshot_there_is_no_before(dataset, baseline):
    first, _ = fix_results(dataset, baseline)
    assert (first.before, first.after) == (None, 0)


def item_with(**changes):
    registry = FIXES["fixes"][0]["items"][1]
    fix = {**FIXES["fixes"][0], "items": [{**registry, **changes}]}
    return {"fixes": [fix]}


@pytest.mark.parametrize(
    "changes",
    [
        {"path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"path": "HKCU:\\SOFTWARE\\Policies\\Microsoft"},
        {"path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Extra"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\..\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\*"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\x'; Remove-Item C:\\; '"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\n"},
        {"name": "Run'; Start-Process calc; '"},
        {"name": ""},
        {"path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"},
        {"type": "QWord"},
        {"value": "1"},
        {"value": -1},
        {"value": 2147483648},
        {"type": "String", "value": 1},
    ],
)
def test_registry_items_are_limited(changes):
    with pytest.raises(ValueError):
        FixList.model_validate(item_with(**changes))


def test_policy_keys_are_allowed():
    path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
    assert FixList.model_validate(item_with(path=path)).fixes[0].items[0].path == path


def test_a_broken_fix_list_names_the_file(root):
    write_fixes(root, {"fixes": [{"id": "F1"}]})
    with pytest.raises(DataError, match="fixes.json"):
        load_dataset(root)
```

In `tests/test_real_data.py`, replace:

```python
from ecc.load import load_dataset, load_snapshots
```

with:

```python
from ecc.load import load_dataset, load_snapshots
from ecc.remediation import fix_results
```

Append to the end of `tests/test_real_data.py`:

```python


def test_the_planned_fixes():
    dataset, snapshots, assessment = baseline_assessment()
    rows = fix_results(dataset, assessment.snapshot)
    assert len(rows) == 12
    assert sum(len(row.fix.checks) for row in rows) == 57
    assert [row.fix.id for row in rows if row.fix.optional] == ["F08"]
    assert all(row.after == 0 for row in rows)
    assert {control for row in rows for control in row.controls} == {
        "2-2-3", "2-3-3", "2-5-3", "2-7-2", "2-12-3"
    }
```

Run: `.venv/Scripts/python -m pytest -q`
Expected: errors and failures, because `ecc.remediation`, `FixList` and `remediation/fixes.json` do not exist yet.

- [ ] **Step 2: Implement**

Create `remediation/fixes.json`:

```json
{
  "fixes": [
    {
      "id": "F01",
      "title": "Let the detailed audit settings take effect",
      "why": "Windows applies the subcategory audit settings in F02 only when this option is on.",
      "effect": "None on its own.",
      "checks": [
        26013
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
          "name": "SCENoApplyLegacyAuditPolicy",
          "type": "DWord",
          "value": 1
        }
      ]
    },
    {
      "id": "F02",
      "title": "Audit sign-ins, account and group changes, process starts and policy changes",
      "why": "Records the Security events an analyst needs, such as failed sign-ins, new accounts, group changes, new processes and firewall rule changes. Wazuh forwards them.",
      "effect": "More events in the Security log and in Wazuh. Sensitive Privilege Use is left out because it floods a desktop's log.",
      "checks": [
        26139,
        26140,
        26142,
        26143,
        26144,
        26145,
        26146,
        26149,
        26151,
        26152,
        26153,
        26154,
        26157,
        26158,
        26159,
        26161,
        26164
      ],
      "items": [
        {
          "kind": "audit",
          "guid": "{0CCE923F-69AE-11D9-BED3-505054503030}",
          "subcategory": "Credential Validation",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9239-69AE-11D9-BED3-505054503030}",
          "subcategory": "Application Group Management",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9235-69AE-11D9-BED3-505054503030}",
          "subcategory": "User Account Management",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9248-69AE-11D9-BED3-505054503030}",
          "subcategory": "Plug and Play Events",
          "require": "success"
        },
        {
          "kind": "audit",
          "guid": "{0CCE922B-69AE-11D9-BED3-505054503030}",
          "subcategory": "Process Creation",
          "require": "success"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9217-69AE-11D9-BED3-505054503030}",
          "subcategory": "Account Lockout",
          "require": "failure"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9249-69AE-11D9-BED3-505054503030}",
          "subcategory": "Group Membership",
          "require": "success"
        },
        {
          "kind": "audit",
          "guid": "{0CCE921C-69AE-11D9-BED3-505054503030}",
          "subcategory": "Other Logon/Logoff Events",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9244-69AE-11D9-BED3-505054503030}",
          "subcategory": "Detailed File Share",
          "require": "failure"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9224-69AE-11D9-BED3-505054503030}",
          "subcategory": "File Share",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9227-69AE-11D9-BED3-505054503030}",
          "subcategory": "Other Object Access Events",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9245-69AE-11D9-BED3-505054503030}",
          "subcategory": "Removable Storage",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9231-69AE-11D9-BED3-505054503030}",
          "subcategory": "Authorization Policy Change",
          "require": "success"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9232-69AE-11D9-BED3-505054503030}",
          "subcategory": "MPSSVC Rule-Level Policy Change",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9234-69AE-11D9-BED3-505054503030}",
          "subcategory": "Other Policy Change Events",
          "require": "failure"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9213-69AE-11D9-BED3-505054503030}",
          "subcategory": "IPsec Driver",
          "require": "both"
        },
        {
          "kind": "audit",
          "guid": "{0CCE9211-69AE-11D9-BED3-505054503030}",
          "subcategory": "Security System Extension",
          "require": "success"
        }
      ]
    },
    {
      "id": "F03",
      "title": "Record the command line of new processes",
      "why": "Process-start events (4688) then show how a program was started, not only its name.",
      "effect": "Command lines appear in the Security log and in Wazuh on this PC, including anything typed as an argument, so passwords must never be passed on a command line.",
      "checks": [
        26222
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
          "name": "ProcessCreationIncludeCmdLine_Enabled",
          "type": "DWord",
          "value": 1
        }
      ]
    },
    {
      "id": "F04",
      "title": "Keep more history in the Windows event logs",
      "why": "Bigger logs keep weeks of events instead of days, so older activity can still be investigated.",
      "effect": "The four logs may use up to about 290 MB of disk in total.",
      "checks": [
        26374,
        26376,
        26378,
        26380
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application",
          "name": "MaxSize",
          "type": "DWord",
          "value": 32768
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
          "name": "MaxSize",
          "type": "DWord",
          "value": 196608
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup",
          "name": "MaxSize",
          "type": "DWord",
          "value": 32768
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System",
          "name": "MaxSize",
          "type": "DWord",
          "value": 32768
        }
      ]
    },
    {
      "id": "F05",
      "title": "Turn on Windows Firewall logging for all three profiles",
      "why": "Logs dropped packets and allowed connections, so blocked scans and unexpected connections leave a trace.",
      "effect": "Up to 16 MB of firewall log per profile under System32\\logfiles\\firewall.",
      "checks": [
        26119,
        26120,
        26121,
        26122,
        26126,
        26127,
        26128,
        26129,
        26135,
        26136,
        26137,
        26138
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging",
          "name": "LogFilePath",
          "type": "String",
          "value": "%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log"
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging",
          "name": "LogFileSize",
          "type": "DWord",
          "value": 16384
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging",
          "name": "LogDroppedPackets",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging",
          "name": "LogSuccessfulConnections",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging",
          "name": "LogFilePath",
          "type": "String",
          "value": "%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log"
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging",
          "name": "LogFileSize",
          "type": "DWord",
          "value": 16384
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging",
          "name": "LogDroppedPackets",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging",
          "name": "LogSuccessfulConnections",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging",
          "name": "LogFilePath",
          "type": "String",
          "value": "%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log"
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging",
          "name": "LogFileSize",
          "type": "DWord",
          "value": 16384
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging",
          "name": "LogDroppedPackets",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging",
          "name": "LogSuccessfulConnections",
          "type": "DWord",
          "value": 1
        }
      ]
    },
    {
      "id": "F06",
      "title": "Send Microsoft only the required diagnostic data",
      "why": "Limits the data Windows sends to Microsoft and keeps memory dumps and extra logs out of it.",
      "effect": "Settings shows diagnostic data as managed by your organisation.",
      "checks": [
        26360,
        26361,
        26362,
        26363,
        26364,
        26365,
        26366
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
          "name": "AllowTelemetry",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
          "name": "DisableEnterpriseAuthProxy",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
          "name": "DisableOneSettingsDownloads",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
          "name": "DoNotShowFeedbackNotifications",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
          "name": "EnableOneSettingsAuditing",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
          "name": "LimitDiagnosticLogCollection",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
          "name": "LimitDumpCollection",
          "type": "DWord",
          "value": 1
        }
      ]
    },
    {
      "id": "F07",
      "title": "Require longer local passwords and remember old ones",
      "why": "Local passwords need at least 14 characters and cannot reuse any of the last 24.",
      "effect": "Nothing changes until the next password change, which then needs 14 or more characters and cannot happen twice in one day.",
      "checks": [
        26000,
        26002,
        26003,
        26004
      ],
      "items": [
        {
          "kind": "account",
          "option": "uniquepw",
          "value": 24
        },
        {
          "kind": "account",
          "option": "minpwage",
          "value": 1
        },
        {
          "kind": "account",
          "option": "minpwlen",
          "value": 14
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SAM",
          "name": "RelaxMinimumPasswordLengthLimits",
          "type": "DWord",
          "value": 1
        }
      ]
    },
    {
      "id": "F08",
      "title": "Lock an account for 15 minutes after 5 wrong passwords",
      "why": "Slows down password guessing against local accounts (Windows 11 already locks after 10).",
      "effect": "Five wrong passwords within 15 minutes lock the account for 15 minutes, including during failed-logon test bursts. Applied only with -IncludeLockout.",
      "optional": true,
      "checks": [
        26005,
        26006,
        26007
      ],
      "items": [
        {
          "kind": "account",
          "option": "lockoutthreshold",
          "value": 5
        },
        {
          "kind": "account",
          "option": "lockoutduration",
          "value": 15
        },
        {
          "kind": "account",
          "option": "lockoutwindow",
          "value": 15
        }
      ]
    },
    {
      "id": "F09",
      "title": "Tighten User Account Control for other accounts",
      "why": "The built-in Administrator gets approval prompts, and standard users cannot elevate.",
      "effect": "None for an administrator account that already gets UAC prompts.",
      "checks": [
        26064,
        26066
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          "name": "FilterAdministratorToken",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          "name": "ConsentPromptBehaviorUser",
          "type": "DWord",
          "value": 0
        }
      ]
    },
    {
      "id": "F10",
      "title": "Turn off AutoPlay and AutoRun",
      "why": "USB drives, discs and phones can no longer start programs or prompts when plugged in.",
      "effect": "No AutoPlay pop-up when a drive or phone is connected; open it from File Explorer instead.",
      "checks": [
        26301,
        26302,
        26303
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
          "name": "NoAutoplayfornonVolume",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
          "name": "NoAutorun",
          "type": "DWord",
          "value": 1
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
          "name": "NoDriveTypeAutoRun",
          "type": "DWord",
          "value": 255
        }
      ]
    },
    {
      "id": "F11",
      "title": "Turn off multicast name resolution and allow DNS over HTTPS",
      "why": "Without LLMNR, a device on the same network cannot answer for a mistyped name and capture a sign-in, the trick tools like Responder use.",
      "effect": "Names are no longer resolved by LLMNR (DNS, NetBIOS and mDNS still work); DNS over HTTPS is allowed, not forced.",
      "checks": [
        26191,
        26193
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
          "name": "DoHPolicy",
          "type": "DWord",
          "value": 2
        },
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
          "name": "EnableMulticast",
          "type": "DWord",
          "value": 0
        }
      ]
    },
    {
      "id": "F12",
      "title": "Turn off Windows Remote Assistance invitations",
      "why": "Removes a remote-control entry point the PC does not use.",
      "effect": "Remote Assistance invitations stop working; Quick Assist is not affected.",
      "checks": [
        26288
      ],
      "items": [
        {
          "kind": "registry",
          "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
          "name": "fAllowToGetHelp",
          "type": "DWord",
          "value": 0
        }
      ]
    }
  ]
}
```

In `ecc/models.py`, replace:

```python
LABEL_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
```

with:

```python
LABEL_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
FIX_PATTERN = r"^F\d{2}$"
# Fixes may only touch policy keys and the two security-option keys under Control. Key and value
# names use plain characters only, so a path cannot climb out with '..' or match keys with '*'.
REGISTRY_KEY = r"\\[A-Za-z0-9_-][A-Za-z0-9 _-]*"
REGISTRY_PATTERN = (
    rf"^HKLM:\\(SOFTWARE\\Policies({REGISTRY_KEY})+"
    rf"|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies({REGISTRY_KEY})+"
    r"|SYSTEM\\CurrentControlSet\\Control\\(Lsa|SAM))$"
)
REGISTRY_NAME_PATTERN = r"^[A-Za-z0-9_]+$"
# Keys a fix may never touch, even under a policy root: autostart lists and Defender exclusions.
DENIED_REGISTRY_KEYS = frozenset({"run", "runonce", "exclusions"})
AUDIT_GUID_PATTERN = r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$"
```

In `ecc/models.py`, replace:

```python
    vulnerabilities: VulnerabilityCounts
    logging: LoggingFacts
```

with:

```python
    vulnerabilities: VulnerabilityCounts
    logging: LoggingFacts


class RegistryItem(Strict):
    """A registry value that apply.ps1 sets."""

    kind: Literal["registry"]
    path: str = Field(pattern=REGISTRY_PATTERN)
    name: str = Field(pattern=REGISTRY_NAME_PATTERN)
    type: Literal["DWord", "String"]
    value: int | str

    @model_validator(mode="after")
    def _not_an_autostart_key(self) -> RegistryItem:
        if DENIED_REGISTRY_KEYS & {part.lower() for part in self.path.split("\\")}:
            raise ValueError("a fix may not touch Run, RunOnce or Defender exclusion keys")
        return self

    @model_validator(mode="after")
    def _value_fits_type(self) -> RegistryItem:
        if self.type == "DWord" and not (
            isinstance(self.value, int) and 0 <= self.value <= 0x7FFFFFFF
        ):
            # Windows reads larger DWords back as negative numbers, so they could not be verified.
            raise ValueError("a DWord value must be a whole number from 0 to 2147483647")
        if self.type == "String" and not isinstance(self.value, str):
            raise ValueError("a String value must be text")
        return self


class AuditItem(Strict):
    """An advanced audit policy subcategory; apply.ps1 adds the required results to it."""

    kind: Literal["audit"]
    guid: str = Field(pattern=AUDIT_GUID_PATTERN)
    subcategory: Paragraph
    require: Literal["success", "failure", "both"]


class AccountItem(Strict):
    """A local account policy that apply.ps1 sets with 'net accounts'."""

    kind: Literal["account"]
    option: Literal[
        "uniquepw", "minpwage", "minpwlen", "lockoutthreshold", "lockoutduration", "lockoutwindow"
    ]
    value: int = Field(ge=0, le=999)


FixItem = Annotated[RegistryItem | AuditItem | AccountItem, Field(discriminator="kind")]


class Fix(Strict):
    """One reversible change to WS-01 and the failed CIS checks it should make pass."""

    id: str = Field(pattern=FIX_PATTERN)
    title: Paragraph
    why: Paragraph
    effect: Paragraph
    optional: bool = False
    checks: tuple[int, ...] = Field(min_length=1)
    items: tuple[FixItem, ...] = Field(min_length=1)


class FixList(Strict):
    fixes: tuple[Fix, ...]
```

In `ecc/load.py`, replace:

```python
    Evidence,
    Mapping,
```

with:

```python
    Evidence,
    FixList,
    Mapping,
```

In `ecc/load.py`, replace:

```python
    sama_mapping: SamaMapping
```

with:

```python
    sama_mapping: SamaMapping
    fixes: FixList
```

In `ecc/load.py`, replace:

```python
def load_catalog(path: Path) -> tuple[Control, ...]:
```

with:

```python
def load_json_model(model: type[ModelT], path: Path) -> ModelT:
    try:
        return model.model_validate_json(read_text(path))
    except ValidationError as error:
        raise DataError(f"{path.name}: {error}") from error


def load_catalog(path: Path) -> tuple[Control, ...]:
```

In `ecc/load.py`, replace:

```python
    """Read all nine data files; if any are broken, report every one of them together."""
```

with:

```python
    """Read all ten data files; if any are broken, report every one of them together."""
```

In `ecc/load.py`, replace:

```python
        "sama_mapping": lambda: load_model(SamaMapping, data / "sama_mapping.yaml"),
```

with:

```python
        "sama_mapping": lambda: load_model(SamaMapping, data / "sama_mapping.yaml"),
        "fixes": lambda: load_json_model(FixList, root / "remediation" / "fixes.json"),
```

In `ecc/load.py`, replace:

```python
def load_snapshot(path: Path) -> Snapshot:
    try:
        return Snapshot.model_validate_json(read_text(path))
    except ValidationError as error:
        raise DataError(f"{path.name}: {error}") from error
```

with:

```python
def load_snapshot(path: Path) -> Snapshot:
    return load_json_model(Snapshot, path)
```

In `ecc/validate.py`, replace:

```python
    report("snapshots: labels used twice", duplicates(s.label for s in snapshots))
    check_ids = {check.id for check in dataset.policy.checks}
```

with:

```python
    fixes = dataset.fixes.fixes
    fixed = [check for fix in fixes for check in fix.checks]
    check_ids = {check.id for check in dataset.policy.checks}
    report("fixes.json: fix ids used twice", duplicates(fix.id for fix in fixes))
    report("fixes.json: unknown CIS checks", [str(c) for c in sorted(set(fixed) - check_ids)])
    report("fixes.json: checks listed in two fixes", duplicates(str(c) for c in fixed))
    if snapshots:
        first = snapshots[0]
        failed = {check.id for check in first.checks if check.result == "failed"}
        report(
            f"fixes.json: checks that were not failing in snapshot '{first.label}'",
            [str(c) for c in sorted((set(fixed) & check_ids) - failed)],
        )

    report("snapshots: labels used twice", duplicates(s.label for s in snapshots))
```

Create `ecc/remediation.py`:

```python
"""What each fix in remediation/fixes.json changed, measured in the snapshots."""

from __future__ import annotations

from dataclasses import dataclass

from ecc.load import Dataset
from ecc.mapping import controls_for
from ecc.models import Fix, Snapshot


@dataclass(frozen=True)
class FixResult:
    fix: Fix
    controls: tuple[str, ...]
    before: int | None
    after: int


def control_key(control_id: str) -> tuple[int, ...]:
    return tuple(int(part) for part in control_id.split("-"))


def passing(snapshot: Snapshot, checks: tuple[int, ...]) -> int:
    """How many of the given checks passed in a snapshot."""
    results = {check.id: check.result for check in snapshot.checks}
    return sum(1 for check in checks if results.get(check) == "passed")


def fix_results(
    dataset: Dataset, after: Snapshot, before: Snapshot | None = None
) -> tuple[FixResult, ...]:
    """Each fix with the ECC controls its checks map to and how many of its checks pass."""
    by_id = {check.id: check for check in dataset.policy.checks}
    rows: list[FixResult] = []
    for fix in dataset.fixes.fixes:
        controls = {
            control
            for check in fix.checks
            if check in by_id
            for control in controls_for(by_id[check], dataset.mapping)
        }
        rows.append(
            FixResult(
                fix=fix,
                controls=tuple(sorted(controls, key=control_key)),
                before=passing(before, fix.checks) if before is not None else None,
                after=passing(after, fix.checks),
            )
        )
    return tuple(rows)
```

- [ ] **Step 3: Verify and commit**

Run:
- `.venv/Scripts/python -m pytest -q -W error`: `260 passed`.
- `.venv/Scripts/python -m ruff check .`
- `.venv/Scripts/python -m ecc check`: `OK: 108 controls, 482 checks, 1 snapshot(s).`

```bash
git add remediation/fixes.json ecc/models.py ecc/load.py ecc/validate.py ecc/remediation.py tests/fixtures.py tests/test_validate.py tests/test_remediation.py tests/test_real_data.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "List the remediation fixes and validate them against the checks they target"
```

---

### Task 2: The PowerShell module, apply.ps1 and undo.ps1

**Files:** Create `remediation/Remediation.psm1`, `remediation/apply.ps1`, `remediation/undo.ps1`, `tests/test_remediation_scripts.py`.

**Interfaces produced (PowerShell module functions):**
- **Reading the fix list:** `Get-FixItems -Path [-IncludeOptional]`, `Assert-ItemAllowed`.
- **Reading settings:**
  - `Get-AccountSettings` and `ConvertFrom-NetAccounts`;
  - `Get-AuditSettings` and `ConvertFrom-AuditBackup`;
  - `Get-ItemState`, `Get-TargetState` and `Get-Plan -Items`.
- **Showing a plan or backup:** `Format-Plan`, `Format-Backup`, `Get-ChangeCount`, `Get-StateLabel`, `Format-StateValue`, `Test-StateMatch`.
- **Changing and restoring:** `Set-ItemState`, `Set-AccountOption`, `Invoke-Apply -Plan -BackupDirectory` (returns the backup path), `Read-Backup` (validates every entry with `Assert-StateValid`), `Invoke-Undo -Backup` (attempts every restore and reports all failures together).
- **Checking:** `Find-Mismatches`, `Assert-Administrator`.

`apply.ps1 [-IncludeLockout] [-WhatIf]` and `undo.ps1 -Backup <file> [-WhatIf]` require an administrator PowerShell and ask once for confirmation.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_remediation_scripts.py`:

```python
"""Tests for remediation/Remediation.psm1, run through Windows PowerShell.

They only create and delete test keys under HKCU and read 'net accounts'; nothing here needs an
administrator or changes a system setting. CI's Windows job also applies and undoes the real
fixes on its throwaway runner.
"""

import ctypes
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "remediation" / "Remediation.psm1"
POWERSHELL = shutil.which("powershell")

pytestmark = pytest.mark.skipif(
    os.name != "nt" or POWERSHELL is None, reason="needs Windows PowerShell"
)

# Run before every test script: strict mode, the module, and a helper that builds a fix item.
PREAMBLE = f"""\
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module '{MODULE}' -Force
function Reg($fix, $path, $name, $type, $value) {{
    [pscustomobject]@{{
        kind = 'registry'; fix = $fix; path = $path; name = $name; type = $type; value = $value
    }}
}}
"""

NET_ACCOUNTS = """\
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           10
Lockout observation window (minutes):                 10
Computer role:                                        WORKSTATION
The command completed successfully.
"""

AUDIT_BACKUP = """\
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,\
Setting Value
DESKTOP-TEST1,System,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success,,1
DESKTOP-TEST1,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,,0
,,Option:CrashOnAuditFail,,Disabled,,0
"""

CREDENTIAL_VALIDATION = "{0CCE923F-69AE-11D9-BED3-505054503030}"
RUN_KEY = "Microsoft\\Windows\\CurrentVersion\\Run"
POLICIES = "Microsoft\\Windows\\CurrentVersion\\Policies"


def run_file(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    command = [POWERSHELL or "powershell", "-NoProfile", "-NonInteractive"]
    command += ["-ExecutionPolicy", "Bypass", "-File", str(script), *args]
    return subprocess.run(command, capture_output=True, text=True, timeout=120)


def powershell(tmp_path: Path, body: str) -> subprocess.CompletedProcess[str]:
    script = tmp_path / f"test-{uuid.uuid4().hex[:8]}.ps1"
    script.write_text(PREAMBLE + body, encoding="utf-8")
    return run_file(script)


def result(tmp_path: Path, body: str) -> Any:
    """Run a script whose last output line is JSON (lines before it are progress messages)."""
    done = powershell(tmp_path, body)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


@pytest.fixture
def key(tmp_path: Path):
    """A fresh, empty registry key under HKCU, deleted after the test."""
    path = f"HKCU:\\Software\\ecc-remediation-test-{uuid.uuid4().hex[:8]}"
    yield path
    powershell(tmp_path, f"Remove-Item -LiteralPath '{path}' -Recurse -ErrorAction Ignore")


def test_the_fix_list_is_read_and_checked(tmp_path):
    fixes = ROOT / "remediation" / "fixes.json"
    found = result(
        tmp_path,
        f"""
$all = @(Get-FixItems -Path '{fixes}' -IncludeOptional)
$default = @(Get-FixItems -Path '{fixes}')
@{{
    all = $all.Count
    default = $default.Count
    lockout = @($default | Where-Object {{ $_.fix -eq 'F08' }}).Count
    kinds = @($all | ForEach-Object {{ $_.kind }} | Sort-Object -Unique)
}} | ConvertTo-Json -Compress
""",
    )
    kinds = ["account", "audit", "registry"]
    assert found == {"all": 57, "default": 54, "lockout": 0, "kinds": kinds}


@pytest.mark.parametrize(
    ("key", "name", "message"),
    [
        (f"HKLM:\\SOFTWARE\\{RUN_KEY}", "Updater", "path"),
        (f"HKLM:\\SOFTWARE\\Policies\\..\\{RUN_KEY}", "Updater", "path"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\*", "Updater", "path"),
        (f"HKLM:\\SOFTWARE\\{POLICIES}\\Explorer\\Run", "Updater", "path"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions", "x", "path"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft", "Up'; Start-Process calc; '", "value name"),
    ],
)
def test_a_fix_outside_the_policy_keys_is_refused(tmp_path, key, name, message):
    item = {"kind": "registry", "path": key, "name": name, "type": "String", "value": "x"}
    fix = {"id": "F01", "title": "t", "why": "w", "effect": "e", "checks": [1], "items": [item]}
    path = tmp_path / "fixes.json"
    path.write_text(json.dumps({"fixes": [fix]}), encoding="utf-8")
    done = powershell(tmp_path, f"Get-FixItems -Path '{path}' | Out-Null")
    assert done.returncode != 0
    assert f"Registry {message} not allowed" in done.stderr


def test_net_accounts_output_is_read(tmp_path):
    text = tmp_path / "net.txt"
    text.write_text(NET_ACCOUNTS, encoding="utf-8")
    found = result(
        tmp_path,
        f"ConvertFrom-NetAccounts -Lines (Get-Content '{text}') | ConvertTo-Json -Compress",
    )
    assert found == {
        "uniquepw": 0,
        "minpwage": 0,
        "minpwlen": 0,
        "lockoutthreshold": 0,
        "lockoutduration": 10,
        "lockoutwindow": 10,
    }


def test_unreadable_net_accounts_output_stops(tmp_path):
    text = tmp_path / "net.txt"
    text.write_text(NET_ACCOUNTS.replace("Never\nLockout duration", "Nunca\nLockout duration"))
    done = powershell(tmp_path, f"ConvertFrom-NetAccounts -Lines (Get-Content '{text}')")
    assert done.returncode != 0
    assert "Cannot read 'Lockout threshold'" in done.stderr


def test_this_pcs_account_settings_can_be_read(tmp_path):
    found = result(tmp_path, "Get-AccountSettings | ConvertTo-Json -Compress")
    options = {"uniquepw", "minpwage", "minpwlen", "lockoutthreshold", "lockoutduration"}
    assert set(found) == options | {"lockoutwindow"}
    assert all(isinstance(value, int) and value >= 0 for value in found.values())


def audit_item(subcategory: str, require: str) -> str:
    return f"""
$audit = ConvertFrom-AuditBackup -Lines (Get-Content (Join-Path '{{dir}}' 'audit.csv'))
$item = [pscustomobject]@{{
    kind = 'audit'; fix = 'F02'; guid = '{CREDENTIAL_VALIDATION}'
    subcategory = '{subcategory}'; require = '{require}'
}}
"""


def test_lockout_changes_keep_the_window_within_the_duration(tmp_path):
    # A fake 'net accounts' that refuses a window longer than the duration, as Windows does,
    # starting from GitHub's runner defaults (no threshold, 30-minute duration and window).
    found = result(
        tmp_path,
        """
$module = Get-Module Remediation
& $module {
    $script:Fake = @{
        uniquepw = 0; minpwage = 0; minpwlen = 0
        lockoutthreshold = 0; lockoutduration = 30; lockoutwindow = 30
    }
    function script:Get-AccountSettings { $script:Fake.Clone() }
    function script:Set-AccountOption($Option, $Value) {
        $next = $script:Fake.Clone()
        $next[$Option] = $Value
        if ($next.lockoutduration -gt 0 -and $next.lockoutwindow -gt $next.lockoutduration) {
            throw 'window longer than duration'
        }
        $script:Fake = $next
    }
}
function Acct($option, $value) {
    [pscustomobject]@{ kind = 'account'; fix = 'F08'; option = $option; value = $value }
}
function Now {
    $f = & $module { $Fake }
    '{0}/{1}/{2}' -f $f.lockoutthreshold, $f.lockoutduration, $f.lockoutwindow
}
$apply = @((Acct 'lockoutthreshold' 5), (Acct 'lockoutduration' 15), (Acct 'lockoutwindow' 15))
foreach ($step in $apply) { Set-ItemState $step }
$applied = Now
$undo = @((Acct 'lockoutwindow' 30), (Acct 'lockoutduration' 30), (Acct 'lockoutthreshold' 0))
foreach ($step in $undo) { Set-ItemState $step }
@{ applied = $applied; restored = Now } | ConvertTo-Json -Compress
""",
    )
    assert found == {"applied": "5/15/15", "restored": "0/30/30"}


def test_audit_settings_are_read_and_only_ever_added(tmp_path):
    (tmp_path / "audit.csv").write_text(AUDIT_BACKUP, encoding="utf-8")
    setup = audit_item("Credential Validation", "failure").replace("{dir}", str(tmp_path))
    found = result(
        tmp_path,
        setup
        + """
$current = Get-ItemState -Item $item -Audit $audit
$target = Get-TargetState -Item $item -Current $current
@{
    guids = @($audit.Keys | Sort-Object)
    now = Format-StateValue $current
    after = Format-StateValue $target
} | ConvertTo-Json -Compress
""",
    )
    assert found == {
        "guids": ["{0CCE922B-69AE-11D9-BED3-505054503030}", CREDENTIAL_VALIDATION],
        "now": "Success",
        "after": "Success and Failure",
    }


def test_a_renamed_audit_subcategory_stops(tmp_path):
    (tmp_path / "audit.csv").write_text(AUDIT_BACKUP, encoding="utf-8")
    setup = audit_item("Process Creation", "success").replace("{dir}", str(tmp_path))
    done = powershell(tmp_path, setup + "Get-ItemState -Item $item -Audit $audit\n")
    assert done.returncode != 0
    assert "not 'Process Creation'" in done.stderr


def test_registry_changes_are_backed_up_and_undone(tmp_path, key):
    found = result(
        tmp_path,
        f"""
$key = '{key}'
$deeper = Join-Path $key 'New\\Deeper'
$null = New-Item -Path $key
$null = New-ItemProperty -LiteralPath $key -Name Kept -PropertyType DWord -Value 7
$old = '%SystemRoot%\\old.log'
$null = New-ItemProperty -LiteralPath $key -Name Expand -PropertyType ExpandString -Value $old
$items = @(
    Reg 'F01' $key 'Kept' 'DWord' 1
    Reg 'F01' $key 'Expand' 'String' '%SystemRoot%\\new.log'
    Reg 'F02' $deeper 'Added' 'DWord' 255
)
$plan = @(Get-Plan -Items $items)
$backupPath = Invoke-Apply -Plan $plan -BackupDirectory (Join-Path '{tmp_path}' 'backups')
$applied = (Get-ItemProperty -LiteralPath $deeper).Added
$kindAfter = (Get-Item -LiteralPath $key).GetValueKind('Expand').ToString()
$backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
Invoke-Undo -Backup $backup
$restored = Get-Item -LiteralPath $key
@{{
    applied = $applied
    kindAfter = $kindAfter
    created = @($backup.created_keys)
    kept = $restored.GetValue('Kept')
    expand = $restored.GetValue('Expand', $null, 'DoNotExpandEnvironmentNames')
    kind = $restored.GetValueKind('Expand').ToString()
    newKeyGone = -not (Test-Path -LiteralPath (Join-Path $key 'New'))
}} | ConvertTo-Json -Compress
""",
    )
    assert found == {
        "applied": 255,
        "kindAfter": "String",
        "created": [f"{key}\\New", f"{key}\\New\\Deeper"],
        "kept": 7,
        "expand": "%SystemRoot%\\old.log",
        "kind": "ExpandString",
        "newKeyGone": True,
    }


def test_the_plan_and_the_backup_are_shown(tmp_path, key):
    found = result(
        tmp_path,
        f"""
$key = '{key}'
$null = New-Item -Path $key
$null = New-ItemProperty -LiteralPath $key -Name Same -PropertyType DWord -Value 1
$items = @(Reg 'F01' $key 'Same' 'DWord' 1; Reg 'F02' $key 'New' 'String' 'on')
$plan = @(Get-Plan -Items $items)
$backupPath = Invoke-Apply -Plan $plan -BackupDirectory (Join-Path '{tmp_path}' 'backups')
$backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
Invoke-Undo -Backup $backup
@{{
    plan = @(Format-Plan -Plan $plan | ForEach-Object {{ "$($_.Fix) $($_.Now) -> $($_.After)" }})
    changes = Get-ChangeCount -Plan $plan
    backup = @(Format-Backup -Backup $backup | ForEach-Object {{ "$($_.Fix) $($_.RestoreTo)" }})
}} | ConvertTo-Json -Compress
""",
    )
    assert found == {
        "plan": ["F01 1 -> 1", "F02 (not set) -> on"],
        "changes": 1,
        "backup": ["F01 1", "F02 (not set)"],
    }


def test_a_failed_restore_does_not_stop_the_others(tmp_path, key):
    found = result(
        tmp_path,
        f"""
$key = '{key}'
$null = New-Item -Path $key
$null = New-ItemProperty -LiteralPath $key -Name A -PropertyType DWord -Value 1
$null = New-ItemProperty -LiteralPath $key -Name B -PropertyType DWord -Value 2
function Saved($fix, $name, $value) {{
    [pscustomobject]@{{
        kind = 'registry'; fix = $fix; path = $key; name = $name
        exists = $true; type = 'DWord'; value = $value
    }}
}}
$backup = [pscustomobject]@{{
    format = 1; created_keys = @()
    items = @((Saved 'F01' 'A' 7), (Saved 'F02' 'Bad' 'not a number'), (Saved 'F03' 'B' 8))
}}
$message = ''
try {{ Invoke-Undo -Backup $backup }} catch {{ $message = $_.Exception.Message }}
$restored = Get-Item -LiteralPath $key
@{{
    a = $restored.GetValue('A')
    b = $restored.GetValue('B')
    namesBad = $message.Contains('\\Bad (')
}} | ConvertTo-Json -Compress
""",
    )
    assert found == {"a": 7, "b": 8, "namesBad": True}


def test_only_empty_created_keys_are_removed(tmp_path, key):
    found = result(
        tmp_path,
        f"""
$key = '{key}'
$null = New-Item -Path (Join-Path $key 'Empty') -Force
$null = New-Item -Path (Join-Path $key 'Used') -Force
$null = New-ItemProperty -LiteralPath (Join-Path $key 'Used') -Name Other -Value 'kept'
Remove-EmptyKeys -Keys @((Join-Path $key 'Empty'), (Join-Path $key 'Used'))
@{{
    empty = Test-Path -LiteralPath (Join-Path $key 'Empty')
    used = Test-Path -LiteralPath (Join-Path $key 'Used')
}} | ConvertTo-Json -Compress
""",
    )
    assert found == {"empty": False, "used": True}


ALLOWED = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"


@pytest.mark.parametrize(
    ("items", "created", "message"),
    [
        (
            [{"kind": "account", "fix": "F07", "option": "uniquepw", "value": '5" /maxpwage:1 "'}],
            [],
            "Backup entry for net accounts /uniquepw is not valid",
        ),
        (
            [
                {
                    "kind": "audit",
                    "fix": "F02",
                    "guid": CREDENTIAL_VALIDATION,
                    "subcategory": "Credential Validation",
                    "value": 7,
                }
            ],
            [],
            "Backup entry for Audit Credential Validation is not valid",
        ),
        (
            [
                {
                    "kind": "registry",
                    "fix": "F11",
                    "path": ALLOWED,
                    "name": "EnableMulticast",
                    "exists": "yes",
                    "type": "DWord",
                    "value": 0,
                }
            ],
            [],
            "is not valid",
        ),
        (
            [
                {
                    "kind": "registry",
                    "fix": "F11",
                    "path": [ALLOWED, 0],
                    "name": "EnableMulticast",
                    "exists": False,
                    "type": None,
                    "value": None,
                }
            ],
            [],
            "Registry path not allowed",
        ),
        ([], [f"HKLM:\\SOFTWARE\\{POLICIES}\\Explorer\\Run"], "Registry path not allowed"),
    ],
)
def test_a_crafted_backup_is_refused(tmp_path, items, created, message):
    path = tmp_path / "backup.json"
    backup = {"format": 1, "taken_at": "2026-10-10T00:00:00Z", "created_keys": created}
    path.write_text(json.dumps({**backup, "items": items}), encoding="utf-8")
    done = powershell(tmp_path, f"Read-Backup -Path '{path}' | Out-Null")
    assert done.returncode != 0
    assert message in done.stderr


def test_a_backup_of_this_pcs_settings_can_be_read_back(tmp_path):
    # Reads the real registry and 'net accounts' (nothing is changed); only the audit settings,
    # which need an administrator to read, are faked as 'No auditing'.
    fixes = ROOT / "remediation" / "fixes.json"
    found = result(
        tmp_path,
        f"""
$items = @(Get-FixItems -Path '{fixes}' -IncludeOptional)
$csv = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,' +
    'Inclusion Setting,Exclusion Setting,Setting Value')
foreach ($item in ($items | Where-Object {{ $_.kind -eq 'audit' }})) {{
    $csv += "DESKTOP-TEST1,System,$($item.subcategory),$($item.guid),No Auditing,,0"
}}
& (Get-Module Remediation) {{
    param($lines)
    $script:FakeAudit = ConvertFrom-AuditBackup -Lines $lines
    function script:Get-AuditSettings {{ $script:FakeAudit }}
}} $csv
$plan = @(Get-Plan -Items $items)
$states = @($plan | ForEach-Object {{ $_.Current }})
$path = Save-Backup -States $states -Directory (Join-Path '{tmp_path}' 'backups')
$backup = Read-Backup -Path $path
@{{ items = @($backup.items).Count; rows = @(Format-Backup -Backup $backup).Count }} |
    ConvertTo-Json -Compress
""",
    )
    assert found == {"items": 57, "rows": 57}


def test_a_failed_change_undoes_the_others(tmp_path, key):
    found = result(
        tmp_path,
        f"""
$WarningPreference = 'SilentlyContinue'
$key = '{key}'
$null = New-Item -Path $key
$null = New-ItemProperty -LiteralPath $key -Name Kept -PropertyType DWord -Value 7
$items = @(
    Reg 'F01' $key 'Kept' 'DWord' 1
    Reg 'F02' (Join-Path $key 'Fails') 'Bad' 'DWord' 'not a number'
)
$plan = @(Get-Plan -Items $items)
$failed = $false
try {{
    $null = Invoke-Apply -Plan $plan -BackupDirectory (Join-Path '{tmp_path}' 'backups')
}} catch {{ $failed = $true }}
@{{
    failed = $failed
    kept = (Get-Item -LiteralPath $key).GetValue('Kept')
    newKeyGone = -not (Test-Path -LiteralPath (Join-Path $key 'Fails'))
}} | ConvertTo-Json -Compress
""",
    )
    assert found == {"failed": True, "kept": 7, "newKeyGone": True}


@pytest.mark.skipif(
    os.name == "nt" and ctypes.windll.shell32.IsUserAnAdmin() != 0,
    reason="the check only shows without administrator rights",
)
@pytest.mark.parametrize(
    ("script", "args"),
    [("apply.ps1", ["-WhatIf"]), ("undo.ps1", ["-Backup", "missing.json", "-WhatIf"])],
)
def test_the_scripts_need_an_administrator(script, args):
    done = run_file(ROOT / "remediation" / script, *args)
    assert done.returncode != 0
    assert "administrator PowerShell" in done.stderr
```

Run: `.venv/Scripts/python -m pytest tests/test_remediation_scripts.py -q`
Expected: failures, because `remediation/Remediation.psm1` does not exist yet. The tests only create and delete keys under `HKCU:\Software\ecc-remediation-test-*`, and the administrator check is skipped when the shell is already elevated.

- [ ] **Step 2: Implement**

Create `remediation/Remediation.psm1`:

```powershell
# Read, change and restore the Windows settings listed in fixes.json.
# Used by apply.ps1 and undo.ps1. Written for Windows PowerShell 5.1.

Set-StrictMode -Version Latest
# Every failure stops the function, however the calling script was started.
$ErrorActionPreference = 'Stop'

# Fixes may only touch policy keys and the two security-option keys under Control. Key and value
# names use plain characters only, so a path cannot climb out with '..' or match keys with '*'.
$RegistryKey = '\\[A-Za-z0-9_-][A-Za-z0-9 _-]*'
$AllowedRegistryPath = "^HKLM:\\(SOFTWARE\\Policies($RegistryKey)+|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies($RegistryKey)+|SYSTEM\\CurrentControlSet\\Control\\(Lsa|SAM))\z"
$AllowedRegistryName = '^[A-Za-z0-9_]+\z'
# Keys a fix may never touch, even under a policy root: autostart lists and Defender exclusions.
$DeniedRegistryKeys = @('Run', 'RunOnce', 'Exclusions')
$AuditGuidPattern = '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}\z'
$AuditBits = @{ success = 1; failure = 2; both = 3 }
$AuditNames = @('No auditing', 'Success', 'Failure', 'Success and Failure')

# The 'net accounts' option for each setting, and the label its output uses.
$AccountLabels = [ordered]@{
    uniquepw         = 'Length of password history maintained'
    minpwage         = 'Minimum password age (days)'
    minpwlen         = 'Minimum password length'
    lockoutthreshold = 'Lockout threshold'
    lockoutduration  = 'Lockout duration (minutes)'
    lockoutwindow    = 'Lockout observation window (minutes)'
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'Run this from an administrator PowerShell (right-click Windows PowerShell, Run as administrator).'
    }
}

function Test-AllowedRegistryPath {
    param([Parameter(Mandatory = $true)] [AllowNull()] $Path)
    if ($Path -isnot [string] -or $Path -notmatch $AllowedRegistryPath) { return $false }
    -not @($Path.Split('\') | Where-Object { $DeniedRegistryKeys -contains $_ }).Count
}

function Test-WholeNumber {
    param([AllowNull()] $Value, [long] $Min, [long] $Max)
    ($Value -is [int] -or $Value -is [long]) -and $Value -ge $Min -and $Value -le $Max
}

function Assert-ItemAllowed {
    # Refuse anything outside the three kinds of change the project allows. Every field must be a
    # single string, so an array or an injected switch cannot slip through a pattern match.
    param([Parameter(Mandatory = $true)] $Item)
    if ($Item.kind -isnot [string]) { throw "Unknown kind of change: $($Item.kind)" }
    switch ($Item.kind) {
        'registry' {
            if (-not (Test-AllowedRegistryPath $Item.path)) { throw "Registry path not allowed: $($Item.path)" }
            if ($Item.name -isnot [string] -or $Item.name -notmatch $AllowedRegistryName) {
                throw "Registry value name not allowed: $($Item.name)"
            }
        }
        'audit' {
            if ($Item.guid -isnot [string] -or $Item.guid -notmatch $AuditGuidPattern) {
                throw "Not an audit subcategory GUID: $($Item.guid)"
            }
        }
        'account' {
            if ($Item.option -isnot [string] -or -not $AccountLabels.Contains($Item.option)) {
                throw "Unknown account option: $($Item.option)"
            }
        }
        default { throw "Unknown kind of change: $($Item.kind)" }
    }
}

function Assert-StateValid {
    # A backup entry must hold only what Get-ItemState records: nothing that could become a switch.
    param([Parameter(Mandatory = $true)] $State)
    Assert-ItemAllowed $State
    $label = Get-StateLabel $State
    switch ($State.kind) {
        'registry' {
            $valid = $State.exists -is [bool]
            if ($valid -and $State.exists) {
                if ($State.type -eq 'DWord') { $valid = Test-WholeNumber $State.value -2147483648 4294967295 }
                elseif ($State.type -in @('String', 'ExpandString')) { $valid = $State.value -is [string] }
                else { $valid = $false }
            }
            if (-not $valid) { throw "Backup entry for $label is not valid." }
        }
        'audit' { if (-not (Test-WholeNumber $State.value 0 3)) { throw "Backup entry for $label is not valid." } }
        'account' { if (-not (Test-WholeNumber $State.value 0 99999)) { throw "Backup entry for $label is not valid." } }
    }
}

function Get-FixItems {
    # Every item of every fix in fixes.json, in file order, tagged with its fix id.
    param([Parameter(Mandatory = $true)] [string] $Path, [switch] $IncludeOptional)
    $list = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($fix in $list.fixes) {
        $optional = ($fix.PSObject.Properties.Name -contains 'optional') -and $fix.optional
        if ($optional -and -not $IncludeOptional) { continue }
        foreach ($item in $fix.items) {
            Assert-ItemAllowed $item
            if ($item.kind -eq 'registry') {
                $fits = switch ($item.type) {
                    # Larger DWords read back as negative numbers and could not be verified.
                    'DWord' { Test-WholeNumber $item.value 0 2147483647 }
                    'String' { $item.value -is [string] }
                    default { $false }
                }
                if (-not $fits) { throw "Unsupported registry type or value: $($item.type) $($item.value)" }
            }
            if ($item.kind -eq 'audit' -and -not $AuditBits.ContainsKey([string]$item.require)) {
                throw "Unknown audit requirement: $($item.require)"
            }
            if ($item.kind -eq 'account' -and -not (Test-WholeNumber $item.value 0 999)) {
                throw "Account value must be a whole number from 0 to 999: $($item.value)"
            }
            $copy = $item.PSObject.Copy()
            $copy | Add-Member -NotePropertyName fix -NotePropertyValue $fix.id
            $copy | Add-Member -NotePropertyName title -NotePropertyValue $fix.title
            $copy
        }
    }
}

function ConvertFrom-NetAccounts {
    # The six account settings from the text 'net accounts' prints.
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string[]] $Lines)
    $settings = @{}
    foreach ($option in $AccountLabels.Keys) {
        $label = $AccountLabels[$option]
        $line = $Lines | Where-Object { $_.StartsWith("${label}:") } | Select-Object -First 1
        if (-not $line) { throw "net accounts did not report '$label'." }
        $text = $line.Substring($label.Length + 1).Trim()
        if ($text -match '^\d+$') { $settings[$option] = [int]$text }
        elseif ($text -in @('None', 'Never')) { $settings[$option] = 0 }
        else { throw "Cannot read '$label' from net accounts: '$text'." }
    }
    $settings
}

function Get-AccountSettings {
    $lines = & net.exe accounts
    if ($LASTEXITCODE -ne 0) { throw "net accounts failed with exit code $LASTEXITCODE." }
    ConvertFrom-NetAccounts -Lines $lines
}

function Format-AuditGuid {
    param([Parameter(Mandatory = $true)] [string] $Guid)
    '{' + $Guid.Trim('{', '}').ToUpperInvariant() + '}'
}

function ConvertFrom-AuditBackup {
    # Subcategory settings from the CSV 'auditpol /backup' writes: GUID -> name and value 0-3.
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string[]] $Lines)
    $settings = @{}
    foreach ($row in ($Lines | ConvertFrom-Csv)) {
        $guid = $row.'Subcategory GUID'
        if ($guid) {
            $settings[(Format-AuditGuid $guid)] = @{ name = $row.Subcategory; value = [int]$row.'Setting Value' }
        }
    }
    $settings
}

function Get-AuditSettings {
    # The backup file names the computer, so it lives in TEMP only while it is read.
    $file = Join-Path $env:TEMP ('audit-{0}.csv' -f [guid]::NewGuid())
    try {
        $null = & auditpol.exe /backup "/file:$file"
        if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed with exit code $LASTEXITCODE." }
        ConvertFrom-AuditBackup -Lines (Get-Content -LiteralPath $file)
    }
    finally {
        # -WhatIf on apply.ps1 must not keep this file, so this removal ignores it.
        Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
    }
}

function Get-ItemState {
    # The current value of one setting, in the form the backup file stores.
    param([Parameter(Mandatory = $true)] $Item, $Audit, $Account)
    switch ($Item.kind) {
        'registry' {
            $state = [ordered]@{
                kind = 'registry'; fix = $Item.fix; path = $Item.path; name = $Item.name
                exists = $false; type = $null; value = $null
            }
            if (Test-Path -LiteralPath $Item.path) {
                $key = Get-Item -LiteralPath $Item.path
                if ($key.GetValueNames() -contains $Item.name) {
                    $kind = $key.GetValueKind($Item.name).ToString()
                    if ($kind -notin @('DWord', 'String', 'ExpandString')) {
                        throw "$($Item.path)\$($Item.name) holds a $kind value, which these scripts cannot restore."
                    }
                    $state.exists = $true
                    $state.type = $kind
                    $state.value = $key.GetValue($Item.name, $null, 'DoNotExpandEnvironmentNames')
                }
            }
            [pscustomobject]$state
        }
        'audit' {
            $guid = Format-AuditGuid $Item.guid
            $value = 0
            if ($Audit.ContainsKey($guid)) {
                $windowsName = $Audit[$guid].name
                if ($windowsName -ne $Item.subcategory) {
                    throw "Windows calls $guid '$windowsName', not '$($Item.subcategory)'."
                }
                $value = $Audit[$guid].value
            }
            [pscustomobject][ordered]@{
                kind = 'audit'; fix = $Item.fix; guid = $guid; subcategory = $Item.subcategory; value = $value
            }
        }
        'account' {
            [pscustomobject][ordered]@{
                kind = 'account'; fix = $Item.fix; option = $Item.option; value = $Account[[string]$Item.option]
            }
        }
    }
}

function Get-TargetState {
    # What the setting should be after the fix. Auditing is only ever added, never removed.
    param([Parameter(Mandatory = $true)] $Item, [Parameter(Mandatory = $true)] $Current)
    $target = $Current.PSObject.Copy()
    switch ($Item.kind) {
        'registry' { $target.exists = $true; $target.type = $Item.type; $target.value = $Item.value }
        'audit' { $target.value = $Current.value -bor $AuditBits[[string]$Item.require] }
        'account' { $target.value = [int]$Item.value }
    }
    $target
}

function Get-Plan {
    # For each item: what it is now and what the fix will make it.
    param([Parameter(Mandatory = $true)] $Items)
    $audit = @{}
    $account = @{}
    if (@($Items | Where-Object { $_.kind -eq 'audit' }).Count) { $audit = Get-AuditSettings }
    if (@($Items | Where-Object { $_.kind -eq 'account' }).Count) { $account = Get-AccountSettings }
    foreach ($item in $Items) {
        $current = Get-ItemState -Item $item -Audit $audit -Account $account
        [pscustomobject]@{ Item = $item; Current = $current; Target = (Get-TargetState -Item $item -Current $current) }
    }
}

function Get-StateLabel {
    param([Parameter(Mandatory = $true)] $State)
    switch ($State.kind) {
        'registry' { "$($State.path)\$($State.name)" }
        'audit' { "Audit $($State.subcategory)" }
        'account' { "net accounts /$($State.option)" }
    }
}

function Format-StateValue {
    param([Parameter(Mandatory = $true)] $State)
    switch ($State.kind) {
        'registry' { if ($State.exists) { "$($State.value)" } else { '(not set)' } }
        'audit' { $AuditNames[[int]$State.value] }
        'account' { "$($State.value)" }
    }
}

function Format-Plan {
    # One row per setting: the fix, the setting, its value now and after the fix.
    param([Parameter(Mandatory = $true)] $Plan)
    foreach ($step in $Plan) {
        [pscustomobject]@{
            Fix     = $step.Item.fix
            Setting = Get-StateLabel $step.Current
            Now     = Format-StateValue $step.Current
            After   = Format-StateValue $step.Target
        }
    }
}

function Format-Backup {
    # One row per setting in a backup: the fix, the setting and the value it goes back to.
    param([Parameter(Mandatory = $true)] $Backup)
    foreach ($state in $Backup.items) {
        [pscustomobject]@{ Fix = $state.fix; Setting = Get-StateLabel $state; RestoreTo = Format-StateValue $state }
    }
}

function Test-StateMatch {
    param([Parameter(Mandatory = $true)] $Actual, [Parameter(Mandatory = $true)] $Expected)
    if ($Expected.kind -eq 'registry') {
        if ([bool]$Actual.exists -ne [bool]$Expected.exists) { return $false }
        if (-not $Expected.exists) { return $true }
        return ($Actual.type -eq $Expected.type) -and ("$($Actual.value)" -eq "$($Expected.value)")
    }
    return [int]$Actual.value -eq [int]$Expected.value
}

function Find-Mismatches {
    # Labels of the settings whose current value differs from the expected one.
    param([Parameter(Mandatory = $true)] $Expected)
    $audit = @{}
    $account = @{}
    if (@($Expected | Where-Object { $_.kind -eq 'audit' }).Count) { $audit = Get-AuditSettings }
    if (@($Expected | Where-Object { $_.kind -eq 'account' }).Count) { $account = Get-AccountSettings }
    foreach ($state in $Expected) {
        $actual = Get-ItemState -Item $state -Audit $audit -Account $account
        if (-not (Test-StateMatch -Actual $actual -Expected $state)) { Get-StateLabel $state }
    }
}

function Get-ChangeCount {
    # How many settings in a plan are not already at their target.
    param([Parameter(Mandatory = $true)] $Plan)
    @($Plan | Where-Object { -not (Test-StateMatch -Actual $_.Current -Expected $_.Target) }).Count
}

function Get-MissingKeys {
    # The registry keys on the way to $Path that do not exist yet, outermost first.
    param([Parameter(Mandatory = $true)] [string] $Path)
    $missing = @()
    $current = $Path
    while ($current -and -not (Test-Path -LiteralPath $current)) {
        $missing = @($current) + $missing
        $current = Split-Path -Path $current -Parent
    }
    $missing
}

function Set-ItemState {
    # Make one setting match a state: a fix's target, or a value from a backup.
    param([Parameter(Mandatory = $true)] $State)
    switch ($State.kind) {
        'registry' {
            if ($State.exists) {
                foreach ($key in (Get-MissingKeys $State.path)) { $null = New-Item -Path $key }
                $null = New-ItemProperty -LiteralPath $State.path -Name $State.name -PropertyType $State.type -Value $State.value -Force
            }
            elseif ((Test-Path -LiteralPath $State.path) -and ((Get-Item -LiteralPath $State.path).GetValueNames() -contains $State.name)) {
                Remove-ItemProperty -LiteralPath $State.path -Name $State.name
            }
        }
        'audit' {
            $success = if ($State.value -band 1) { 'enable' } else { 'disable' }
            $failure = if ($State.value -band 2) { 'enable' } else { 'disable' }
            $null = & auditpol.exe /set "/subcategory:$($State.guid)" "/success:$success" "/failure:$failure"
            if ($LASTEXITCODE -ne 0) { throw "auditpol could not set $($State.subcategory) (exit code $LASTEXITCODE)." }
        }
        'account' {
            $value = [int]$State.value
            # Windows refuses a lockout window longer than the lockout duration. When this change
            # would break that, the other setting moves first; its own item sets it again later.
            # This relies on F08 listing both settings, so both are backed up and restored.
            if ($State.option -in @('lockoutduration', 'lockoutwindow')) {
                $now = Get-AccountSettings
                if ($State.option -eq 'lockoutduration' -and $value -gt 0 -and $now['lockoutwindow'] -gt $value) {
                    Set-AccountOption -Option 'lockoutwindow' -Value $value
                }
                if ($State.option -eq 'lockoutwindow' -and $now['lockoutduration'] -gt 0 -and $value -gt $now['lockoutduration']) {
                    Set-AccountOption -Option 'lockoutduration' -Value $value
                }
            }
            Set-AccountOption -Option $State.option -Value $value
        }
    }
}

function Set-AccountOption {
    param([Parameter(Mandatory = $true)] [string] $Option, [Parameter(Mandatory = $true)] [int] $Value)
    $setting = '/{0}:{1}' -f $Option, $Value
    $null = & net.exe accounts $setting
    if ($LASTEXITCODE -ne 0) { throw "net accounts could not set $setting (exit code $LASTEXITCODE)." }
}

function Remove-EmptyKeys {
    # Delete the keys apply.ps1 created, deepest first, if nothing else has been put in them.
    param([string[]] $Keys = @())
    foreach ($key in ($Keys | Sort-Object { $_.Length } -Descending)) {
        if (Test-Path -LiteralPath $key) {
            $item = Get-Item -LiteralPath $key
            if ($item.ValueCount -eq 0 -and $item.SubKeyCount -eq 0) { Remove-Item -LiteralPath $key }
        }
    }
}

function Save-Backup {
    param(
        [Parameter(Mandatory = $true)] $States,
        [string[]] $CreatedKeys = @(),
        [Parameter(Mandatory = $true)] [string] $Directory
    )
    $null = New-Item -ItemType Directory -Path $Directory -Force
    $now = (Get-Date).ToUniversalTime()
    $path = Join-Path $Directory ($now.ToString('yyyyMMdd-HHmmss-fff') + '.json')
    $backup = [ordered]@{
        format       = 1
        taken_at     = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        created_keys = @($CreatedKeys)
        items        = @($States)
    }
    $backup | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
    $path
}

function Read-Backup {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $backup = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not ($backup.PSObject.Properties.Name -contains 'format') -or $backup.format -ne 1) {
        throw "$Path is not a backup written by apply.ps1."
    }
    foreach ($state in $backup.items) { Assert-StateValid $state }
    foreach ($key in $backup.created_keys) {
        if (-not (Test-AllowedRegistryPath $key)) { throw "Registry path not allowed: $key" }
    }
    $backup
}

function Invoke-Undo {
    # Put every setting back as the backup recorded it, last change first. A setting that cannot be
    # restored does not stop the others; every problem is reported together at the end.
    param([Parameter(Mandatory = $true)] $Backup)
    $states = @($Backup.items)
    [array]::Reverse($states)
    $problems = @()
    foreach ($state in $states) {
        try { Set-ItemState $state }
        catch { $problems += "$(Get-StateLabel $state) ($($_.Exception.Message))" }
    }
    try { Remove-EmptyKeys -Keys @($Backup.created_keys) }
    catch { $problems += "removing the keys apply.ps1 created ($($_.Exception.Message))" }
    try { $problems += @(Find-Mismatches -Expected $states) }
    catch { $problems += "checking the restored values ($($_.Exception.Message))" }
    if ($problems.Count) { throw "These settings were not restored: $($problems -join '; ')" }
}

function Invoke-Apply {
    # Save a backup, apply every target, check them, and undo everything if anything fails.
    param([Parameter(Mandatory = $true)] $Plan, [Parameter(Mandatory = $true)] [string] $BackupDirectory)
    $created = @(
        $Plan | Where-Object { $_.Item.kind -eq 'registry' } |
            ForEach-Object { Get-MissingKeys $_.Item.path } | Sort-Object -Unique
    )
    $backupPath = Save-Backup -States @($Plan | ForEach-Object { $_.Current }) -CreatedKeys $created -Directory $BackupDirectory
    # Shown before any change, so the path is on screen even if the window is closed mid-way.
    Write-Host "Saved the current values to $backupPath"
    try {
        foreach ($step in $Plan) { Set-ItemState $step.Target }
        $mismatches = @(Find-Mismatches -Expected @($Plan | ForEach-Object { $_.Target }))
        if ($mismatches.Count) { throw "These settings did not take effect: $($mismatches -join ', ')" }
    }
    catch {
        $failure = $_.Exception.Message
        Write-Warning "A change failed ($failure), so every change is being undone from $backupPath."
        try { Invoke-Undo -Backup (Get-Content -LiteralPath $backupPath -Raw -Encoding UTF8 | ConvertFrom-Json) }
        catch {
            throw "A change failed ($failure), and undoing it was not complete: $($_.Exception.Message) Run undo.ps1 with $backupPath."
        }
        throw "A change failed ($failure). Every change was undone from $backupPath."
    }
    $backupPath
}

Export-ModuleMember -Function *
```

Create `remediation/apply.ps1`:

```powershell
<#
.SYNOPSIS
Applies the fixes in fixes.json to this PC, after saving every current value to a backup.

.DESCRIPTION
Run it from an administrator Windows PowerShell in the repository folder:

    powershell -ExecutionPolicy Bypass -File .\remediation\apply.ps1 -WhatIf
    powershell -ExecutionPolicy Bypass -File .\remediation\apply.ps1

-WhatIf shows every setting with its current and new value and changes nothing. Without it,
the script asks once for confirmation, writes remediation\backups\<time>.json, applies the
changes and checks each one. If any change fails, it undoes all of them from the backup.
undo.ps1 restores a backup later. Copy the backup file somewhere outside the repository too.

The CIS checks see every change at once, without a restart. Windows itself applies firewall
logging, event log sizes and name resolution at its next policy refresh (gpupdate /force or a
restart), and the built-in Administrator setting at that account's next sign-in.

.PARAMETER IncludeLockout
Also apply F08 (lock an account for 15 minutes after 5 wrong passwords).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param([switch] $IncludeLockout)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Remediation.psm1') -Force

Assert-Administrator
$items = @(Get-FixItems -Path (Join-Path $PSScriptRoot 'fixes.json') -IncludeOptional:$IncludeLockout)
$plan = @(Get-Plan -Items $items)

Write-Host 'Fixes:'
$items | Group-Object fix | ForEach-Object { Write-Host ('  {0}  {1}' -f $_.Name, $_.Group[0].title) }
Format-Plan -Plan $plan | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
$changing = Get-ChangeCount -Plan $plan
Write-Host "$changing of $($plan.Count) settings will change."
if (-not $IncludeLockout) { Write-Host 'F08 (account lockout) is left out; add -IncludeLockout to apply it.' }
$backups = Join-Path $PSScriptRoot 'backups'
$earlier = @(Get-ChildItem -Path $backups -Filter '*.json' -ErrorAction SilentlyContinue)
if ($earlier.Count) {
    Write-Warning ("remediation\backups already holds $($earlier.Count) backup(s). This run backs up " +
        'the values as they are now; to get back to the original settings, undo every backup, newest first.')
}

if (-not $PSCmdlet.ShouldProcess('this PC', "Change $changing Windows settings")) { return }

$backup = Invoke-Apply -Plan $plan -BackupDirectory $backups
Write-Host "Done. Every setting was checked after the change."
Write-Host "Backup of the old values: $backup (copy it outside the repository as well)"
Write-Host "To undo: powershell -ExecutionPolicy Bypass -File .\remediation\undo.ps1 -Backup `"$backup`""
Write-Host 'Next: run gpupdate /force so Windows applies the policy settings now.'
```

Create `remediation/undo.ps1`:

```powershell
<#
.SYNOPSIS
Restores every setting that apply.ps1 changed, from one of its backup files.

.DESCRIPTION
Run it from an administrator Windows PowerShell in the repository folder:

    powershell -ExecutionPolicy Bypass -File .\remediation\undo.ps1 -Backup .\remediation\backups\<time>.json -WhatIf
    powershell -ExecutionPolicy Bypass -File .\remediation\undo.ps1 -Backup .\remediation\backups\<time>.json

Settings that did not exist before are removed again, and registry keys that apply.ps1 created
are deleted if they are empty. Each restored value is checked afterwards.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param([Parameter(Mandatory = $true)] [string] $Backup)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Remediation.psm1') -Force

Assert-Administrator
$saved = Read-Backup -Path $Backup

Format-Backup -Backup $saved | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host

$count = @($saved.items).Count
if (-not $PSCmdlet.ShouldProcess('this PC', "Restore $count Windows settings from $Backup")) { return }

Invoke-Undo -Backup $saved
Write-Host "Restored $count settings from $Backup. Every value was checked after the change."
```

- [ ] **Step 3: Verify and commit**

Run:
- `.venv/Scripts/python -m pytest -q -W error`: `286 passed`.
- `.venv/Scripts/python -m ruff check .`
- This command, which must print `0 parse errors` for each file:

```powershell
powershell -NoProfile -Command "foreach ($f in 'remediation\apply.ps1','remediation\undo.ps1','remediation\Remediation.psm1') { $t = $null; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f), [ref]$t, [ref]$e); \"$f : $($e.Count) parse errors\" }"
```

Do not run `apply.ps1` or `undo.ps1` yourself: they change system settings, and only Ahmed runs them (Task 6).

```bash
git add tests/test_remediation_scripts.py remediation/Remediation.psm1 remediation/apply.ps1 remediation/undo.ps1
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the PowerShell scripts that apply and undo the fixes"
```

---

### Task 3: Remediation in the workbook and the report

**Files:** Modify `ecc/assess.py`, `ecc/html.py`, `ecc/excel.py`, `ecc/templates/report.html.j2`, `tests/test_assess.py`, `tests/test_html.py`, `tests/test_excel.py`.

**Interfaces produced:**
- `CheckProgress(control, before, after)`, where `before` and `after` are `(passed, usable)` pairs, plus `check_counts(result)` and `check_progress(before, after)` in `ecc/assess.py`.
- The report context gains `progress` and `fixes`.
- `SHEETS` gains `"Remediation"` between `"Roadmap"` and `"SAMA CSF view (indicative)"`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_assess.py`, replace:

```python
from ecc.assess import assess, compare, compliance, domain_scores, rate_checks
```

with:

```python
from ecc.assess import (
    assess,
    check_progress,
    compare,
    compliance,
    domain_scores,
    rate_checks,
)
```

Append to the end of `tests/test_assess.py`:

```python


def test_check_progress_counts_passing_checks_per_control(dataset, baseline, after):
    progress = check_progress(assess(dataset, baseline), assess(dataset, after))
    found = {p.control.id: (p.before, p.after) for p in progress}
    assert found == {"2-2-3": ((1, 2), (2, 2)), "2-12-3": ((0, 1), (1, 1))}
```

Append to the end of `tests/test_html.py`:

```python


def test_the_report_shows_remediation_results(dataset, baseline, after):
    html = render_html(dataset, assess(dataset, after), assess(dataset, baseline))
    assert "<h2>Remediation on WS-01</h2>" in html
    assert "were applied with remediation/apply.ps1" in html
    assert "<b>2 of 2 targeted checks pass</b> (was 0)." in html
    assert "<td>2-12-3</td><td class=\"nowrap\">0 &rarr; 1 of 1</td>" in html
    assert "Audit sign-ins</b> (optional)" in html
    assert "<h3>CIS checks passing, by control</h3>" in html
    assert "<td>2-2-3 Identity and Access Management</td><td>1 of 2</td><td>2 of 2</td>" in html


def test_a_single_snapshot_report_shows_the_planned_fixes(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "2 reversible fixes are planned in remediation/fixes.json" in html
    assert "<b>0 of 2 targeted checks pass</b>." in html
    assert "CIS checks passing, by control" not in html
```

Append to the end of `tests/test_excel.py`:

```python


def test_the_remediation_sheet_compares_two_snapshots(tmp_path, dataset, baseline, after):
    sheet = workbook(tmp_path, dataset, after, baseline)["Remediation"]
    header = ["CIS checks", "ECC controls", "baseline passing", "after passing"]
    assert values(sheet, 1)[5:] == header
    assert values(sheet, 2)[0] == "F01"
    assert values(sheet, 3)[4:] == ["Yes", "26139", "2-12-3", 0, 1]


def test_the_remediation_sheet_for_one_snapshot(tmp_path, dataset, baseline):
    sheet = workbook(tmp_path, dataset, baseline)["Remediation"]
    assert values(sheet, 1)[-2:] == ["ECC controls", "baseline passing"]
    assert values(sheet, 2)[-1] == 0
```

Run: `.venv/Scripts/python -m pytest tests/test_assess.py tests/test_html.py tests/test_excel.py -q`
Expected: an import error for `check_progress`.

- [ ] **Step 2: Implement**

Append to the end of `ecc/assess.py`:

```python


@dataclass(frozen=True)
class CheckProgress:
    control: Control
    before: tuple[int, int]
    after: tuple[int, int]


def check_counts(result: ControlResult) -> tuple[int, int]:
    """Passed and usable CIS checks of one control."""
    usable = [outcome.result for outcome in result.checks if outcome.result in USABLE]
    return usable.count("passed"), len(usable)


def check_progress(before: Assessment, after: Assessment) -> tuple[CheckProgress, ...]:
    """Passed checks in both snapshots, for every control that CIS checks measure."""
    old = {result.control.id: result for result in before.results}
    return tuple(
        CheckProgress(result.control, check_counts(old[result.control.id]), check_counts(result))
        for result in after.results
        if result.checks and result.control.id in old
    )
```

In `ecc/html.py`, replace:

```python
from ecc.assess import Assessment, compare, compliance, domain_scores
```

with:

```python
from ecc.assess import Assessment, check_progress, compare, compliance, domain_scores
```

In `ecc/html.py`, replace:

```python
from ecc.models import Status
```

with:

```python
from ecc.models import Status
from ecc.remediation import fix_results
```

In `ecc/html.py`, replace:

```python
        "changes": compare(before, after) if before is not None else (),
```

with:

```python
        "changes": compare(before, after) if before is not None else (),
        "progress": check_progress(before, after) if before is not None else (),
        "fixes": fix_results(
            dataset, after.snapshot, before.snapshot if before is not None else None
        ),
```

In `ecc/templates/report.html.j2`, replace:

```html
<p class="note">No control changed status.</p>
{% endif %}
{% endif %}
```

with:

```html
<p class="note">No control changed status.</p>
{% endif %}
{% if progress %}
<h3>CIS checks passing, by control</h3>
<div class="table-wrap"><table>
<thead><tr><th>Control</th><th>{{ before_snapshot.label }}</th><th>{{ snapshot.label }}</th></tr></thead>
<tbody>
{% for p in progress %}
<tr><td>{{ p.control.id }} {{ p.control.subdomain_title }}</td><td>{{ p.before[0] }} of {{ p.before[1] }}</td><td>{{ p.after[0] }} of {{ p.after[1] }}</td></tr>
{% endfor %}
</tbody></table></div>
<p class="note">A control is Implemented only when every one of its checks passes, so it can gain many passing checks and keep its rating.</p>
{% endif %}
{% endif %}
```

In `ecc/templates/report.html.j2`, replace:

```html
{% if not roadmap %}
<p class="note">No open risks.</p>
{% endif %}
```

with:

```html
{% if not roadmap %}
<p class="note">No open risks.</p>
{% endif %}

{% if fixes %}
<h2>Remediation on {{ snapshot.host }}</h2>
{% if before_snapshot %}
<p class="note">The fixes in remediation/fixes.json were applied with remediation/apply.ps1 between the &ldquo;{{ before_snapshot.label }}&rdquo; and &ldquo;{{ snapshot.label }}&rdquo; snapshots (an optional fix only when chosen). Each row counts the fix's own CIS checks that pass.</p>
{% else %}
<p class="note">{{ fixes|length }} reversible fixes are planned in remediation/fixes.json. remediation/apply.ps1 applies them after saving the old values, and remediation/undo.ps1 restores them. Each row counts the fix's own CIS checks that pass now.</p>
{% endif %}
<p><b>{{ fixes|sum(attribute="after") }} of {{ fixes|map(attribute="fix.checks")|map("length")|sum }} targeted checks pass</b>{% if before_snapshot %} (was {{ fixes|sum(attribute="before") }}){% endif %}.</p>
<div class="table-wrap"><table>
<thead><tr><th>Fix</th><th>Change</th><th>ECC controls</th><th>Checks passing</th></tr></thead>
<tbody>
{% for row in fixes %}
<tr><td>{{ row.fix.id }}</td><td><b>{{ row.fix.title }}</b>{% if row.fix.optional %} (optional){% endif %}<br>{{ row.fix.why }}</td><td>{{ row.controls|join(", ") }}</td><td class="nowrap">{% if row.before is not none %}{{ row.before }} &rarr; {% endif %}{{ row.after }} of {{ row.fix.checks|length }}</td></tr>
{% endfor %}
</tbody></table></div>
{% endif %}
```

In `ecc/excel.py`, replace:

```python
from ecc.models import Status
```

with:

```python
from ecc.models import Status
from ecc.remediation import fix_results
```

In `ecc/excel.py`, replace:

```python
    "Roadmap",
    "SAMA CSF view (indicative)",
```

with:

```python
    "Roadmap",
    "Remediation",
    "SAMA CSF view (indicative)",
```

In `ecc/excel.py`, replace:

```python
def write_workbook(
```

with:

```python
def write_remediation(
    sheet: Worksheet, dataset: Dataset, after: Assessment, before: Assessment | None
) -> None:
    rows = fix_results(dataset, after.snapshot, before.snapshot if before is not None else None)
    header = ["Fix", "Change", "Why", "What changes on the PC", "Optional", "CIS checks"]
    header.append("ECC controls")
    if before is not None:
        header.append(f"{before.snapshot.label} passing")
    header.append(f"{after.snapshot.label} passing")
    table(
        sheet,
        header,
        [
            [
                row.fix.id,
                row.fix.title,
                row.fix.why,
                row.fix.effect,
                "Yes" if row.fix.optional else "No",
                ", ".join(str(check) for check in row.fix.checks),
                ", ".join(row.controls),
                *([row.before] if before is not None else []),
                row.after,
            ]
            for row in rows
        ],
        [6, 36, 48, 48, 9, 30, 18, 12, 12],
        autofilter=True,
    )


def write_workbook(
```

In `ecc/excel.py`, replace:

```python
    write_risks(sheets[3], sheets[4], dataset, after)
    write_sama(sheets[5], dataset, after)
```

with:

```python
    write_risks(sheets[3], sheets[4], dataset, after)
    write_remediation(sheets[5], dataset, after, before)
    write_sama(sheets[6], dataset, after)
```

- [ ] **Step 3: Verify and commit**

Run:
- `.venv/Scripts/python -m pytest -q -W error`: `291 passed`.
- `.venv/Scripts/python -m ruff check .`
- `.venv/Scripts/python -m ecc build --no-pdf`: `26.0% compliant (baseline)`. The single-snapshot report shows "12 reversible fixes are planned".

```bash
git add ecc/assess.py ecc/html.py ecc/templates/report.html.j2 ecc/excel.py tests/test_assess.py tests/test_html.py tests/test_excel.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Show each fix and the passing checks per control in the workbook and report"
```

---

### Task 4: Items left over from the plan 2 and 2b reviews

**Files:** Modify `ecc/models.py`, `ecc/excel.py`, `ecc/html.py`, `ecc/templates/report.html.j2`, `data/risks.yaml`, `data/applicability.yaml`, three policies in `docs/policies/`, `tests/test_models.py`, `tests/test_html.py`.

What changes and why:
- **Dates** print as "8 October 2026", not "08 October 2026" (`long_date`).
- **The page title** names the company.
- **The Method section** replaces "anything else" with a precise rule.
- **R-04's** statement now matches its Low score.
- **R-09** explains why phishing stays likely despite multi-factor sign-in.
- **The 4-1-3 reason** covers the router firmware updates the internet provider applies on request.
- **The yearly document reviews** in the access control, vulnerability management and logging policies cite ECC 1-3-4 (review of policies) instead of 2-x-4 (review of implementation). The quarterly items still cite 2-x-4.

No rating changes: `tests/test_real_data.py` must pass unchanged.

- [ ] **Step 1: Write the failing tests**

Append to the end of `tests/test_models.py`:

```python


def test_long_dates_have_no_leading_zero():
    assert long_date(date(2026, 10, 8)) == "8 October 2026"
    assert long_date(datetime(2026, 10, 12, 18, 0, tzinfo=UTC)) == "12 October 2026"
```

Append to the end of `tests/test_html.py`:

```python


def test_the_title_and_scope_name_the_company_safely(dataset, baseline):
    report = dataset.report.model_copy(update={"company": "<b>Co</b>"})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, baseline))
    assert "<title>&lt;b&gt;Co&lt;/b&gt; &middot; NCA ECC Gap Assessment</title>" in html
    assert "The assessment covers &lt;b&gt;Co&lt;/b&gt; as a whole." in html
    assert "taken 12 October 2026" in html
```

In `tests/test_models.py`, replace:

```python
from datetime import UTC, datetime
```

with:

```python
from datetime import UTC, date, datetime
```

In `tests/test_models.py`, replace:

```python
from ecc.models import HOST_PLACEHOLDER, EvidenceEntry, Risk, Rule, Snapshot, Status, weakest
```

with:

```python
from ecc.models import (
    HOST_PLACEHOLDER,
    EvidenceEntry,
    Risk,
    Rule,
    Snapshot,
    Status,
    long_date,
    weakest,
)
```

Run: `.venv/Scripts/python -m pytest tests/test_models.py tests/test_html.py -q`
Expected: an import error for `long_date`.

- [ ] **Step 2: Implement**

In `ecc/models.py`, replace:

```python
HOST_PLACEHOLDER = "WS-01"
```

with:

```python
HOST_PLACEHOLDER = "WS-01"


def long_date(moment: date) -> str:
    """'8 October 2026': the day without a leading zero, the month in full."""
    return f"{moment.day} {moment:%B %Y}"
```

In `ecc/excel.py`, replace:

```python
from ecc.models import Status
```

with:

```python
from ecc.models import Status, long_date
```

In `ecc/excel.py`, replace:

```python
            f"{snapshot.taken_at:%d %B %Y}, snapshot '{snapshot.label}', "
```

with:

```python
            f"{long_date(snapshot.taken_at)}, snapshot '{snapshot.label}', "
```

In `ecc/html.py`, replace:

```python
from ecc.models import Status
```

with:

```python
from ecc.models import Status, long_date
```

In `ecc/html.py`, replace:

```python
def environment() -> Environment:
    return Environment(
        loader=PackageLoader("ecc", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
```

with:

```python
def environment() -> Environment:
    env = Environment(
        loader=PackageLoader("ecc", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["long_date"] = long_date
    return env
```

In `ecc/templates/report.html.j2`, replace:

```html
taken {{ snapshot.taken_at.strftime("%d %B %Y") }}
```

with:

```html
taken {{ snapshot.taken_at|long_date }}
```

In `ecc/templates/report.html.j2`, replace:

```html
({{ before_snapshot.taken_at.strftime("%d %B %Y") }})
```

with:

```html
({{ before_snapshot.taken_at|long_date }})
```

In `ecc/templates/report.html.j2`, replace:

```html
<title>NCA ECC Gap Assessment</title>
```

with:

```html
<title>{{ report.company }} &middot; NCA ECC Gap Assessment</title>
```

In `ecc/templates/report.html.j2`, replace:

```html
a review with a set cycle that has not yet run is Partially implemented, and anything else is Not implemented.</li>
```

with:

```html
a review with a set cycle that has not yet run is Partially implemented, and a requirement that is neither documented nor carried out is Not implemented.</li>
```

In `data/risks.yaml`, replace:

```yaml
      The first reviews of the policies, the roles and the risk method are not due until
      October 2027, so until then duties such as the daily alert review could drift
      without an owner and an incident could be missed.
```

with:

```yaml
      The first reviews of the policies, the roles and the risk method are not due until
      October 2027, so a change in the business before then could leave a document out of date
      for a few months.
```

In `data/risks.yaml`, replace:

```yaml
      Staff have no security awareness training, so a phishing email is likely to lead to a
      compromised Microsoft 365 account.
```

with:

```yaml
      Staff have no security awareness training. Multi-factor sign-in stops simple password
      theft, but phishing pages that relay the sign-in and steal the session still work, so a
      phishing email is likely to lead to a compromised Microsoft 365 account.
```

In `data/applicability.yaml`, replace:

```yaml
      Rimal Byte does not outsource IT or cybersecurity operations or managed services: the
      internet provider supplies connectivity and its own router but does not run Rimal Byte's
      systems, and its cloud service (Microsoft 365) is assessed under 4-2.
```

with:

```yaml
      Rimal Byte does not outsource IT or cybersecurity operations or managed services: the
      internet provider supplies connectivity and its own router, and applies the router's
      firmware updates on request as part of that standard service, but does not run Rimal
      Byte's systems; its cloud service (Microsoft 365) is assessed under 4-2.
```

In `docs/policies/access-control-policy.md`, replace:

```markdown
business changes significantly. Changes are recorded and approved by the General Manager. [2-2-4]
```

with:

```markdown
business changes significantly. Changes are recorded and approved by the General Manager. [1-3-4]
```

In `docs/policies/vulnerability-management-policy.md`, replace:

```markdown
business changes significantly. Changes are recorded and approved by the General Manager. [2-10-4]
```

with:

```markdown
business changes significantly. Changes are recorded and approved by the General Manager. [1-3-4]
```

In `docs/policies/logging-and-monitoring-policy.md`, replace:

```markdown
business changes significantly. Changes are recorded and approved by the General Manager. [2-12-4]
```

with:

```markdown
business changes significantly. Changes are recorded and approved by the General Manager. [1-3-4]
```

- [ ] **Step 3: Verify and commit**

Run:
- `.venv/Scripts/python -m pytest -q -W error`: `293 passed`. This includes `tests/test_policies.py`, which keeps every policy within 400-900 words, and `tests/test_real_data.py` unchanged.
- `.venv/Scripts/python -m ruff check .`
- `.venv/Scripts/python -m ecc check`

```bash
git add ecc/models.py ecc/excel.py ecc/html.py ecc/templates/report.html.j2 data/risks.yaml data/applicability.yaml docs/policies/access-control-policy.md docs/policies/vulnerability-management-policy.md docs/policies/logging-and-monitoring-policy.md tests/test_models.py tests/test_html.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Tidy dates, the page title, two risk statements, the 4-1-3 reason and policy review citations"
```

---

### Task 5: CI and the Pages site

**Files:** Replace `.github/workflows/ci.yml`; create `.github/workflows/pages.yml`.

What the workflows do:
- **CI on Ubuntu:** lint, tests, `check`, and a build without the PDF.
- **CI on Windows:**
  - runs the tests, including the PowerShell ones;
  - applies every fix with `-IncludeLockout` on GitHub's throwaway runner and checks each one took;
  - undoes them from the backup, and checks that every setting and every registry key is back as it was.
- **Pages:** builds the workbook, page and PDF from the committed snapshots, comparing with the baseline once an after snapshot exists, and deploys from `main`.

These workflows first run when the repository is first pushed: privately before Task 6 if Ahmed agrees, otherwise in Task 8.

- [ ] **Step 1: Write the workflows**

Replace the whole of `.github/workflows/ci.yml` with:

```yaml
name: CI

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    name: Lint, test and build (Ubuntu)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r requirements.txt
      - run: ruff check .
      - run: pytest -q
      - name: Check the data files and build the report from the committed snapshots
        run: |
          python -m ecc check
          python -m ecc build --no-pdf

  fix-scripts:
    name: Apply and undo the fixes (Windows)
    runs-on: windows-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r requirements.txt
      - run: pytest -q
      # The runner is a throwaway VM with administrator rights, so the real scripts can run here.
      - name: Apply every fix, check it took, undo it, and check nothing is left changed
        shell: powershell
        run: |
          Import-Module .\remediation\Remediation.psm1
          $items = @(Get-FixItems -Path .\remediation\fixes.json -IncludeOptional)
          # Every key on the way to each setting, so keys that apply.ps1 creates are checked too.
          $keys = @($items | Where-Object { $_.kind -eq 'registry' } | ForEach-Object {
              $path = $_.path
              while ($path -and $path -ne 'HKLM:\') { $path; $path = Split-Path -Path $path -Parent }
          } | Sort-Object -Unique)
          $before = @(Get-Plan -Items $items | ForEach-Object { $_.Current }) | ConvertTo-Json -Depth 5
          $keysBefore = @($keys | ForEach-Object { Test-Path -LiteralPath $_ }) -join ','

          .\remediation\apply.ps1 -IncludeLockout -Confirm:$false
          $missed = @(Get-Plan -Items $items | Where-Object { -not (Test-StateMatch -Actual $_.Current -Expected $_.Target) })
          if ($missed.Count) { throw "apply.ps1 left $($missed.Count) settings unchanged" }

          $backup = Get-ChildItem .\remediation\backups\*.json | Sort-Object Name | Select-Object -Last 1
          .\remediation\undo.ps1 -Backup $backup.FullName -Confirm:$false
          $after = @(Get-Plan -Items $items | ForEach-Object { $_.Current }) | ConvertTo-Json -Depth 5
          $keysAfter = @($keys | ForEach-Object { Test-Path -LiteralPath $_ }) -join ','
          if ($before -cne $after) { throw 'undo.ps1 did not restore every setting' }
          if ($keysBefore -cne $keysAfter) { throw 'undo.ps1 left registry keys behind' }
          Write-Host "apply.ps1 changed and undo.ps1 restored all $($items.Count) settings."
```

Create `.github/workflows/pages.yml`:

```yaml
name: Report site

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages-${{ github.ref }}
  cancel-in-progress: true

jobs:
  build:
    name: Build the report from the committed snapshots
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r requirements.txt

      # Ubuntu 24.04 blocks the user namespaces Chrome's sandbox needs; allow them on this VM
      # instead of turning the sandbox off. Images without the setting need nothing.
      - name: Let headless Chrome use its sandbox
        run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true

      - name: Build the workbook, web page and PDF
        run: |
          if ls snapshots/????-??-after.json > /dev/null 2>&1; then
            python -m ecc build --before baseline --after after
          else
            python -m ecc build
          fi

      - uses: actions/configure-pages@v6
        if: github.ref == 'refs/heads/main'

      - uses: actions/upload-pages-artifact@v5
        if: github.ref == 'refs/heads/main'
        with:
          path: build

  deploy:
    name: Deploy to GitHub Pages
    needs: build
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@v5
```

- [ ] **Step 2: Verify and commit**

Run this, which must print the job names `['test', 'fix-scripts']` and `['build', 'deploy']`:

```bash
.venv/Scripts/python -c "import yaml; [print(list(yaml.safe_load(open(f'.github/workflows/{n}.yml', encoding='utf-8'))['jobs'])) for n in ('ci', 'pages')]"
```

```bash
git add .github/workflows/ci.yml .github/workflows/pages.yml
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Test the fix scripts on a Windows runner and publish the report to Pages"
```

---

### Task 6 (Ahmed): Apply the fixes and collect the after snapshot

Claude prepares the commands and explains them; Ahmed runs every one of them himself.

Before this task:
- The final review must be fixed and the branch merged, so that `remediation/` is on `main`.
- With Ahmed's agreement, CI's Windows apply-and-undo job should have passed once on a private copy of the repository. That way his PC is not the first real Windows run of the scripts. Push only the branch: GitHub Free has no Pages for private repositories, so the Pages workflow would fail there.
- If he prefers not to push yet, step 2 below gives backups that do not depend on the scripts.

1. Open **Windows PowerShell as administrator** (right-click, Run as administrator), then `cd` to the repository.
2. Optional extra safety, if CI has not run the scripts yet. These backups do not depend on `apply.ps1`:
   ```powershell
   Checkpoint-Computer -Description 'Before ECC fixes'
   auditpol /backup /file:$HOME\Documents\audit-before.csv
   net accounts > $HOME\Documents\accounts-before.txt
   Get-ComputerRestorePoint | Select-Object -Last 1
   ```
   The last command confirms the restore point exists. Windows skips a new one, with only a warning, if one was made in the last 24 hours, and fails if System Protection is off. To use these backups instead of `undo.ps1`, use System Restore, or run `auditpol /restore /file:$HOME\Documents\audit-before.csv` and set the values in `accounts-before.txt` again with `net accounts`.
3. Preview without changing anything:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\remediation\apply.ps1 -WhatIf
   ```
   It lists the fixes by title, then 54 settings with their current and new values (57 with `-IncludeLockout`).
4. Decide on F08. Windows 11 already locks an account for 10 minutes after 10 wrong passwords. F08 makes that 15 minutes after 5, which also applies to failed-logon test bursts against his own account.
5. Apply, and answer `Y` to the confirmation. Add `-IncludeLockout` only if he chose F08:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\remediation\apply.ps1
   ```
   The backup path is printed before any change. If anything goes wrong, the newest file in `remediation\backups` is the backup. Copy it outside the repository (for example to Documents), because a `git clean` or a fresh clone would delete it. To undo everything at any time:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\remediation\undo.ps1 -Backup <that path>
   ```
6. Let Windows apply the policy settings now, then check:
   ```powershell
   gpupdate /force
   powershell -ExecutionPolicy Bypass -File .\remediation\apply.ps1 -WhatIf
   Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, LogBlocked, LogAllowed, LogFileName
   ```
   The second command must report "0 of 54 settings will change" (or 0 of 57). Its warning that earlier backups exist is expected. The third must show logging on for all three profiles; if it still shows logging off, restart the PC and check again.
7. Optional, for ECC 2-10-3: install pending Windows updates, and update or remove the apps that the Wazuh dashboard lists under Vulnerability Detection with High severity. Note what was patched, so the report can tell these changes apart from the fixes. Updates may restart the PC.
8. Start Docker and Wazuh if they are not running. Restart the agent so it scans again, then wait until the dashboard's Configuration Assessment shows a scan time after the change:
   ```powershell
   Restart-Service WazuhSvc
   ```
9. Set the same environment variables as for the baseline (indexer URL, TLS server name, CA path; password and names typed with `Read-Host`). Then run:
   ```powershell
   .venv\Scripts\python -m ecc collect --label after
   ```
10. Tell Claude, and say whether F08 was applied and what was patched. Claude reviews `snapshots/<yyyy-mm>-after.json` before it is committed: allowlisted fields only, host `WS-01`, no names, and plausible counts.

What Ahmed will notice afterwards:
- Settings shows some pages as managed by your organisation.
- AutoPlay no longer pops up when a drive or phone is connected (F10).
- The next local password change needs 14 or more characters (F07). His Microsoft-account sign-in is not affected.
- With F08, five wrong passwords lock the account for 15 minutes.
- Standard (non-administrator) accounts can no longer approve elevation prompts (F09).
- Mistyped names are no longer answered by LLMNR (F11).
- Remote Assistance invitations stop working (F12).
- The Security log and Wazuh receive more events (F02, F03).
- Firewall logs appear under `System32\LogFiles\Firewall` (F05).
- The bigger event logs and the firewall logs can use about 340 MB of disk in total.

---

### Task 7 (Claude): The after results, README and licence

The work in this task depends on the real after snapshot, so Claude writes it after Task 6 rather than copying it from this plan.

1. Commit the reviewed snapshot: `git add snapshots/<yyyy-mm>-after.json`.
2. Run `.venv/Scripts/python -m ecc build --before baseline --after after` and record the figures:
   - overall and per-domain compliance before and after;
   - the controls that changed status;
   - passing checks overall and per fix;
   - the vulnerability counts and SAMA levels.
3. Rewrite `data/report.yaml` so the executive summary, key findings and limitations describe both snapshots. Say plainly why the ECC score moves little while many checks start passing: a control is Implemented only when all of its checks pass, and BitLocker cannot be enabled on Windows 11 Home.
4. Fix the presentation items the final review deferred to this task:
   - **Optional fixes:** record in `data/report.yaml` which optional fixes were applied. Show "Not applied" for the others and leave them out of the totals. Make `check` fail if a not-applied fix's checks changed.
   - **Wording:** the Remediation note must be true whether or not `--before` is given; drop "planned" once an after snapshot exists.
   - **Denominators:** add "of n" to the workbook's passing columns, and state which checks each table counts.
   - **Changes outside the fixes:** in compare mode, list CIS checks that changed outside the fixes, especially any that went from passed to failed.
   - **Evidence for the fix values:** commit the script that checks each fix value against its Wazuh SCA rule (as `tools/check_fixes.py`, with a test on a small synthetic policy).
   - **Content:**
     - the three policy headers list 1-3-4;
     - R-04 says "until the first review";
     - the 4-1-3 reason says "Rimal Byte's cloud service", and the company profile states the router firmware arrangement;
     - the Method rule covers a requirement that is documented but not approved and not carried out;
     - remove the unused local in `test_the_planned_fixes`.
5. Add a drift test to `tests/test_real_data.py`: every figure the narrative quotes (percentages, check counts, vulnerability counts and the SAMA counts) must match what `assess()` computes from the committed snapshots.
6. Rewrite `README.md`, with the honesty statement from spec section 3, covering:
   - what the project is;
   - the before/after results table;
   - what is measured and what is judged;
   - how to run `check`, `build`, `collect`, `apply.ps1` and `undo.ps1`;
   - the repository layout;
   - links to the live report.
7. Add `LICENSE` (MIT, code) and `NOTICE`, which credits the sources and their terms:
   - the NCA ECC text in `data/catalog.yaml`;
   - Wazuh's GPLv2 SCA policy behind `data/cis_checks.yaml`;
   - the CIS Benchmark titles;
   - SAMA's framework structure in `data/sama_csf.yaml`.
8. Build with the PDF, then check the page in the browser: desktop, phone width, and light and dark themes.
9. Run the final whole-branch review (opus), apply the fixes it calls for, and merge to `main`.

---

### Task 8 (Ahmed decides, Claude publishes)

1. Ahmed confirms:
   - the public repository (`CS-Abuhelal/ecc-gap-assessment`, public);
   - the licence;
   - the commit email (decision M9). The history and the plan documents use `abuh3lal@gmail.com`, which SENTINEL's public history already shows. The alternative is GitHub's noreply address, which means rewriting this unpublished history first.
2. Claude scans the full history for private data: the Windows user name in paths, the computer name and the agent's real name. The only exception is the email address Ahmed chose.
3. Claude creates the repository with `gh` (or makes the private copy public), sets Pages to deploy from GitHub Actions before pushing `main`, pushes, and confirms that both CI jobs pass, including the Windows apply-and-undo round trip, and that the Pages site is live.
4. Claude proposes one CV line and one LinkedIn project entry for Ahmed to approve, in the style of his existing CV.
