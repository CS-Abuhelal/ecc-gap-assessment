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
