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
undo.ps1 restores a backup later. No change needs a restart.

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
Write-Host "Backup of the old values: $backup"
Write-Host "To undo: powershell -ExecutionPolicy Bypass -File .\remediation\undo.ps1 -Backup `"$backup`""
