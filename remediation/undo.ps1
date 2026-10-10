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
