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
                    'DWord' { Test-WholeNumber $item.value 0 4294967295 }
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
