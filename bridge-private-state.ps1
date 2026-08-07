param(
    [switch]$AttestPrivatePaths,
    [Alias('Path')][string[]]$PrivatePath,
    [string]$PathListBase64
)

$ErrorActionPreference = 'Stop'

function Get-PrivateAclPolicy {
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return [pscustomobject]@{
        CurrentSid = $currentSid
        AllowedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
        SidType = [Security.Principal.SecurityIdentifier]
    }
}

function Test-PrivatePathAcl {
    param([Parameter(Mandatory=$true)][string]$Path)
    $policy = Get-PrivateAclPolicy
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return [pscustomobject]@{ Ok=$false; Kind='reparse'; RuleCount=0; Reason='reparse' }
        }
        $isDirectory = $item.PSIsContainer
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules = @($acl.Access)
        $reason = 'ok'
        $ok = [bool]$acl.AreAccessRulesProtected -and $rules.Count -eq 3
        if (-not $acl.AreAccessRulesProtected) { $reason = 'inheritance' }
        elseif ($rules.Count -ne 3) { $reason = 'rule_count' }
        foreach ($rule in $rules) {
            try { $sid = $rule.IdentityReference.Translate($policy.SidType).Value }
            catch { $ok = $false; $reason = 'identity'; continue }
            $expectedInheritance = if ($isDirectory) {
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            } else { [Security.AccessControl.InheritanceFlags]::None }
            $valid = $sid -in $policy.AllowedSids -and
                $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                [long]$rule.FileSystemRights -eq [long][Security.AccessControl.FileSystemRights]::FullControl -and
                $rule.InheritanceFlags -eq $expectedInheritance -and
                $rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None -and
                -not $rule.IsInherited
            if (-not $valid) { $ok = $false; $reason = 'rule' }
        }
        foreach ($sid in $policy.AllowedSids) {
            $count = @($rules | Where-Object {
                try { $_.IdentityReference.Translate($policy.SidType).Value -eq $sid }
                catch { $false }
            }).Count
            if ($count -ne 1) { $ok = $false; $reason = 'principal' }
        }
        return [pscustomobject]@{
            Ok = [bool]$ok
            Kind = if ($isDirectory) { 'directory' } else { 'file' }
            RuleCount = [int]$rules.Count
            Reason = $reason
        }
    } catch {
        $detail = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($detail)) {
            $detail = $_.FullyQualifiedErrorId
        }
        return [pscustomobject]@{
            Ok = $false
            Kind = 'missing'
            RuleCount = 0
            Reason = "unavailable: $($_.Exception.GetType().FullName): $detail"
        }
    }
}

function Assert-PrivatePathAcl {
    param([Parameter(Mandatory=$true)][string]$Path)
    $result = Test-PrivatePathAcl -Path $Path
    if (-not $result.Ok) { throw "Private DACL verification failed ($($result.Reason))." }
    return $result
}

function Set-ExactPrivatePathAcl {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][bool]$IsDirectory
    )
    $policy = Get-PrivateAclPolicy
    $sections = [Security.AccessControl.AccessControlSections]::Access
    $acl = if ($IsDirectory) {
        [Security.AccessControl.DirectorySecurity]::new($Path, $sections)
    } else {
        [Security.AccessControl.FileSecurity]::new($Path, $sections)
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    $inheritance = if ($IsDirectory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sidValue in $policy.AllowedSids) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    if ($IsDirectory) {
        [IO.Directory]::SetAccessControl($Path, $acl)
    } else {
        [IO.File]::SetAccessControl($Path, $acl)
    }
}

function Protect-PrivateFile {
    param([Parameter(Mandatory=$true)][string]$Path, [switch]$RequireExisting)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($RequireExisting) { throw 'Required private file is missing.' }
        $parent = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        New-Item -ItemType File -Path $Path -Force | Out-Null
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Private file is a forbidden reparse point.'
    }
    Set-ExactPrivatePathAcl -Path $Path -IsDirectory $false
    [void](Assert-PrivatePathAcl -Path $Path)
}

function Protect-PrivateDirectory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Private directory is a forbidden reparse point.'
    }
    Set-ExactPrivatePathAcl -Path $Path -IsDirectory $true
    [void](Assert-PrivatePathAcl -Path $Path)
}

function Initialize-BridgePrivateState {
    param([Parameter(Mandatory=$true)][string]$StateRoot)
    if ([string]::IsNullOrWhiteSpace($StateRoot)) {
        throw 'State root is empty.'
    }
    $privateRoot = Join-Path $StateRoot 'private'
    $jobsRoot = Join-Path $privateRoot 'jobs'
    $logsRoot = Join-Path $privateRoot 'logs'
    $metricsRoot = Join-Path $privateRoot 'metrics'
    foreach ($directory in @($StateRoot, $privateRoot, $jobsRoot, $logsRoot, $metricsRoot)) {
        Protect-PrivateDirectory -Path $directory
    }
    $jobState = Join-Path $jobsRoot 'jobs.json'
    $settlementJournal = "$jobState.settlements.json"
    $pressureState = Join-Path $jobsRoot 'resource-pressure.json'
    $bridgeLog = Join-Path $logsRoot 'bridge.log'
    $metricsLog = Join-Path $metricsRoot 'bridge-metrics.jsonl'
    foreach ($path in @(
            $jobState, $settlementJournal, $pressureState, $bridgeLog, $metricsLog)) {
        Protect-PrivateFile -Path $path
    }
    return [pscustomobject]@{
        StateRoot = $StateRoot
        PrivateRoot = $privateRoot
        JobState = $jobState
        SettlementJournal = $settlementJournal
        PressureState = $pressureState
        BridgeLog = $bridgeLog
        MetricsLog = $metricsLog
    }
}

function Test-PrivateAclSet {
    param([Parameter(Mandatory=$true)][string[]]$Paths)
    $results = @($Paths | ForEach-Object { Test-PrivatePathAcl -Path $_ })
    return [pscustomobject]@{
        Ok = (@($results | Where-Object { -not $_.Ok }).Count -eq 0)
        Checked = [int]$results.Count
        Failed = [int]@($results | Where-Object { -not $_.Ok }).Count
        Results = $results
    }
}

if ($AttestPrivatePaths) {
    if ($PathListBase64 -and $PrivatePath) {
        throw 'Specify exactly one private path-list transport.'
    }
    $pathsToTest = @($PrivatePath)
    if ($PathListBase64) {
        if ($PathListBase64.Length -gt 65536) {
            throw 'Private path-list transport is too large.'
        }
        try {
            $json = [Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($PathListBase64))
            $decoded = $json | ConvertFrom-Json -ErrorAction Stop
            $pathsToTest = [string[]]$decoded
        } catch {
            throw 'Invalid private path-list transport.'
        }
    }
    if ($pathsToTest.Count -lt 1 -or
            @($pathsToTest | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
        throw 'Private path-list transport is empty.'
    }
    $result = Test-PrivateAclSet -Paths $pathsToTest
    [pscustomobject]@{
        ok = [bool]$result.Ok
        checked = [int]$result.Checked
        failed = [int]$result.Failed
    } | ConvertTo-Json -Compress
    if (-not $result.Ok) { exit 1 }
    return
}
