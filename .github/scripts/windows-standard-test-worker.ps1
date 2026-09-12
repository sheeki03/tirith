param([Parameter(Mandatory)][string]$Manifest)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows-test-common.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'windows-test-process.cs')

$manifestFile = Get-CiRegularFile $Manifest
if ($manifestFile.Length -gt 65536) { throw 'Worker manifest exceeds its bound' }
$inputData = [IO.File]::ReadAllText($manifestFile.FullName) | ConvertFrom-Json -Depth 15
if ($inputData.schema -ne 1 -or $inputData.nonce -notmatch '^[0-9a-f]{32}$') { throw 'Invalid worker manifest' }
$profileRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
if (-not [IO.Path]::IsPathFullyQualified($profileRoot) -or -not (Test-Path -LiteralPath $profileRoot -PathType Container)) {
    throw 'The standard account has no actual user profile'
}
$outputRoot = Join-Path $profileRoot ('tirith-ci-' + $inputData.nonce)
New-Item -ItemType Directory -Path $outputRoot -ErrorAction Stop | Out-Null
$report = [ordered]@{ schema = 1; success = $false; profile = $profileRoot; mode = $inputData.mode; error = $null }
$leases = [Collections.Generic.List[IO.FileStream]]::new()
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -cne $inputData.sid -or
        [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Worker account identity does not match its manifest'
    }
    foreach ($variable in @(Get-ChildItem Env:)) {
        if ($variable.Name -eq 'TIRITH' -or $variable.Name.StartsWith('TIRITH_', [StringComparison]::OrdinalIgnoreCase)) {
            [Environment]::SetEnvironmentVariable($variable.Name, $null, 'Process')
        }
    }
    $env:HOME = $profileRoot
    $env:USERPROFILE = $profileRoot
    $env:APPDATA = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
    $env:LOCALAPPDATA = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrEmpty($env:APPDATA) -or [string]::IsNullOrEmpty($env:LOCALAPPDATA)) { throw 'Actual profile application directories are unavailable' }
    $env:TEMP = Join-Path $outputRoot 'temp'
    $env:TMP = $env:TEMP
    New-Item -ItemType Directory -Path $env:TEMP | Out-Null
    $report.temp_owner_sid = (Get-Acl -LiteralPath $env:TEMP).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($report.temp_owner_sid -cne $inputData.sid) { throw 'Disposable state is not owned by the real standard account' }
    # Retain the actual descriptors for diagnosing native owner/ancestor refusals.
    # These observations never admit an ACL or replace a product trust check.
    $aclObservations = [Collections.Generic.List[object]]::new()
    $seenAclPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($start in @($env:TEMP, [IO.Path]::GetDirectoryName($inputData.cli.path))) {
        for ($directory = [IO.DirectoryInfo]::new($start); $null -ne $directory; $directory = $directory.Parent) {
            if ($seenAclPaths.Add($directory.FullName)) {
                $aclObservations.Add(@{ path = $directory.FullName; sddl = (Get-Acl -LiteralPath $directory.FullName).Sddl })
            }
        }
    }
    $report.ancestor_acls = $aclObservations.ToArray()
    $env:TIRITH_OFFLINE = '1'
    if ($inputData.mode -eq 'lifetime-probe') {
        $child = [Diagnostics.Process]::Start([Diagnostics.ProcessStartInfo]@{
            FileName = $inputData.powershell.path; UseShellExecute = $false;
            Arguments = '-NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 600"'
        })
        Write-CiJson (Join-Path $outputRoot 'lifetime-child.json') @{ pid = $child.Id }
        Start-Sleep -Seconds 600
        throw 'Lifetime probe unexpectedly survived its deadline'
    }
    if ($inputData.mode -ne 'dashboard') { throw 'Unknown worker mode' }
    foreach ($pin in @($inputData.harness, $inputData.cli, $inputData.powershell)) {
        $leases.Add((Open-CiPinnedFile $pin))
    }
    $env:CARGO_MANIFEST_DIR = $inputData.cwd
    $env:CARGO_MANIFEST_PATH = Join-Path $inputData.cwd 'Cargo.toml'
    $env:PATH = ($inputData.runtime_paths -join [IO.Path]::PathSeparator) + [IO.Path]::PathSeparator + $env:PATH
    $list = [TirithCi.ProcessRunner]::Run($inputData.harness.path, @('--list', '--format', 'terse'), $inputData.cwd, $null, 30, 1048576)
    $report.list_process = Save-CiProcessResult $outputRoot 'list' $list
    Assert-CiProcessSucceeded $list
    $names = @(Get-CiTestNames $list.Stdout)
    $report.listed_tests = $names
    # No filter, skip, ignored-only option or test-specific product override.
    $run = [TirithCi.ProcessRunner]::Run($inputData.harness.path, @('--test-threads=1', '--nocapture'), $inputData.cwd, $null, 840, 33554432)
    $report.test_process = Save-CiProcessResult $outputRoot 'tests' $run
    $report.counts = Assert-CiDashboardResult $run $names
    foreach ($pin in @($inputData.harness, $inputData.cli, $inputData.powershell)) {
        $after = Get-CiFilePin $pin.path
        if ($after.sha256 -cne $pin.sha256 -or $after.size -ne $pin.size) { throw 'Executed input changed' }
    }
    $report.success = $true
} catch {
    $report.error = $_.Exception.Message
} finally {
    foreach ($lease in $leases) { $lease.Dispose() }
    Write-CiJson (Join-Path $outputRoot 'result.json') $report
}
if (-not $report.success) { exit 1 }
