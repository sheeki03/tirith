param([string]$EvidenceDirectory = (Join-Path $env:RUNNER_TEMP 'tirith-powershell-targets'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This controller requires native Windows' }
. (Join-Path $PSScriptRoot 'windows-test-common.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'windows-test-process.cs')
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Fresh resolver evidence directory required' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$EvidenceDirectory = (Get-Item -LiteralPath $EvidenceDirectory).FullName
$report = [ordered]@{ schema_version = 1; passed = $false; status = 'refused'; cases = @(); automatic_adapter_qualified = $false }
$leases = [Collections.Generic.List[IO.FileStream]]::new()
try {
    $inventoryPath = Join-Path $env:RUNNER_TEMP 'tirith-windows-tests/inventory.json'
    $inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json -Depth 30
    $selected = @($inventory.artifacts | Where-Object { $_.package_name -eq 'tirith' -and $_.target -eq 'tirith' -and $_.kind.Count -eq 1 -and $_.kind[0] -eq 'bin' })
    if ($selected.Count -ne 1) { throw 'Expected exactly one Cargo-built CLI test image' }
    $binary = $selected[0].executable
    $leases.Add((Open-CiPinnedFile $binary))
    $report.test_binary = $binary
    $report.inventory = Get-CiFilePin $inventoryPath
    $report.controller = Get-CiFilePin $PSCommandPath
    $report.workflow_event_revision = $env:GITHUB_SHA
    $test = 'cli::shell_target::native_tests::native_powershell_profile_matches_resolver'
    $required = @(
        @{ shell = 'powershell'; path = (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') },
        @{ shell = 'pwsh'; path = (Join-Path $PSHOME 'pwsh.exe') }
    )
    foreach ($candidate in $required) {
        $case = [ordered]@{ shell = $candidate.shell; passed = $false; status = 'refused'; process = $null; error = $null }
        $report.cases += $case
        $directory = Join-Path $EvidenceDirectory $candidate.shell
        New-Item -ItemType Directory -Path $directory | Out-Null
        try {
            if (-not (Test-Path -LiteralPath $candidate.path -PathType Leaf)) {
                $case.status = 'unsupported'
                throw 'Required native PowerShell variant is absent; absence is not a pass'
            }
            $shell = Get-CiFilePin $candidate.path
            $leases.Add((Open-CiPinnedFile $shell))
            $case.executable = $shell
            $nativePath = Join-Path $directory 'native.json'
            $environment = [Collections.Generic.Dictionary[string,string]]::new()
            $environment['TIRITH_NATIVE_PROFILE_SHELL'] = $candidate.shell
            $environment['TIRITH_NATIVE_PROFILE_EXECUTABLE'] = $shell.path
            $environment['TIRITH_NATIVE_PROFILE_SHA256'] = $shell.sha256
            $environment['TIRITH_NATIVE_PROFILE_TEST_SHA256'] = $binary.sha256
            $environment['TIRITH_NATIVE_PROFILE_REPORT'] = $nativePath
            $environment['PATH'] = ($inventory.runtime_paths -join [IO.Path]::PathSeparator) + [IO.Path]::PathSeparator + $env:PATH
            $run = [TirithCi.ProcessRunner]::Run($binary.path,
                @('--exact', $test, '--ignored', '--nocapture', '--test-threads=1'), $directory, $environment, 60, 1048576)
            $case.process = Save-CiProcessResult $directory 'test' $run
            Assert-CiProcessSucceeded $run
            if ($run.Stdout -notmatch '1 passed; 0 failed; 0 ignored') { throw 'Required native resolver test was omitted or skipped' }
            $file = Get-CiRegularFile $nativePath
            if ($file.Length -gt 131072) { throw 'Native resolver report exceeds bound' }
            $native = Get-Content -LiteralPath $nativePath -Raw | ConvertFrom-Json -Depth 30
            if ($native.passed -isnot [bool] -or -not $native.passed -or $native.status -cne 'native_target_matched' -or
                $native.scope -cne 'native_current_user_console_profile_resolution_only' -or
                $native.test_binary.sha256 -cne $binary.sha256 -or $native.native_executable.sha256 -cne $shell.sha256 -or
                $native.test_binary.pid -ne $run.ProcessId -or
                $native.profile_unchanged -isnot [bool] -or -not $native.profile_unchanged -or
                $native.child.supervised_cleanup_confirmed -isnot [bool] -or -not $native.child.supervised_cleanup_confirmed) {
                throw 'Native resolver identity, result or cleanup contract differs'
            }
            foreach ($field in @('profile_writes', 'profile_loaded', 'automatic_adapter_qualified')) {
                if ($native.$field -isnot [bool] -or $native.$field) { throw 'Native resolver scope changed' }
            }
            $case.native_report = Get-CiFilePin $nativePath
            $case.passed = $true
            $case.status = 'native_target_matched'
        } catch { $case.error = $_.Exception.Message }
    }
    if ($report.cases.Count -ne 2 -or @($report.cases | Where-Object { -not $_.passed }).Count -ne 0) {
        throw 'Both native Windows PowerShell 5.1 and 7 resolver checks are required'
    }
    $report.passed = $true
    $report.status = 'native_targets_matched'
} catch { $report.error = $_.Exception.Message }
finally {
    foreach ($lease in $leases) { $lease.Dispose() }
    Write-CiJson (Join-Path $EvidenceDirectory 'report.json') $report
}
if (-not $report.passed) { throw 'Native PowerShell resolver qualification failed; retained original evidence' }
