$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows-test-common.ps1')
. (Join-Path $PSScriptRoot 'windows-compiler-telemetry.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'windows-test-process.cs')
$passed = 0
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Refuses([scriptblock]$Action, [string]$Message) {
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $true }
    Assert-True $refused $Message
}

if ($IsWindows -and $env:GITHUB_ACTIONS -ceq 'true' -and $env:RUNNER_OS -ceq 'Windows' -and
    $env:RUNNER_ENVIRONMENT -ceq 'github-hosted') {
    $telemetryScope = New-CiCompilerTelemetryScope 'native-runner-contract'
    try {
        Set-CiCompilerTelemetryOptOut $telemetryScope
        Assert-True $telemetryScope.Evidence.applied 'Compiler telemetry opt-out did not apply'
        Assert-True ($telemetryScope.Evidence.settings.Count -eq 2) 'Compiler telemetry registry views omitted'
        foreach ($setting in $telemetryScope.Evidence.settings) {
            Assert-True ($setting.readback_kind -ceq 'DWord' -and $setting.readback_value -eq 0) 'Compiler telemetry readback was not DWORD zero'
        }
    } finally { Restore-CiCompilerTelemetryScope $telemetryScope }
    Assert-True $telemetryScope.Evidence.restored 'Compiler telemetry prior state was not restored'
    $passed++
    $failedTelemetryScope = New-CiCompilerTelemetryScope 'native-runner-failure-contract'
    Assert-Refuses {
        try {
            Set-CiCompilerTelemetryOptOut $failedTelemetryScope
            throw 'Injected compiler-phase failure'
        } finally { Restore-CiCompilerTelemetryScope $failedTelemetryScope }
    } 'Injected compiler-phase failure was lost'
    Assert-True ($failedTelemetryScope.Evidence.applied -and $failedTelemetryScope.Evidence.restored) 'Compiler failure did not restore telemetry state'
    $passed++
} elseif (-not $IsWindows) {
    $telemetryScope = New-CiCompilerTelemetryScope 'non-windows-refusal'
    Assert-Refuses { Set-CiCompilerTelemetryOptOut $telemetryScope } 'Non-Windows compiler telemetry mutation accepted'
    Assert-True ($telemetryScope.States.Count -eq 0) 'Non-Windows compiler telemetry changed state'
    $passed++
}

$names = @(
    'activity_starts_with_newest_checks_and_pages_older_without_shifting_on_append',
    'real_service_reuses_identity_and_rejects_unauthorized_mutations',
    'browser_profile_plan_is_read_only_until_apply_and_retries_keep_identity',
    'no_change_request_remains_immutable_after_policy_drift',
    'trickled_body_hits_overall_deadline_without_saving_a_plan',
    'explicit_project_review_is_inert_and_revalidates_retained_files',
    'failed_lifecycle_apply_retry_returns_saved_state_without_starting_work',
    'browser_npm_inspection_and_comparison_are_project_scoped_and_inert',
    'real_service_reports_writer_failure_even_when_no_history_record_was_saved'
)
$list = ($names | ForEach-Object { $_ + ': test' }) -join "`n"
Assert-True (@(Get-CiTestNames $list).Count -eq 9) 'Exact dashboard inventory was not preserved'
$passed++
Assert-Refuses { Get-CiTestNames (($names[0..7] | ForEach-Object { $_ + ': test' }) -join "`n") } 'Missing test accepted'
Assert-Refuses { Get-CiTestNames ($list + "`n" + $names[0] + ': test') } 'Duplicated test accepted'
Assert-Refuses { Get-CiTestNames ($list + "`nmalformed test declaration") } 'Malformed listing accepted'
$passed += 3
$stdout = (($names | ForEach-Object { 'test ' + $_ + ' ... ok' }) -join "`n") + "`n`ntest result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s`n"
$result = [pscustomobject]@{
    ExitCode = 0; TimedOut = $false; OutputOverflow = $false; Stdout = $stdout; Stderr = '';
    NativeJob = $true; JobEmpty = $true; LeaderReaped = $true; OutputDrained = $true;
    DescendantsLeaked = $false; Error = ''; CleanupError = ''
}
Assert-True ((Assert-CiDashboardResult $result $names).passed -eq 9) 'Full dashboard success rejected'
$passed++
foreach ($bad in @(
    $stdout.Replace('9 passed; 0 failed; 0 ignored', '8 passed; 0 failed; 1 ignored'),
    $stdout.Replace('0 filtered out', '1 filtered out'),
    $stdout.Replace('test result: ok.', 'test result: FAILED.'),
    $stdout.Replace(('test ' + $names[0] + ' ... ok'), ''),
    ($stdout + $stdout)
)) {
    $result.Stdout = $bad
    Assert-Refuses { Assert-CiDashboardResult $result $names } 'Incomplete or malformed result accepted'
    $passed++
}
$result.Stdout = $stdout
$result.OutputOverflow = $true
Assert-Refuses { Assert-CiDashboardResult $result $names } 'Truncated output accepted'
$passed++

# These portable fixtures test the actual controller predicate. A runner error
# maps to exit -1, so matching refusal text must never hide missing cleanup.
$result.OutputOverflow = $false
$refusal = $result.PSObject.Copy()
$refusal.ExitCode = 1
$refusal.Stdout = ''
$refusal.Stderr = 'open the dashboard from a normal, non-administrator terminal'
Assert-CiElevatedDashboardRefusal $refusal
$passed++
foreach ($fault in @(
    @{ name = 'NativeJob'; value = $false },
    @{ name = 'JobEmpty'; value = $false },
    @{ name = 'LeaderReaped'; value = $false },
    @{ name = 'OutputDrained'; value = $false },
    @{ name = 'DescendantsLeaked'; value = $true },
    @{ name = 'Error'; value = 'process launch failed' },
    @{ name = 'CleanupError'; value = 'owned descendant cleanup failed' }
)) {
    $failedRefusal = $refusal.PSObject.Copy()
    $failedRefusal.ExitCode = -1
    $failedRefusal.($fault.name) = $fault.value
    Assert-Refuses { Assert-CiElevatedDashboardRefusal $failedRefusal } ("Refusal text hid a native failure: " + $fault.name)
    $failedSuccess = $result.PSObject.Copy()
    $failedSuccess.($fault.name) = $fault.value
    Assert-Refuses { Assert-CiDashboardResult $failedSuccess $names } ("Dashboard success hid a native failure: " + $fault.name)
    $passed += 2
}
foreach ($name in @('TimedOut', 'OutputOverflow')) {
    $failedRefusal = $refusal.PSObject.Copy()
    $failedRefusal.$name = $true
    Assert-Refuses { Assert-CiElevatedDashboardRefusal $failedRefusal } ("Refusal text hid a process bound: " + $name)
    $passed++
}
$failedRefusal = $refusal.PSObject.Copy()
$failedRefusal.ExitCode = 0
Assert-Refuses { Assert-CiElevatedDashboardRefusal $failedRefusal } 'Zero exit accepted as product refusal'
$failedRefusal = $refusal.PSObject.Copy()
$failedRefusal.Stderr = 'an unrelated failure'
Assert-Refuses { Assert-CiElevatedDashboardRefusal $failedRefusal } 'Unrelated failure accepted as product refusal'
$passed += 2

$tempBase = if ($IsMacOS) { '/private/tmp' } else { [IO.Path]::GetTempPath() }
$temp = Join-Path $tempBase ('tirith-ci-contract-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $target = Join-Path $temp 'target'
    New-Item -ItemType Directory -Path $target | Out-Null
    $file = Join-Path $target 'control_dashboard.exe'
    [IO.File]::WriteAllText($file, 'immutable fixture executable bytes')
    $pin = Get-CiFilePin $file
    $lease = Open-CiPinnedFile $pin
    $lease.Dispose()
    $passed++
    $pin.sha256 = '0' * 64
    Assert-Refuses { Open-CiPinnedFile $pin } 'Changed input hash accepted'
    $passed++
    $metadata = [pscustomobject]@{
        target_directory = $target; workspace_members = @('package#tirith');
        packages = @([pscustomobject]@{ id = 'package#tirith'; name = 'tirith'; manifest_path = (Join-Path $temp 'Cargo.toml') })
    }
    $artifact = [ordered]@{
        reason = 'compiler-artifact'; executable = $file; package_id = 'package#tirith';
        profile = @{ test = $true }; target = @{ name = 'control_dashboard'; kind = @('test') }
    }
    $artifactJson = $artifact | ConvertTo-Json -Depth 5 -Compress
    $messages = $artifactJson + "`n" + '{"reason":"build-finished","success":true}'
    Assert-True (@(Get-CiArtifactInventory $messages $metadata).Count -eq 1) 'Cargo inventory rejected its test target'
    $passed++
    Assert-Refuses { Get-CiArtifactInventory $artifactJson $metadata } 'Missing build completion accepted'
    Assert-Refuses { Get-CiArtifactInventory ($artifactJson + "`n" + $messages) $metadata } 'Duplicate executable accepted'
    $passed += 2
    $artifact.executable = Join-Path $temp 'outside.exe'
    $outside = ($artifact | ConvertTo-Json -Depth 5 -Compress) + "`n" + '{"reason":"build-finished","success":true}'
    Assert-Refuses { Get-CiArtifactInventory $outside $metadata } 'Executable outside target root accepted'
    $passed++
    $cliFile = Join-Path $target 'tirith.exe'
    [IO.File]::WriteAllText($cliFile, 'companion CLI bytes')
    $artifact.executable = $cliFile
    $artifact.profile.test = $false
    $artifact.target.name = 'tirith'
    $artifact.target.kind = @('bin')
    $cliMessage = $artifact | ConvertTo-Json -Depth 5 -Compress
    Assert-True ((Get-CiCompanionArtifact $cliMessage $metadata).path -eq $cliFile) 'Exact companion CLI discovery failed'
    Assert-Refuses { Get-CiCompanionArtifact $messages $metadata } 'Missing companion CLI accepted'
    $passed += 2
    New-Item -ItemType Directory -Path (Join-Path $target 'deps') | Out-Null
    $native = Join-Path $target 'native'
    New-Item -ItemType Directory -Path $native | Out-Null
    $links = @{ reason = 'build-script-executed'; linked_paths = @(('native=' + $native), ('native=' + $temp)) } | ConvertTo-Json -Compress
    $runtimePaths = @(Get-CiRuntimePaths $links $target $target $temp)
    Assert-True ($runtimePaths.Count -eq 4 -and $runtimePaths[0] -eq $native -and $runtimePaths[3] -eq $temp) 'Cargo runtime link directories were not preserved'
    $passed++
    $powerShellExecutable = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
    $child = [TirithCi.ProcessRunner]::Run($powerShellExecutable, @('-NoProfile', '-NonInteractive', '-Command', '[Console]::Write("bounded"); [Console]::Error.Write("diagnostic"); exit 7'), $temp, $null, 10, 65536)
    Assert-True ($child.ExitCode -eq 7 -and $child.Stdout -eq 'bounded' -and $child.Stderr -eq 'diagnostic') 'Native stdout/stderr/exit capture changed'
    $passed++
    $overflow = [TirithCi.ProcessRunner]::Run($powerShellExecutable, @('-NoProfile', '-NonInteractive', '-Command', 'while ($true) { [Console]::Write("x" * 4096) }'), $temp, $null, 10, 4096)
    Assert-True ($overflow.OutputOverflow -and $overflow.Stdout.Length -le 4096) 'Output overflow did not terminate capture'
    $passed++
    $timeout = [TirithCi.ProcessRunner]::Run($powerShellExecutable, @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60'), $temp, $null, 1, 4096)
    Assert-True $timeout.TimedOut 'Process deadline was not enforced'
    $passed++
    if ($IsWindows) {
        foreach ($nativeResult in @($child, $overflow, $timeout)) {
            Assert-True ($nativeResult.NativeJob -and $nativeResult.JobEmpty -and $nativeResult.LeaderReaped -and
                $nativeResult.OutputDrained -and $nativeResult.CleanupError -ceq '') 'Native process tree or output cleanup was not confirmed'
        }
        $passed++
        # Verify the native argument encoder against the actual Windows process
        # entry point, including trailing slashes, quotes and empty arguments.
        $argumentFixture = Join-Path $temp 'argument fixture.ps1'
        [IO.File]::WriteAllText($argumentFixture, '[Console]::Write((ConvertTo-Json -Compress -InputObject @($args)))')
        $expectedArguments = @('', 'space separated', 'quote"inside', 'C:\path with space\', 'slash\"quote')
        $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $argumentFixture) + $expectedArguments
        $roundtrip = [TirithCi.ProcessRunner]::Run($powerShellExecutable, $arguments, $temp, $null, 10, 65536)
        Assert-True ($roundtrip.ExitCode -eq 0 -and $roundtrip.NativeJob -and $roundtrip.JobEmpty -and
            $roundtrip.OutputDrained -and $roundtrip.CleanupError -ceq '') 'Native argument fixture failed'
        $observed = @($roundtrip.Stdout | ConvertFrom-Json)
        Assert-True ($observed.Count -eq $expectedArguments.Count) 'Native argv count changed'
        for ($i = 0; $i -lt $observed.Count; $i++) { Assert-True ($observed[$i] -ceq $expectedArguments[$i]) 'Native argument bytes changed' }
        $passed++

        $leaf = Join-Path $temp 'long-lived-leaf.ps1'
        $leader = Join-Path $temp 'exiting-leader.ps1'
        $pidFile = Join-Path $temp 'descendant.json'
        $readyFile = Join-Path $temp 'descendant-ready'
        [IO.File]::WriteAllText($leaf, @'
param([string]$Ready)
[Console]::WriteLine('descendant retains stdout')
[Console]::Error.WriteLine('descendant retains stderr')
[IO.File]::WriteAllText($Ready, 'ready')
Start-Sleep -Seconds 60
'@)
        [IO.File]::WriteAllText($leader, @'
param([string]$PowerShell, [string]$Leaf, [string]$PidFile, [string]$Ready)
$ErrorActionPreference = 'Stop'
$start = [Diagnostics.ProcessStartInfo]::new($PowerShell)
$start.UseShellExecute = $false
foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $Leaf, $Ready)) { $start.ArgumentList.Add($argument) }
$descendant = [Diagnostics.Process]::Start($start)
[IO.File]::WriteAllText($PidFile, (@{ pid = $descendant.Id; creation_ticks = $descendant.StartTime.ToUniversalTime().Ticks } | ConvertTo-Json -Compress))
$deadline = [DateTime]::UtcNow.AddSeconds(5)
while (-not [IO.File]::Exists($Ready)) {
    if ([DateTime]::UtcNow -ge $deadline) { throw 'Descendant did not reach its ready point' }
    Start-Sleep -Milliseconds 10
}
[Console]::WriteLine('leader exits before descendant')
exit 0
'@)
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $orphan = [TirithCi.ProcessRunner]::Run($powerShellExecutable,
            @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $leader, $powerShellExecutable, $leaf, $pidFile, $readyFile),
            $temp, $null, 15, 65536)
        Assert-True ($orphan.ExitCode -ne 0 -and -not $orphan.TimedOut -and $orphan.DescendantsLeaked -and
            $orphan.NativeJob -and $orphan.JobEmpty -and $orphan.LeaderReaped -and $orphan.OutputDrained -and
            $orphan.CleanupError -ceq '') 'Exited leader left its descendant or output pipes alive, or leak passed as success'
        Assert-True ($clock.Elapsed.TotalSeconds -lt 35) 'Exited-leader cleanup exceeded its bound'
        Assert-True ($orphan.Stdout.Contains('descendant retains stdout') -and $orphan.Stdout.Contains('leader exits before descendant') -and
            $orphan.Stderr.Contains('descendant retains stderr')) 'Real descendant did not inherit both output channels'
        $identity = [IO.File]::ReadAllText($pidFile) | ConvertFrom-Json
        Assert-True ($orphan.LeaderExitCode -eq 0 -and $orphan.ExitCode -ne 0 -and $orphan.ProcessId -gt 0) 'Cleanup failure lost the original leader result'
        $diagnostic = $orphan.BeforeCleanup
        Assert-True ($null -ne $diagnostic -and $diagnostic.Reason -ceq 'descendant-grace-exceeded' -and
            $diagnostic.AccountingActiveProcesses -ge 1 -and $diagnostic.ListedProcesses -ge 1 -and
            $diagnostic.ProcessListComplete -and -not $diagnostic.Truncated -and $diagnostic.Error -ceq '') 'Owned Job leak diagnostics were unavailable or incomplete'
        $observedChild = @($diagnostic.Processes | Where-Object { $_.ProcessId -eq $identity.pid })
        Assert-True ($observedChild.Count -eq 1 -and $observedChild[0].JobMember -eq $true -and
            $observedChild[0].Running -eq $true -and -not $observedChild[0].IsLeader -and
            $observedChild[0].CreationTimeUtcTicks -eq $identity.creation_ticks -and
            [IO.Path]::GetFileName($observedChild[0].ImagePath) -ieq 'pwsh.exe' -and
            $observedChild[0].Error -ceq '') 'Leak diagnostics did not identify the held owned descendant'
        $survivor = Get-Process -Id $identity.pid -ErrorAction SilentlyContinue
        if ($null -ne $survivor) {
            try { Assert-True ($survivor.HasExited -or $survivor.StartTime.ToUniversalTime().Ticks -ne $identity.creation_ticks) 'Owned descendant survived cleanup' }
            finally { $survivor.Dispose() }
        }
        $passed++
        Write-Host 'Native Windows Job controls passed: argv identity, output/timeout cleanup, and exited leader with a live descendant retaining both pipes.'
    }

} finally { Remove-Item -LiteralPath $temp -Recurse -Force }

# Parse all entry points without invoking account provisioning on this host.
foreach ($name in @('test-workspace-windows.ps1', 'windows-standard-test-worker.ps1', 'windows-test-common.ps1', 'windows-compiler-telemetry.ps1')) {
    $tokens = $null; $errors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$errors) | Out-Null
    Assert-True ($errors.Count -eq 0) ("PowerShell syntax error in $name`: " + ($errors -join '; '))
    $passed++
}
Write-Host "$passed Windows runner parser and bounded-process contracts passed; native Windows token/logon/job/ACL gates are not exercised by this script."
