param([string]$EvidenceDirectory = (Join-Path $env:RUNNER_TEMP 'tirith-windows-tests'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

# This entry point creates/deletes a local account. It is only for the disposable
# hosted Windows job, never a developer workstation or self-hosted runner.
if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or [string]::IsNullOrEmpty($env:GITHUB_WORKSPACE)) {
    throw 'Standard-account qualification requires a disposable GitHub-hosted Windows runner'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'CI provisioning requires its existing administrator token'
}
. (Join-Path $PSScriptRoot 'windows-test-common.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'windows-test-process.cs')
$workspace = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
if ((Get-Location).Path -ine $workspace) { throw 'Run this controller from the checked-out workspace root' }
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Evidence destination must be fresh' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$EvidenceDirectory = (Get-Item -LiteralPath $EvidenceDirectory).FullName
$report = [ordered]@{ schema = 1; success = $false; build = $null; harnesses = @(); doctests = $null; standard_account = $null; cleanup = @(); errors = @() }
$leases = [Collections.Generic.List[IO.FileStream]]::new()
$aclPaths = [Collections.Generic.List[string]]::new()
$newUser = $null
$securePassword = $null
$profile = $null
$stage = $null
$jobsClean = $true
$buildSucceeded = $false

function Add-CiAccountReadAccess([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    $acl = Get-Acl -LiteralPath $Path
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($Sid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
    $aclPaths.Add($Path)
}

function Copy-CiWorkerEvidence([string]$Profile, [string]$Nonce, [string]$Name) {
    $directory = Join-Path $Profile ('tirith-ci-' + $Nonce)
    $destination = Join-Path $EvidenceDirectory $Name
    New-Item -ItemType Directory -Path $destination | Out-Null
    # Read only the known bounded files. Never traverse a worker-supplied tree.
    foreach ($file in @('result.json', 'lifetime-child.json', 'list.stdout.log', 'list.stderr.log', 'tests.stdout.log', 'tests.stderr.log')) {
        $source = Join-Path $directory $file
        if (Test-Path -LiteralPath $source) {
            $item = Get-CiRegularFile $source
            $limit = if ($file.EndsWith('.json')) { 1048576 } else { 33554432 }
            if ($item.Length -gt $limit) { throw 'Worker evidence exceeded its bound' }
            Copy-Item -LiteralPath $source -Destination (Join-Path $destination $file)
        }
    }
    return $destination
}

try {
    $cargo = (Get-Command cargo.exe -CommandType Application -ErrorAction Stop).Source
    $rustc = (Get-Command rustc.exe -CommandType Application -ErrorAction Stop).Source
    $powershell = Get-CiFilePin (Join-Path $PSHOME 'pwsh.exe')
    $metadataRun = [TirithCi.ProcessRunner]::Run($cargo, @('metadata', '--format-version', '1', '--no-deps', '--locked'), $workspace, $null, 120, 16777216)
    Assert-CiProcessSucceeded $metadataRun
    $metadata = $metadataRun.Stdout | ConvertFrom-Json -Depth 60
    $build = [TirithCi.ProcessRunner]::Run($cargo, @('test', '--workspace', '--locked', '--no-run', '--message-format=json'), $workspace, $null, 1800, 67108864)
    $report.build = Save-CiProcessResult $EvidenceDirectory 'cargo-build' $build
    Assert-CiProcessSucceeded $build
    $inventory = @(Get-CiArtifactInventory $build.Stdout $metadata)
    $cli = Get-CiCompanionArtifact $build.Stdout $metadata
    $dashboard = @($inventory | Where-Object { $_.package_name -eq 'tirith' -and $_.target -eq 'control_dashboard' -and 'test' -in $_.kind })[0]
    $libdir = [TirithCi.ProcessRunner]::Run($rustc, @('--print', 'target-libdir'), $workspace, $null, 30, 65536)
    Assert-CiProcessSucceeded $libdir
    $binaryDirectory = [IO.Path]::GetDirectoryName($cli.path)
    $runtimePaths = @(Get-CiRuntimePaths $build.Stdout $metadata.target_directory $binaryDirectory $libdir.Stdout.Trim())
    Write-CiJson (Join-Path $EvidenceDirectory 'inventory.json') @{ artifacts = $inventory; cli = $cli; runtime_paths = $runtimePaths; powershell = $powershell }
    foreach ($entry in $inventory) { $leases.Add((Open-CiPinnedFile $entry.executable)) }
    $leases.Add((Open-CiPinnedFile $cli))
    $buildSucceeded = $true

    # Ordinary targets retain Cargo's existing account, package cwd and runtime
    # search paths. A failure cannot stop later inventory entries from running.
    $index = 0
    foreach ($entry in $inventory) {
        $index++
        if ($entry -eq $dashboard) { continue }
        $result = [ordered]@{ package = $entry.package_name; target = $entry.target; executable = $entry.executable; account = 'ci'; success = $false; error = $null }
        try {
            $environment = [Collections.Generic.Dictionary[string,string]]::new()
            $environment['CARGO_MANIFEST_DIR'] = $entry.cwd
            $environment['CARGO_MANIFEST_PATH'] = Join-Path $entry.cwd 'Cargo.toml'
            $environment['CARGO'] = $cargo
            $environment['PATH'] = ($runtimePaths -join [IO.Path]::PathSeparator) + [IO.Path]::PathSeparator + $env:PATH
            $run = [TirithCi.ProcessRunner]::Run($entry.executable.path, @('--nocapture'), $entry.cwd, $environment, 900, 33554432)
            $result.process = Save-CiProcessResult $EvidenceDirectory ('harness-' + $index) $run
            Assert-CiProcessSucceeded $run
            $result.success = $true
            Write-Host ('{0}/{1}: exit {2}' -f $entry.package_name, $entry.target, $run.ExitCode)
        } catch { $result.error = $_.Exception.Message }
        $report.harnesses += $result
    }

    $standard = [ordered]@{ target = $dashboard.target; success = $false; error = $null; elevated_negative = $null; wrong_sid = $null; wrong_hash = $null; lifetime_probe = $null; native = $null; worker = $null }
    $report.standard_account = $standard
    try {
        # The same binary must continue refusing an elevated dashboard launch.
        $negativeRoot = Join-Path $EvidenceDirectory 'elevated-negative-state'
        New-Item -ItemType Directory -Path $negativeRoot | Out-Null
        $environment = [Collections.Generic.Dictionary[string,string]]::new()
        foreach ($variable in @(Get-ChildItem Env:)) {
            if ($variable.Name -eq 'TIRITH' -or $variable.Name.StartsWith('TIRITH_', [StringComparison]::OrdinalIgnoreCase)) { $environment[$variable.Name] = $null }
        }
        foreach ($name in @('HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME')) { $environment[$name] = $negativeRoot }
        $environment['TIRITH_OFFLINE'] = '1'
        $negative = [TirithCi.ProcessRunner]::Run($cli.path, @('dashboard', '--no-browser', '--json'), $negativeRoot, $environment, 30, 1048576)
        $standard.elevated_negative = Save-CiProcessResult $EvidenceDirectory 'elevated-negative' $negative
        Assert-CiElevatedDashboardRefusal $negative
        if (@(Get-ChildItem -LiteralPath $negativeRoot -Recurse -Force -File).Count -ne 0) { throw 'Elevated refusal published state' }

        $username = 'tci' + [Guid]::NewGuid().ToString('N').Substring(0, 16)
        if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) { throw 'Refusing an existing local account' }
        $random = [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
        $securePassword = [Security.SecureString]::new()
        # Fixed mixed classes satisfy local policy; the random suffix provides
        # entropy. Neither the native argv nor any environment/log gets it.
        foreach ($char in ('Aa9!' + [Convert]::ToBase64String($random)).ToCharArray()) { $securePassword.AppendChar($char) }
        [Array]::Clear($random, 0, $random.Length)
        $securePassword.MakeReadOnly()
        $newUser = New-LocalUser -Name $username -Password $securePassword -AccountNeverExpires -UserMayNotChangePassword -Description 'Disposable Tirith CI standard-account qualification'
        $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        if (@(Get-LocalGroupMember -SID $users | Where-Object { $_.SID.Value -eq $newUser.SID.Value }).Count -eq 0) {
            Add-LocalGroupMember -SID $users -Member $newUser
        }
        $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        if (@(Get-LocalGroupMember -SID $administrators | Where-Object { $_.SID.Value -eq $newUser.SID.Value }).Count -ne 0) { throw 'New account unexpectedly belongs to Administrators' }
        $standard.sid = $newUser.SID.Value
        $stage = Join-Path $env:RUNNER_TEMP ('tirith-standard-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $stage | Out-Null
        foreach ($name in @('windows-test-common.ps1', 'windows-test-process.cs', 'windows-standard-test-worker.ps1')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage $name)
        }
        # Explicitly protect the staging DACL. The new user receives RX only;
        # administrators and SYSTEM keep full control of immutable inputs.
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sidValue in @($identity.User.Value, 'S-1-5-18')) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sidValue), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        Set-Acl -LiteralPath $stage -AclObject $acl
        Add-CiAccountReadAccess $stage $newUser.SID
        Add-CiAccountReadAccess $workspace $newUser.SID
        # A custom target directory outside the workspace needs its own RX ACE.
        if (-not ([IO.Path]::GetFullPath($metadata.target_directory) + '\').StartsWith($workspace.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            Add-CiAccountReadAccess $metadata.target_directory $newUser.SID
        }
        foreach ($path in $runtimePaths) {
            if (-not ($path.TrimEnd('\') + '\').StartsWith($workspace.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -and
                -not ($path.TrimEnd('\') + '\').StartsWith(([IO.Path]::GetFullPath($metadata.target_directory).TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
                Add-CiAccountReadAccess $path $newUser.SID
            }
        }
        $worker = Join-Path $stage 'windows-standard-test-worker.ps1'
        $manifest = [ordered]@{
            schema = 1; mode = 'dashboard'; nonce = [Guid]::NewGuid().ToString('N'); sid = $newUser.SID.Value;
            harness = $dashboard.executable; cli = $cli; powershell = $powershell; cwd = $dashboard.cwd; runtime_paths = $runtimePaths
        }
        $manifestPath = Join-Path $stage 'manifest.json'
        Write-CiJson $manifestPath $manifest
        $standard.inputs = @(Get-ChildItem -LiteralPath $stage -File | ForEach-Object { Get-CiFilePin $_.FullName })
        $wrongSid = [TirithCi.StandardProcess]::Run($username, $securePassword, 'S-1-5-18', $powershell.path, $worker, $manifestPath, $stage, 30)
        $standard.wrong_sid = $wrongSid
        $jobsClean = $jobsClean -and $wrongSid.JobEmpty
        $profile = $wrongSid.Profile
        if ($wrongSid.Error -notmatch 'suspended worker token is not the expected standard account' -or -not $wrongSid.JobEmpty) { throw 'Wrong-SID negative control failed' }
        if (Test-Path -LiteralPath (Join-Path $profile ('tirith-ci-' + $manifest.nonce))) { throw 'Wrong-SID worker executed before attestation' }

        # Prove containment with a real long-lived descendant before relying on
        # it for the service tests. Timeout is expected only for this probe.
        $manifest.mode = 'lifetime-probe'
        $manifest.nonce = [Guid]::NewGuid().ToString('N')
        Write-CiJson $manifestPath $manifest
        $lifetime = [TirithCi.StandardProcess]::Run($username, $securePassword, $newUser.SID.Value, $powershell.path, $worker, $manifestPath, $stage, 30)
        $standard.lifetime_probe = $lifetime
        $jobsClean = $jobsClean -and $lifetime.JobEmpty
        if (-not $lifetime.JobEmpty) { throw 'Lifetime probe native job did not empty' }
        $probeEvidence = Copy-CiWorkerEvidence $profile $manifest.nonce 'lifetime-probe'
        if (-not $lifetime.TimedOut -or -not $lifetime.JobEmpty -or $lifetime.Error -ne '' -or
            -not (Test-Path -LiteralPath (Join-Path $probeEvidence 'lifetime-child.json'))) { throw 'Descendant lifetime negative control failed' }
        $manifest.mode = 'dashboard'
        $manifest.nonce = [Guid]::NewGuid().ToString('N')
        $correctHash = $manifest.harness.sha256
        $manifest.harness = [ordered]@{ path = $dashboard.executable.path; size = $dashboard.executable.size; sha256 = ('0' * 64) }
        Write-CiJson $manifestPath $manifest
        $wrongHash = [TirithCi.StandardProcess]::Run($username, $securePassword, $newUser.SID.Value, $powershell.path, $worker, $manifestPath, $stage, 60)
        $standard.wrong_hash = $wrongHash
        $jobsClean = $jobsClean -and $wrongHash.JobEmpty
        if (-not $wrongHash.JobEmpty) { throw 'Wrong-hash probe native job did not empty' }
        $wrongHashEvidence = Copy-CiWorkerEvidence $profile $manifest.nonce 'wrong-hash'
        $wrongHashResult = [IO.File]::ReadAllText((Join-Path $wrongHashEvidence 'result.json')) | ConvertFrom-Json -Depth 20
        if ($wrongHash.ExitCode -eq 0 -or $wrongHash.TimedOut -or $wrongHash.Error -ne '' -or $wrongHashResult.success -or
            $wrongHashResult.error -cne 'Pinned input changed') { throw 'Wrong-hash native worker negative control failed' }
        $manifest.harness.sha256 = $correctHash
        $manifest.nonce = [Guid]::NewGuid().ToString('N')
        Write-CiJson $manifestPath $manifest
        $standard.manifest = Get-CiFilePin $manifestPath
        $native = [TirithCi.StandardProcess]::Run($username, $securePassword, $newUser.SID.Value, $powershell.path, $worker, $manifestPath, $stage, 900)
        $standard.native = $native
        $jobsClean = $jobsClean -and $native.JobEmpty
        if (-not $native.JobEmpty) { throw 'Dashboard native job did not empty' }
        $workerEvidence = Copy-CiWorkerEvidence $profile $manifest.nonce 'dashboard-standard'
        if ($native.ExitCode -ne 0 -or $native.TimedOut -or $native.DescendantsLeaked -or -not $native.JobEmpty -or $native.Error -ne '') { throw 'Standard-account dashboard process failed' }
        $workerResult = [IO.File]::ReadAllText((Join-Path $workerEvidence 'result.json')) | ConvertFrom-Json -Depth 20
        if (-not $workerResult.success -or $workerResult.counts.passed -lt 9 -or $workerResult.counts.ignored -ne 0 -or $workerResult.counts.filtered -ne 0) { throw 'Standard-account dashboard tests were not all executed successfully' }
        $standard.worker = $workerResult
        $standard.success = $true
    } catch { $standard.error = $_.Exception.Message }
    $report.harnesses += [ordered]@{ package = $dashboard.package_name; target = $dashboard.target; executable = $dashboard.executable; account = 'standard'; success = $standard.success; error = $standard.error }
    if ($report.harnesses.Count -ne $inventory.Count) { throw 'Workspace execution omitted a retained test artifact' }
} catch { $report.errors += $_.Exception.Message }
finally {
    foreach ($lease in $leases) { $lease.Dispose() }
    # Doctests are not present in --no-run compiler-artifact output. Preserve
    # their coverage even when a build, harness or account qualification fails.
    try {
        $cargoForDocs = (Get-Command cargo.exe -CommandType Application -ErrorAction Stop).Source
        $docs = [TirithCi.ProcessRunner]::Run($cargoForDocs, @('test', '--workspace', '--doc', '--locked', '--no-fail-fast'), $workspace, $null, 900, 33554432)
        $report.doctests = Save-CiProcessResult $EvidenceDirectory 'cargo-doctests' $docs
        Assert-CiProcessSucceeded $docs
    } catch { $report.errors += ('Doctests: ' + $_.Exception.Message) }
    if ($null -ne $newUser) {
        try {
            if (-not $jobsClean) { throw 'Native job cleanup was not confirmed; account/profile cleanup withheld' }
            $current = Get-LocalUser -Name $newUser.Name -ErrorAction Stop
            if ($current.SID.Value -cne $newUser.SID.Value) { throw 'Local account identity changed during qualification' }
            foreach ($path in $aclPaths) {
                $acl = Get-Acl -LiteralPath $path
                $acl.PurgeAccessRules($newUser.SID)
                Set-Acl -LiteralPath $path -AclObject $acl
            }
            if (-not [string]::IsNullOrEmpty($profile)) { [TirithCi.StandardProcess]::RemoveProfile($newUser.SID.Value, $profile) }
            Remove-LocalUser -SID $newUser.SID
            $report.cleanup += 'Native descendants terminated; exact account/profile and account-specific ACL entries removed'
        } catch { $report.errors += ('Account cleanup: ' + $_.Exception.Message) }
    }
    if ($null -ne $securePassword) { $securePassword.Dispose() }
    if ($null -ne $stage) {
        try { Remove-Item -LiteralPath $stage -Recurse -Force } catch { $report.errors += ('Staging cleanup: ' + $_.Exception.Message) }
    }
    $report.success = $buildSucceeded -and $report.errors.Count -eq 0 -and $report.harnesses.Count -gt 0 -and
        @($report.harnesses | Where-Object { -not $_.success }).Count -eq 0 -and $null -ne $report.doctests -and
        $report.doctests.exit_code -eq 0 -and -not $report.doctests.timed_out -and -not $report.doctests.output_overflow
    Write-CiJson (Join-Path $EvidenceDirectory 'summary.json') $report
}
if (-not $report.success) {
    Write-Error ('Windows workspace qualification failed. See summary.json and the complete retained logs. ' + ($report.errors -join '; '))
    exit 1
}
