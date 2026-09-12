Set-StrictMode -Version Latest

function Write-CiJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
}

function Get-CiRegularFile([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw 'Expected a regular file' }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing a reparse-point input: $full"
        }
        if ($current -is [IO.FileInfo]) { $current = $current.Directory; if ($null -eq $current) { break } }
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing a reparse-point ancestor: $full"
        }
    }
    return $item
}

function Get-CiFilePin([string]$Path) {
    $item = Get-CiRegularFile $Path
    return [ordered]@{ path = $item.FullName; size = $item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}

function Open-CiPinnedFile($Pin) {
    $item = Get-CiRegularFile $Pin.path
    # Retain a read-only, non-write/non-delete-sharing handle through execution.
    $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        if ($stream.Length -ne $Pin.size -or $hash -cne $Pin.sha256) { throw 'Pinned input changed' }
        $stream.Position = 0
        return $stream
    } catch { $stream.Dispose(); throw }
}

function Get-CiTestNames([string]$Text) {
    $names = @(foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^([A-Za-z0-9_:]+): test$') { $Matches[1] }
        elseif ($line.Trim().Length -ne 0) { throw 'Unexpected dashboard test list format' }
    })
    if ($names.Count -lt 9 -or $names.Count -gt 512 -or @($names | Sort-Object -Unique).Count -ne $names.Count) {
        throw 'Dashboard test list is missing, excessive or duplicated'
    }
    $required = @(
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
    foreach ($name in $required) { if ($name -cnotin $names) { throw "Missing required dashboard test: $name" } }
    return $names
}

function Assert-CiProcessCompleted($Result) {
    # Output text and a nonzero exit are not a product refusal unless the owned
    # native process tree was reaped and both bounded streams reached EOF.
    foreach ($name in @('NativeJob', 'JobEmpty', 'LeaderReaped', 'OutputDrained')) {
        if ($Result.$name -isnot [bool] -or -not $Result.$name) { throw "Native process completion was not confirmed: $name" }
    }
    foreach ($name in @('DescendantsLeaked', 'TimedOut', 'OutputOverflow')) {
        if ($Result.$name -isnot [bool] -or $Result.$name) { throw "Native process failed or exceeded a bound: $name" }
    }
    foreach ($name in @('Error', 'CleanupError')) {
        if ($Result.$name -isnot [string] -or $Result.$name.Length -ne 0) { throw "Native process reported a failure: $name" }
    }
}

function Assert-CiProcessSucceeded($Result) {
    Assert-CiProcessCompleted $Result
    if ($Result.ExitCode -ne 0) { throw 'Native process exited unsuccessfully' }
}

function Assert-CiElevatedDashboardRefusal($Result) {
    Assert-CiProcessCompleted $Result
    if ($Result.ExitCode -eq 0 -or
        $Result.Stderr -notmatch 'open the dashboard from a normal, non-administrator terminal') {
        throw 'Elevated dashboard refusal was not preserved'
    }
}

function Assert-CiDashboardResult($Result, [string[]]$Names) {
    Assert-CiProcessSucceeded $Result
    $matches = [regex]::Matches($Result.Stdout, '(?m)^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [^\r\n]+\r?$')
    if ($matches.Count -ne 1) { throw 'Missing or ambiguous dashboard test summary' }
    $counts = @($matches[0].Groups | Select-Object -Skip 1 | ForEach-Object { [int]$_.Value })
    if ($counts[0] -ne $Names.Count -or $counts[1] -ne 0 -or $counts[2] -ne 0 -or $counts[3] -ne 0 -or $counts[4] -ne 0) {
        throw 'Dashboard tests were failed, ignored, filtered or omitted'
    }
    foreach ($name in $Names) {
        if ($Result.Stdout -notmatch ('(?m)^test ' + [regex]::Escape($name) + ' \.\.\. ok\r?$')) {
            throw "Missing successful execution: $name"
        }
    }
    return [ordered]@{ passed = $counts[0]; failed = 0; ignored = 0; measured = 0; filtered = 0 }
}

function Get-CiArtifactInventory([string]$Messages, $Metadata) {
    $targetRoot = [IO.Path]::GetFullPath($Metadata.target_directory).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $packages = @{}
    foreach ($package in $Metadata.packages) { $packages[$package.id] = $package }
    $artifacts = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $finished = 0
    foreach ($line in ($Messages -split '\r?\n')) {
        if (-not $line.StartsWith('{')) { continue }
        $message = $line | ConvertFrom-Json -Depth 30
        if ($message.reason -eq 'build-finished') {
            if (-not $message.success) { throw 'Cargo reported a failed build' }
            $finished++
        }
        if ($message.reason -ne 'compiler-artifact' -or -not $message.profile.test -or $null -eq $message.executable) { continue }
        $path = [IO.Path]::GetFullPath($message.executable)
        if (-not $path.StartsWith($targetRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cargo executable escaped its target directory' }
        if ($message.package_id -notin $Metadata.workspace_members -or -not $packages.ContainsKey($message.package_id)) { throw 'Unknown workspace test artifact' }
        if (-not $seen.Add($path)) { throw 'Duplicate Cargo test executable' }
        if ($artifacts.Count -ge 512) { throw 'Cargo test inventory exceeds its bound' }
        $package = $packages[$message.package_id]
        $artifacts.Add([ordered]@{
            package_id = $message.package_id; package_name = $package.name; target = $message.target.name;
            kind = @($message.target.kind); cwd = [IO.Path]::GetDirectoryName($package.manifest_path);
            executable = (Get-CiFilePin $path)
        })
    }
    if ($finished -ne 1 -or $artifacts.Count -eq 0) { throw 'Cargo inventory has no unique successful completion' }
    $dashboard = @($artifacts | Where-Object { $_.package_name -eq 'tirith' -and $_.target -eq 'control_dashboard' -and 'test' -in $_.kind })
    if ($dashboard.Count -ne 1) { throw 'Expected exactly one dashboard integration target' }
    return $artifacts.ToArray()
}

function Get-CiCompanionArtifact([string]$Messages, $Metadata) {
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $tirith = @($Metadata.packages | Where-Object { $_.name -eq 'tirith' -and $_.id -in $Metadata.workspace_members })
    if ($tirith.Count -ne 1) { throw 'Expected one Tirith workspace package' }
    foreach ($line in ($Messages -split '\r?\n')) {
        if (-not $line.StartsWith('{')) { continue }
        $message = $line | ConvertFrom-Json -Depth 30
        if ($message.reason -eq 'compiler-artifact' -and $message.package_id -eq $tirith[0].id -and
            $message.target.name -eq 'tirith' -and 'bin' -in $message.target.kind -and
            -not $message.profile.test -and $null -ne $message.executable) {
            $null = $paths.Add([IO.Path]::GetFullPath($message.executable))
        }
    }
    if ($paths.Count -ne 1) { throw 'Expected the exact Cargo-built companion CLI artifact' }
    $path = @($paths)[0]
    $targetRoot = [IO.Path]::GetFullPath($Metadata.target_directory).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($targetRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Companion CLI escaped the Cargo target directory' }
    return Get-CiFilePin $path
}

function Get-CiRuntimePaths([string]$Messages, [string]$TargetRoot, [string]$BinaryDirectory, [string]$RustLibdir) {
    $paths = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $targetPrefix = [IO.Path]::GetFullPath($TargetRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    # Cargo also adds build-script native link search directories inside target.
    foreach ($line in ($Messages -split '\r?\n')) {
        if (-not $line.StartsWith('{')) { continue }
        $message = $line | ConvertFrom-Json -Depth 30
        if ($message.reason -ne 'build-script-executed') { continue }
        foreach ($linked in $message.linked_paths) {
            $path = [IO.Path]::GetFullPath(($linked -replace '^(native|framework|all|dependency|crate)=', ''))
            if ($path.StartsWith($targetPrefix, [StringComparison]::OrdinalIgnoreCase) -and $seen.Add($path)) { $paths.Add($path) }
        }
    }
    foreach ($path in @((Join-Path $BinaryDirectory 'deps'), $BinaryDirectory, $RustLibdir)) {
        if ($seen.Add($path)) { $paths.Add($path) }
    }
    if ($paths.Count -gt 512) { throw 'Rust runtime path inventory exceeds its bound' }
    foreach ($path in $paths) {
        if (-not [IO.Path]::IsPathFullyQualified($path) -or -not (Test-Path -LiteralPath $path -PathType Container)) { throw 'Invalid Rust runtime path' }
    }
    return $paths.ToArray()
}

function Save-CiProcessResult([string]$Directory, [string]$Name, $Result) {
    [IO.File]::WriteAllText((Join-Path $Directory "$Name.stdout.log"), $Result.Stdout)
    [IO.File]::WriteAllText((Join-Path $Directory "$Name.stderr.log"), $Result.Stderr)
    return [ordered]@{
        exit_code = $Result.ExitCode; timed_out = $Result.TimedOut; output_overflow = $Result.OutputOverflow;
        leader_exit_code = $Result.LeaderExitCode; process_id = $Result.ProcessId;
        before_cleanup = $Result.BeforeCleanup; after_cleanup = $Result.AfterCleanup;
        native_job = $Result.NativeJob; leader_reaped = $Result.LeaderReaped; job_empty = $Result.JobEmpty;
        output_drained = $Result.OutputDrained; descendants_leaked = $Result.DescendantsLeaked;
        error = $Result.Error; cleanup_error = $Result.CleanupError
    }
}
