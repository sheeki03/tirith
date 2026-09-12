# CI-only LLVM compiler profile. The native process completion gates stay strict.
function Get-CiCompilerToolPlan {
    # The hosted image installs LLVM here. Never search PATH or a repository
    # preference for these tools; missing/mismatched installed inputs refuse.
    $root = 'C:\Program Files\LLVM\bin'
    $tools = @(
        [ordered]@{ name = 'clang-cl'; path = "$root\clang-cl.exe"; arguments = @('--version'); marker = '(?m)^clang version (?<version>[0-9]+\.[0-9]+\.[0-9]+)' },
        [ordered]@{ name = 'llvm-lib'; path = "$root\llvm-lib.exe"; arguments = @('/?'); marker = '(?m)^OVERVIEW: LLVM Lib\r?$' },
        [ordered]@{ name = 'lld-link'; path = "$root\lld-link.exe"; arguments = @('--version'); marker = '(?m)^LLD (?<version>[0-9]+\.[0-9]+\.[0-9]+)' }
    )
    $environment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @(@('CC', $tools[0].path), @('CXX', $tools[0].path), @('AR', $tools[1].path))) {
        # cc 1.2.55 checks these exact spellings in this priority order.
        foreach ($name in @(($entry[0] + '_x86_64-pc-windows-msvc'), ($entry[0] + '_x86_64_pc_windows_msvc'),
            ('HOST_' + $entry[0]), ('TARGET_' + $entry[0]), $entry[0])) {
            $environment[$name] = $entry[1]
        }
    }
    $environment['CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER'] = $tools[2].path
    # An encoded flag is one complete argv element even when the path has spaces.
    # This explicit CI profile replaces ambient/project rustflags and wrappers.
    $environment['CARGO_ENCODED_RUSTFLAGS'] = '-Clinker=' + $tools[2].path
    $environment['CARGO_ENCODED_RUSTDOCFLAGS'] = '-Clinker=' + $tools[2].path
    $environment['RUSTC_WRAPPER'] = ''
    $environment['RUSTC_WORKSPACE_WRAPPER'] = ''
    $environment['CC_ENABLE_DEBUG_OUTPUT'] = '1'
    $environment['RUSTUP_TOOLCHAIN'] = 'stable-x86_64-pc-windows-msvc'
    # Ordinary $null converts to an empty string in this typed dictionary.
    $environment.Add('CARGO_BUILD_TARGET', [NullString]::Value)
    return [pscustomobject]@{ Tools = $tools; Environment = $environment; CargoArguments = @() }
}

function Assert-CiCompilerToolIdentity($Tool, $Pin, [string]$FileVersion, [string]$Output) {
    if ($Pin.path -ine $Tool.path -or $Pin.size -le 0 -or $Pin.size -gt 536870912 -or
        $Pin.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'LLVM compiler tool identity is missing or invalid' }
    if ($FileVersion -cnotmatch '^[1-9][0-9]*\.[0-9]+\.[0-9]+$') { throw 'LLVM compiler tool version resource is missing' }
    if ($Output.Length -gt 65536 -or $Output -cnotmatch $Tool.marker) { throw 'LLVM compiler tool probe did not identify the expected driver' }
    if ($Tool.name -ne 'llvm-lib' -and $Matches['version'] -cne $FileVersion) { throw 'LLVM compiler tool version sources disagree' }
    if ($Tool.name -eq 'clang-cl' -and $Output -cnotmatch '(?m)^Target: x86_64-pc-windows-msvc\r?$') {
        throw 'LLVM compiler default target is not the required Windows MSVC target'
    }
}

function Assert-CiCompilerConfiguration([string]$Workspace) {
    # Native host mode is intentional: supplying --target prevents Rust flags
    # from reaching host build-script/proc-macro compilation. Cargo configuration
    # can also force CC or replace compilers; this fixed CI profile refuses it.
    $current = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Workspace))
    $depth = 0
    while ($null -ne $current) {
        if (++$depth -gt 64) { throw 'Compiler configuration ancestor bound exceeded' }
        foreach ($relative in @('.cargo/config', '.cargo/config.toml')) {
            if (Test-Path -LiteralPath (Join-Path $current.FullName $relative)) { throw 'Fixed CI compiler profile refuses project/ancestor Cargo configuration' }
        }
        $current = $current.Parent
    }
    $cargoHome = if ([string]::IsNullOrEmpty($env:CARGO_HOME)) { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cargo' } else { $env:CARGO_HOME }
    foreach ($relative in @('config', 'config.toml')) {
        if (Test-Path -LiteralPath (Join-Path $cargoHome $relative)) { throw 'Fixed CI compiler profile refuses Cargo home configuration' }
    }
}

function Get-CiCompilerTools([string]$EvidenceDirectory, [string]$Workspace, $Leases) {
    if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted') { throw 'LLVM compiler profile requires a disposable GitHub-hosted Windows job' }
    Assert-CiCompilerConfiguration $Workspace
    $plan = Get-CiCompilerToolPlan
    $plan.Environment['RUSTC'] = (Get-Command rustc.exe -CommandType Application -ErrorAction Stop).Source
    $plan.Environment['RUSTDOC'] = (Get-Command rustdoc.exe -CommandType Application -ErrorAction Stop).Source
    $evidence = [ordered]@{
        profile = 'llvm-windows-msvc'; target = 'x86_64-pc-windows-msvc'; tools = @(); rustc = $null;
        environment = $plan.Environment; cargo_arguments = $plan.CargoArguments;
        sources = @(
            'https://clang.llvm.org/docs/UsersManual.html#clang-cl',
            'https://lld.llvm.org/windows_support.html',
            'https://docs.rs/cc/1.2.55/cc/#external-configuration-via-environment-variables',
            'https://doc.rust-lang.org/cargo/reference/environment-variables.html',
            'https://github.com/actions/runner-images/blob/main/images/windows/scripts/build/Install-LLVM.ps1'
        )
    }
    # Write an initial record so unavailable tools or failed probes leave evidence.
    Write-CiJson (Join-Path $EvidenceDirectory 'compiler-tools.json') $evidence
    $rustcProbe = [TirithCi.ProcessRunner]::Run($plan.Environment['RUSTC'], @('--version', '--verbose'), $Workspace, $plan.Environment, 30, 65536)
    $evidence.rustc = Save-CiProcessResult $EvidenceDirectory 'compiler-tool-rustc' $rustcProbe
    Write-CiJson (Join-Path $EvidenceDirectory 'compiler-tools.json') $evidence
    Assert-CiProcessSucceeded $rustcProbe
    if ($rustcProbe.Stdout -cnotmatch '(?m)^host: x86_64-pc-windows-msvc\r?$') { throw 'Rust compiler host is not the required Windows MSVC target' }
    $versions = [Collections.Generic.List[string]]::new()
    foreach ($tool in $plan.Tools) {
        $item = Get-CiRegularFile $tool.path
        if ($item.FullName -ine $tool.path -or $item.Length -le 0 -or $item.Length -gt 536870912) {
            throw 'LLVM compiler tool is unavailable at its required fixed path'
        }
        $pin = Get-CiFilePin $tool.path
        $Leases.Add((Open-CiPinnedFile $pin))
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($pin.path)
        $version = '{0}.{1}.{2}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart
        $run = [TirithCi.ProcessRunner]::Run($pin.path, [string[]]$tool.arguments, $Workspace, $null, 30, 65536)
        $entry = [ordered]@{ name = $tool.name; executable = $pin; version = $version; version_source = 'PE VERSIONINFO';
            probe = Save-CiProcessResult $EvidenceDirectory ('compiler-tool-' + $tool.name) $run }
        $evidence.tools += $entry
        Write-CiJson (Join-Path $EvidenceDirectory 'compiler-tools.json') $evidence
        Assert-CiProcessSucceeded $run
        Assert-CiCompilerToolIdentity $tool $pin $version ($run.Stdout + $run.Stderr)
        $versions.Add($version)
    }
    if (@($versions | Select-Object -Unique).Count -ne 1) { throw 'LLVM compiler/archive/linker versions do not match' }
    return [pscustomobject]@{ Environment = $plan.Environment; CargoArguments = $plan.CargoArguments; Evidence = $evidence }
}
