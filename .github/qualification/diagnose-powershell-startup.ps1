# Diagnostic proposal only. No target qualification is claimed by this script.
param(
    [Parameter(Mandatory)][string]$Workspace,
    [Parameter(Mandatory)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows -or $PSVersionTable.PSEdition -cne 'Core') { throw 'Native Windows PowerShell 7 controller required' }
$Workspace = [IO.Path]::GetFullPath($Workspace)
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Fresh evidence directory required' }
$pins = @{
    '.github/scripts/windows-test-common.ps1'='eb8ff8fa13df735938edcfa327b7de95d770c119ac54ba670aa04468a5637dd6'
    '.github/scripts/windows-test-process.cs'='5cb34bdbda11f0ca50dd2d088d7fc2d155a1793d1e87d70dc81a9c63f04781a8'
    'crates/tirith/src/cli/shell_target_native_tests.rs'='6ab3f0615d9b15c6258fb705bc60effaa56b460c08cee495fa7b54ab9b2fa8d3'
    'crates/tirith-core/src/trusted_child/windows.rs'='b64b24989cb4ed464744f201120725c24cb85c7ed562b0c81f5246f77f65d42d'
}
# A different source/controller needs review, not an implicit continuation.
foreach ($relative in $pins.Keys) {
    $file = Get-Item -LiteralPath (Join-Path $Workspace $relative) -Force
    if ($file.PSIsContainer -or $file.Length -gt 1048576 -or
        ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pins[$relative]) {
        throw 'Diagnostic source pin differs'
    }
}
. (Join-Path $Workspace '.github/scripts/windows-test-common.ps1')
Add-Type -Path (Join-Path $Workspace '.github/scripts/windows-test-process.cs')
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$report = [ordered]@{
    schema_version=1; status='refused'; scope='powershell_startup_path_environment_differential_only';
    product_supervisor_exercised=$false; automatic_adapter_qualified=$false;
    profile_loaded=$false; profile_writes=$false; source_pins=$pins; workflow_event_revision=$env:GITHUB_SHA; cases=@()
}
$leases=[Collections.Generic.List[IO.FileStream]]::new()
function Assert-DiagnosticCleanup($Result) {
    # Timeout is an observation only when no native process or pipe remains.
    foreach ($name in @('NativeJob','JobEmpty','LeaderReaped','OutputDrained')) {
        if ($Result.$name -isnot [bool] -or -not $Result.$name) { throw ('Unconfirmed diagnostic cleanup: '+$name) }
    }
    foreach ($name in @('DescendantsLeaked','OutputOverflow')) {
        if ($Result.$name -isnot [bool] -or $Result.$name) { throw ('Diagnostic ownership/capture failed: '+$name) }
    }
    foreach ($name in @('Error','CleanupError')) {
        if ($Result.$name -isnot [string] -or $Result.$name.Length -ne 0) { throw ('Diagnostic process failure: '+$name) }
    }
    if ($Result.TimedOut -isnot [bool]) { throw 'Missing diagnostic timeout state' }
}
function Profile-State([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @{exists=$false} }
    $file=Get-CiRegularFile $Path
    if ($file.Length -gt 4194304) { throw 'Profile exceeds read bound' }
    return @{exists=$true; pin=(Get-CiFilePin $Path); last_write_utc=$file.LastWriteTimeUtc.Ticks}
}
try {
    foreach ($relative in $pins.Keys) { $leases.Add((Open-CiPinnedFile (Get-CiFilePin (Join-Path $Workspace $relative)))) }
    $source=[IO.File]::ReadAllText((Join-Path $Workspace 'crates/tirith/src/cli/shell_target_native_tests.rs'))
    $match=[regex]::Match($source, '(?m)^const QUERY: &str = r#"([^\r\n]+)"#;$')
    if (-not $match.Success) { throw 'Missing exact native target query' }
    $query="[Console]::Error.WriteLine('TIRITH_NATIVE_QUERY_ENTERED');"+$match.Groups[1].Value+";[Console]::Error.WriteLine('TIRITH_NATIVE_QUERY_FINISHED')"
    $baseKeys=@('HOME','USERPROFILE','HOMEDRIVE','HOMEPATH','XDG_CONFIG_HOME','SystemRoot','WINDIR','APPDATA','LOCALAPPDATA','TEMP','TMP','TMPDIR','LANG','LC_ALL')
    $documents=[Environment]::GetFolderPath('MyDocuments')
    $variants=@(
        @{name='powershell'; path=(Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/powershell.exe'); profile=(Join-Path $documents 'WindowsPowerShell/Microsoft.PowerShell_profile.ps1'); envs=@('current','empty')},
        @{name='pwsh'; path=(Join-Path $PSHOME 'pwsh.exe'); profile=(Join-Path $documents 'PowerShell/Microsoft.PowerShell_profile.ps1'); envs=@('current')}
    )
    foreach ($variant in $variants) {
        $pin=Get-CiFilePin $variant.path
        $leases.Add((Open-CiPinnedFile $pin))
        if ($pin.path -notmatch '^[A-Za-z]:\\' -or $pin.size -gt 268435456) { throw 'Ordinary DOS executable path required' }
        foreach ($envKind in $variant.envs) {
            foreach ($pathKind in @('canonical','dos')) {
                $case=[ordered]@{shell=$variant.name; environment_kind=$envKind; path_kind=$pathKind; native_executable=$pin; process=$null}
                $report.cases += $case
                $dir=Join-Path $EvidenceDirectory ($variant.name+'-'+$envKind+'-'+$pathKind)
                New-Item -ItemType Directory -Path $dir | Out-Null
                $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
                # ProcessRunner starts with inherited variables, so explicitly
                # remove every entry before adding the same finite ChildSpec.
                $ambient=[Environment]::GetEnvironmentVariables('Process')
                $setter=$environment.GetType().GetProperty('Item')
                foreach ($key in $ambient.Keys) {
                    # PowerShell coerces a direct typed-index assignment of
                    # $null to an empty string. PropertyInfo takes an object
                    # value, preserving the null used by ProcessRunner.Remove.
                    $setter.SetValue($environment,$null,[object[]]@([string]$key))
                }
                $expected=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
                $keys=if ($envKind -ceq 'current') {@($baseKeys)} else {@()}
                foreach ($key in $keys) {
                    $value=[Environment]::GetEnvironmentVariable($key,'Process')
                    if ($null -ne $value) { $environment[$key]=$value; $expected[$key]=$value }
                }
                if ($envKind -ceq 'current') {
                    $environment['POWERSHELL_TELEMETRY_OPTOUT']='1'
                    $environment['POWERSHELL_UPDATECHECK']='Off'
                    $environment['PSModuleAnalysisCachePath']=Join-Path $dir 'module-cache'
                    foreach ($key in @('POWERSHELL_TELEMETRY_OPTOUT','POWERSHELL_UPDATECHECK','PSModuleAnalysisCachePath')) { $expected[$key]=$environment[$key] }
                }
                foreach ($key in $ambient.Keys) {
                    if (-not $expected.ContainsKey([string]$key) -and $null -ne $environment[[string]$key]) { throw 'Ambient environment entry was not removed with actual null' }
                }
                $surviving=@($environment.Keys | Where-Object {$null -ne $environment[$_]})
                if ($surviving.Count -ne $expected.Count) { throw 'Finite environment key count differs' }
                foreach ($key in $surviving) {
                    if (-not $expected.ContainsKey($key) -or $environment[$key] -cne $expected[$key]) { throw 'Finite environment key or value differs' }
                }
                if ($envKind -ceq 'empty' -and $surviving.Count -ne 0) { throw 'Empty environment retained an entry' }
                $case.environment_exactly_admitted=$true
                $case.environment_names=@($environment.Keys | Where-Object {$null -ne $environment[$_]} | Sort-Object)
                $application=if ($pathKind -ceq 'canonical') {'\\?\'+$pin.path} else {$pin.path}
                $cwd=[IO.Path]::GetDirectoryName($pin.path)
                $case.application=$application
                $case.cwd=$cwd
                $before=Profile-State $variant.profile
                $case.profile_before=$before
                $run=[TirithCi.ProcessRunner]::Run($application,@('-NoLogo','-NoProfile','-NonInteractive','-Command',$query),$cwd,$environment,20,65536)
                $case.process=Save-CiProcessResult $dir 'query' $run
                # Nonzero/timeout is data; uncertain native cleanup halts the matrix.
                Assert-DiagnosticCleanup $run
                $case.query_entered=$run.Stderr.Contains('TIRITH_NATIVE_QUERY_ENTERED')
                $case.query_finished=$run.Stderr.Contains('TIRITH_NATIVE_QUERY_FINISHED')
                $after=Profile-State $variant.profile
                $case.profile_after=$after
                $case.profile_unchanged=($before|ConvertTo-Json -Depth 10 -Compress) -ceq ($after|ConvertTo-Json -Depth 10 -Compress)
                if (-not $case.profile_unchanged) { throw 'Personal profile changed' }
                $case.query_succeeded=($run.ExitCode -eq 0 -and -not $run.TimedOut)
                if ($case.query_succeeded) {
                    if (-not $case.query_entered -or -not $case.query_finished) { throw 'Successful query omitted progress markers' }
                    $observed=$run.Stdout|ConvertFrom-Json -Depth 10
                    if ($observed.host_name -cne 'ConsoleHost' -or $observed.profile -cne $variant.profile -or
                        $observed.current_user_current_host -cne $variant.profile -or
                        $observed.executable -ine $pin.path) { throw 'Query returned an unexpected native target' }
                    $case.observed=$observed
                }
                $afterPin=Get-CiFilePin $pin.path
                if ($afterPin.sha256 -cne $pin.sha256 -or $afterPin.size -ne $pin.size) { throw 'Native executable changed' }
                Write-CiJson (Join-Path $EvidenceDirectory 'report.json') $report
            }
        }
    }
    if ($report.cases.Count -ne 6) { throw 'Diagnostic matrix incomplete' }
    foreach ($relative in $pins.Keys) {
        if ((Get-CiFilePin (Join-Path $Workspace $relative)).sha256 -cne $pins[$relative]) { throw 'Diagnostic source changed' }
    }
    $report.status='diagnostic_complete_not_product_qualification'
} catch { $report.error=$_.Exception.Message }
finally {
    foreach ($lease in $leases) { $lease.Dispose() }
    Write-CiJson (Join-Path $EvidenceDirectory 'report.json') $report
}
if ($report.status -cne 'diagnostic_complete_not_product_qualification') { throw 'Startup diagnostic incomplete; original evidence retained' }
