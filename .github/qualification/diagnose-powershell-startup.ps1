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
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class TirithDiagnosticWindowsDirectory {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern uint GetSystemWindowsDirectoryW(StringBuilder value, uint size);
    public static string Read() {
        var value = new StringBuilder(32768);
        uint length = GetSystemWindowsDirectoryW(value, (uint)value.Capacity);
        if (length == 0 || length >= value.Capacity) throw new InvalidOperationException("System Windows directory unavailable or oversized");
        string path = value.ToString();
        if (path.Length != length || path.Length < 3 || !Char.IsLetter(path[0]) || path[1] != ':' || path[2] != '\\') throw new InvalidOperationException("Unexpected system Windows directory form");
        return path;
    }
}
'@
$systemWindowsDirectory=[TirithDiagnosticWindowsDirectory]::Read()
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$report = [ordered]@{
    schema_version=1; status='refused'; scope='powershell_query_statement_and_minimal_environment_differential_only';
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
    $originalQuery=$match.Groups[1].Value
    $fields=[ordered]@{
        profile='[string]$PROFILE'
        current_user_current_host='[string]$PROFILE.CurrentUserCurrentHost'
        documents="[Environment]::GetFolderPath('MyDocuments')"
        home='[string]$HOME'
        version='$PSVersionTable.PSVersion.ToString()'
        major='$PSVersionTable.PSVersion.Major'
        minor='$PSVersionTable.PSVersion.Minor'
        edition='[string]$PSVersionTable.PSEdition'
        host_name='$Host.Name'
        executable='[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName'
        xdg='$env:XDG_CONFIG_HOME'
    }
    $pairs=@(foreach ($key in $fields.Keys) { $key+'='+$fields[$key] })
    $reconstructed='$ErrorActionPreference=''Stop''; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Out.Write(([ordered]@{'+($pairs -join ';')+'}|ConvertTo-Json -Compress))'
    if ($originalQuery -cne $reconstructed) { throw 'Diagnostic fields differ from exact pinned original query' }
    $preamble="[Console]::Error.WriteLine('TIRITH_NATIVE_QUERY_ENTERED');"+
        '$ErrorActionPreference=''Stop'';[Console]::Error.WriteLine(''TIRITH_ERROR_MODE_SET'');'+
        '[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::Error.WriteLine(''TIRITH_ENCODING_SET'');'+
        '[Console]::Error.WriteLine(''TIRITH_MODULE_PATH_BASE64='' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$env:PSModulePath)));'+
        '$observation=[ordered]@{};'
    $collect=@(foreach ($key in $fields.Keys) {
        '$observation['''+$key+''']='+$fields[$key]+';[Console]::Error.WriteLine(''TIRITH_FIELD_'+$key.ToUpperInvariant()+''');'
    }) -join ''
    $finish="[Console]::Error.WriteLine('TIRITH_NATIVE_QUERY_FINISHED')"
    $queries=@{
        statements=$preamble+$collect+'[Console]::Error.WriteLine(''TIRITH_SERIALIZE_BEGIN'');$json=$observation|ConvertTo-Json -Compress;[Console]::Error.WriteLine(''TIRITH_SERIALIZE_END'');[Console]::Out.Write($json);'+$finish
        no_module='$PSModuleAutoloadingPreference=''None'';'+$preamble+$collect+
            '[Console]::Out.WriteLine(''TIRITH_FIELDS_V1'');foreach($key in $observation.Keys){[Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$observation[$key])))};'+$finish
    }
    $baseKeys=@('HOME','USERPROFILE','HOMEDRIVE','HOMEPATH','XDG_CONFIG_HOME','SystemRoot','WINDIR','APPDATA','LOCALAPPDATA','TEMP','TMP','TMPDIR','LANG','LC_ALL')
    $documents=[Environment]::GetFolderPath('MyDocuments')
    $report.system_windows_directory=$systemWindowsDirectory
    $variants=@(
        @{name='powershell'; path=(Join-Path $systemWindowsDirectory 'System32/WindowsPowerShell/v1.0/powershell.exe'); profile=(Join-Path $documents 'WindowsPowerShell/Microsoft.PowerShell_profile.ps1'); env='current'; path_kind='dos'; query='statements'},
        @{name='powershell'; path=(Join-Path $systemWindowsDirectory 'System32/WindowsPowerShell/v1.0/powershell.exe'); profile=(Join-Path $documents 'WindowsPowerShell/Microsoft.PowerShell_profile.ps1'); env='current'; path_kind='dos'; query='no_module'},
        @{name='powershell'; path=(Join-Path $systemWindowsDirectory 'System32/WindowsPowerShell/v1.0/powershell.exe'); profile=(Join-Path $documents 'WindowsPowerShell/Microsoft.PowerShell_profile.ps1'); env='system_root'; path_kind='dos'; query='no_module'},
        @{name='pwsh'; path=(Join-Path $PSHOME 'pwsh.exe'); profile=(Join-Path $documents 'PowerShell/Microsoft.PowerShell_profile.ps1'); env='system_root'; path_kind='canonical'; query='no_module'}
    )
    foreach ($variant in $variants) {
        $pin=Get-CiFilePin $variant.path
        $leases.Add((Open-CiPinnedFile $pin))
        if ($pin.path -notmatch '^[A-Za-z]:\\' -or $pin.size -gt 268435456) { throw 'Ordinary DOS executable path required' }
        $envKind=$variant.env
        $pathKind=$variant.path_kind
        $query=$queries[$variant.query]
                $case=[ordered]@{shell=$variant.name; environment_kind=$envKind; path_kind=$pathKind; native_executable=$pin; query_kind=$variant.query; process=$null}
                $report.cases += $case
                $dir=Join-Path $EvidenceDirectory ($variant.name+'-'+$envKind+'-'+$pathKind+'-'+$variant.query)
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
                if ($envKind -ceq 'system_root') {
                    $environment['SystemRoot']=$systemWindowsDirectory
                    $expected['SystemRoot']=$systemWindowsDirectory
                }
                foreach ($key in $ambient.Keys) {
                    if (-not $expected.ContainsKey([string]$key) -and $null -ne $environment[[string]$key]) { throw 'Ambient environment entry was not removed with actual null' }
                }
                $surviving=@($environment.Keys | Where-Object {$null -ne $environment[$_]})
                if ($surviving.Count -ne $expected.Count) { throw 'Finite environment key count differs' }
                foreach ($key in $surviving) {
                    if (-not $expected.ContainsKey($key) -or $environment[$key] -cne $expected[$key]) { throw 'Finite environment key or value differs' }
                }
                if ($envKind -ceq 'system_root' -and ($surviving.Count -ne 1 -or -not $expected.ContainsKey('SystemRoot'))) { throw 'Minimal native environment differs' }
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
                $case.progress_markers=@([regex]::Matches($run.Stderr,'(?m)^TIRITH_[A-Z_]+\r?$') | ForEach-Object {$_.Value.TrimEnd([char]13)})
                $moduleMatch=[regex]::Match($run.Stderr,'(?m)^TIRITH_MODULE_PATH_BASE64=([A-Za-z0-9+/=]*)\r?$')
                if ($moduleMatch.Success) { $case.reconstructed_module_path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($moduleMatch.Groups[1].Value)) }
                $after=Profile-State $variant.profile
                $case.profile_after=$after
                $case.profile_unchanged=($before|ConvertTo-Json -Depth 10 -Compress) -ceq ($after|ConvertTo-Json -Depth 10 -Compress)
                if (-not $case.profile_unchanged) { throw 'Personal profile changed' }
                $case.query_succeeded=($run.ExitCode -eq 0 -and -not $run.TimedOut)
                if ($case.query_succeeded) {
                    if (-not $case.query_entered -or -not $case.query_finished) { throw 'Successful query omitted progress markers' }
                    if ($variant.query -ceq 'statements') { $observed=$run.Stdout|ConvertFrom-Json -Depth 10 }
                    else {
                        $lines=$run.Stdout.Replace("`r`n","`n").Split([char]10)
                        if ($lines.Count -ne $fields.Count+2 -or $lines[0] -cne 'TIRITH_FIELDS_V1' -or $lines[-1] -cne '') { throw 'Fixed field wire framing differs' }
                        $values=[ordered]@{}; $index=1
                        foreach ($key in $fields.Keys) {
                            if ($lines[$index] -cnotmatch '^[A-Za-z0-9+/=]*$') { throw 'Fixed field wire encoding differs' }
                            $values[$key]=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($lines[$index])); $index++
                        }
                        $observed=[pscustomobject]$values
                    }
                    if ($observed.host_name -cne 'ConsoleHost' -or $observed.profile -cne $variant.profile -or
                        $observed.current_user_current_host -cne $variant.profile -or
                        $observed.executable -ine $pin.path) { throw 'Query returned an unexpected native target' }
                    $case.observed=$observed
                }
                $afterPin=Get-CiFilePin $pin.path
                if ($afterPin.sha256 -cne $pin.sha256 -or $afterPin.size -ne $pin.size) { throw 'Native executable changed' }
                Write-CiJson (Join-Path $EvidenceDirectory 'report.json') $report
    }
    if ($report.cases.Count -ne 4) { throw 'Diagnostic matrix incomplete' }
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
