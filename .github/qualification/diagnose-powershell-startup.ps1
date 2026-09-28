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
    'crates/tirith/src/cli/shell_target.rs'='abeb82b27c88715fdb2b26dedb3925805074eef08589fafd6c03b609bbc15a34'
    'crates/tirith-core/src/trusted_child/windows.rs'='b612f2703b7721d509d058e0fa762599886b8352b99ccb63afc6dda63c635584'
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
    schema_version=1; status='refused'; scope='powershell_ancestor_command_line_differential_only';
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
    $source=[IO.File]::ReadAllText((Join-Path $Workspace 'crates/tirith/src/cli/shell_target.rs'))
    $match=[regex]::Match($source, '(?m)^    let script = format!\(("[^\r\n]+")\);$')
    if (-not $match.Success) { throw 'Missing exact native command-line query' }
    $template=($match.Groups[1].Value | ConvertFrom-Json).Replace('{{','{').Replace('}}','}')
    $query=$template.Replace('{pid}',[string]$PID)
    if ($query.Contains('{pid}') -or -not $query.Contains("ProcessId = $PID")) { throw 'Query PID construction differs' }
    $report.queried_own_controller_pid=$PID
    $report.raw_command_line_retained=$false
    $report.stdout_identity_unit='UTF-8 re-encoding of captured command-line text'
    $report.cold_start_claim=$false
    $report.arm_order='serial; earlier queries may warm operating-system services'
    $queries=@{
        exact=$query
        staged="[Console]::Error.WriteLine('TIRITH_QUERY_ENTERED');"+
          $query.Replace(';Import-Module ',";[Console]::Error.WriteLine('TIRITH_IMPORT_BEGIN');Import-Module ").Replace(';'+ '$p=CimCmdlets',";[Console]::Error.WriteLine('TIRITH_IMPORT_END');"+'$p=CimCmdlets').Replace(';if($null',";[Console]::Error.WriteLine('TIRITH_CIM_RETURNED');if("+'$null')+
          ";[Console]::Error.WriteLine('TIRITH_QUERY_FINISHED')"
        wmi='$PSModuleAutoloadingPreference=''None'';$ErrorActionPreference=''Stop'';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);'+
          '$p=[wmi]"Win32_Process.Handle='''+[string]$PID+'''";$p.Get();if($null -eq $p -or [uint32]$p.ProcessId -ne '+[string]$PID+
          '){throw ''Observed process unavailable''};[Console]::Out.Write($p.CommandLine)'
    }
    $documents=[Environment]::GetFolderPath('MyDocuments')
    $report.system_windows_directory=$systemWindowsDirectory
    $legacy=Join-Path $systemWindowsDirectory 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $modern=Join-Path $PSHOME 'pwsh.exe'
    $variants=@(
        @{name='powershell-exact-2'; path=$legacy; family='powershell'; query='exact'; seconds=2},
        @{name='powershell-exact-20'; path=$legacy; family='powershell'; query='exact'; seconds=20},
        @{name='powershell-staged-20'; path=$legacy; family='powershell'; query='staged'; seconds=20},
        @{name='powershell-wmi-2'; path=$legacy; family='powershell'; query='wmi'; seconds=2},
        @{name='powershell-wmi-20'; path=$legacy; family='powershell'; query='wmi'; seconds=20},
        @{name='pwsh-exact-2'; path=$modern; family='pwsh'; query='exact'; seconds=2}
    )
    foreach ($variant in $variants) {
        $pin=Get-CiFilePin $variant.path
        $leases.Add((Open-CiPinnedFile $pin))
        if ($pin.path -notmatch '^[A-Za-z]:\\' -or $pin.size -gt 268435456) { throw 'Ordinary DOS executable path required' }
        $query=$queries[$variant.query]
        $case=[ordered]@{name=$variant.name; shell=$variant.family; native_executable=$pin; query_kind=$variant.query; deadline_seconds=$variant.seconds; process=$null}
        $report.cases += $case
        $dir=Join-Path $EvidenceDirectory $variant.name
        New-Item -ItemType Directory -Path $dir | Out-Null
        $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        $ambient=[Environment]::GetEnvironmentVariables('Process')
        foreach ($key in $ambient.Keys) { $environment.Add([string]$key,[NullString]::Value) }
        $environment['SystemRoot']=$systemWindowsDirectory
        foreach ($key in $ambient.Keys) {
            if ([string]$key -ine 'SystemRoot' -and $null -ne $environment[[string]$key]) { throw 'Ambient variable survived clearing' }
        }
        $surviving=@($environment.Keys | Where-Object {$null -ne $environment[$_]})
        if ($surviving.Count -ne 1 -or $surviving[0] -ine 'SystemRoot' -or $environment['SystemRoot'] -cne $systemWindowsDirectory) { throw 'Finite environment differs' }
        $case.environment_names=$surviving
        $case.environment_exactly_admitted=$true
        $profile=if ($variant.family -ceq 'powershell') {Join-Path $documents 'WindowsPowerShell/Microsoft.PowerShell_profile.ps1'} else {Join-Path $documents 'PowerShell/Microsoft.PowerShell_profile.ps1'}
        $before=Profile-State $profile
        $case.profile_before=$before
        $watch=[Diagnostics.Stopwatch]::StartNew()
        $run=[TirithCi.ProcessRunner]::Run($pin.path,@('-NoLogo','-NoProfile','-NonInteractive','-Command',$query),[IO.Path]::GetDirectoryName($pin.path),$environment,$variant.seconds,65536)
        $watch.Stop()
        $case.elapsed_ms=$watch.Elapsed.TotalMilliseconds
        $raw=[Text.Encoding]::UTF8.GetBytes($run.Stdout)
        $case.stdout_bytes=$raw.Length
        $case.stdout_sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
        # Never write a process command line to the evidence logs.
        $run.Stdout='[command line omitted; original length and SHA-256 in report]'
        $case.process=Save-CiProcessResult $dir 'query' $run
        Assert-DiagnosticCleanup $run
        $case.progress_markers=@([regex]::Matches($run.Stderr,'(?m)^TIRITH_[A-Z_]+\r?$') | ForEach-Object {$_.Value.TrimEnd([char]13)})
        $after=Profile-State $profile
        $case.profile_after=$after
        $case.profile_unchanged=($before|ConvertTo-Json -Depth 10 -Compress) -ceq ($after|ConvertTo-Json -Depth 10 -Compress)
        if (-not $case.profile_unchanged) { throw 'Personal profile changed' }
        $case.query_succeeded=($run.ExitCode -eq 0 -and -not $run.TimedOut -and $raw.Length -gt 0)
        $afterPin=Get-CiFilePin $pin.path
        if ($afterPin.sha256 -cne $pin.sha256 -or $afterPin.size -ne $pin.size) { throw 'Native executable changed' }
        Write-CiJson (Join-Path $EvidenceDirectory 'report.json') $report
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
if ($report.status -cne 'diagnostic_complete_not_product_qualification') { throw 'Command-line diagnostic incomplete; original evidence retained' }
