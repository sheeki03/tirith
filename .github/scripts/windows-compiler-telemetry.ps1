# CI-only, temporary Visual Studio compiler telemetry policy. No product code.
function New-CiCompilerTelemetryScope([string]$Phase) {
    return [pscustomobject]@{
        States = [Collections.Generic.List[object]]::new()
        Evidence = [ordered]@{
            phase = $Phase; applied = $false; restored = $false; settings = @(); errors = @()
            sources = @(
                'https://learn.microsoft.com/en-us/visualstudio/ide/visual-studio-experience-improvement-program#registry-settings',
                'https://github.com/microsoft/BuildXL/blob/main/Public/Sdk/Experimental/Msvc/VisualCpp/visualCpp.dsc'
            )
        }
    }
}

function Assert-CiCompilerTelemetryHost {
    if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
        throw 'Compiler telemetry policy is restricted to disposable GitHub-hosted Windows jobs'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Compiler telemetry policy requires the existing hosted CI administrator token'
    }
}

function Set-CiCompilerTelemetryOptOut($Scope) {
    Assert-CiCompilerTelemetryHost
    if ($Scope.States.Count -ne 0) { throw 'Compiler telemetry scope must be fresh' }
    $path = 'Software\Policies\Microsoft\VisualStudio\SQM'
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        $key = $null
        try {
            $missingKeys = [Collections.Generic.List[string]]::new()
            $prefix = ''
            foreach ($part in $path.Split('\')) {
                $prefix = if ($prefix.Length -eq 0) { $part } else { $prefix + '\' + $part }
                $probe = $base.OpenSubKey($prefix, $false)
                if ($null -eq $probe) { $missingKeys.Add($prefix) } else { $probe.Dispose() }
            }
            $key = $base.OpenSubKey($path, $true)
            $keyExisted = $null -ne $key
            $missing = [object]::new()
            $previous = $missing
            $valueExisted = $false
            $kind = $null
            if ($keyExisted) {
                try { $kind = $key.GetValueKind('OptIn'); $valueExisted = $true }
                catch [IO.IOException] {
                    if (($_.Exception.HResult -band 0xffff) -ne 2) { throw } # ERROR_FILE_NOT_FOUND
                }
                if ($valueExisted) {
                    if ($kind -notin @([Microsoft.Win32.RegistryValueKind]::DWord, [Microsoft.Win32.RegistryValueKind]::QWord,
                        [Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString,
                        [Microsoft.Win32.RegistryValueKind]::Binary, [Microsoft.Win32.RegistryValueKind]::MultiString)) {
                        throw 'Unsupported prior compiler telemetry value type; registry left unchanged'
                    }
                    $previous = $key.GetValue('OptIn', $missing, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if ($null -eq $previous -or [object]::ReferenceEquals($previous, $missing)) {
                        throw 'Prior compiler telemetry value could not be retained; registry left unchanged'
                    }
                }
            }
            # Preserve the exact object/type for restoration, but never retain
            # arbitrary prior registry contents in the public evidence report.
            $state = [pscustomobject]@{
                View = $view; Path = $path; KeyExisted = $keyExisted; ValueExisted = $valueExisted
                Previous = $previous; Kind = $kind; MissingKeys = $missingKeys
                Evidence = [ordered]@{
                    hive = 'LocalMachine'; view = $view.ToString(); key = $path; value_name = 'OptIn'
                    prior_key_existed = $keyExisted; prior_value_existed = $valueExisted
                    prior_kind = if ($valueExisted) { $kind.ToString() } else { $null }
                    readback_kind = $null; readback_value = $null; restored = $false
                }
            }
            # Register rollback before either key creation or value mutation.
            $Scope.States.Add($state)
            $Scope.Evidence.settings += $state.Evidence
            if ($null -eq $key) { $key = $base.CreateSubKey($path, $true) }
            $key.SetValue('OptIn', [int]0, [Microsoft.Win32.RegistryValueKind]::DWord)
            $actualKind = $key.GetValueKind('OptIn')
            $actual = $key.GetValue('OptIn', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($actualKind -ne [Microsoft.Win32.RegistryValueKind]::DWord -or $actual -isnot [int] -or $actual -ne 0) {
                throw 'Compiler telemetry policy readback did not confirm DWORD zero'
            }
            $state.Evidence.readback_kind = 'DWord'
            $state.Evidence.readback_value = 0
        } finally {
            if ($null -ne $key) { $key.Dispose() }
            $base.Dispose()
        }
    }
    $Scope.Evidence.applied = $true
}

function Restore-CiCompilerTelemetryScope($Scope) {
    Assert-CiCompilerTelemetryHost
    $failures = [Collections.Generic.List[string]]::new()
    # Registry views can alias the same policy key. Reverse-order restoration
    # therefore also restores the original value when both views are shared.
    for ($index = $Scope.States.Count - 1; $index -ge 0; $index--) {
        $state = $Scope.States[$index]
        $base = $null
        $key = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $state.View)
            $key = $base.OpenSubKey($state.Path, $true)
            if ($null -eq $key -and $state.KeyExisted) { $key = $base.CreateSubKey($state.Path, $true) }
            if ($null -ne $key) {
                if ($state.ValueExisted) { $key.SetValue('OptIn', $state.Previous, $state.Kind) }
                else { $key.DeleteValue('OptIn', $false) }
                $missing = [object]::new()
                $actual = $key.GetValue('OptIn', $missing, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($state.ValueExisted) {
                    if ($key.GetValueKind('OptIn') -ne $state.Kind -or
                        -not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($state.Previous, $actual)) {
                        throw 'Original compiler telemetry value/type was not restored'
                    }
                } elseif (-not [object]::ReferenceEquals($actual, $missing)) {
                    throw 'Previously absent compiler telemetry value was not removed'
                }
                $key.Dispose(); $key = $null
            } elseif ($state.ValueExisted) { throw 'Original compiler telemetry key is missing' }
            # Remove only keys this scope created, deepest first, and only if
            # they are still empty. Never recursively delete registry content.
            for ($at = $state.MissingKeys.Count - 1; $at -ge 0; $at--) {
                $created = $state.MissingKeys[$at]
                $key = $base.OpenSubKey($created, $true)
                if ($null -eq $key) { continue }
                if ($key.ValueCount -ne 0 -or $key.SubKeyCount -ne 0) { throw 'New compiler telemetry key is no longer empty' }
                $key.Dispose(); $key = $null
                $base.DeleteSubKey($created, $false)
            }
            $key = $base.OpenSubKey($state.Path, $false)
            if (($null -ne $key) -ne $state.KeyExisted) { throw 'Original compiler telemetry key existence was not restored' }
            $state.Evidence.restored = $true
        } catch {
            $message = $_.Exception.Message
            if ($message.Length -gt 256) { $message = $message.Substring(0, 256) }
            $failures.Add($state.View.ToString() + ': ' + $message)
        } finally {
            if ($null -ne $key) { $key.Dispose() }
            if ($null -ne $base) { $base.Dispose() }
        }
    }
    $Scope.Evidence.restored = $failures.Count -eq 0
    $Scope.Evidence.errors = @($failures.ToArray())
    if ($failures.Count -gt 0) { throw ('Compiler telemetry policy restoration failed: ' + ($failures -join '; ')) }
}
