# tirith PowerShell hook
# Overrides Enter key via PSReadLine to check commands before execution.
# Overrides Ctrl+V to check pasted content.

# Guard against double-loading (session-local only).
# If inherited from environment (exported by attacker/parent), ignore it.
if ($global:_TIRITH_PS_LOADED) {
    if ([Environment]::GetEnvironmentVariable('_TIRITH_PS_LOADED')) {
        [Environment]::SetEnvironmentVariable('_TIRITH_PS_LOADED', $null)
        $global:_TIRITH_PS_LOADED = $false
        # Fall through to load fresh
    } else {
        return  # Set in this session - genuine double-source guard
    }
}
$global:_TIRITH_PS_LOADED = $true

# Session tracking: generate ID per session if not inherited
if (-not $env:TIRITH_SESSION_ID) {
    $env:TIRITH_SESSION_ID = '{0:x}-{1:x}' -f $PID, [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

# Check for PSReadLine
$psrlModule = Get-Module PSReadLine -ErrorAction SilentlyContinue
if (-not $psrlModule) {
    Write-Host "tirith: PSReadLine not found, hooks disabled. Install PSReadLine for shell protection." -ForegroundColor Yellow
    return
}

# --- Approval workflow helpers (ADR-7) ---

function _tirith_parse_approval {
    param($FilePath)
    $script:_tirith_ap_required = "no"
    $script:_tirith_ap_timeout = 0
    $script:_tirith_ap_fallback = "block"
    $script:_tirith_ap_rule = ""
    $script:_tirith_ap_desc = ""

    if (-not (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
        [Console]::Error.WriteLine("tirith: warning: approval file missing or unreadable, failing closed")
        Remove-Item $FilePath -Force -ErrorAction SilentlyContinue  # ADR-7: delete on all paths
        $script:_tirith_ap_required = "yes"
        $script:_tirith_ap_fallback = "block"
        return $false
    }

    $validKeys = 0
    try {
        foreach ($rawLine in [System.IO.File]::ReadAllLines($FilePath)) {
            $parts = $rawLine -split '=', 2
            if ($parts.Count -ge 2) {
                switch ($parts[0]) {
                    "TIRITH_REQUIRES_APPROVAL" { $script:_tirith_ap_required = $parts[1]; $validKeys++ }
                    "TIRITH_APPROVAL_TIMEOUT" {
                        $parsed = 0
                        if ([int]::TryParse($parts[1], [ref]$parsed)) {
                            $script:_tirith_ap_timeout = $parsed
                        } else {
                            [Console]::Error.WriteLine("tirith: warning: invalid approval timeout '$($parts[1])', using 0")
                        }
                    }
                    "TIRITH_APPROVAL_FALLBACK" { $script:_tirith_ap_fallback = $parts[1] }
                    "TIRITH_APPROVAL_RULE" { $script:_tirith_ap_rule = $parts[1] }
                    "TIRITH_APPROVAL_DESCRIPTION" { $script:_tirith_ap_desc = $parts[1] }
                }
            }
        }
    } catch {
        [Console]::Error.WriteLine("tirith: warning: approval file read failed: $_")
        $script:_tirith_ap_required = "yes"
        $script:_tirith_ap_fallback = "block"
        $validKeys = 0
    }

    Remove-Item $FilePath -Force -ErrorAction SilentlyContinue

    if ($validKeys -eq 0) {
        [Console]::Error.WriteLine("tirith: warning: approval file corrupt, failing closed")
        $script:_tirith_ap_required = "yes"
        $script:_tirith_ap_fallback = "block"
        return $false
    }
    return $true
}

# Read a single line with timeout using Console.KeyAvailable polling.
# Returns the user's input, or empty string on timeout.
function _tirith_read_with_timeout {
    param([int]$TimeoutSecs, [string]$Prompt)
    Write-Host -NoNewline $Prompt
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSecs)
    $buffer = ""
    while ([DateTime]::UtcNow -lt $deadline) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter') { break }
            if ($key.Key -eq 'Backspace') {
                if ($buffer.Length -gt 0) {
                    $buffer = $buffer.Substring(0, $buffer.Length - 1)
                    Write-Host -NoNewline "`b `b"
                }
                continue
            }
            $buffer += $key.KeyChar
            Write-Host -NoNewline $key.KeyChar
        }
        Start-Sleep -Milliseconds 50
    }
    Write-Host ""  # newline after input
    return $buffer
}

# Override Enter key
Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
    $line = $null
    $cursor = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

    # Empty input: pass through
    if ([string]::IsNullOrWhiteSpace($line)) {
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        return
    }

    # Run tirith check with approval workflow (stdout=approval file path, stderr=human output)
    $errfile = [System.IO.Path]::GetTempFileName()
    $approvalPath = & tirith check --approval-check --non-interactive --interactive --shell powershell -- $line 2>$errfile
    $rc = $LASTEXITCODE
    $output = Get-Content $errfile -Raw -ErrorAction SilentlyContinue
    Remove-Item $errfile -Force -ErrorAction SilentlyContinue

    if ($rc -eq 0) {
        # Allow: no output
    } elseif ($rc -eq 2) {
        Write-Host "command> $line"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
    } elseif ($rc -eq 1) {
        Write-Host "command> $line"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
    } else {
        # Unexpected rc: warn + execute (fail-open to avoid terminal breakage)
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        Write-Host "tirith: unexpected exit code $rc - running unprotected"
        if (-not [string]::IsNullOrWhiteSpace($approvalPath)) {
            Remove-Item $approvalPath.Trim() -Force -ErrorAction SilentlyContinue
        }
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        return
    }

    # Approval workflow: runs for ALL exit codes (0, 1, 2).
    # For rc=1 (block), approval gives user a chance to override.
    if (-not [string]::IsNullOrWhiteSpace($approvalPath)) {
        _tirith_parse_approval $approvalPath.Trim()
        if ($script:_tirith_ap_required -eq "yes") {
            Write-Host "tirith: approval required for $($script:_tirith_ap_rule)"
            if (-not [string]::IsNullOrWhiteSpace($script:_tirith_ap_desc)) {
                Write-Host "  $($script:_tirith_ap_desc)"
            }
            if ($script:_tirith_ap_timeout -gt 0) {
                $response = _tirith_read_with_timeout -TimeoutSecs $script:_tirith_ap_timeout -Prompt "Approve? ($($script:_tirith_ap_timeout) sec timeout) [y/N] "
            } else {
                Write-Host -NoNewline "Approve? [y/N] "
                $response = Read-Host
            }
            if ($response -match '^[yY]') {
                # Approved: fall through to execute
            } else {
                switch ($script:_tirith_ap_fallback) {
                    "allow" {
                        Write-Host "tirith: approval not granted - fallback: allow"
                    }
                    "warn" {
                        Write-Host "tirith: approval not granted - fallback: warn"
                    }
                    default {
                        Write-Host "tirith: approval not granted - fallback: block"
                        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
                        return
                    }
                }
            }
        } elseif ($rc -eq 1) {
            # Approval not required but command was blocked: honor block
            [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
            return
        }
    } elseif ($rc -eq 1) {
        # No approval file: honor block
        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
        return
    }

    [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
}

# Override Ctrl+V for paste interception
Set-PSReadLineKeyHandler -Key Ctrl+v -ScriptBlock {
    # Get clipboard content
    $pasted = Get-Clipboard -ErrorAction SilentlyContinue

    if ([string]::IsNullOrEmpty($pasted)) {
        return
    }

    # Check with tirith paste, use temp file to prevent output leakage
    $tmpfile = [System.IO.Path]::GetTempFileName()
    $pasted | & tirith paste --shell powershell > $tmpfile 2>&1
    $rc = $LASTEXITCODE
    $output = Get-Content $tmpfile -Raw -ErrorAction SilentlyContinue
    Remove-Item $tmpfile -Force -ErrorAction SilentlyContinue

    if ($rc -eq 0) {
        # Allow: fall through to insert
    } elseif ($rc -eq 2) {
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        # Warn: fall through to insert
    } else {
        # Block or unexpected: discard paste
        Write-Host "paste> $pasted"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        if ($rc -ne 1) { Write-Host "tirith: unexpected exit code $rc - paste blocked for safety" }
        return
    }

    [Microsoft.PowerShell.PSConsoleReadLine]::Insert($pasted)
}
