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
        return  # Set in this session — genuine double-source guard
    }
}
$global:_TIRITH_PS_LOADED = $true

# Check for PSReadLine
$psrlModule = Get-Module PSReadLine -ErrorAction SilentlyContinue
if (-not $psrlModule) {
    Write-Host "tirith: PSReadLine not found, hooks disabled. Install PSReadLine for shell protection." -ForegroundColor Yellow
    return
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

    # Run tirith check, use temp file to prevent output leakage
    $tmpfile = [System.IO.Path]::GetTempFileName()
    & tirith check --non-interactive --shell powershell -- $line > $tmpfile 2>&1
    $rc = $LASTEXITCODE
    $output = Get-Content $tmpfile -Raw -ErrorAction SilentlyContinue
    Remove-Item $tmpfile -Force -ErrorAction SilentlyContinue

    if ($rc -eq 0) {
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    } elseif ($rc -eq 2) {
        Write-Host "command> $line"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    } elseif ($rc -eq 1) {
        # Block: tirith intentionally blocked
        Write-Host "command> $line"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    } else {
        # Unexpected rc: warn + execute (fail-open to avoid terminal breakage)
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        Write-Host "tirith: unexpected exit code $rc — running unprotected"
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    }
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
        if ($rc -ne 1) { Write-Host "tirith: unexpected exit code $rc — paste blocked for safety" }
        return
    }

    [Microsoft.PowerShell.PSConsoleReadLine]::Insert($pasted)
}
