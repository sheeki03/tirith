# tirith PowerShell hook
# Overrides Enter key via PSReadLine to check commands before execution.
# Overrides Ctrl+V to check pasted content.

# Guard against double-loading
if ($global:_TIRITH_PS_LOADED) { return }
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

    if ($rc -eq 1) {
        # Block: show what was blocked, then warning, revert line
        Write-Host "command> $line"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    } elseif ($rc -eq 2) {
        # Warn: show warning then execute
        Write-Host "command> $line"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    } else {
        # Allow: execute normally
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

    if ($rc -eq 1) {
        # Block: show what was pasted, then warning, discard paste
        Write-Host "paste> $pasted"
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
        return
    } elseif ($rc -eq 2) {
        # Warn: show warning, keep paste
        if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output }
    }

    # Allow (0) or Warn (2): insert pasted content
    [Microsoft.PowerShell.PSConsoleReadLine]::Insert($pasted)
}
