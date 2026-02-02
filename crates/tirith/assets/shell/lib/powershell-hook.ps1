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

    # Run tirith check. Binary prints warnings/blocks directly to stderr.
    # No output capture: binary writes to stderr which is the terminal.
    & tirith check --shell powershell -- $line
    $rc = $LASTEXITCODE

    if ($rc -eq 1) {
        # Block: revert the line
        [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    } else {
        # Allow (0) or Warn (2): execute normally
        # Warn message already printed to stderr by the binary
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

    # Check with tirith paste
    $pasted | & tirith paste --shell powershell
    $rc = $LASTEXITCODE

    if ($rc -eq 1) {
        # Block: discard paste, warning already printed by binary
        return
    }

    # Allow (0) or Warn (2): insert pasted content
    [Microsoft.PowerShell.PSConsoleReadLine]::Insert($pasted)
}
