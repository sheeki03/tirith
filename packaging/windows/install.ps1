# tirith Windows installer
# Downloads and installs the latest tirith release

$ErrorActionPreference = 'Stop'

$installDir = "$env:LOCALAPPDATA\tirith\bin"
$profileLine = "Invoke-Expression (& `"$installDir\tirith.exe`" init --shell powershell)"

Write-Host "Installing tirith to $installDir..."

# Create install directory
if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Download latest release
$repo = "sheeki03/tirith"
$releaseUrl = "https://api.github.com/repos/$repo/releases/latest"
$release = Invoke-RestMethod -Uri $releaseUrl
$asset = $release.assets | Where-Object { $_.name -like "*Windows*" } | Select-Object -First 1
$checksums = $release.assets | Where-Object { $_.name -eq "checksums.txt" } | Select-Object -First 1

if (!$asset) {
    Write-Error "Could not find Windows release asset"
    exit 1
}

$zipPath = "$env:TEMP\tirith.zip"
$checksumsPath = "$env:TEMP\tirith-checksums.txt"

if (!$checksums) {
    Write-Error "Could not find checksums.txt asset"
    exit 1
}

Write-Host "Downloading $($asset.name)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath

# Download checksums and verify SHA256
Write-Host "Downloading checksums.txt..."
Invoke-WebRequest -Uri $checksums.browser_download_url -OutFile $checksumsPath

$checksumLine = Select-String -Path $checksumsPath -Pattern ("\s+" + [regex]::Escape($asset.name) + "$") | Select-Object -First 1
if (!$checksumLine) {
    Write-Error "No checksum entry found for $($asset.name)"
    exit 1
}

$expected = ($checksumLine.Line -split '\s+')[0].ToLower()
$actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()

if ($actual -ne $expected) {
    Write-Error "Checksum verification failed"
    exit 1
}

# Extract
Write-Host "Extracting..."
Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
Remove-Item $zipPath
Remove-Item $checksumsPath

# Add to PATH if not already there
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
    Write-Host "Added $installDir to PATH"
}

Write-Host ""
Write-Host "tirith installed successfully!"
Write-Host ""
Write-Host "Activate tirith by adding to your PowerShell profile (`$PROFILE):"
Write-Host "  $profileLine"
Write-Host ""
Write-Host "Then restart your terminal."
Write-Host ""
Write-Host "Verify: tirith doctor"
