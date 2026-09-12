# tirith Windows installer
# Downloads and installs the latest tirith release

$ErrorActionPreference = 'Stop'

function Get-TirithWindowsReleaseAsset {
    param($Release)
    $assetName = 'tirith-x86_64-pc-windows-msvc.zip'
    $selectedAssets = @($Release.assets | Where-Object { $_.name -ceq $assetName })
    if ($selectedAssets.Count -ne 1) {
        throw "Expected exactly one $assetName release asset; found $($selectedAssets.Count)"
    }
    return $selectedAssets[0]
}

function Get-TirithReleaseCertificateIdentity {
    param([string]$Tag)
    if ($Tag -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
        throw 'The release tag is not a Tirith version'
    }
    return "https://github.com/sheeki03/tirith/.github/workflows/release.yml@refs/tags/$Tag"
}

if ($env:TIRITH_INSTALL_PS_LIB -eq '1') {
    return
}

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
$asset = Get-TirithWindowsReleaseAsset $release
$certificateIdentity = Get-TirithReleaseCertificateIdentity $release.tag_name
$checksums = $release.assets | Where-Object { $_.name -eq "checksums.txt" } | Select-Object -First 1
$checksumsSig = $release.assets | Where-Object { $_.name -eq "checksums.txt.sig" } | Select-Object -First 1
$checksumsPem = $release.assets | Where-Object { $_.name -eq "checksums.txt.pem" } | Select-Object -First 1

$zipPath = "$env:TEMP\tirith.zip"
$checksumsPath = "$env:TEMP\tirith-checksums.txt"
$sigPath = "$env:TEMP\tirith-checksums.txt.sig"
$pemPath = "$env:TEMP\tirith-checksums.txt.pem"

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

# Verify the cosign signature over checksums.txt. This is MANDATORY by default
# (fail-closed): a missing cosign, a missing signature/certificate asset, or a
# failed verification aborts the install. Set $env:TIRITH_ALLOW_UNSIGNED = "1"
# to fall back to checksum-only verification with a warning. Uses the SAME
# pinned Sigstore identity and OIDC issuer as the Unix installer.
$allowUnsigned = ($env:TIRITH_ALLOW_UNSIGNED -eq "1")
$cosign = Get-Command cosign -ErrorAction SilentlyContinue

if (!$cosign) {
    if ($allowUnsigned) {
        Write-Warning "cosign not found - skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
    } else {
        Write-Error "cosign is required to verify the release signature but was not found. Install cosign (https://github.com/sigstore/cosign), or set `$env:TIRITH_ALLOW_UNSIGNED = '1' to install with checksum-only verification (NOT recommended)."
        exit 1
    }
} elseif (!$checksumsSig -or !$checksumsPem) {
    if ($allowUnsigned) {
        Write-Warning "release signature/certificate not published - skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
    } else {
        Write-Error "the release did not publish a cosign signature (checksums.txt.sig / .pem). Set `$env:TIRITH_ALLOW_UNSIGNED = '1' to install with checksum-only verification (NOT recommended)."
        exit 1
    }
} else {
    Write-Host "Downloading checksums.txt.sig and checksums.txt.pem..."
    # A DOWNLOAD failure is "signature not available": fatal by default, but it
    # may fall back to checksum-only under the opt-out. $ErrorActionPreference is
    # 'Stop', so wrap the fetch to keep the fallback reachable.
    $sigDownloaded = $true
    try {
        Invoke-WebRequest -Uri $checksumsSig.browser_download_url -OutFile $sigPath
        Invoke-WebRequest -Uri $checksumsPem.browser_download_url -OutFile $pemPath
    } catch {
        if (-not $allowUnsigned) {
            Write-Error "could not download the release signature/certificate (checksums.txt.sig / .pem). The download failed, or the release is unsigned. Set `$env:TIRITH_ALLOW_UNSIGNED = '1' to install with checksum-only verification (NOT recommended)."
            exit 1
        }
        Write-Warning "could not download the release signature/certificate - skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
        $sigDownloaded = $false
    }

    if ($sigDownloaded) {
        Write-Host "Verifying checksums signature with cosign..."
        & cosign verify-blob `
            --signature $sigPath `
            --certificate $pemPath `
            --certificate-identity $certificateIdentity `
            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' `
            $checksumsPath
        if ($LASTEXITCODE -ne 0) {
            # A FAILED verification is always fatal, even under TIRITH_ALLOW_UNSIGNED:
            # a present-but-bad signature means tampering, not a missing-tool fallback.
            Write-Error "cosign verification failed - the release signature did NOT verify. Do not trust these artifacts."
            exit 1
        }
        Remove-Item $sigPath -ErrorAction SilentlyContinue
        Remove-Item $pemPath -ErrorAction SilentlyContinue
    }
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
