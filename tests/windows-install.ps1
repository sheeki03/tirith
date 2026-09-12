$ErrorActionPreference = 'Stop'
$previousLibraryMode = $env:TIRITH_INSTALL_PS_LIB
try {
    $env:TIRITH_INSTALL_PS_LIB = '1'
    . "$PSScriptRoot/../packaging/windows/install.ps1"
} finally {
    $env:TIRITH_INSTALL_PS_LIB = $previousLibraryMode
}

$asset = [pscustomobject]@{
    name = 'tirith-x86_64-pc-windows-msvc.zip'
    browser_download_url = 'https://example.invalid/windows.zip'
}
$release = [pscustomobject]@{
    tag_name = 'v0.4.2'
    assets = @([pscustomobject]@{ name = 'Windows-unrelated.zip' }, $asset)
}
$selected = Get-TirithWindowsReleaseAsset $release
if ($selected.browser_download_url -ne $asset.browser_download_url) {
    throw 'Canonical Windows archive was not selected'
}
foreach ($assetCount in @(0, 2)) {
    $fixtureAssets = @()
    if ($assetCount -eq 2) {
        $fixtureAssets = @($asset, $asset)
    }
    $rejected = $false
    try {
        Get-TirithWindowsReleaseAsset ([pscustomobject]@{ assets = $fixtureAssets }) | Out-Null
    } catch {
        $rejected = $true
    }
    if (!$rejected) {
        throw 'Missing or duplicate Windows assets were accepted'
    }
}
$identity = Get-TirithReleaseCertificateIdentity 'v0.4.2'
if ($identity -cne 'https://github.com/sheeki03/tirith/.github/workflows/release.yml@refs/tags/v0.4.2') {
    throw 'Certificate identity is not bound to the selected release tag'
}
foreach ($tag in @('threatdb-2026-09-12', 'main', 'v0.4.2/../../main', '')) {
    $rejected = $false
    try {
        Get-TirithReleaseCertificateIdentity $tag | Out-Null
    } catch {
        $rejected = $true
    }
    if (!$rejected) {
        throw "Invalid release tag was accepted: $tag"
    }
}
Write-Output 'PASS: Windows installer resolves canonical assets and binds signature identity without installation or elevation'
