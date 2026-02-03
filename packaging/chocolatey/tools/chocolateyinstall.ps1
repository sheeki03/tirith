$ErrorActionPreference = 'Stop'

$packageName = 'tirith'
$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

# Version and checksum templated by CI
$version = '0.1.3'
$checksum = 'PLACEHOLDER'

$url = "https://github.com/sheeki03/tirith/releases/download/v$version/tirith-x86_64-pc-windows-msvc.zip"

$packageArgs = @{
  packageName    = $packageName
  unzipLocation  = $toolsDir
  url64bit       = $url
  checksum64     = $checksum
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

# Add to PATH via shim (Chocolatey handles this automatically for .exe in tools/)
