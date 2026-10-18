<#
.SYNOPSIS
    Fetches development dependencies for OpenShield (currently WinDivert).

.DESCRIPTION
    Downloads the official WinDivert release archive from GitHub into
    third_party\windivert, verifies its SHA-256 against a pinned value,
    extracts it and checks the Authenticode signature of the x64 driver.

    The script installs nothing and changes no system settings. It does not
    need administrator rights.

    Antivirus products may block the archive (Microsoft Defender reports
    Misleading:Win32/Malgent!AMTB). See ADR-005 in docs\ARCHITECTURE.md.

.PARAMETER Force
    Re-download and re-extract even if WinDivert is already present.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\dev-setup.ps1
#>
# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$WinDivertVersion = '2.2.2'
$WinDivertAsset = "WinDivert-$WinDivertVersion-A.zip"
$WinDivertUrl = "https://github.com/basil00/WinDivert/releases/download/v$WinDivertVersion/$WinDivertAsset"
# SHA-256 of the official release asset, computed 2026-10-18 from the GitHub
# release over HTTPS (size 405137 bytes, matching the GitHub API).
$WinDivertSha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Dest = Join-Path $RepoRoot 'third_party\windivert'
$ZipPath = Join-Path $Dest $WinDivertAsset
$ExtractDir = Join-Path $Dest "WinDivert-$WinDivertVersion-A"
$DriverPath = Join-Path $ExtractDir 'x64\WinDivert64.sys'

function Write-AvHint {
    Write-Warning ('Your antivirus may have blocked the WinDivert archive. This is a known false ' +
        'positive for packet capture tools (see ADR-005 in docs\ARCHITECTURE.md). If you choose ' +
        'to proceed, allow this specific file in your antivirus and run the script again. ' +
        'Do not disable your antivirus.')
}

if ((Test-Path $DriverPath) -and -not $Force) {
    Write-Host "WinDivert $WinDivertVersion is already present in $ExtractDir (use -Force to refetch)."
    exit 0
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$TempZip = "$ZipPath.download"
Write-Host "Downloading $WinDivertUrl"
try {
    Invoke-WebRequest -Uri $WinDivertUrl -OutFile $TempZip -UseBasicParsing
} catch {
    Write-AvHint
    throw
}

try {
    $actual = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash
} catch {
    Write-AvHint
    throw
}
if ($actual -ne $WinDivertSha256) {
    Remove-Item -Force $TempZip
    throw "SHA-256 mismatch for ${WinDivertAsset}: expected $WinDivertSha256, got $actual"
}
Write-Host "SHA-256 verified: $actual"
Move-Item -Force -Path $TempZip -Destination $ZipPath

if (Test-Path $ExtractDir) {
    Remove-Item -Recurse -Force $ExtractDir
}
try {
    Expand-Archive -Path $ZipPath -DestinationPath $Dest -Force
} catch {
    Write-AvHint
    throw
}

if (-not (Test-Path $DriverPath)) {
    throw "Driver not found after extraction: $DriverPath"
}
$sig = Get-AuthenticodeSignature -FilePath $DriverPath
if ($sig.Status -ne 'Valid') {
    throw "WinDivert64.sys signature status is '$($sig.Status)', expected 'Valid'"
}
Write-Host "Driver signature: $($sig.Status), signer: $($sig.SignerCertificate.Subject)"
Write-Host "WinDivert $WinDivertVersion is ready in $ExtractDir"
