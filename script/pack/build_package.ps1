# script\pack\build_package.ps1

# Package application for Windows
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $ProjectRoot

function Test-RequiredPath {
    param (
        [Parameter(Mandatory)]
        [string] $Path,
        [string] $Description = "Path",
        [switch] $Required
    )
    if (Test-Path $Path) { return $true }
    $msg = "$Description not found: $Path"
    if ($Required) { throw $msg }
    Write-Warning $msg
    return $false
}

# -----------------------------------------------------------------------------
# Build NSIS installer
# -----------------------------------------------------------------------------
$NSISExe = "C:\Program Files (x86)\NSIS\makensis.exe"
$NSISScript = Join-Path $ProjectRoot "script\pack\installer.nsi"

Test-RequiredPath $NSISExe    "NSIS executable" -Required
Test-RequiredPath $NSISScript "NSIS script"     -Required

Write-Host "Building NSIS installer..."
& $NSISExe $NSISScript
Write-Host "Installer package created successfully."
