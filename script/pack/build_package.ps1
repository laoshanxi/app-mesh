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
# Package root
# -----------------------------------------------------------------------------
$PackageRoot = if ($env:CMAKE_INSTALL_PREFIX) {
    $env:CMAKE_INSTALL_PREFIX
}
else {
    Join-Path $ProjectRoot "build\package_root"
}

# -----------------------------------------------------------------------------
# SSL certificate generation
# -----------------------------------------------------------------------------
$SSLDir = Join-Path $PackageRoot "ssl"
$SSLScript = Join-Path $SSLDir "generate_ssl_cert.ps1"
Test-RequiredPath $SSLScript "SSL generation script" -Required
Write-Host "Generating SSL certificates..."

Push-Location $SSLDir
try {
    & $SSLScript
}
catch {
    Write-Warning "SSL certificate generation failed: $($_.Exception.Message)"
}
finally {
    Pop-Location
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
