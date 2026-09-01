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
Test-RequiredPath (Join-Path $ProjectRoot "build\package_root\bin\appm.exe") "Rust CLI binary" -Required

# The authentication runtime is built by install_build_deps.ps1 into the same
# prepared-runtime prefix as the other Windows packaging dependencies. Keep it
# in the main package so the protected System App is self-contained.
$DexSource = "C:\local\bin\dex.exe"
$DexDestination = Join-Path $ProjectRoot "build\package_root\bin\dex.exe"
Test-RequiredPath $DexSource "Dex server binary" -Required
Copy-Item $DexSource $DexDestination -Force

Write-Host "Building NSIS installer..."
& $NSISExe $NSISScript
if ($LASTEXITCODE -ne 0) { throw "NSIS build failed with exit code $LASTEXITCODE" }
Write-Host "Installer package created successfully."
