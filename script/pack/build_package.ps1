# PowerShell script to package the application for Windows
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Visual Studio build type
$BuildType = $env:BUILD_TYPE  # Options: Debug, Release, RelWithDebInfo, MinSizeRel
if (-not $BuildType) {
    $BuildType = "Release"  # fallback default
}
Write-Host "Detected Build Type: $BuildType"

# Resolve paths
$ProjectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
Set-Location -Path $ProjectRoot

$PackageRoot = Join-Path $ProjectRoot "build\package_root"
if (Test-Path "env:CMAKE_INSTALL_PREFIX") {
    $PackageRoot = $env:CMAKE_INSTALL_PREFIX
}

# Prepare package directory
New-Item -ItemType Directory -Path (Join-Path $PackageRoot "ssl") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PackageRoot "script") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PackageRoot "apps") | Out-Null

# Copy build binaries
$BinDest = Join-Path $PackageRoot "bin"
Copy-Item -Path (Join-Path $ProjectRoot "src\sdk\python\py_*.py") -Destination $BinDest -Force

# Generate SSL certs in ssl directory
$SSLDest = Join-Path $PackageRoot "ssl"
Copy-Item -Path (Join-Path $ProjectRoot "script\ssl\generate_ssl_cert.ps1") -Destination $SSLDest
Push-Location $SSLDest
try {
    & .\generate_ssl_cert.ps1
}
catch {
    Write-Error "Failed to generate SSL certificates: $_"
    Pop-Location
    exit 1
}
Pop-Location

# Copy scripts and configs
Copy-Item -Path "src\daemon\rest\index.html", "src\daemon\rest\openapi.yaml", "script\pack\grafana_infinity.html" -Destination (Join-Path $PackageRoot "script")
Copy-Item -Path "src\daemon\config.yaml", "src\daemon\security\security.yaml", "src\daemon\security\oauth2.yaml", "src\sdk\agent\pkg\cloud\consul.yaml" -Destination $PackageRoot
Copy-Item -Path "script\apps\*.yaml" -Destination (Join-Path $PackageRoot "apps")

# Patch: replace 'python3' with 'python' in all .yaml files
$AppYamlDir = (Join-Path $PackageRoot "apps")
if (Test-Path $AppYamlDir) {
    Get-ChildItem -Path (Join-Path $AppYamlDir '*.yaml') -File | ForEach-Object {
        $file = $_.FullName
        try {
            $content = Get-Content -Raw -Encoding UTF8 $file
            $new = [regex]::Replace($content, '\bpython3\b', 'python.exe')
            if ($new -ne $content) {
                Set-Content -Path $file -Value $new -Encoding UTF8
                Write-Host "Patched: $file"
            }
        }
        catch {
            Write-Warning "Failed to patch ${file}: $($_.Exception.Message)"
            Write-Host "Exception details: $($_ | Out-String)"
        }
    }
}
else {
    Write-Warning "Target path not found: $AppYamlDir"
}

# Optional: Create installer using NSIS
$nssmExe = "$env:ChocolateyInstall\lib\nssm\tools\nssm.exe"
Write-Host "Copy nssm.exe from $nssmExe to $BinDest"
Copy-Item -Path $nssmExe -Destination $BinDest -Force

$NSISScript = Join-Path $ProjectRoot "script\pack\installer.nsi"
$NSISExe = "C:\Program Files (x86)\NSIS\makensis.exe"
if (Test-Path $NSISScript) {
    & $NSISExe $NSISScript
    Write-Host "Install package created"
}
else {
    Write-Warning "NSIS not found or installer.nsi missing."
}

