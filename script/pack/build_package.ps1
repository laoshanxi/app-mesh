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

$PackageDir = Join-Path $ProjectRoot "build\appmesh"
$BuildDir = Join-Path $ProjectRoot "build\gen\$BuildType"


# Prepare package directory
Remove-Item -Recurse -Force $PackageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path (Join-Path $PackageDir "bin") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PackageDir "ssl") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PackageDir "script") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PackageDir "apps") | Out-Null

# Copy build binaries
$BinDest = Join-Path $PackageDir "bin"
if (Test-Path $BuildDir) {
    Copy-Item -Path "build\gen\agent.exe" -Destination $BinDest -Force
    Copy-Item -Path "$BuildDir\*" -Destination $BinDest -Recurse -Force
    Copy-Item -Path (Join-Path $ProjectRoot "src\sdk\python\py_*.py") -Destination $BinDest -Force
    Remove-Item -Path "$BuildDir\*.pdb" -Force -ErrorAction SilentlyContinue
    Write-Host "Copied build output to $BinDest"
}
else {
    Write-Error "Binary directory $BuildDir not found"
    exit 1
}

# Generate SSL certs in ssl directory
$SSLDest = Join-Path $PackageDir "ssl"
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
Copy-Item -Path "src\daemon\rest\openapi.yaml", "script\pack\grafana_infinity.html" -Destination (Join-Path $PackageDir "script")
Copy-Item -Path "src\daemon\config.yaml", "src\daemon\security\security.yaml", "src\daemon\security\oauth2.yaml", "src\sdk\agent\pkg\cloud\consul.yaml" -Destination $PackageDir
Copy-Item -Path "script\apps\*.yaml" -Destination (Join-Path $PackageDir "apps")

# Patch: replace 'python3' with 'python' in all .yaml files
$AppYamlDir = (Join-Path $PackageDir "apps")
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
Copy-Item "$env:ChocolateyInstall\lib\nssm\tools\nssm.exe" "$BinDest"

$NSISScript = Join-Path $ProjectRoot "script\pack\installer.nsi"
$NSISExe = "C:\Program Files (x86)\NSIS\makensis.exe"
if (Test-Path $NSISScript) {
    & $NSISExe $NSISScript
    Write-Host "Install package created"
}
else {
    Write-Warning "NSIS not found or installer.nsi missing."
}

