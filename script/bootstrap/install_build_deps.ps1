#!/usr/bin/env powershell
################################################################################
## Windows MSVC Build Environment Setup Script for App-Mesh
## This script installs all dependencies needed to build the C++/Go application
################################################################################

# Ensure script runs with admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Set error handling and global variables
$ErrorActionPreference = "Stop"
# Set-PSDebug -Trace 1
$architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
    "ARM64" { "arm64" }
    "AMD64" { "amd64" }
    default { 
        Write-Warning "Unknown architecture: $env:PROCESSOR_ARCHITECTURE. Defaulting to amd64"
        "amd64" 
    }
}

$ROOTDIR = "$env:TEMP\appmesh-build-setup"
$SRC_DIR = (Get-Location).Path

Write-Host "App-Mesh Build Environment Setup" -ForegroundColor Green
Write-Host "Detected architecture: $architecture" -ForegroundColor Green
Write-Host "Working directory: $ROOTDIR" -ForegroundColor Green

################################################################################
# Helper Functions
################################################################################

function Initialize-BuildEnvironment {
    Write-Host "Initializing build environment..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $ROOTDIR | Out-Null
    Set-Location $ROOTDIR
}

function Save-File {
    param($url, $output)
    # Simple check: if the target file already exists, skip downloading to avoid redundancy
    if (Test-Path $output) {
        Write-Host "File $output already exists. Skipping download of $url." -ForegroundColor Green
        return
    }

    Write-Host "Downloading $url..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
        Write-Host "Successfully downloaded $output" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download $url`: $_"
        throw
    }
}

function Expand-File {
    param($archive, $destination)
    Write-Host "Extracting $archive..." -ForegroundColor Yellow
    try {
        Expand-Archive -Path $archive -DestinationPath $destination -Force
        Write-Host "Successfully extracted $archive" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to extract $archive`: $_"
        throw
    }
}

################################################################################
# Installation Functions
################################################################################

function Install-Chocolatey {
    Write-Host "Installing Chocolatey package manager..." -ForegroundColor Cyan
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        refreshenv
        Write-Host "Chocolatey installed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "Chocolatey is already installed" -ForegroundColor Green
    }
}

function Install-VisualStudioBuildTools {
    Write-Host "Installing Visual Studio Build Tools..." -ForegroundColor Cyan
    choco install -y visualstudio2022buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621"
    Write-Host "Visual Studio Build Tools installed successfully" -ForegroundColor Green
}

function Install-DevelopmentTools {
    Write-Host "Ensuring development tools (CMake, Git, Wget, 7zip, OpenSSL, NSIS, NSSM, MinGW) are installed..." -ForegroundColor Cyan

    # Map chocolatey package name -> command to test for
    $toolMap = @{
        'cmake'   = 'cmake'
        'git'     = 'git'
        'wget'    = 'wget'
        '7zip'    = '7z'
        'openssl' = 'openssl'
        'python3' = 'python'
        'nsis'    = 'makensis'
        'nssm'    = 'nssm'
        'ninja'   = 'ninja'
        'mingw'   = 'gcc'
    }

    # Ensure choco is available (Install-Chocolatey will set it up)
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Warning "Chocolatey not found. Installing Chocolatey first..."
        Install-Chocolatey
    }

    $toInstall = @()
    foreach ($pkg in $toolMap.Keys) {
        $cmd = $toolMap[$pkg]
        if (Get-Command $cmd -ErrorAction SilentlyContinue) {
            Write-Host ("Skipping {0}: command '{1}' already available" -f $pkg, $cmd) -ForegroundColor Green
        }
        else {
            $toInstall += $pkg
        }
    }

    if ($toInstall.Count -gt 0) {
        Write-Host "Installing missing packages: $($toInstall -join ', ')" -ForegroundColor Yellow
        # Pass package list to choco in one call to reduce overhead
        & choco install -y $toInstall
        refreshenv
    }
    else {
        Write-Host "All development tools already present; nothing to install." -ForegroundColor Green
    }
}

function Install-Vcpkg {
    Write-Host "Installing vcpkg package manager..." -ForegroundColor Cyan
    if (!(Test-Path "C:\vcpkg")) {
        git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
        C:\vcpkg\bootstrap-vcpkg.bat
        C:\vcpkg\vcpkg.exe integrate install
        Write-Host "vcpkg installed and integrated successfully" -ForegroundColor Green
    }
    else {
        Write-Host "vcpkg is already installed" -ForegroundColor Green
    }
    $env:VCPKG_ROOT = "C:\vcpkg"
}

function Install-VcpkgPackages {
    $packages = @(
        'openssl:x64-windows',
        'boost-atomic:x64-windows',
        'boost-algorithm:x64-windows',
        'boost-iostreams:x64-windows',
        'boost-system:x64-windows',
        'boost-filesystem:x64-windows',
        'boost-date-time:x64-windows',
        'boost-thread:x64-windows',
        'boost-regex:x64-windows',
        'boost-program-options:x64-windows',
        'boost-asio:x64-windows',
        'boost-process:x64-windows',
        'boost-interprocess:x64-windows',
        'boost-unordered:x64-windows',
        'boost-variant:x64-windows',
        'boost-serialization:x64-windows',
        'boost-lockfree:x64-windows',
        'drogon:x64-windows',
        # spdlog is intentionally NOT in this list: it is built from source
        # (pinned to v1.17.0, see Install-SpdlogFromSource) so should_log()
        # behaviour is identical across platforms.
        'yaml-cpp:x64-windows'
    )

    Write-Host "Installing packages: $($packages -join ', ')" -ForegroundColor Yellow
    & "C:\vcpkg\vcpkg.exe" install @packages --recurse --clean-after-build
    if ($LASTEXITCODE -eq 0) {
        Write-Host "All packages installed successfully." -ForegroundColor Green
    }
    else {
        Write-Host "Some packages failed to install. Check the log above." -ForegroundColor Red
    }
}

function Install-SpdlogFromSource {
    Write-Host "Installing spdlog from source (pinned to v1.17.0)..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force "spdlog-src" -ErrorAction Ignore
    git clone -b v1.17.0 --depth 1 https://github.com/gabime/spdlog.git spdlog-src
    Set-Location spdlog-src
    New-Item -ItemType Directory -Force -Path "build" | Out-Null
    Set-Location build
    cmake .. -G "Visual Studio 17 2022" -A x64 `
        -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
        -DCMAKE_INSTALL_PREFIX="C:/local" `
        -DSPDLOG_BUILD_SHARED=ON `
        -DSPDLOG_BUILD_EXAMPLES=OFF `
        -DSPDLOG_BUILD_TESTS=OFF
    cmake --build . --config Release --parallel
    cmake --install . --config Release
    Set-Location $ROOTDIR
}

function Install-HeaderOnlyLibraries {
    Write-Host "Installing header-only libraries..." -ForegroundColor Cyan

    # Message Pack
    Write-Host "Installing MessagePack..." -ForegroundColor Yellow
    git clone -b cpp_master --depth 1 https://github.com/msgpack/msgpack-c.git
    Set-Location msgpack-c
    cmake . -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_INSTALL_PREFIX="C:/local"
    cmake --install . --config Release
    Set-Location $ROOTDIR
    
    # Additional header-only libraries
    Write-Host "Installing additional header-only libraries..." -ForegroundColor Yellow
    
    # hashidsxx
    Remove-Item -Recurse -Force "hashidsxx" -ErrorAction Ignore
    git clone --depth=1 https://github.com/schoentoon/hashidsxx.git
    Copy-Item -Recurse "hashidsxx" "C:\local\include\" -Force
    
    # croncpp
    Remove-Item -Recurse -Force "croncpp" -ErrorAction Ignore
    git clone --depth=1 https://github.com/mariusbancila/croncpp.git
    Copy-Item "croncpp\include\croncpp.h" "C:\local\include\" -Force
    
    # wildcards
    Remove-Item -Recurse -Force "wildcards" -ErrorAction Ignore
    git clone --depth=1 https://github.com/laoshanxi/wildcards.git
    Copy-Item -Recurse "wildcards\single_include" "C:\local\include\wildcards" -Force

    # prometheus-cpp
    Remove-Item -Recurse -Force "prometheus-cpp" -ErrorAction Ignore
    git clone --depth=1 https://github.com/jupp0r/prometheus-cpp.git
    New-Item -ItemType Directory -Force -Path "C:\local\src\prometheus" | Out-Null
    Copy-Item -Recurse "prometheus-cpp\core\src\*" "C:\local\src\prometheus\" -Force
    Copy-Item -Recurse "prometheus-cpp\core\include\prometheus" "C:\local\include\" -Force

    # Create prometheus export header
    @"
#ifndef PROMETHEUS_CPP_CORE_EXPORT
#define PROMETHEUS_CPP_CORE_EXPORT
#endif
"@ | Out-File -FilePath "C:\local\include\prometheus\detail\core_export.h" -Encoding ascii
    
    # jwt-cpp
    git clone --depth=1 https://github.com/Thalhammer/jwt-cpp.git
    Copy-Item -Recurse "jwt-cpp\include\jwt-cpp" "C:\local\include\" -Force
    
    # Catch2
    git clone --depth=1 -b v2.x https://github.com/catchorg/Catch2.git
    Copy-Item "Catch2\single_include\catch2\catch.hpp" "C:\local\include\" -Force

    # concurrentqueue
    git clone --depth=1 https://github.com/cameron314/concurrentqueue.git
    Copy-Item -Recurse "concurrentqueue" "C:\local\include\" -Force

    # uriparser
    git clone --depth=1 https://github.com/uriparser/uriparser.git
    Set-Location "uriparser"
    New-Item -ItemType Directory -Force -Path "build" | Out-Null
    Set-Location "build"
    cmake .. -G "Visual Studio 17 2022" -A x64 -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_INSTALL_PREFIX="C:/local"
    cmake --build . --config Release
    cmake --install . --config Release
    Set-Location $ROOTDIR

    Write-Host "Header-only libraries installed successfully" -ForegroundColor Green
}

function Install-PythonPackages {
    param (
        [string]$PythonExe = "python"
    )

    Write-Host "Installing Python packages..." -ForegroundColor Cyan

    $packages = @(
        "pip",
        "setuptools",
        "requests",
        "urllib3",
        "wheel"
    )

    foreach ($pkg in $packages) {
        Write-Host "Installing $pkg..." -ForegroundColor Yellow
        try {
            & $PythonExe -m pip install --upgrade $pkg --quiet
            Write-Host "$pkg installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Failed to install $pkg : $_" -ForegroundColor Yellow
        }
    }

    Write-Host "Python packages installed successfully" -ForegroundColor Green

}

function Install-Go {
    Write-Host "Installing Go programming language..." -ForegroundColor Cyan
    
    $goVersion = "1.27.1"
    # keep a system Go that is newer than (or equal to) the pinned version
    $installedVer = $null
    if (Get-Command go -ErrorAction SilentlyContinue) {
        if ((go version) -match 'go(\d+\.\d+(\.\d+)?)') { $installedVer = $Matches[1] }
    }
    if ($installedVer -and ([version]$installedVer -ge [version]$goVersion)) {
        Write-Host "Go already installed: $(go version)" -ForegroundColor Green
        return
    }

    Remove-Item "go.zip" -Force -ErrorAction SilentlyContinue
    $goArch = if ($architecture -eq "arm64") { "arm64" } else { "amd64" }
    $goUrl = "https://go.dev/dl/go$goVersion.windows-$goArch.zip"
    Save-File $goUrl "go.zip"
    Expand-File "go.zip" "C:\"
    $env:PATH = "C:\go\bin;$env:PATH"
    [Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::Machine)
    Write-Host "Go installed successfully" -ForegroundColor Green
}

function Install-Rust {
    Write-Host "Installing Rust toolchain..." -ForegroundColor Cyan

    if (!(Get-Command rustup -ErrorAction SilentlyContinue)) {
        $rustupUrl = "https://win.rustup.rs/x86_64"
        Save-File $rustupUrl "rustup-init.exe"
        Start-Process -FilePath ".\rustup-init.exe" -ArgumentList "-y --default-toolchain stable" -Wait -NoNewWindow
        $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
        [Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::Machine)
    }
    rustup update stable
    Write-Host "Rust installed: $(rustc --version)" -ForegroundColor Green
}

function Install-GoTools {
    Write-Host "Installing Go tools (min binary size)..." -ForegroundColor Cyan

    $env:GOBIN = "C:\local\bin"
    $env:CGO_ENABLED = "0"

    New-Item -ItemType Directory -Force -Path $env:GOBIN | Out-Null

    go env -w GOPROXY="https://goproxy.cn,direct"
    go env -w GOBIN="$env:GOBIN"
    go env -w GO111MODULE=on

    $ldflags = "-s -w"
    $buildFlags = @("-trimpath", "-buildvcs=false")

    $goTools = @(
        'github.com/cloudflare/cfssl/cmd/cfssl@latest',
        'github.com/cloudflare/cfssl/cmd/cfssljson@latest'
    )

    foreach ($tool in $goTools) {
        Write-Host "Installing $tool (stripped)..." -ForegroundColor Yellow
        go install @buildFlags -ldflags="$ldflags" $tool
    }

    Write-Host "Go tools installed successfully (minimal size)" -ForegroundColor Green
}

function Install-Dex {
    Write-Host "Installing Dex OIDC server..." -ForegroundColor Cyan

    $env:GOBIN = "C:\local\bin"
    # CGO stays off so the binary has no mingw/C runtime dependency. The fork's
    # no-cgo build backs the SQLite storage with the pure-Go modernc.org/sqlite
    # driver, so identities and refresh tokens persist on disk like on Linux.
    $env:CGO_ENABLED = "0"

    New-Item -ItemType Directory -Force -Path $env:GOBIN | Out-Null

    $ldflags = "-s -w"
    $buildFlags = @("-trimpath", "-buildvcs=false")

    Write-Host "Cloning the project fork's appmesh branch..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force dex -ErrorAction SilentlyContinue
    # The appmesh branch carries the refresh-token rotation SQLite deadlock
    # fix, the upstream sync, and the pure-Go SQLite driver for CGO-free
    # builds. Keep off the fork's master: it is the head of the upstream
    # deadlock-fix PR and must stay clean.
    git clone --quiet --depth 1 -b appmesh https://github.com/laoshanxi/dex.git dex
    if ($LASTEXITCODE -ne 0) {
        throw "git clone failed for Dex"
    }

    try {
        Push-Location dex
        go build @buildFlags -ldflags="$ldflags" -o "$env:GOBIN\dex.exe" ./cmd/dex
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for Dex"
        }
        Pop-Location
        # Dex administration web UI (the fork's examples/example-app, a
        # separate Go module): packaged as dexuser and run as the dexuser
        # System App.
        Push-Location dex\examples
        go build @buildFlags -tags "netgo,osusergo" -ldflags="$ldflags" -o "$env:GOBIN\dexuser.exe" ./example-app
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for Dex example-app"
        }
    }
    finally {
        Pop-Location
        Remove-Item -Recurse -Force dex -ErrorAction SilentlyContinue
    }

    Write-Host "Dex installed successfully (minimal size)" -ForegroundColor Green
}

function Install-NsisPlugin {
    # https://nsis.sourceforge.io/EnVar_plug-in
    Write-Host "Installing NSIS EnVar plugin..." -ForegroundColor Cyan
    
    $pluginUrl = "https://nsis.sourceforge.io/mediawiki/images/7/7f/EnVar_plugin.zip"
    $downloadPath = "$env:TEMP\EnVar_plugin.zip" # Download to a temporary location
    $nsisPath = "C:\Program Files (x86)\NSIS" # CHANGE THIS IF YOUR NSIS PATH IS DIFFERENT
    
    Save-File $pluginUrl $downloadPath
    Expand-File $downloadPath $nsisPath
    
    # Optional: Clean up the downloaded zip file
    Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue
    
    Write-Host "EnVar plugin downloaded and extracted to $nsisPath" -ForegroundColor Green
}

function Set-EnvironmentVariables {
    Write-Host "Setting environment variables..." -ForegroundColor Cyan
    
    $newPaths = @(
        "C:\local\bin",
        "C:\go\bin",
        "C:\vcpkg\installed\x64-windows\bin"
    )
    
    # Get current PATH and split into array
    $currentPaths = $env:PATH -split ';' | Where-Object { $_ -and $_.Trim() }
    
    # Combine new and existing paths, remove duplicates, keep all (even if they don't exist yet)
    $allPaths = ($newPaths + $currentPaths) | ForEach-Object { $_.Trim() } | Select-Object -Unique | Where-Object { $_ }
    
    # Join back into PATH string
    $env:PATH = $allPaths -join ';'
    
    Write-Host "PATH: $env:PATH" -ForegroundColor Yellow
    
    try {
        [Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::Machine)
        [Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\vcpkg", [EnvironmentVariableTarget]::Machine)
        
        
        Write-Host "Environment variables set successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Error setting environment variables: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Remove-TempFiles {
    Write-Host "Cleaning up temporary files..." -ForegroundColor Cyan
    Set-Location $SRC_DIR
    Remove-Item -Recurse -Force $ROOTDIR -ErrorAction SilentlyContinue
    Write-Host "Temporary files cleaned up successfully" -ForegroundColor Green
}

function Show-Summary {
    Write-Host ""
    Write-Host "=== Build Environment Setup Complete ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "To build your project, use:" -ForegroundColor Yellow
    Write-Host "  Use Ninja  (MSVC dev shell): cmake -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows && cmake --build build --target pack --parallel" -ForegroundColor White
    Write-Host "  Use Visual Studio generator: cmake -S . -B build -G `"Visual Studio 17 2022`" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows && cmake --build build --config Release" -ForegroundColor White
    Write-Host ""
    Write-Host "Important paths:" -ForegroundColor Yellow
    Write-Host "  Libraries: C:\local\lib" -ForegroundColor White
    Write-Host "  Headers: C:\local\include" -ForegroundColor White
    Write-Host "  Binaries: C:\local\bin" -ForegroundColor White
    Write-Host "  vcpkg: C:\vcpkg" -ForegroundColor White
    Write-Host ""
    Write-Host "Please restart your terminal or run 'refreshenv' to use the new environment." -ForegroundColor Cyan
    exit 0
}

################################################################################
# Main Execution
################################################################################

try {
    Initialize-BuildEnvironment
    Install-Chocolatey
    Install-VisualStudioBuildTools
    Install-DevelopmentTools
    Install-Vcpkg
    Install-VcpkgPackages
    Install-SpdlogFromSource
    Install-HeaderOnlyLibraries
    Install-PythonPackages
    Install-Go
    Install-GoTools

    Install-Dex

    Install-Rust
    Install-NsisPlugin
    Set-EnvironmentVariables
    # Remove-TempFiles
    Show-Summary
}
catch {
    Write-Error "Setup failed: $_"
    Write-Host "Please check the error messages above and retry." -ForegroundColor Red
    exit 1
}
