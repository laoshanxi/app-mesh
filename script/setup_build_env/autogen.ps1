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
$script:PerlPath = $null

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

function Find-Perl {
    if ($script:PerlPath) { return $script:PerlPath }
    
    $possiblePaths = @(
        "C:\vcpkg\downloads\tools\perl\*\perl\bin",
        "C:\Perl*\bin",
        "C:\Strawberry\perl\bin",
        "$env:ProgramFiles\Perl\bin",
        "${env:ProgramFiles(x86)}\Perl\bin"
    )
    
    foreach ($pathPattern in $possiblePaths) {
        $perlExe = Get-ChildItem -Path $pathPattern -Filter "perl.exe" -Recurse -ErrorAction SilentlyContinue | 
        Select-Object -First 1
        if ($perlExe) {
            $script:PerlPath = $perlExe.Directory.FullName
            Write-Host "Found Perl in: $script:PerlPath" -ForegroundColor Green
            return $script:PerlPath
        }
    }
    return $null
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
    Write-Host "Ensuring development tools (CMake, Git, Wget, 7zip, OpenSSL, NSIS, NSSM) are installed..." -ForegroundColor Cyan

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
        'boost-variant:x64-windows',
        'boost-serialization:x64-windows',
        'boost-lockfree:x64-windows',
        'ace[ssl]:x64-windows',
        'uwebsockets[core,ssl]:x64-windows',
        'spdlog:x64-windows',
        'cryptopp:x64-windows',
        'curl:x64-windows',
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

function Install-HeaderOnlyLibraries {
    Write-Host "Installing header-only libraries..." -ForegroundColor Cyan
    
    # nlohmann/json
    Write-Host "Installing nlohmann/json..." -ForegroundColor Yellow
    $jsonUrl = "https://github.com/nlohmann/json/releases/download/v3.11.3/include.zip"
    Save-File $jsonUrl "json-include.zip"
    Expand-File "json-include.zip" "json-temp"
    New-Item -ItemType Directory -Force -Path "C:\local\include" | Out-Null
    Copy-Item -Recurse "json-temp\include\nlohmann" "C:\local\include\" -Force
    
    # Message Pack
    Write-Host "Installing MessagePack..." -ForegroundColor Yellow
    git clone -b cpp_master --depth 1 https://github.com/laoshanxi/msgpack-c.git
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

    # linenoise-ng
    Remove-Item -Recurse -Force "linenoise-ng" -ErrorAction Ignore
    git clone --depth=1 https://github.com/arangodb/linenoise-ng.git
    Set-Location linenoise-ng
    New-Item -ItemType Directory -Force -Path "build" | Out-Null
    Set-Location build
    # Patch CMakeLists.txt
    $cmakeFile = "..\CMakeLists.txt"
    if (Test-Path $cmakeFile) {
        $lines = Get-Content $cmakeFile
        $lines = $lines -replace '^\s*cmake_minimum_required\s*\(.*\)', 'cmake_minimum_required(VERSION 3.20)'
        Set-Content $cmakeFile $lines
    }
    cmake .. -Wno-dev -G "Visual Studio 17 2022" -A x64 -DCMAKE_INSTALL_PREFIX="C:/local"
    cmake --build . --config Release --target linenoise
    cmake --install . --config Release
    Set-Location $ROOTDIR

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

    # libwebsockets
    git clone --depth=1 https://libwebsockets.org/repo/libwebsockets
    Set-Location "libwebsockets"
    (Get-Content "include\libwebsockets.h" -Raw) -replace 'typedef unsigned int uid_t;', 'typedef long uid_t;' | Set-Content "include\libwebsockets.h"
    (Get-Content "include\libwebsockets.h" -Raw) -replace 'typedef unsigned int gid_t;', 'typedef long gid_t;' | Set-Content "include\libwebsockets.h"
    (Get-Content "include\libwebsockets.h" -Raw) -replace 'typedef unsigned int useconds_t;', 'typedef unsigned long useconds_t;' | Set-Content "include\libwebsockets.h"
    (Get-Content "include\libwebsockets.h" -Raw) -replace 'typedef int suseconds_t;', 'typedef long suseconds_t;' | Set-Content "include\libwebsockets.h"
    New-Item -ItemType Directory -Force -Path "build" | Out-Null
    Set-Location "build"
    cmake .. -Wno-dev -G "Visual Studio 17 2022" -A x64 -DLWS_WITHOUT_TESTAPPS=ON -DCMAKE_C_FLAGS="/wd4819" -DCMAKE_CXX_FLAGS="/wd4819" -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_INSTALL_PREFIX="C:/local"
    cmake --build . --config Release
    cmake --install . --config Release
    Set-Location $ROOTDIR

    # uriparser
    git clone --depth=1 https://github.com/uriparser/uriparser.git
    Set-Location "uriparser"
    New-Item -ItemType Directory -Force -Path "build" | Out-Null
    Set-Location "build"
    cmake .. -G "Visual Studio 17 2022" -A x64 -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_INSTALL_PREFIX="C:/local"
    cmake --build . --config Release
    cmake --install . --config Release
    Set-Location $ROOTDIR

    # QR Code Generator
    git clone --depth=1 https://github.com/nayuki/QR-Code-generator.git
    Set-Location "QR-Code-generator\cpp"
    cmd /c "`"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat`" -arch=amd64 && cl /EHsc /MD /c qrcodegen.cpp && lib qrcodegen.obj /OUT:qrcodegencpp.lib"
    Copy-Item "qrcodegen.hpp" "C:\local\include\" -Force
    Copy-Item "qrcodegen.cpp" "C:\local\include\" -Force
    Copy-Item "qrcodegencpp.lib" "C:\local\lib\" -Force
    Set-Location $ROOTDIR
    
    Write-Host "Header-only libraries installed successfully" -ForegroundColor Green
}

function Install-Python {
    param (
        [string]$Version = "3.13.7",
        [string]$InstallDir = "C:\Python313",
        [ValidateSet("amd64", "arm64")]
        [string]$Arch = $(if ($env:PROCESSOR_ARCHITECTURE -match "ARM") { "arm64" } else { "amd64" })
    )

    Write-Host "Installing Python programming language..." -ForegroundColor Cyan

    # Auto-detect architecture if not specified
    if (-not $Arch) {
        $Arch = if ($env:PROCESSOR_ARCHITECTURE -match "ARM|arm") { "arm64" } else { "amd64" }
    }

    $pythonExe = Join-Path $InstallDir "python.exe"

    # Check if Python is already installed
    $existingVersion = $null
    if (Get-Command python -ErrorAction SilentlyContinue) {
        try {
            $out = & python --version 2>&1
            if ($null -ne $out) {
                # join possible array output and trim safely
                $existingVersion = ($out -join "`n").Trim()
            }
            else {
                $existingVersion = $null
            }
        }
        catch {
            # If invoking python fails for any reason, treat as not installed
            $existingVersion = $null
        }
    }
    elseif (Test-Path $pythonExe) {
        try {
            $out = & $pythonExe --version 2>&1
            if ($null -ne $out) {
                $existingVersion = ($out -join "`n").Trim()
            }
            else {
                $existingVersion = $null
            }
        }
        catch {
            $existingVersion = $null
        }
    }
    if ($existingVersion -and $existingVersion -like "Python $Version*") {
        Write-Host "Python $Version is already installed" -ForegroundColor Green
        return
    }
    elseif ($existingVersion) {
        Write-Host "Found $existingVersion, will install Python $Version..." -ForegroundColor Yellow
    }

    Write-Host "Preparing to install Python $Version ($Arch) to $InstallDir..." -ForegroundColor Cyan

    $installerName = "python-$Version-$Arch.exe"
    $installerUrl = "https://www.python.org/ftp/python/$Version/$installerName"

    # Download installer
    Save-File $installerUrl $installerName

    Write-Host "Running installer (quiet mode)..." -ForegroundColor Yellow
    $installerArgs = @(
        "/quiet",
        "InstallAllUsers=1",
        "PrependPath=1",
        "TargetDir=$InstallDir",
        "Include_doc=0",
        "Include_test=0"
    )
    $proc = Start-Process -FilePath $installerName -ArgumentList $installerArgs -Wait -NoNewWindow -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Python installer failed with exit code $($proc.ExitCode)"
    }

    # Verify installation
    if (-not (Test-Path $pythonExe)) {
        throw "Installation completed but python.exe not found at $pythonExe"
    }

    # Upgrade pip and essential packages
    Install-PythonPackages -PythonExe $pythonExe

    Write-Host "Python $Version installed successfully" -ForegroundColor Green
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
    
    if (!(Get-Command go -ErrorAction SilentlyContinue)) {
        $goVersion = "1.25.3"
        $goArch = if ($architecture -eq "arm64") { "arm64" } else { "amd64" }
        $goUrl = "https://go.dev/dl/go$goVersion.windows-$goArch.zip"
        Save-File $goUrl "go.zip"
        Expand-File "go.zip" "C:\"
        $env:PATH = "C:\go\bin;$env:PATH"
        [Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::Machine)
        Write-Host "Go installed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "Go is already installed" -ForegroundColor Green
    }
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

function Build-NativeLibraries {
    Write-Host "Building native libraries..." -ForegroundColor Cyan
    Write-Host "Native library compilation completed" -ForegroundColor Green
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
        
        if ($env:ACE_ROOT) {
            [Environment]::SetEnvironmentVariable("ACE_ROOT", $env:ACE_ROOT, [EnvironmentVariableTarget]::Machine)
        }
        
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
    Write-Host "  mkdir build && cd build" -ForegroundColor White
    Write-Host "  cmake .. -G `"Visual Studio 17 2022`" -A x64" -ForegroundColor White
    Write-Host "  cmake --build . --config Release" -ForegroundColor White
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
    Install-HeaderOnlyLibraries
    #Install-Python
    Install-PythonPackages
    Install-Go
    Install-GoTools
    Install-NsisPlugin
    Build-NativeLibraries
    Set-EnvironmentVariables
    # Remove-TempFiles
    Show-Summary
}
catch {
    Write-Error "Setup failed: $_"
    Write-Host "Please check the error messages above and retry." -ForegroundColor Red
    exit 1
}
