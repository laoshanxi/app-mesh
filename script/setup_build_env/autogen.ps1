#!/usr/bin/env powershell
################################################################################
## Windows MSVC Build Environment Setup Script for App-Mesh
## This script installs all dependencies needed to build the C++/Go application
################################################################################

# Ensure script runs with admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Exiting..."
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
    Write-Host "Installing development tools (CMake, Git, Wget, 7zip)..." -ForegroundColor Cyan
    $tools = @('cmake', 'git', 'wget', '7zip', 'openssl', 'nsis', 'nssm')
    
    foreach ($tool in $tools) {
        choco install -y $tool
    }
    
    Write-Host "Refreshing environment variables..." -ForegroundColor Yellow
    refreshenv
    
    # Verify installations
    $toolCommands = @('cmake', 'git', 'wget', '7z')
    foreach ($tool in $toolCommands) {
        if (!(Get-Command $tool -ErrorAction SilentlyContinue)) {
            Write-Warning "Tool $tool not found in PATH. Please ensure it is installed correctly."
        }
        else {
            Write-Host "Verified: $tool is available" -ForegroundColor Green
        }
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
    Write-Host "Installing vcpkg packages..." -ForegroundColor Cyan
    
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
        'cryptopp:x64-windows',
        'curl:x64-windows',
        'yaml-cpp:x64-windows'
    )
    
    foreach ($package in $packages) {
        Write-Host "Installing $package..." -ForegroundColor Yellow
        C:\vcpkg\vcpkg.exe install $package
        Write-Host "$package installed successfully" -ForegroundColor Green
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
    
    # log4cpp
    Write-Host "Installing log4cpp..." -ForegroundColor Yellow
    Save-File "https://jaist.dl.sourceforge.net/project/log4cpp/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.4.tar.gz" "log4cpp.tar.gz"
    tar -xvf log4cpp.tar.gz
    Set-Location log4cpp
    New-Item -ItemType Directory -Force -Path "build" | Out-Null
    Set-Location build
    
    # Patch CMakeLists.txt
    $cmakeFile = "..\CMakeLists.txt"
    if (Test-Path $cmakeFile) {
        $lines = Get-Content $cmakeFile
        if ($lines[0] -notmatch 'cmake_minimum_required') {
            $newLines = @("cmake_minimum_required(VERSION 3.10)") + $lines
            Set-Content $cmakeFile $newLines
        }
    }
    
    # Patch config-win32.h
    $configFile = "..\include\log4cpp\config-win32.h"
    $content = Get-Content $configFile
    $content = $content -replace 'typedef\s+int\s+mode_t;', 'typedef unsigned short mode_t;'
    Set-Content $configFile $content
    
    cmake .. -Wno-dev -G "Visual Studio 17 2022" -A x64 -DCMAKE_INSTALL_PREFIX="C:/local"
    cmake --build . --config Release
    cmake --install . --config Release
    Set-Location $ROOTDIR
    
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
    git clone --depth=1 https://github.com/schoentoon/hashidsxx.git
    Copy-Item -Recurse "hashidsxx" "C:\local\include\" -Force
    
    # croncpp
    git clone --depth=1 https://github.com/mariusbancila/croncpp.git
    Copy-Item "croncpp\include\croncpp.h" "C:\local\include\" -Force
    
    # wildcards
    git clone --depth=1 https://github.com/laoshanxi/wildcards.git
    Copy-Item -Recurse "wildcards\single_include" "C:\local\include\wildcards" -Force
    
    # prometheus-cpp
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

function Install-Go {
    Write-Host "Installing Go programming language..." -ForegroundColor Cyan
    
    if (!(Get-Command go -ErrorAction SilentlyContinue)) {
        $goVersion = "1.23.8"
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
    Write-Host "Installing Go development tools..." -ForegroundColor Cyan
    
    $env:GOBIN = "C:\local\bin"
    New-Item -ItemType Directory -Force -Path $env:GOBIN | Out-Null
    
    go env -w GOPROXY="https://goproxy.io,direct"
    go env -w GOBIN="C:\local\bin"
    go env -w GO111MODULE=on
    
    $goTools = @(
        'github.com/cloudflare/cfssl/cmd/cfssl@latest',
        'github.com/cloudflare/cfssl/cmd/cfssljson@latest'
    )
    
    foreach ($tool in $goTools) {
        Write-Host "Installing $tool..." -ForegroundColor Yellow
        go install $tool
    }
    
    Write-Host "Go tools installed successfully" -ForegroundColor Green
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


function New-CMakeToolchain {
    Write-Host "Creating CMake toolchain file..." -ForegroundColor Cyan
    
    @"
# Windows MSVC Toolchain for App-Mesh
if(DEFINED CMAKE_TOOLCHAIN_FILE_INCLUDED)
    return()
endif()
set(CMAKE_TOOLCHAIN_FILE_INCLUDED TRUE)

set(CMAKE_SYSTEM_NAME Windows)
add_compile_options("/utf-8")
# execute_process(COMMAND chcp 65001)

# Explicitly include vcpkg toolchain
include("C:/vcpkg/scripts/buildsystems/vcpkg.cmake")

# Set additional include and library paths
include_directories("C:/local/include")
link_directories("C:/local/lib")
list(PREPEND CMAKE_PREFIX_PATH "C:/local")

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimization flags
set(CMAKE_CXX_FLAGS_RELEASE_INIT "/O2 /Ob2 /DNDEBUG /MD")
set(CMAKE_C_FLAGS_RELEASE_INIT "/O2 /Ob2 /DNDEBUG /MD")

# Windows specific definitions
add_compile_definitions(
    WIN32
    _WIN32
    _WINDOWS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

# Disable all warnings (DO NOT USE for production use)
add_compile_options(
    /W0
    /external:anglebrackets /external:W0
    /wd4244 /wd4267 /wd4996
)

# Debugging output
message(STATUS "Toolchain CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")
"@ | Out-File -FilePath "C:\local\windows-toolchain.cmake" -Encoding utf8
    
    Write-Host "CMake toolchain file created at C:\local\windows-toolchain.cmake" -ForegroundColor Green
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
    Write-Host "  cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\local\windows-toolchain.cmake -G `"Visual Studio 17 2022`" -A x64" -ForegroundColor White
    Write-Host "  cmake --build ." -ForegroundColor White
    Write-Host ""
    Write-Host "Important paths:" -ForegroundColor Yellow
    Write-Host "  Libraries: C:\local\lib" -ForegroundColor White
    Write-Host "  Headers: C:\local\include" -ForegroundColor White
    Write-Host "  Binaries: C:\local\bin" -ForegroundColor White
    Write-Host "  vcpkg: C:\vcpkg" -ForegroundColor White
    Write-Host ""
    Write-Host "Please restart your terminal or run 'refreshenv' to use the new environment." -ForegroundColor Cyan
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
    Install-Go
    Install-GoTools
    Install-NsisPlugin
    Build-NativeLibraries
    Set-EnvironmentVariables
    New-CMakeToolchain
    #Remove-TempFiles
    Show-Summary
}
catch {
    Write-Error "Setup failed: $_"
    Write-Host "Please check the error messages above and retry." -ForegroundColor Red
    exit 1
}
