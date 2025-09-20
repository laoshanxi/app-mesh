# generate_ssl_cert.ps1
################################################################################
# Script to generate self-signed SSL certificate files for Windows
# PowerShell port of the original Bash script
################################################################################

param(
    [string]$WorkingDir
)
$env:PATH = "C:\local\bin;C:\go\bin;C:\vcpkg\installed\x64-windows\bin;" + $env:PATH

Set-PSDebug -Trace 0
$ErrorActionPreference = "Stop"
$CA_CONFIG = "ca-config.json"
$CA_CSR = "ca-csr.json"

function Set-WorkingDir {
    # Use script-level variables to modify the global variables
    if (-not $WorkingDir -or [string]::IsNullOrWhiteSpace($WorkingDir)) {
        $script:WorkingDir = $PSScriptRoot
    }
    Set-Location -Path $script:WorkingDir
    Write-Log "Working directory set to: $script:WorkingDir"

    # Update the global variables with full paths
    $script:CA_CONFIG = Join-Path -Path $script:WorkingDir -ChildPath "ca-config.json"
    $script:CA_CSR = Join-Path -Path $script:WorkingDir -ChildPath "ca-csr.json"
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

function Test-Dependencies {
    $dependencies = @("cfssl", "cfssljson", "openssl")
    
    foreach ($cmd in $dependencies) {
        try {
            $null = Get-Command $cmd -ErrorAction Stop
        }
        catch {
            Write-Log "Error: Missing required dependency: $cmd"
            Write-Log "Please install CloudFlare SSL tools and OpenSSL"
            exit 1
        }
    }
}

function New-CAConfig {
    $config = @{
        signing = @{
            default  = @{
                expiry = "87600h"
            }
            profiles = @{
                client = @{
                    expiry = "87600h"
                    usages = @(
                        "signing",
                        "key encipherment", 
                        "client auth"
                    )
                }
                server = @{
                    expiry = "87600h"
                    usages = @(
                        "signing",
                        "key encipherment",
                        "server auth",
                        "client auth"
                    )
                }
            }
        }
    }
    
    [System.IO.File]::WriteAllText($CA_CONFIG, ($config | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
}

function New-CACSR {
    $csr = @{
        CN    = "AppMesh"
        key   = @{
            algo = "ecdsa"
            size = 256
        }
        names = @(
            @{
                C  = "CN"
                L  = "Shaanxi"
                O  = "DevGroup"
                ST = "Beijing"
                OU = "System"
            }
        )
    }
    
    [System.IO.File]::WriteAllText($CA_CSR, ($csr | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
}

function Get-HostAddresses {
    $addresses = @()
    
    # Get computer name
    $hostname = $env:COMPUTERNAME
    $fqdn = [System.Net.Dns]::GetHostEntry($hostname).HostName
    
    $addresses += $hostname
    $addresses += $fqdn
    
    # Get IP addresses
    $networkAdapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
        $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual"
    }
    
    foreach ($adapter in $networkAdapters) {
        $addresses += $adapter.IPAddress
    }
    
    # Add localhost entries
    $addresses += "localhost"
    $addresses += "127.0.0.1"
    
    return ($addresses | Sort-Object -Unique) -join ","
}

function New-Certificates {
    param([string]$Hosts)
    
    $hostname = $env:COMPUTERNAME
    
    Write-Log "Generating CA certificate..."
    & cfssl gencert -initca $CA_CSR | & cfssljson -bare ca
    
    Write-Log "Generating server certificate..."
    $serverCSR = @{
        CN    = $hostname
        hosts = @("")
        key   = @{
            algo = "ecdsa"
            size = 256
        }
    } | ConvertTo-Json -Compress
    
    # Write server CSR to file
    $serverCsrPath = Join-Path -Path $script:WorkingDir -ChildPath "server-csr.json"
    [System.IO.File]::WriteAllText($serverCsrPath, $serverCSR, [System.Text.UTF8Encoding]::new($false))
    & cfssl gencert "-ca=ca.pem" "-ca-key=ca-key.pem" "-config=$CA_CONFIG" "-profile=server" "-hostname=$Hosts" $serverCsrPath | & cfssljson -bare server

    # Combine fullchain for multiple level (not include root CA)
    # $serverPem = Join-Path $script:WorkingDir "server.pem"
    # $caPem = Join-Path $script:WorkingDir "ca.pem"
    # $fullchain = Join-Path $script:WorkingDir "server_fullchain.pem"
    # Get-Content $serverPem, $caPem | Set-Content $fullchain -Encoding ascii
    # Write-Log "Generated server full chain: $fullchain"

    Write-Log "Generating client certificate..."
    $clientCSR = @{
        CN    = "appmesh-client"
        hosts = @("")
        key   = @{
            algo = "ecdsa"
            size = 256
        }
    } | ConvertTo-Json -Compress

    $clientCsrPath = Join-Path -Path $script:WorkingDir -ChildPath "client-csr.json"
    [System.IO.File]::WriteAllText($clientCsrPath, $clientCSR, [System.Text.UTF8Encoding]::new($false))
    & cfssl gencert "-ca=ca.pem" "-ca-key=ca-key.pem" "-config=$CA_CONFIG" "-profile=client" "-hostname=$Hosts" $clientCsrPath | & cfssljson -bare client

    # Remove template files
    Remove-Item -Path "$serverCsrPath", "$clientCsrPath" -ErrorAction SilentlyContinue
}

function Test-Certificates {
    $errorCount = 0
    Write-Log "Verifying certificates..."
    
    # Get current directory in OpenSSL-friendly format
    $caFile = Join-Path $script:WorkingDir "ca.pem" -Resolve
    $serverCert = Join-Path $script:WorkingDir "server.pem" -Resolve
    $serverKey = Join-Path $script:WorkingDir "server-key.pem" -Resolve
    $clientCert = Join-Path $script:WorkingDir "client.pem" -Resolve
    $clientKey = Join-Path $script:WorkingDir "client-key.pem" -Resolve
    
    # Convert to forward slashes for OpenSSL compatibility
    $caFile = $caFile -replace "\\", "/"
    $serverCert = $serverCert -replace "\\", "/"
    $serverKey = $serverKey -replace "\\", "/"
    $clientCert = $clientCert -replace "\\", "/"
    $clientKey = $clientKey -replace "\\", "/"
    
    # Verify CA certificate
    Write-Log "Verifying CA certificate..."
    $result = & openssl x509 -in $caFile -text -noout 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "✓ CA certificate is valid"
        $caDetails = & openssl x509 -in $caFile -noout -subject -issuer -dates 2>$null
        $caDetails | ForEach-Object { Write-Log "    $_" }
    }
    else {
        Write-Log "✗ CA certificate verification failed: $result"
        $errorCount++
    }
    
    # Verify server certificate and key match using a more reliable method
    Write-Log "Verifying server certificate and key..."
    # Create a temporary file to test if cert and key work together
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        # Try to create a PKCS12 file - this will fail if cert and key don't match
        $null = & openssl pkcs12 -export -in $serverCert -inkey $serverKey -out $tempFile -passout pass:test 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ Server certificate and private key match"
        }
        else {
            Write-Log "✗ Server certificate and private key do not match"
            $errorCount++
        }
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
    }

    # Verify client certificate and key match
    Write-Log "Verifying client certificate and key..."
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        # Try to create a PKCS12 file - this will fail if cert and key don't match
        $null = & openssl pkcs12 -export -in $clientCert -inkey $clientKey -out $tempFile -passout pass:test 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ Client certificate and private key match"
        }
        else {
            Write-Log "✗ Client certificate and private key do not match"
            $errorCount++
        }
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
    }
    
    # Verify certificate chains
    Write-Log "Verifying certificate chains..."
    $serverVerify = & openssl verify -CAfile $caFile $serverCert 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "✓ Server certificate chain is valid"
    }
    else {
        Write-Log "✗ Server certificate chain verification failed: $serverVerify"
        $errorCount++
    }
    
    $clientVerify = & openssl verify -CAfile $caFile $clientCert 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "✓ Client certificate chain is valid"
    }
    else {
        Write-Log "✗ Client certificate chain verification failed: $clientVerify"
        $errorCount++
    }
    
    return $errorCount -eq 0
}

function New-ES256KeyPair {
    Write-Log "Generating ECDSA keys for JWT ES256..."
    
    if ((Test-Path "jwt-ec-private.pem") -or (Test-Path "jwt-ec-public.pem")) {
        Write-Log "Warning: JWT EC key files already exist, skipping generation"
        return $true
    }
    
    try {
        & openssl ecparam -genkey -name prime256v1 -noout -out jwt-ec-private.pem
        & openssl ec -in jwt-ec-private.pem -pubout -out jwt-ec-public.pem
        
        Write-Log "✓ Successfully created jwt-ec-private.pem and jwt-ec-public.pem"
        return $true
    }
    catch {
        Write-Log "Error: Failed to generate ES256 key pair"
        return $false
    }
}

function New-RS256KeyPair {
    Write-Log "Converting SSL keys to JWT RS256 format..."
    
    if (!(Test-Path "server-key.pem") -or !(Test-Path "server.pem")) {
        Write-Log "Error: Required input files (server-key.pem, server.pem) not found"
        return $false
    }
    
    if ((Test-Path "jwt-private.pem") -or (Test-Path "jwt-public.pem")) {
        Write-Log "Warning: JWT key files already exist, skipping conversion"
        return $true
    }
    
    try {
        & openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in server-key.pem -out jwt-private.pem
        & openssl x509 -pubkey -noout -in server.pem | Out-File -FilePath jwt-public.pem -Encoding ASCII
        
        Write-Log "✓ Successfully created jwt-private.pem and jwt-public.pem"
        return $true
    }
    catch {
        Write-Log "Error: Failed to convert to RS256 format"
        return $false
    }
}

function Remove-TempFiles {
    Write-Log "Cleaning up configuration files..."
    Remove-Item -Path $CA_CONFIG, $CA_CSR -ErrorAction SilentlyContinue
}

function Main {
    Write-Log "Starting SSL certificate generation..."

    Set-WorkingDir
    
    Test-Dependencies
    
    New-CAConfig
    New-CACSR
    
    $hosts = Get-HostAddresses
    Write-Log "Using hosts: $hosts"
    
    New-Certificates -Hosts $hosts
    
    if (Test-Certificates) {
        Write-Log "All certificates verified successfully"
    }
    else {
        Write-Log "Certificate verification failed"
        exit 1
    }
    
    $null = New-RS256KeyPair
    $null = New-ES256KeyPair
    Remove-TempFiles
    
    Write-Log "Certificate generation completed successfully"
    Write-Log "Generated files: ca.pem, ca-key.pem, server.pem, server-key.pem, client.pem, client-key.pem"
    
    Write-Log "To test the certificates, you can use these commands:"
    Write-Log "Server test:"
    Write-Log "    openssl s_server -cert server.pem -key server-key.pem -CAfile ca.pem -verify 1 -port 8443"
    Write-Log "Client test:"
    Write-Log "    openssl s_client -cert client.pem -key client-key.pem -CAfile ca.pem -verify 1 -connect localhost:8443"
}

# Run main function
Main