# script/ssl/generate_ssl_cert.ps1
################################################################################
# Script to generate self-signed SSL certificate files for Windows
################################################################################

param(
    [string]$WorkingDir
)

# Normalize empty string to $null
if ([string]::IsNullOrWhiteSpace($WorkingDir)) {
    $WorkingDir = $PSScriptRoot
    Write-Host "WorkingDir not provided. Defaulting to script directory: $WorkingDir"
}

# Ensure OpenSSL is in path if installed via common methods, or rely on system PATH
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;C:\local\bin;C:\go\bin;C:\vcpkg\installed\x64-windows\bin;" + $env:PATH

Set-PSDebug -Trace 0
$ErrorActionPreference = "Stop"

function Set-WorkingDir {
    Set-Location -Path $WorkingDir
    Write-Log "Working directory set to: $WorkingDir"
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

function Test-Dependencies {
    $dependencies = @("openssl")
    
    foreach ($cmd in $dependencies) {
        try {
            $null = Get-Command $cmd -ErrorAction Stop
        }
        catch {
            Write-Log "Error: Missing required dependency: $cmd"
            Write-Log "Please install OpenSSL for Windows."
            exit 1
        }
    }
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
        $_.IPAddress -ne "127.0.0.1" -and ($_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual")
    }
    
    foreach ($adapter in $networkAdapters) {
        $addresses += $adapter.IPAddress
    }
    
    # Add localhost entries
    $addresses += "localhost"
    $addresses += "127.0.0.1"
    
    return ($addresses | Sort-Object -Unique) -join ","
}

function Generate-OpenSSLConfig {
    param(
        [string]$CN,
        [string]$Type, # "server" or "client"
        [string]$HostsStr
    )

    $sanBlock = ""
    if ($Type -eq "server" -and -not [string]::IsNullOrEmpty($HostsStr)) {
        $dnsIndex = 1
        $ipIndex = 1
        $hosts = $HostsStr -split ","
        $sanLines = @()

        foreach ($h in $hosts) {
            # Simple regex to check if it's an IP address
            if ($h -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
                $sanLines += "IP.$ipIndex = $h"
                $ipIndex++
            } else {
                $sanLines += "DNS.$dnsIndex = $h"
                $dnsIndex++
            }
        }
        $sanBlock = "[alt_names]`n" + ($sanLines -join "`n")
    }

    $keyUsage = "critical, digitalSignature, keyEncipherment"
    if ($Type -eq "server") {
        # Server certs usually perform both auths in modern setups, but mainly ServerAuth
        $extKeyUsage = "serverAuth, clientAuth" 
        $sanSectionHeader = "subjectAltName = @alt_names"
    } else {
        $extKeyUsage = "clientAuth"
        $sanSectionHeader = "" # Clients usually don't strictly need SANs for this use case
        $sanBlock = ""
    }

    $configContent = @"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = CN
L = Shaanxi
O = DevGroup
ST = Beijing
OU = System
CN = $CN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = $keyUsage
extendedKeyUsage = $extKeyUsage
$sanSectionHeader

$sanBlock
"@
    
    $configPath = Join-Path $script:WorkingDir "$Type.cnf"
    [System.IO.File]::WriteAllText($configPath, $configContent, [System.Text.UTF8Encoding]::new($false))
    return $configPath
}

function New-Certificates {
    param([string]$Hosts)
    
    $hostname = $env:COMPUTERNAME
    
    # 1. CA Generation
    Write-Log "Generating CA certificate (ECDSA)..."
    
    # Generate CA Private Key (prime256v1)
    & openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
    
    # Generate CA Root Certificate (Self-Signed)
    # Subject matches the original script's JSON config
    & openssl req -new -x509 -nodes -days 3650 -key ca-key.pem -out ca.pem -subj "/C=CN/L=Shaanxi/O=DevGroup/ST=Beijing/OU=System/CN=AppMesh"
    
    # 2. Server Certificate Generation
    Write-Log "Generating server certificate..."
    
    # Generate Server Private Key
    & openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
    
    # Generate Server Config for SANs
    $serverConf = Generate-OpenSSLConfig -CN $hostname -Type "server" -HostsStr $Hosts
    
    # Generate Server CSR
    & openssl req -new -key server-key.pem -out server.csr -config $serverConf
    
    # Sign Server Certificate with CA
    & openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server.pem -days 3650 -sha256 -extfile $serverConf -extensions v3_req

    # 3. Client Certificate Generation
    Write-Log "Generating client certificate..."
    
    # Generate Client Private Key
    & openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
    
    # Generate Client Config
    $clientConf = Generate-OpenSSLConfig -CN "appmesh-client" -Type "client" -HostsStr ""
    
    # Generate Client CSR
    & openssl req -new -key client-key.pem -out client.csr -config $clientConf
    
    # Sign Client Certificate with CA
    & openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client.pem -days 3650 -sha256 -extfile $clientConf -extensions v3_req

    # Cleanup intermediate files
    Remove-Item -Path "server.csr", "client.csr" -ErrorAction SilentlyContinue
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
    Remove-Item -Path "server.cnf", "client.cnf", "ca.srl" -ErrorAction SilentlyContinue
}

function Main {
    Write-Log "Starting SSL certificate generation (OpenSSL mode)..."

    Set-WorkingDir
    
    Test-Dependencies
    
    # Gather hosts to populate SANs (Subject Alternative Names)
    $hosts = Get-HostAddresses
    Write-Log "Using hosts for Server SANs: $hosts"
    
    # Generate CA, Server, and Client certs using OpenSSL
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
