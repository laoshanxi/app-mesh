# script/ssl/generate_ssl_cert.ps1
################################################################################
# Script to generate self-signed SSL certificate files for Windows
# Supports both CFSSL (preferred) and pure OpenSSL (fallback) strategies
################################################################################

param(
    [string]$WorkingDir
)
$env:PATH = "C:\local\appmesh\bin;C:\Program Files\OpenSSL-Win64\bin;C:\local\bin;C:\go\bin;C:\vcpkg\installed\x64-windows\bin;" + $env:PATH

Set-PSDebug -Trace 0
$ErrorActionPreference = "Stop"
$CA_CONFIG = "ca-config.json"
$CA_CSR = "ca-csr.json"
$script:UsePureOpenSSL = $false

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

function Test-CommandExists {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-Dependencies {
    # 1. Always check for OpenSSL (Required for verification and fallback)
    if (-not (Test-CommandExists "openssl")) {
        Write-Log "Error: OpenSSL is not installed or not in PATH."
        Write-Log "Please install OpenSSL."
        exit 1
    }

    # If CFSSL usage is already forced off, skip checks
    if ($script:UsePureOpenSSL) { return }

    # 2. Check for CFSSL
    if ((Test-CommandExists "cfssl") -and (Test-CommandExists "cfssljson")) {
        $script:UsePureOpenSSL = $false
        Write-Log "Found CFSSL tools. Using CFSSL generation strategy."
    }
    else {
        $script:UsePureOpenSSL = $true
        Write-Log "CFSSL tools not found. Falling back to pure OpenSSL generation strategy."
    }
}

function New-CAConfig {
    if ($script:UsePureOpenSSL) { return }

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
    if ($script:UsePureOpenSSL) { return }

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

function New-Certificates-CFSSL {
    param([string]$Hosts)
    
    $hostname = $env:COMPUTERNAME
    
    Write-Log "Generating CA certificate (CFSSL)..."
    & cfssl gencert -initca $CA_CSR | & cfssljson -bare ca
    
    Write-Log "Generating server certificate (CFSSL)..."
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

    Write-Log "Generating client certificate (CFSSL)..."
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

function New-Certificates-OpenSSL {
    param([string]$Hosts)
    
    $hostname = $env:COMPUTERNAME
    
    # Define absolute paths for all files
    $caKeyPath = Join-Path $script:WorkingDir "ca-key.pem"
    $caCertPath = Join-Path $script:WorkingDir "ca.pem"
    $caCnfPath = Join-Path $script:WorkingDir "ca.cnf"  # Config for CA
    
    $serverKeyPath = Join-Path $script:WorkingDir "server-key.pem"
    $serverCnfPath = Join-Path $script:WorkingDir "server.cnf"
    $serverCsrPath = Join-Path $script:WorkingDir "server.csr"
    $serverCertPath = Join-Path $script:WorkingDir "server.pem"
    
    $clientKeyPath = Join-Path $script:WorkingDir "client-key.pem"
    $clientCnfPath = Join-Path $script:WorkingDir "client.cnf"
    $clientCsrPath = Join-Path $script:WorkingDir "client.csr"
    $clientCertPath = Join-Path $script:WorkingDir "client.pem"

    # --- Helper to generate OpenSSL Config with SANs (For Leaf Certs) ---
    function Get-OpenSSLConfig {
        param($CN, $Profile)
        
        $sanList = @()
        $dnsIdx = 1
        $ipIdx = 1
        
        $hostsArray = $Hosts -split ","
        foreach ($h in $hostsArray) {
            $h = $h.Trim()
            if ($h -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
                $sanList += "IP.$ipIdx = $h"
                $ipIdx++
            }
            else {
                $sanList += "DNS.$dnsIdx = $h"
                $dnsIdx++
            }
        }
        $sanBlock = $sanList -join "`n"

        $eku = "serverAuth, clientAuth"
        if ($Profile -eq "client") { $eku = "clientAuth" }

        return @"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
C = CN
ST = Beijing
L = Shaanxi
O = DevGroup
OU = System
CN = $CN
[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = $eku
subjectAltName = @alt_names
[alt_names]
$sanBlock
"@
    }

    # --- NEW: Generate CA Config with required Extensions ---
    $caCnf = @"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no
[req_distinguished_name]
C = CN
ST = Beijing
L = Shaanxi
O = DevGroup
OU = System
CN = AppMesh
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
"@
    [System.IO.File]::WriteAllText($caCnfPath, $caCnf, [System.Text.Encoding]::ASCII)

    # 1. Generate CA (ECDSA P-256)
    Write-Log "Generating CA certificate (OpenSSL)..."
    # Generate Key
    & openssl ecparam -name prime256v1 -genkey -noout -out $caKeyPath

    # Generate Root Cert using the config to apply extensions
    & openssl req -new -x509 -nodes -days 3650 -key $caKeyPath -out $caCertPath -config $caCnfPath

    # 2. Generate Server Certificate
    Write-Log "Generating server certificate (OpenSSL)..."
    & openssl ecparam -name prime256v1 -genkey -noout -out $serverKeyPath
    
    $serverCnf = Get-OpenSSLConfig -CN $hostname -Profile "server"
    # Use [System.Text.Encoding]::ASCII to avoid BOM issues with OpenSSL on Windows
    [System.IO.File]::WriteAllText($serverCnfPath, $serverCnf, [System.Text.Encoding]::ASCII)
    
    & openssl req -new -key $serverKeyPath -out $serverCsrPath -config $serverCnfPath
    & openssl x509 -req -in $serverCsrPath -CA $caCertPath -CAkey $caKeyPath -CAcreateserial -out $serverCertPath -days 3650 -extensions v3_req -extfile $serverCnfPath

    # 3. Generate Client Certificate
    Write-Log "Generating client certificate (OpenSSL)..."
    & openssl ecparam -name prime256v1 -genkey -noout -out $clientKeyPath

    $clientCnf = Get-OpenSSLConfig -CN "appmesh-client" -Profile "client"
    [System.IO.File]::WriteAllText($clientCnfPath, $clientCnf, [System.Text.Encoding]::ASCII)

    & openssl req -new -key $clientKeyPath -out $clientCsrPath -config $clientCnfPath
    & openssl x509 -req -in $clientCsrPath -CA $caCertPath -CAkey $caKeyPath -CAcreateserial -out $clientCertPath -days 3650 -extensions v3_req -extfile $clientCnfPath

    # Cleanup temp OpenSSL files
    $srlPath = Join-Path $script:WorkingDir "ca.srl"
    Remove-Item $serverCnfPath, $clientCnfPath, $serverCsrPath, $clientCsrPath, $srlPath, $caCnfPath -ErrorAction SilentlyContinue
}

function New-Certificates {
    param([string]$Hosts)

    if ($script:UsePureOpenSSL) {
        New-Certificates-OpenSSL -Hosts $Hosts
    }
    else {
        New-Certificates-CFSSL -Hosts $Hosts
    }
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
