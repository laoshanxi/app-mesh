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
}

# Ensure OpenSSL is in path
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;C:\local\bin;C:\go\bin;C:\vcpkg\installed\x64-windows\bin;" + $env:PATH

Set-PSDebug -Trace 0
$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

function Set-WorkingDir {
    Set-Location -Path $WorkingDir
    Write-Log "Working directory set to: $WorkingDir"
}

function Test-Dependencies {
    try {
        $null = Get-Command openssl -ErrorAction Stop
    }
    catch {
        Write-Log "Error: Missing required dependency: openssl"
        exit 1
    }
}

function Get-HostAddresses {
    $addresses = @("localhost", "127.0.0.1", $env:COMPUTERNAME)
    try { 
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { $addresses += $fqdn }
    } catch {}
    
    $networkAdapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
        $_.IPAddress -ne "127.0.0.1" -and ($_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual")
    }
    foreach ($adapter in $networkAdapters) { $addresses += $adapter.IPAddress }
    return ($addresses | Sort-Object -Unique) -join ","
}

function New-Certificates {
    param([string]$Hosts)
    
    # Define OpenSSL Config locally to ensure extensions are written correctly
    $confFile = Join-Path $WorkingDir "openssl_temp.cnf"
    
    $dnsIndex = 1; $ipIndex = 1; $sanLines = @()
    foreach ($h in ($Hosts -split ",")) {
        if ($h -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") { 
            $sanLines += "IP.$ipIndex = $h"; $ipIndex++ 
        } else { 
            $sanLines += "DNS.$dnsIndex = $h"; $dnsIndex++ 
        }
    }
    $sanBlock = $sanLines -join "`n"

    $configContent = @"
[ req ]
distinguished_name = req_dn
prompt = no
[ req_dn ]
C = CN
ST = Beijing
L = Shaanxi
O = DevGroup
OU = System
CN = AppMesh

[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ v3_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = @alt_names

[ alt_names ]
$sanBlock
"@
    [System.IO.File]::WriteAllText($confFile, $configContent)

    # 1. Generate CA (with keyCertSign for Python/Go compliance)
    Write-Log "Generating CA certificate (ECDSA)..."
    & openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
    & openssl req -new -x509 -nodes -days 3650 -key ca-key.pem -out ca.pem -config $confFile -extensions v3_ca

    # 2. Generate Server Certificate
    Write-Log "Generating server certificate..."
    & openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
    & openssl req -new -key server-key.pem -out server.csr -config $confFile -subj "/C=CN/ST=Beijing/L=Shaanxi/O=DevGroup/OU=System/CN=$env:COMPUTERNAME"
    & openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server.pem -days 3650 -sha256 -extfile $confFile -extensions v3_cert

    # 3. Generate Client Certificate
    Write-Log "Generating client certificate..."
    & openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
    & openssl req -new -key client-key.pem -out client.csr -config $confFile -subj "/C=CN/ST=Beijing/L=Shaanxi/O=DevGroup/OU=System/CN=appmesh-client"
    & openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client.pem -days 3650 -sha256 -extfile $confFile -extensions v3_cert

    # Cleanup
    Remove-Item server.csr, client.csr, ca.srl, $confFile -ErrorAction SilentlyContinue
}

function New-ES256KeyPair {
    Write-Log "Generating ECDSA keys for JWT ES256..."
    & openssl ecparam -genkey -name prime256v1 -noout -out jwt-ec-private.pem
    & openssl ec -in jwt-ec-private.pem -pubout -out jwt-ec-public.pem
}

function New-RS256KeyPair {
    Write-Log "Converting SSL keys to JWT RS256 format..."
    & openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in server-key.pem -out jwt-private.pem
    & openssl x509 -pubkey -noout -in server.pem | Out-File -FilePath jwt-public.pem -Encoding ASCII
}

function Main {
    Write-Log "Starting SSL certificate generation (OpenSSL mode)..."
    Set-WorkingDir
    Test-Dependencies
    
    $hosts = Get-HostAddresses
    Write-Log "Using hosts: $hosts"
    
    New-Certificates -Hosts $hosts
    New-RS256KeyPair
    New-ES256KeyPair
    
    Write-Log "Certificate generation completed successfully."
    Write-Log "Verifying..."
    & openssl verify -CAfile ca.pem server.pem
    & openssl verify -CAfile ca.pem client.pem
}

Main
