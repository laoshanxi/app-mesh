#!/usr/bin/env bash
################################################################################
## Script to generate self-signed SSL certificate files
##
## References:
## https://www.bookstack.cn/read/tidb-v2.1/how-to-secure-generate-self-signed-certificates.md
## https://www.cnblogs.com/fanqisoft/p/10765038.html
## https://blog.csdn.net/kozazyh/article/details/79844609
## https://github.com/cloudflare/cfssl/wiki/Creating-a-new-CSR
## https://github.com/coreos/docs/blob/master/os/generate-self-signed-certificates.md
################################################################################

readonly WORKING_DIR=$(pwd)
readonly CA_CONFIG="ca-config.json"
readonly CA_CSR="ca-csr.json"
readonly OPENSSL_CA_CNF="openssl-ca.cnf"
readonly OPENSSL_SERVER_CNF="openssl-server.cnf"
readonly OPENSSL_CLIENT_CNF="openssl-client.cnf"
readonly CERT_VALIDITY_DAYS=3650  # 10 years (87600h)
PATH=${WORKING_DIR}:${PATH:-}

# Flag to track which tool we're using
USE_CFSSL=false

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

ensure_dependencies() {
    # Check for openssl (required)
    if ! command -v openssl >/dev/null 2>&1; then
        log "Error: Missing required dependency: openssl"
        exit 1
    fi

    if ! command -v hostname >/dev/null 2>&1; then
        log "Error: Missing required dependency: hostname"
        exit 1
    fi

    # Check for cfssl (optional)
    if command -v cfssl >/dev/null 2>&1 && command -v cfssljson >/dev/null 2>&1; then
        USE_CFSSL=true
        log "Using cfssl for certificate generation"
    else
        USE_CFSSL=false
        log "cfssl not found, using pure openssl for certificate generation"
    fi
}

setup_ca_config() {
    cat >"$CA_CONFIG" <<EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "server": {
        "expiry": "87600h",
        "usages": [
          "digital signature",
          "server auth",
          "client auth"
        ]
      },
      "client": {
        "expiry": "87600h",
        "usages": [
          "digital signature",
          "server auth",
          "client auth"
        ]
      }
    }
  }
}
EOF
}

setup_ca_csr() {
    cat >"$CA_CSR" <<EOF
{
    "CN": "AppMesh",
    "key": {
        "algo": "ecdsa",
        "size": 256
    },
    "names": [
        {
            "C": "CN",
            "L": "Shaanxi",
            "O": "DevGroup",
            "ST": "Beijing",
            "OU": "System"
        }
    ]
}
EOF
}

# Generate OpenSSL configuration for CA
setup_openssl_ca_config() {
    cat >"$OPENSSL_CA_CNF" <<EOF
[ req ]
default_bits       = 256
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
C  = CN
ST = Beijing
L  = Shaanxi
O  = DevGroup
OU = System
CN = AppMesh

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:1
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
EOF
}

# Generate OpenSSL configuration for server certificate
setup_openssl_server_config() {
    local hosts="$1"
    local hostname_full
    hostname_full=$(hostname)
    local hostname_cn="$hostname_full"

    if [ ${#hostname_full} -gt 64 ]; then
        hostname_cn="AppMesh-Server"
    fi

    # Build SAN entries
    local san_entries=""
    local dns_count=1
    local ip_count=1

    IFS=',' read -ra HOST_ARRAY <<< "$hosts"
    for host in "${HOST_ARRAY[@]}"; do
        host=$(echo "$host" | xargs)  # trim whitespace
        [[ -z "$host" ]] && continue

        # Check if it's an IP address
        if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            san_entries="${san_entries}IP.${ip_count} = ${host}"$'\n'
            ip_count=$((ip_count + 1))
        else
            san_entries="${san_entries}DNS.${dns_count} = ${host}"$'\n'
            dns_count=$((dns_count + 1))
        fi
    done

    cat >"$OPENSSL_SERVER_CNF" <<EOF
[ req ]
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = CN
ST = Beijing
L  = Shaanxi
O  = DevGroup
OU = System
CN = ${hostname_cn}

[ req_ext ]
subjectAltName = critical,@alt_names

[ v3_server ]
basicConstraints    = CA:FALSE
keyUsage            = critical, digitalSignature, keyEncipherment
extendedKeyUsage    = serverAuth
subjectAltName      = @alt_names

[ alt_names ]
${san_entries}
EOF
}

# Generate OpenSSL configuration for client certificate
setup_openssl_client_config() {
    local hosts="$1"

    # Build SAN entries
    local san_entries=""
    local dns_count=1
    local ip_count=1

    IFS=',' read -ra HOST_ARRAY <<< "$hosts"
    for host in "${HOST_ARRAY[@]}"; do
        host=$(echo "$host" | xargs)  # trim whitespace
        [[ -z "$host" ]] && continue
        # Check if it's an IP address
        if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            san_entries="${san_entries}IP.${ip_count} = ${host}"$'\n'
            ip_count=$((ip_count + 1))
        else
            san_entries="${san_entries}DNS.${dns_count} = ${host}"$'\n'
            dns_count=$((dns_count + 1))
        fi
    done

    if [ -z "$san_entries" ]; then
        echo "DNS.1 = localhost" >> /tmp/san_fallback
        san_entries=$(cat /tmp/san_fallback)
    fi

    cat >"$OPENSSL_CLIENT_CNF" <<EOF
[ req ]
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = CN
ST = Beijing
L  = Shaanxi
O  = DevGroup
OU = System
CN = appmesh-client

[ req_ext ]
subjectAltName = critical,@alt_names

[ v3_client ]
basicConstraints    = CA:FALSE
keyUsage            = critical, digitalSignature, keyEncipherment
extendedKeyUsage    = clientAuth
subjectAltName      = @alt_names

[ alt_names ]
${san_entries}
EOF
}

resolve_host_addresses() {
    local entries=()
    local ip

    ########################################################################
    # 1. Mandatory SANs (TLS-safe defaults)
    ########################################################################
    entries+=("localhost")
    entries+=("127.0.0.1")

    ########################################################################
    # 2. Hostnames
    ########################################################################

    # Short hostname
    if command -v hostname >/dev/null 2>&1; then
        local hn
        hn=$(hostname 2>/dev/null)
        [ -n "$hn" ] && entries+=("$hn")
    fi

    # FQDN (Linux, sometimes works on macOS)
    if hostname -f >/dev/null 2>&1; then
        local fqdn
        fqdn=$(hostname -f 2>/dev/null)
        [ -n "$fqdn" ] && entries+=("$fqdn")
    fi

    # macOS LocalHostName (more reliable than hostname -f)
    if [[ "$OSTYPE" == "darwin"* ]] && command -v scutil >/dev/null 2>&1; then
        local mac_name
        mac_name=$(scutil --get LocalHostName 2>/dev/null)
        [ -n "$mac_name" ] && entries+=("$mac_name")
    fi

    ########################################################################
    # 3. IP address discovery
    ########################################################################

    if [[ "$OSTYPE" == "linux"* ]]; then

        # CentOS 7, Ubuntu 16/22 (preferred)
        if hostname -I >/dev/null 2>&1; then
            for ip in $(hostname -I 2>/dev/null); do
                [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && entries+=("$ip")
            done
        fi

        # Fallback: iproute2
        if command -v ip >/dev/null 2>&1; then
            while read -r ip; do
                entries+=("$ip")
            done < <(
                ip -4 addr show 2>/dev/null |
                awk '/inet / && !/127\.0\.0\.1/ { sub(/\/.*/, "", $2); print $2 }'
            )
        fi

        # Fallback: ifconfig (older systems)
        if command -v ifconfig >/dev/null 2>&1; then
            while read -r ip; do
                entries+=("$ip")
            done < <(
                ifconfig 2>/dev/null |
                awk '/inet / && !/127\.0\.0\.1/ { print $2 }' |
                sed 's/addr://'
            )
        fi

    elif [[ "$OSTYPE" == "darwin"* ]]; then

        # macOS IP discovery
        if command -v ifconfig >/dev/null 2>&1; then
            while read -r ip; do
                entries+=("$ip")
            done < <(
                ifconfig 2>/dev/null |
                awk '/inet / && !/127\.0\.0\.1/ { print $2 }'
            )
        fi
    fi

    ########################################################################
    # 4. Normalize output
    #    - remove empty lines
    #    - sort
    #    - unique
    #    - comma-separated
    ########################################################################

    local result
    result=$(
        printf "%s\n" "${entries[@]}" |
        sed '/^$/d' |
        sort -u |
        paste -sd,
    )

    ########################################################################
    # 5. Absolute safety net (never return empty)
    ########################################################################
    if [ -z "$result" ]; then
        result="localhost,127.0.0.1"
    fi

    echo "$result"
}

# Create certificates using cfssl
create_certificates_cfssl() {
    local hosts="$1"
    local hostname_short
    hostname_short=$(hostname)

    log "Generating CA certificate (cfssl)..."
    cfssl gencert -initca "$CA_CSR" | cfssljson -bare ca -

    log "Generating server certificate (cfssl)..."
    echo '{"CN":"'"$hostname_short"'","hosts":[""],"key":{"algo":"ecdsa","size":256}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$CA_CONFIG" -profile=server -hostname="$hosts" - | cfssljson -bare server

    log "Generating client certificate (cfssl)..."
    echo '{"CN":"appmesh-client","hosts":[""],"key":{"algo":"ecdsa","size":256}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$CA_CONFIG" -profile=client -hostname="$hosts" - | cfssljson -bare client
}

# Create certificates using pure openssl
create_certificates_openssl() {
    local hosts="$1"

    # Setup OpenSSL configuration files
    setup_openssl_ca_config
    setup_openssl_server_config "$hosts"
    setup_openssl_client_config "$hosts"

    log "Generating CA private key (openssl)..."
    openssl ecparam -genkey -name prime256v1 -noout -out ca-key.pem
    if [ $? -ne 0 ]; then
        log "Error: Failed to generate CA private key"
        return 1
    fi

    log "Generating CA certificate (openssl)..."
    openssl req -new -x509 -days $CERT_VALIDITY_DAYS -key ca-key.pem -out ca.pem -config "$OPENSSL_CA_CNF"
    if [ $? -ne 0 ]; then
        log "Error: Failed to generate CA certificate"
        return 1
    fi

    log "Generating server private key (openssl)..."
    openssl ecparam -genkey -name prime256v1 -noout -out server-key.pem
    if [ $? -ne 0 ]; then
        log "Error: Failed to generate server private key"
        return 1
    fi

    log "Generating server CSR (openssl)..."
    openssl req -new -key server-key.pem -out server.csr -config "$OPENSSL_SERVER_CNF"
    if [ $? -ne 0 ]; then
        log "Error: Failed to generate server CSR"
        return 1
    fi

    log "Signing server certificate (openssl)..."
    openssl x509 -req -days $CERT_VALIDITY_DAYS -in server.csr -CA ca.pem -CAkey ca-key.pem \
        -CAcreateserial -out server.pem -extfile "$OPENSSL_SERVER_CNF" -extensions v3_server
    if [ $? -ne 0 ]; then
        log "Error: Failed to sign server certificate"
        return 1
    fi

    log "Generating client private key (openssl)..."
    openssl ecparam -genkey -name prime256v1 -noout -out client-key.pem
    if [ $? -ne 0 ]; then
        log "Error: Failed to generate client private key"
        return 1
    fi

    log "Generating client CSR (openssl)..."
    openssl req -new -key client-key.pem -out client.csr -config "$OPENSSL_CLIENT_CNF"
    if [ $? -ne 0 ]; then
        log "Error: Failed to generate client CSR"
        return 1
    fi

    log "Signing client certificate (openssl)..."
    openssl x509 -req -days $CERT_VALIDITY_DAYS -in client.csr -CA ca.pem -CAkey ca-key.pem \
        -CAcreateserial -out client.pem -extfile "$OPENSSL_CLIENT_CNF" -extensions v3_client
    if [ $? -ne 0 ]; then
        log "Error: Failed to sign client certificate"
        return 1
    fi

    # Cleanup CSR files
    rm -f server.csr client.csr

    return 0
}

create_certificates() {
    local hosts="$1"

    if [ "$USE_CFSSL" = true ]; then
        create_certificates_cfssl "$hosts"
    else
        create_certificates_openssl "$hosts"
    fi
}

validate_certs() {
    local error_count=0
    log "Verifying certificates..."

    # Verify CA certificate
    log "Verifying CA certificate..."
    if openssl x509 -in ca.pem -text -noout >/dev/null 2>&1; then
        log "✓ CA certificate is valid"

        # Show CA certificate details
        log "CA certificate details:"
        openssl x509 -in ca.pem -noout -subject -issuer -dates 2>/dev/null | sed 's/^/    /'
    else
        log "✗ CA certificate verification failed"
        error_count=$((error_count + 1))
    fi

    # Verify server certificate and key
    log "Verifying server certificate and key..."
    if openssl ec -in server-key.pem -noout 2>/dev/null; then
        cert_hash=$(openssl x509 -in server.pem -pubkey -noout | openssl sha256)
        key_hash=$(openssl ec -in server-key.pem -pubout | openssl sha256)
        if [ "$cert_hash" = "$key_hash" ]; then
            log "✓ Server certificate and private key match"
        else
            log "✗ Server certificate and private key do not match"
            error_count=$((error_count + 1))
        fi
    else
        log "✗ Invalid server private key"
        error_count=$((error_count + 1))
    fi

    # Verify client certificate and key
    log "Verifying client certificate and key..."
    if openssl ec -in client-key.pem -noout 2>/dev/null; then
        cert_hash=$(openssl x509 -in client.pem -pubkey -noout | openssl sha256)
        key_hash=$(openssl ec -in client-key.pem -pubout | openssl sha256)
        if [ "$cert_hash" = "$key_hash" ]; then
            log "✓ Client certificate and private key match"
        else
            log "✗ Client certificate and private key do not match"
            error_count=$((error_count + 1))
        fi
    else
        log "✗ Invalid client private key"
        error_count=$((error_count + 1))
    fi

    # Verify certificate chain
    log "Verifying certificate chain..."
    if openssl verify -CAfile ca.pem server.pem >/dev/null 2>&1; then
        log "✓ Server certificate chain is valid"
    else
        log "✗ Server certificate chain verification failed"
        error_count=$((error_count + 1))
    fi

    if openssl verify -CAfile ca.pem client.pem >/dev/null 2>&1; then
        log "✓ Client certificate chain is valid"
    else
        log "✗ Client certificate chain verification failed"
        error_count=$((error_count + 1))
    fi

    # Display SAN entries for server certificate
    log "Server certificate SAN entries:"
    openssl x509 -in server.pem -noout -ext subjectAltName 2>/dev/null | sed 's/^/    /' || log "    (no SAN entries found)"

    return $error_count
}

remove_temp_files() {
    log "Cleaning up configuration files..."
    rm -f "$CA_CONFIG" "$CA_CSR" "$OPENSSL_CA_CNF" "$OPENSSL_SERVER_CNF" "$OPENSSL_CLIENT_CNF"
    rm -f ca.srl  # Serial file created by openssl
}

generate_es256_keypair() {
    log "Generating ECDSA keys for JWT ES256..."
    
    # Check if output files already exist
    if [ -f jwt-ec-private.pem ] || [ -f jwt-ec-public.pem ]; then
        log "Warning: JWT EC key files already exist, skipping generation"
        return 0
    fi

    # Generate private key in PKCS#8 format for better cross-language compatibility
    local temp_key="jwt-ec-temp.pem"
    if ! openssl ecparam -genkey -name prime256v1 -noout -out "$temp_key"; then
        log "Error: Failed to generate private EC key"
        rm -f "$temp_key"
        return 1
    fi

    # Convert to PKCS#8 format for better compatibility with C++/Go/Python
    if ! openssl pkcs8 -topk8 -nocrypt -in "$temp_key" -out jwt-ec-private.pem; then
        log "Error: Failed to convert EC key to PKCS#8 format"
        rm -f "$temp_key"
        return 1
    fi
    rm -f "$temp_key"

    # Generate public key
    if ! openssl ec -in jwt-ec-private.pem -pubout -out jwt-ec-public.pem 2>/dev/null; then
        log "Error: Failed to generate public EC key"
        return 1
    fi

    # Verify the keys match
    local priv_hash pub_hash
    priv_hash=$(openssl ec -in jwt-ec-private.pem -pubout -outform DER 2>/dev/null | openssl sha256)
    pub_hash=$(openssl ec -in jwt-ec-public.pem -pubin -outform DER 2>/dev/null | openssl sha256)
    
    if [ "$priv_hash" = "$pub_hash" ]; then
        log "✓ Successfully created and verified jwt-ec-private.pem and jwt-ec-public.pem"
        return 0
    else
        log "Error: Key verification failed"
        return 1
    fi
}

generate_rs256_keypair() {
    log "Converting SSL keys to JWT format..."
    
    # Check if input files exist
    if [ ! -f server-key.pem ] || [ ! -f server.pem ]; then
        log "Error: Required input files (server-key.pem, server.pem) not found"
        return 1
    fi

    # Check if output files already exist
    if [ -f jwt-private.pem ] || [ -f jwt-public.pem ]; then
        log "Warning: JWT key files already exist, skipping conversion"
        return 0
    fi

    # Convert private key to PKCS#8 format for cross-language compatibility
    if ! openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in server-key.pem -out jwt-private.pem; then
        log "Error: Failed to convert private key"
        return 1
    fi

    # Extract public key from certificate
    if ! openssl x509 -pubkey -noout -in server.pem > jwt-public.pem; then
        log "Error: Failed to extract public key"
        return 1
    fi

    log "✓ Successfully created jwt-private.pem and jwt-public.pem"
}

main() {
    log "Starting SSL certificate generation..."

    ensure_dependencies
    
    PATH="$PATH:$WORKING_DIR"

    setup_ca_config
    setup_ca_csr

    local hosts
    hosts=$(resolve_host_addresses)
    if [ -z "$hosts" ]; then
        hosts="localhost,127.0.0.1"
    fi
    log "Using hosts: $hosts"

    create_certificates "$hosts"

    if validate_certs; then
        log "All certificates verified successfully"
    else
        log "Certificate verification failed"
        exit 1
    fi

    generate_rs256_keypair
    generate_es256_keypair
    remove_temp_files

    log "Certificate generation completed successfully"
    log "Generated files: ca.pem, ca-key.pem, server.pem, server-key.pem, client.pem, client-key.pem"

    # Display test commands
    log "To test the certificates, you can use these commands:"
    log "Server test:"
    log "    openssl s_server -cert server.pem -key server-key.pem -CAfile ca.pem -verify 1 -port 8443"
    log "Client test:"
    log "    openssl s_client -cert client.pem -key client-key.pem -CAfile ca.pem -verify 1 -connect localhost:8443"
}

# Run main function
main "$@"
