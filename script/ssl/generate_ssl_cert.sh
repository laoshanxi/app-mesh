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
PATH=${WORKING_DIR}:${PATH:-}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $@"
}

ensure_dependencies() {
    for cmd in cfssl cfssljson hostname openssl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log "Error: Missing required dependency: $cmd"
            exit 1
        fi
    done
}

setup_ca_config() {
    cat >"$CA_CONFIG" <<EOF
{
    "signing": {
        "default": {
            "expiry": "87600h"
        },
        "profiles": {
            "client": {
                "expiry": "87600h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "client auth"
                ]
            },
            "server": {
                "expiry": "87600h",
                "usages": [
                    "signing",
                    "key encipherment",
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

resolve_host_addresses() {
    local ip_addresses hostname_long hostname_short

    # Get IP addresses
    if [[ "$OSTYPE" == "linux"* ]]; then
        # Linux: Use `hostname -I`
        ip_addresses=$(hostname -I | tr ' ' ',' | sed 's/,$//' | grep -oP '(\d+\.\d+\.\d+\.\d+)')
    else
        # macOS: Use `ifconfig` to get IP addresses
        ip_addresses=$(ifconfig | grep -E 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
    fi

    # Get hostnames
    if [[ "$OSTYPE" == "linux"* ]]; then
        hostname_long=$(hostname --fqdn 2>/dev/null || hostname)
    else
        hostname_long=$(hostname)
    fi
    hostname_short=$(hostname)

    # Combine all hosts with localhost entries
    echo "${hostname_short},${hostname_long},${ip_addresses},localhost,127.0.0.1" | tr ',' '\n' | sort -u -r | tr '\n' ',' | sed 's/,$//'
}

create_certificates() {
    local hosts="$1"
    local hostname_short=$(hostname)

    log "Generating CA certificate..."
    cfssl gencert -initca "$CA_CSR" | cfssljson -bare ca -

    log "Generating server certificate..."
    echo '{"CN":"'"$hostname_short"'","hosts":[""],"key":{"algo":"ecdsa","size":256}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$CA_CONFIG" -profile=server -hostname="$hosts" - | cfssljson -bare server

    # Combine fullchain for multiple level (not include root CA)
    # log "Generating server fullchain certificate..."
    # cat server.pem ca.pem > server_fullchain.pem

    log "Generating client certificate..."
    echo '{"CN":"appmesh-client","hosts":[""],"key":{"algo":"ecdsa","size":256}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$CA_CONFIG" -profile=client -hostname="$hosts" - | cfssljson -bare client
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
        openssl x509 -in ca.pem -noout -subject -issuer -dates | sed 's/^/    /'
    else
        log "✗ CA certificate verification failed"
        error_count=$((error_count + 1))
    fi

    # Verify server certificate and key
    log "Verifying server certificate and key..."
    if openssl ec -in server-key.pem -noout 2>/dev/null; then
        if openssl x509 -in server.pem -noout -pubkey 2>/dev/null | \
           diff <(openssl ec -in server-key.pem -pubout 2>/dev/null) - >/dev/null 2>&1; then
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
        if openssl x509 -in client.pem -noout -pubkey 2>/dev/null | \
           diff <(openssl ec -in client-key.pem -pubout 2>/dev/null) - >/dev/null 2>&1; then
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

    return $error_count
}

remove_temp_files() {
    log "Cleaning up configuration files..."
    rm -f "$CA_CONFIG" "$CA_CSR"
}

generate_es256_keypair() {
    log "Generating ECDSA keys for JWT ES256..."
    
    # Check if output files already exist
    if [ -f jwt-ec-private.pem ] || [ -f jwt-ec-public.pem ]; then
        log "Warning: JWT EC key files already exist, skipping generation"
        return 0
    fi

    # Generate private key
    if ! openssl ecparam -genkey -name prime256v1 -noout -out jwt-ec-private.pem; then
        log "Error: Failed to generate private EC key"
        return 1
    fi

    # Generate public key
    if ! openssl ec -in jwt-ec-private.pem -pubout -out jwt-ec-public.pem; then
        log "Error: Failed to generate public EC key"
        return 1
    fi

    # Verify the keys match
    if openssl ec -in jwt-ec-private.pem -pubout -outform DER | openssl sha256 >/tmp/priv.sha256 &&
       openssl ec -in jwt-ec-public.pem -pubin -outform DER | openssl sha256 >/tmp/pub.sha256 &&
       cmp -s /tmp/priv.sha256 /tmp/pub.sha256; then
        log "✓ Successfully created and verified jwt-ec-private.pem and jwt-ec-public.pem"
        rm -f /tmp/priv.sha256 /tmp/pub.sha256
        return 0
    else
        log "Error: Key verification failed"
        rm -f /tmp/priv.sha256 /tmp/pub.sha256
        return 1
    fi
}

generate_rs256_keypair() {
    log "Converting SSL keys to JWT RS256 format..."
    
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

    # Convert private key to PKCS#8 format
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
