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

check_dependencies() {
    for cmd in cfssl cfssljson hostname openssl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log "Error: Missing required dependency: $cmd"
            exit 1
        fi
    done
}

create_ca_config() {
    cat >"$CA_CONFIG" <<EOF
{
    "signing": {
        "default": {
            "expiry": "438000h"
        },
        "profiles": {
            "client": {
                "expiry": "438000h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "client auth"
                ]
            },
            "server": {
                "expiry": "438000h",
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

create_ca_csr() {
    cat >"$CA_CSR" <<EOF
{
    "CN": "AppMesh",
    "key": {
        "algo": "rsa",
        "size": 2048
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

get_hosts_list() {
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

generate_certificates() {
    local hosts="$1"
    local hostname_short=$(hostname)

    log "Generating CA certificate..."
    cfssl gencert -initca "$CA_CSR" | cfssljson -bare ca -

    log "Generating server certificate..."
    echo '{"CN":"'"$hostname_short"'","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$CA_CONFIG" -profile=server -hostname="$hosts" - | cfssljson -bare server

    log "Generating client certificate..."
    echo '{"CN":"appmesh-client","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$CA_CONFIG" -profile=client -hostname="$hosts" - | cfssljson -bare client
}

verify_certificates() {
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

    # Verify server certificate
    log "Verifying server certificate..."
    if openssl verify -CAfile ca.pem server.pem >/dev/null 2>&1; then
        log "✓ Server certificate is valid"

        # Show server certificate details
        log "Server certificate details:"
        openssl x509 -in server.pem -noout -subject -issuer -dates | sed 's/^/    /'
    else
        log "✗ Server certificate verification failed"
        error_count=$((error_count + 1))
    fi

    # Verify client certificate
    log "Verifying client certificate..."
    if openssl verify -CAfile ca.pem client.pem >/dev/null 2>&1; then
        log "✓ Client certificate is valid"

        # Show client certificate details
        log "Client certificate details:"
        openssl x509 -in client.pem -noout -subject -issuer -dates | sed 's/^/    /'
    else
        log "✗ Client certificate verification failed"
        error_count=$((error_count + 1))
    fi

    # Verify private keys match their certificates
    log "Verifying private key matches..."

    # Verify server key pair
    if openssl x509 -noout -modulus -in server.pem | openssl md5 >/tmp/cert.md5 &&
        openssl rsa -noout -modulus -in server-key.pem | openssl md5 >/tmp/key.md5 &&
        cmp -s /tmp/cert.md5 /tmp/key.md5; then
        log "✓ Server certificate and private key match"
    else
        log "✗ Server certificate and private key do not match"
        error_count=$((error_count + 1))
    fi

    # Verify client key pair
    if openssl x509 -noout -modulus -in client.pem | openssl md5 >/tmp/cert.md5 &&
        openssl rsa -noout -modulus -in client-key.pem | openssl md5 >/tmp/key.md5 &&
        cmp -s /tmp/cert.md5 /tmp/key.md5; then
        log "✓ Client certificate and private key match"
    else
        log "✗ Client certificate and private key do not match"
        error_count=$((error_count + 1))
    fi

    # Cleanup temporary files
    rm -f /tmp/cert.md5 /tmp/key.md5

    # Return verification status
    return $error_count
}

cleanup() {
    log "Cleaning up configuration files..."
    rm -f "$CA_CONFIG" "$CA_CSR"
}

main() {
    log "Starting SSL certificate generation..."

    # Check for required dependencies
    check_dependencies

    # Ensure we're in the correct directory
    PATH="$PATH:$WORKING_DIR"

    # Create configuration files
    create_ca_config
    create_ca_csr

    # Get list of hosts
    local hosts
    hosts=$(get_hosts_list)
    log "Using hosts: $hosts"

    # Generate certificates
    generate_certificates "$hosts"

    # Verify certificates
    if verify_certificates; then
        log "All certificates verified successfully"
    else
        log "Certificate verification failed"
        exit 1
    fi

    # Cleanup temporary files
    cleanup

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
