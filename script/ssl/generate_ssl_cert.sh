#!/usr/bin/env bash
################################################################################
## Self-Signed SSL Certificate Generator
## Generates CA, server, and client certificates using ECDSA (prime256v1)
##
## References:
## https://www.bookstack.cn/read/tidb-v2.1/how-to-secure-generate-self-signed-certificates.md
## https://www.cnblogs.com/fanqisoft/p/10765038.html
## https://blog.csdn.net/kozazyh/article/details/79844609
## https://github.com/cloudflare/cfssl/wiki/Creating-a-new-CSR
## https://github.com/coreos/docs/blob/master/os/generate-self-signed-certificates.md
################################################################################

set -euo pipefail

#===============================================================================
# Configuration
#===============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CERT_VALIDITY_DAYS=3650
readonly CERT_VALIDITY_HOURS="87600h"
readonly KEY_ALGO="ecdsa"
readonly KEY_SIZE=256
readonly EC_CURVE="prime256v1"

# Certificate subject defaults
readonly CERT_COUNTRY="CN"
readonly CERT_STATE="Beijing"
readonly CERT_LOCALITY="Shaanxi"
readonly CERT_ORG="DevGroup"
readonly CERT_OU="System"
readonly CERT_CA_CN="AppMesh"
readonly CERT_CLIENT_CN="appmesh-client"

# Tool detection flag
USE_CFSSL=false
# TODO: macOS keep use cfssl due to SAN and CA extensions compatibility on different OpenSSL versions
export PATH="/opt/appmesh/ssl/:$PATH"

#===============================================================================
# Utility Functions
#===============================================================================

log() {
    printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

log_success() {
    log "+ $*"
}

log_error() {
    log "X $*" >&2
}

die() {
    log_error "$*"
    exit 1
}

cleanup_file() {
    [[ -f "$1" ]] && rm -f "$1"
}

#===============================================================================
# Dependency Check
#===============================================================================

check_dependencies() {
    command -v openssl >/dev/null 2>&1 || die "Required: openssl"
    command -v hostname >/dev/null 2>&1 || die "Required: hostname"

    if command -v cfssl >/dev/null 2>&1 && command -v cfssljson >/dev/null 2>&1; then
        USE_CFSSL=true
        log "Using cfssl for certificate generation"
    else
        log "Using pure openssl for certificate generation"
    fi
}

#===============================================================================
# Host Discovery
#===============================================================================

get_host_addresses() {
    local -a hosts=("localhost" "127.0.0.1")
    local ip

    # Hostname
    local hn
    hn=$(hostname 2>/dev/null) && [[ -n "$hn" ]] && hosts+=("$hn")

    # FQDN
    if hostname -f >/dev/null 2>&1; then
        local fqdn
        fqdn=$(hostname -f 2>/dev/null) && [[ -n "$fqdn" ]] && hosts+=("$fqdn")
    fi

    # macOS LocalHostName
    if [[ "${OSTYPE:-}" == darwin* ]] && command -v scutil >/dev/null 2>&1; then
        local mac_name
        mac_name=$(scutil --get LocalHostName 2>/dev/null) && [[ -n "$mac_name" ]] && hosts+=("$mac_name")
    fi

    # IP addresses
    if [[ "${OSTYPE:-}" == linux* ]]; then
        # Linux: hostname -I or ip command
        if hostname -I >/dev/null 2>&1; then
            for ip in $(hostname -I 2>/dev/null); do
                [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && hosts+=("$ip")
            done
        elif command -v ip >/dev/null 2>&1; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && hosts+=("$ip")
            done < <(ip -4 addr show 2>/dev/null | awk '/inet / && !/127\.0\.0\.1/ {sub(/\/.*/, "", $2); print $2}')
        fi
    elif [[ "${OSTYPE:-}" == darwin* ]]; then
        # macOS: ifconfig
        if command -v ifconfig >/dev/null 2>&1; then
            while IFS= read -r ip; do
                [[ -n "$ip" ]] && hosts+=("$ip")
            done < <(ifconfig 2>/dev/null | awk '/inet / && !/127\.0\.0\.1/ {print $2}')
        fi
    fi

    # Deduplicate and format
    printf "%s\n" "${hosts[@]}" | sort -u | paste -sd, -
}

#===============================================================================
# CFSSL Certificate Generation
#===============================================================================

generate_cfssl_ca_config() {
    cat <<EOF
{
  "signing": {
    "default": {"expiry": "${CERT_VALIDITY_HOURS}"},
    "profiles": {
      "server": {
        "expiry": "${CERT_VALIDITY_HOURS}",
        "usages": ["digital signature", "server auth", "client auth"]
      },
      "client": {
        "expiry": "${CERT_VALIDITY_HOURS}",
        "usages": ["digital signature", "client auth"]
      }
    }
  }
}
EOF
}

generate_cfssl_ca_csr() {
    cat <<EOF
{
  "CN": "${CERT_CA_CN}",
  "key": {"algo": "${KEY_ALGO}", "size": ${KEY_SIZE}},
  "names": [{
    "C": "${CERT_COUNTRY}",
    "ST": "${CERT_STATE}",
    "L": "${CERT_LOCALITY}",
    "O": "${CERT_ORG}",
    "OU": "${CERT_OU}"
  }]
}
EOF
}

generate_cfssl_cert_csr() {
    local cn="$1"
    cat <<EOF
{"CN": "${cn}", "hosts": [""], "key": {"algo": "${KEY_ALGO}", "size": ${KEY_SIZE}}}
EOF
}

create_certs_cfssl() {
    local hosts="$1"
    local server_cn
    server_cn=$(hostname 2>/dev/null || echo "AppMesh-Server")
    [[ ${#server_cn} -gt 64 ]] && server_cn="AppMesh-Server"

    local ca_config="ca-config.json"
    local ca_csr="ca-csr.json"

    log "Generating CA certificate..."
    generate_cfssl_ca_config > "$ca_config"
    generate_cfssl_ca_csr > "$ca_csr"
    cfssl gencert -initca "$ca_csr" | cfssljson -bare ca -

    log "Generating server certificate..."
    generate_cfssl_cert_csr "$server_cn" | \
        cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$ca_config" \
            -profile=server -hostname="$hosts" - | cfssljson -bare server

    log "Generating client certificate..."
    generate_cfssl_cert_csr "$CERT_CLIENT_CN" | \
        cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config="$ca_config" \
            -profile=client -hostname="$hosts" - | cfssljson -bare client

    cleanup_file "$ca_config"
    cleanup_file "$ca_csr"
}

#===============================================================================
# OpenSSL Certificate Generation
#===============================================================================

parse_hosts_to_san() {
    local hosts="$1"
    local dns_idx=1
    local ip_idx=1
    local san=""

    IFS=',' read -ra host_array <<< "$hosts"
    for host in "${host_array[@]}"; do
        host=$(echo "$host" | xargs)
        [[ -z "$host" ]] && continue

        if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            san+="IP.${ip_idx} = ${host}"$'\n'
            ((ip_idx++))
        else
            san+="DNS.${dns_idx} = ${host}"$'\n'
            ((dns_idx++))
        fi
    done

    [[ -z "$san" ]] && san="DNS.1 = localhost"$'\n'"IP.1 = 127.0.0.1"$'\n'
    echo "$san"
}

generate_openssl_ca_conf() {
    cat <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
C  = ${CERT_COUNTRY}
ST = ${CERT_STATE}
L  = ${CERT_LOCALITY}
O  = ${CERT_ORG}
OU = ${CERT_OU}
CN = ${CERT_CA_CN}

[v3_ca]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF
}

generate_openssl_server_conf() {
    local cn="$1"
    local san="$2"

    cat <<EOF
[req]
distinguished_name = dn
req_extensions = req_ext
prompt = no

[dn]
C  = ${CERT_COUNTRY}
ST = ${CERT_STATE}
L  = ${CERT_LOCALITY}
O  = ${CERT_ORG}
OU = ${CERT_OU}
CN = ${cn}

[req_ext]
subjectAltName = @alt_names

[v3_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
${san}
EOF
}

generate_openssl_client_conf() {
    local san="$1"

    cat <<EOF
[req]
distinguished_name = dn
req_extensions = req_ext
prompt = no

[dn]
C  = ${CERT_COUNTRY}
ST = ${CERT_STATE}
L  = ${CERT_LOCALITY}
O  = ${CERT_ORG}
OU = ${CERT_OU}
CN = ${CERT_CLIENT_CN}

[req_ext]
subjectAltName = @alt_names

[v3_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
${san}
EOF
}

openssl_gen_key() {
    local keyfile="$1"
    openssl ecparam -genkey -name "$EC_CURVE" -noout -out "$keyfile"
}

openssl_gen_csr() {
    local keyfile="$1"
    local csrfile="$2"
    local config="$3"
    openssl req -new -key "$keyfile" -out "$csrfile" -config "$config"
}

openssl_sign_cert() {
    local csrfile="$1"
    local certfile="$2"
    local config="$3"
    openssl x509 -req -days "$CERT_VALIDITY_DAYS" \
        -in "$csrfile" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
        -out "$certfile" -extfile "$config" -extensions v3_ext
}

create_certs_openssl() {
    local hosts="$1"
    local san
    san=$(parse_hosts_to_san "$hosts")

    local server_cn
    server_cn=$(hostname 2>/dev/null || echo "AppMesh-Server")
    [[ ${#server_cn} -gt 64 ]] && server_cn="AppMesh-Server"

    local ca_conf="openssl-ca.cnf"
    local server_conf="openssl-server.cnf"
    local client_conf="openssl-client.cnf"

    # Generate CA
    log "Generating CA private key..."
    openssl_gen_key ca-key.pem

    log "Generating CA certificate..."
    generate_openssl_ca_conf > "$ca_conf"
    openssl req -new -x509 -days "$CERT_VALIDITY_DAYS" \
        -key ca-key.pem -out ca.pem -config "$ca_conf"

    # Generate server certificate
    log "Generating server private key..."
    openssl_gen_key server-key.pem

    log "Generating server certificate..."
    generate_openssl_server_conf "$server_cn" "$san" > "$server_conf"
    openssl_gen_csr server-key.pem server.csr "$server_conf"
    openssl_sign_cert server.csr server.pem "$server_conf"

    # Generate client certificate
    log "Generating client private key..."
    openssl_gen_key client-key.pem

    log "Generating client certificate..."
    generate_openssl_client_conf "$san" > "$client_conf"
    openssl_gen_csr client-key.pem client.csr "$client_conf"
    openssl_sign_cert client.csr client.pem "$client_conf"

    # Cleanup
    cleanup_file server.csr
    cleanup_file client.csr
    cleanup_file ca.srl
    cleanup_file "$ca_conf"
    cleanup_file "$server_conf"
    cleanup_file "$client_conf"
}

#===============================================================================
# JWT Key Generation
#===============================================================================

generate_jwt_keys() {
    log "Generating JWT keys..."

    # ES256 keypair
    if [[ ! -f jwt-ec-private.pem ]]; then
        local tmpkey="jwt-ec-temp.pem"
        openssl ecparam -genkey -name "$EC_CURVE" -noout -out "$tmpkey"
        openssl pkcs8 -topk8 -nocrypt -in "$tmpkey" -out jwt-ec-private.pem
        openssl ec -in jwt-ec-private.pem -pubout -out jwt-ec-public.pem 2>/dev/null
        cleanup_file "$tmpkey"
        log_success "Generated jwt-ec-private.pem, jwt-ec-public.pem (ES256)"
    fi

    # Convert server key for RS256/ES256 (from server cert)
    if [[ -f server-key.pem && ! -f jwt-private.pem ]]; then
        openssl pkcs8 -topk8 -nocrypt -in server-key.pem -out jwt-private.pem
        openssl x509 -pubkey -noout -in server.pem > jwt-public.pem
        log_success "Generated jwt-private.pem, jwt-public.pem"
    fi
}

#===============================================================================
# Verification
#===============================================================================

verify_key_cert_match() {
    local keyfile="$1"
    local certfile="$2"
    local name="$3"

    if ! openssl ec -in "$keyfile" -noout 2>/dev/null; then
        log_error "Invalid $name private key"
        return 1
    fi

    local cert_hash key_hash
    cert_hash=$(openssl x509 -in "$certfile" -pubkey -noout 2>/dev/null | openssl sha256)
    key_hash=$(openssl ec -in "$keyfile" -pubout 2>/dev/null | openssl sha256)

    if [[ "$cert_hash" == "$key_hash" ]]; then
        log_success "$name certificate and key match"
        return 0
    else
        log_error "$name certificate and key mismatch"
        return 1
    fi
}

verify_chain() {
    local certfile="$1"
    local name="$2"

    if openssl verify -CAfile ca.pem "$certfile" >/dev/null 2>&1; then
        log_success "$name certificate chain valid"
        return 0
    else
        log_error "$name certificate chain invalid"
        return 1
    fi
}

verify_certificates() {
    log "Verifying certificates..."
    local errors=0

    # CA certificate
    if openssl x509 -in ca.pem -noout 2>/dev/null; then
        log_success "CA certificate valid"
        log "  Subject: $(openssl x509 -in ca.pem -noout -subject 2>/dev/null | sed 's/subject=//')"
        log "  Expires: $(openssl x509 -in ca.pem -noout -enddate 2>/dev/null | sed 's/notAfter=//')"
    else
        log_error "CA certificate invalid"
        ((errors++))
    fi

    # Server certificate
    verify_key_cert_match server-key.pem server.pem "Server" || ((errors++))
    verify_chain server.pem "Server" || ((errors++))

    # Client certificate
    verify_key_cert_match client-key.pem client.pem "Client" || ((errors++))
    verify_chain client.pem "Client" || ((errors++))

    # Show server SAN
    log "Server SAN entries:"
    openssl x509 -in server.pem -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3" | sed 's/^/  /' || log "  (none)"

    return $errors
}

#===============================================================================
# Main
#===============================================================================

main() {
    log "Starting SSL certificate generation..."
    cd "$SCRIPT_DIR"

    check_dependencies

    local hosts
    hosts=$(get_host_addresses)
    log "Hosts: $hosts"

    if [[ "$USE_CFSSL" == true ]]; then
        create_certs_cfssl "$hosts"
    else
        create_certs_openssl "$hosts"
    fi

    if ! verify_certificates; then
        die "Certificate verification failed"
    fi

    generate_jwt_keys

    log "Generated files:"
    log "  CA:     ca.pem, ca-key.pem"
    log "  Server: server.pem, server-key.pem"
    log "  Client: client.pem, client-key.pem"
    log "  JWT:    jwt-private.pem, jwt-public.pem, jwt-ec-private.pem, jwt-ec-public.pem"

    log ""
    log "Test commands:"
    log "  Server: openssl s_server -cert server.pem -key server-key.pem -CAfile ca.pem -Verify 1 -port 8443"
    log "  Client: openssl s_client -cert client.pem -key client-key.pem -CAfile ca.pem -verify 1 -connect localhost:8443"

    log "Certificate generation completed successfully"
}

main "$@"
