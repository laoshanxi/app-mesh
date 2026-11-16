#!/bin/sh
# Vault operator sidecar for the compose cluster: initialize once, unseal
# whenever sealed (a file-storage Vault restarts sealed), enable the engines
# the cluster uses, and hand the engine owner a scoped service token.
# Idempotent; safe to restart. Mounted verbatim (compose configs file: source
# does not interpolate), so plain shell syntax works here.
set -eu
umask 077
STATE=/vault-init-state/init.json
# The official image drops to its vault user (resolve the name: the uid
# differs across image families); this sidecar runs as root, so it prepares
# the writable mounts the server needs. Idempotent no-ops when ownership
# already matches.
[ -d /vault/data ] && chown -R vault:vault /vault/data 2>/dev/null || true
[ -d /vault/audit ] && chown -R vault:vault /vault/audit 2>/dev/null || true
# Wait for the API port, not `vault status`: that exits non-zero (2) for an
# uninitialized or sealed server, so it cannot gate this wait. busybox (the
# official image) ships nc but no curl; the local base ships curl but no nc.
api_up() {
    # Pure shell parsing: busybox sed rejects several standard s||| forms.
    host=${VAULT_ADDR#*//}
    host=${host%%:*}
    port=${VAULT_ADDR##*:}
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 3 "$host" "$port" 2>/dev/null
    else
        curl -s -o /dev/null --max-time 3 "$VAULT_ADDR/v1/sys/health"
    fi
}
while ! api_up; do sleep 2; done
if [ ! -f "$STATE" ]; then
    vault operator init -key-shares=1 -key-threshold=1 -format=json >"$STATE"
    chmod 600 "$STATE"
fi
# The JSON is pretty-printed: the single unseal key sits on the line after
# the field name.
KEY=$(sed -n '/"unseal_keys_b64"/{n;p}' "$STATE" | tr -d ' ",')
ROOT=$(awk -F'"' '/"root_token"/{print $4}' "$STATE")

unseal_until_ready() {
    while vault status -format=json 2>/dev/null | grep -q '"sealed": *true'; do
        # The key goes as an argument: `unseal -` would pass the literal "-"
        # as the key, which the server rejects as an invalid format.
        vault operator unseal "$KEY" >/dev/null
        sleep 1
    done
}
unseal_until_ready
export VAULT_TOKEN="$ROOT"

# KV v2 at secret/, AppRole for machine identities, the audit device, and the
# PKI engine behind the cluster CA (all no-ops when already present).
vault secrets list | grep -q 'secret/' || vault secrets enable -path=secret kv-v2
vault auth list | grep -q 'approle/' || vault auth enable approle
vault audit list | grep -q '^file/' || vault audit enable file file_path=/vault/audit/audit.log
vault secrets list | grep -q '^pki/' || vault secrets enable -path=pki pki
# One trust domain signs every node's leaf certificate; the CA private key
# never leaves Vault. The CA lifetime mirrors the self-signed generator's
# 10-year root, the role's 825-day leaf its server/client pairs.
vault secrets tune -max-lease-ttl=87600h pki
# Roots predating the subject-bearing generation carry an empty subject, and
# strict-chain clients (macOS SecureTransport among them) reject those leaves
# outright. Existence alone cannot stay the only guard: warn loudly instead
# of silently keeping one, because re-creating the root invalidates every
# issued leaf.
if ! vault read pki/cert/ca >/dev/null 2>&1; then
    vault write pki/root/generate/internal \
        common_name="AppMesh Root CA" issuer_name=appmesh-root \
        key_type=ec key_bits=256 ttl=87600h >/dev/null
    touch "$STATE.root-subject-ok"
elif [ ! -f "$STATE.root-subject-ok" ]; then
    echo "WARNING: the existing PKI root predates the subject-bearing root (common_name=\"AppMesh Root CA\"). Strict-chain clients will reject its leaves. To migrate: 'vault secrets disable pki' and restart this sidecar (invalidates every issued leaf)." >&2
fi
# Upsert, unlike an AppRole, is safe to repeat: one role issues both server
# and client certificates (the generator's cfssl profiles carry both usages).
# enforce_hostnames stays off because container hostnames carry underscores;
# Vault drops underscore DNS SANs outright no matter the role (an early
# validation, hashicorp/vault#31925), so the overlay dials the hyphenated
# network alias instead.
vault write pki/roles/appmesh-node \
    allow_any_name=true server_flag=true client_flag=true \
    key_type=ec key_bits=256 ttl=19800h max_ttl=19800h \
    enforce_hostnames=false >/dev/null

# Scoped owner policy for the appmesh engine bootstrap: manage the
# replication KV path, follower policies and follower AppRoles, and issue
# the node's own TLS certificates from the cluster CA.
vault policy write appmesh-replication-owner - <<'HCL'
path "secret/data/appmesh/replication/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/appmesh/replication" {
    capabilities = ["list"]
}
path "secret/metadata/appmesh/replication/*" {
    capabilities = ["read", "list", "delete"]
}
path "pki/issue/appmesh-node" {
    capabilities = ["create", "update"]
}
path "sys/policies/acl/appmesh-follower-*" {
    capabilities = ["create", "read", "update"]
}
path "auth/approle/role/appmesh-follower-*" {
    capabilities = ["create", "read", "update", "delete"]
}
HCL

if [ ! -f /replication/owner.vault-token ]; then
    # An explicit TTL matching the root's horizon: "-ttl=0" silently falls
    # back to the system default (32 days) and nothing renews a service
    # token, so the cluster would stop replicating a month in without this.
    vault token create -policy=appmesh-replication-owner -ttl=87600h \
        -display-name=appmesh-replication-owner -format=json |
        awk -F'"' '/"client_token"/{print $4; exit}' >/replication/owner.vault-token
    chmod 600 /replication/owner.vault-token
fi
# The appmesh owner (uid 482) must read the token this root sidecar wrote.
chown 482:482 /replication/owner.vault-token 2>/dev/null || true

# Watchdog: keep the server unsealed across restarts.
while true; do
    unseal_until_ready
    sleep 10
done
