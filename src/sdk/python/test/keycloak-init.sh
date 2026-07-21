#!/usr/bin/env bash
# Start + initialize Keycloak for App Mesh OAuth2 (Keycloak) mode.
# Requires: curl, jq, python3; docker (only to start a new instance).
#
# Creates: realm `appmesh-realm`, confidential client `appmesh-client` (direct grant +
# service account), all App Mesh permission keys as client roles, user `mesh`/`mesh123`
# with every role assigned, and the service-account realm-management roles the daemon's
# admin-API profile lookup needs. Re-running tolerates "already exists".
#
# The client secret is printed to stdout by default. Set KC_SECRET_FILE=/path to instead
# write it to that file (kept out of terminal output) — useful in shared/logged sessions.
set -euo pipefail

KC_CONTAINER=${KC_CONTAINER:-keycloak-appmesh}
KC_URL=${KC_URL:-http://localhost:8080}
KC_ADMIN=${KC_ADMIN:-admin}
KC_ADMIN_PWD=${KC_ADMIN_PWD:-admin}
REALM=${REALM:-appmesh-realm}
CLIENT_ID=${CLIENT_ID:-appmesh-client}
TEST_USER=${TEST_USER:-mesh}
TEST_PWD=${TEST_PWD:-mesh123}
KC_SECRET_FILE=${KC_SECRET_FILE:-}

# The exact App Mesh permission keys (from daemon PERMISSION_KEY_* — must match byte-for-byte).
PERMISSION_KEYS=(
  app-control app-delete app-output-view app-reg app-run-async app-run-async-output
  app-run-sync app-run-task app-subscribe app-view app-view-all config-set config-view
  file-download file-upload host-resource-view label-delete label-set label-view
  passwd-change-self passwd-change-user permission-list role-delete role-set role-view
  user-add user-delete user-list user-lock user-token-renew user-totp-active
  user-totp-disable user-unlock
)

# 1) Start Keycloak only if it is not already reachable (adapts to an already-running instance
#    regardless of its container name).
if curl -fsS "$KC_URL/realms/master/.well-known/openid-configuration" >/dev/null 2>&1; then
  echo "==> Keycloak already reachable at $KC_URL"
else
  echo "==> starting Keycloak container '$KC_CONTAINER'"
  docker run -d --restart=always -p 8080:8080 \
    -e KEYCLOAK_ADMIN="$KC_ADMIN" -e KEYCLOAK_ADMIN_PASSWORD="$KC_ADMIN_PWD" \
    --name "$KC_CONTAINER" quay.io/keycloak/keycloak:latest start-dev >/dev/null
  echo "==> waiting for Keycloak at $KC_URL"
  for i in $(seq 1 60); do
    curl -fsS "$KC_URL/realms/master/.well-known/openid-configuration" >/dev/null 2>&1 && break
    sleep 2
    [ "$i" = 60 ] && { echo "Keycloak did not become ready"; exit 1; }
  done
fi

adm() { # authenticated admin REST call: adm METHOD PATH [json-body]
  local method=$1 path=$2 body=${3:-}
  local args=(-fsS -X "$method" "$KC_URL/admin$path" -H "Authorization: Bearer $TOKEN")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
  curl "${args[@]}"
}

TOKEN=$(curl -fsS -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  -d username="$KC_ADMIN" -d password="$KC_ADMIN_PWD" | jq -r .access_token)

# 2) Realm.
echo "==> realm: $REALM"
adm POST /realms "{\"realm\":\"$REALM\",\"enabled\":true}" 2>/dev/null || echo "   (realm exists)"

# 2b) Disable default required actions so direct-grant login isn't blocked (Verify Profile, etc.).
for alias in $(adm GET "/realms/$REALM/authentication/required-actions" | jq -r '.[].alias'); do
  cur=$(adm GET "/realms/$REALM/authentication/required-actions/$alias")
  adm PUT "/realms/$REALM/authentication/required-actions/$alias" \
    "$(echo "$cur" | jq '.enabled=false | .defaultAction=false')" >/dev/null || true
done

# 3) Confidential client with direct-access-grant + service account.
echo "==> client: $CLIENT_ID"
adm POST "/realms/$REALM/clients" "{
  \"clientId\":\"$CLIENT_ID\",\"enabled\":true,\"protocol\":\"openid-connect\",
  \"publicClient\":false,\"serviceAccountsEnabled\":true,
  \"directAccessGrantsEnabled\":true,\"standardFlowEnabled\":true
}" 2>/dev/null || echo "   (client exists)"

CUUID=$(adm GET "/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
SECRET=$(adm GET "/realms/$REALM/clients/$CUUID/client-secret" | jq -r '.value')

# 4) Client roles = permission keys.
echo "==> creating ${#PERMISSION_KEYS[@]} client roles"
for key in "${PERMISSION_KEYS[@]}"; do
  adm POST "/realms/$REALM/clients/$CUUID/roles" "{\"name\":\"$key\"}" 2>/dev/null || true
done
ROLE_REPS=$(adm GET "/realms/$REALM/clients/$CUUID/roles" | jq -c '[.[] | {id,name}]')

# 5) Test user + assign every client role.
echo "==> user: $TEST_USER"
adm POST "/realms/$REALM/users" "{
  \"username\":\"$TEST_USER\",\"enabled\":true,\"emailVerified\":true,
  \"email\":\"$TEST_USER@appmesh.com\",\"requiredActions\":[],
  \"credentials\":[{\"type\":\"password\",\"value\":\"$TEST_PWD\",\"temporary\":false}]
}" 2>/dev/null || echo "   (user exists)"
UUID=$(adm GET "/realms/$REALM/users?username=$TEST_USER&exact=true" | jq -r '.[0].id')
adm POST "/realms/$REALM/users/$UUID/role-mappings/clients/$CUUID" "$ROLE_REPS" >/dev/null

# 6) Service-account realm-management roles (view-users, view-clients) for the admin-API lookup.
echo "==> granting service-account admin roles"
SA_UID=$(adm GET "/realms/$REALM/clients/$CUUID/service-account-user" | jq -r '.id')
RM_UUID=$(adm GET "/realms/$REALM/clients?clientId=realm-management" | jq -r '.[0].id')
RM_REPS=$(adm GET "/realms/$REALM/clients/$RM_UUID/roles" \
  | jq -c '[.[] | select(.name=="view-users" or .name=="view-clients") | {id,name}]')
adm POST "/realms/$REALM/users/$SA_UID/role-mappings/clients/$RM_UUID" "$RM_REPS" >/dev/null

# 7) Emit the client secret (to a file if KC_SECRET_FILE is set, else stdout).
if [ -n "$KC_SECRET_FILE" ]; then
  umask 077; printf 'export APPMESH_Keycloak_client_secret=%s\n' "$SECRET" > "$KC_SECRET_FILE"
  SECRET_LINE="Client secret: written to $KC_SECRET_FILE  (source it to export APPMESH_Keycloak_client_secret)"
else
  SECRET_LINE="Client secret: $SECRET"
fi

# 8) Self-verify (Keycloak layer, no App Mesh daemon needed): password-grant login and
#    confirm the issued token carries this client's roles (== App Mesh permissions).
echo "==> verifying: password-grant login for $TEST_USER"
VTOKEN=$(curl -fsS -X POST "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=password -d client_id="$CLIENT_ID" \
  --data-urlencode "client_secret=$SECRET" \
  -d username="$TEST_USER" -d password="$TEST_PWD" -d scope="openid profile email" \
  | jq -r .access_token)
NROLES=$(printf '%s' "$VTOKEN" | python3 -c '
import sys, base64, json
p = sys.stdin.read().split(".")[1]; p += "=" * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
print(len(c.get("resource_access", {}).get(sys.argv[1], {}).get("roles", [])))
' "$CLIENT_ID" 2>/dev/null || echo 0)
if [ "${NROLES:-0}" -gt 0 ] 2>/dev/null; then
  VERIFY_LINE="Self-verify   : OK — login works, token carries $NROLES '$CLIENT_ID' roles"
else
  VERIFY_LINE="Self-verify   : FAILED — login token has no '$CLIENT_ID' roles (check role assignment)"
fi

cat <<EOF

==================== DONE ====================
Realm        : $REALM
Client       : $CLIENT_ID
$SECRET_LINE
$VERIFY_LINE
Test user    : $TEST_USER / $TEST_PWD  (all ${#PERMISSION_KEYS[@]} permission roles assigned)

App Mesh side:
  1) config.yaml:   SecurityInterface: oauth2
  2) oauth2.yaml:   auth_server_url: $KC_URL   realm: $REALM   client_id: $CLIENT_ID
  3) export APPMESH_Keycloak_client_secret=...   # from above; do NOT commit
  4) restart appmesh, then:  python3 src/sdk/python/test/test_oauth2.py
==============================================
EOF
