#!/usr/bin/env bash
################################################################################
# End-to-end verification for the dexuser administration UI (bin/dexuser, the
# Dex fork's examples/example-app) and the add-user/delete-user launcher
# actions that drive it. Runs against an installed package with the daemon
# already up; see .github/workflows/ci-test.yml.
################################################################################
set -euo pipefail

LAUNCHER=${LAUNCHER:-/opt/appmesh/script/appmesh-auth.sh}
POLICY=${APPMESH_POLICY:-/opt/appmesh/work/config/authorization.yaml}

# ci-test runs against the latest *released* package: skip (instead of fail)
# on packages that predate the bundled administration UI.
DEXUSER_APP=${APPMESH_DEXUSER_APP:-/opt/appmesh/apps/dexuser.yaml}
[ -f "${DEXUSER_APP}" ] || { echo "SKIP: the installed package has no dexuser System App"; exit 0; }
ISSUER=${APPMESH_AUTH_ISSUER:-http://127.0.0.1:6062/auth}
TOKEN_URL="${ISSUER}/token"
REST_ENTRY=${APPMESH_REST_ENTRY:-https://127.0.0.1:6060}
TEST_EMAIL="ci-user@appmesh.local"
TEST_PASSWORD="Ci-Test-Pw-2026"

login() {
    curl --silent --output /dev/null --write-out '%{http_code}' --request POST "${TOKEN_URL}" \
        --user 'appmesh-cli:' \
        --data-urlencode 'grant_type=password' \
        --data-urlencode "username=$1" \
        --data-urlencode "password=$2" \
        --data-urlencode 'scope=openid'
}

echo "== administration UI becomes healthy =="
healthy=0
for _ in $(seq 1 30); do
    if "${LAUNCHER}" admin-ui-health >/dev/null 2>&1; then
        healthy=1
        break
    fi
    sleep 2
done
[ "${healthy}" -eq 1 ] || { echo "FAIL: administration UI never became healthy"; exit 1; }

echo "== add-user creates the identity and binds the role =="
PRINCIPAL=$(printf '%s' "${TEST_PASSWORD}" | "${LAUNCHER}" add-user "${TEST_EMAIL}" appmesh-viewer)
[[ "${PRINCIPAL}" == oidc:* ]] || { echo "FAIL: add-user did not report a Principal ID"; exit 1; }
grep -F "    ${PRINCIPAL}:" "${POLICY}" >/dev/null || { echo "FAIL: role binding missing from ${POLICY}"; exit 1; }
[ "$(login "${TEST_EMAIL}" "${TEST_PASSWORD}")" = "200" ] || { echo "FAIL: the new user cannot sign in"; exit 1; }

echo "== duplicate add-user fails =="
if printf '%s' "${TEST_PASSWORD}" | "${LAUNCHER}" add-user "${TEST_EMAIL}" 2>/dev/null; then
    echo "FAIL: duplicate add-user succeeded"
    exit 1
fi

echo "== static identities are rejected =="
if printf '%s' x | "${LAUNCHER}" add-user admin@appmesh.local 2>/dev/null; then
    echo "FAIL: add-user accepted the static admin identity"
    exit 1
fi
if "${LAUNCHER}" delete-user admin@appmesh.local 2>/dev/null; then
    echo "FAIL: delete-user accepted the static admin identity"
    exit 1
fi

echo "== the dexuser system App cannot be enabled through the REST API =="
CODE=$(curl --silent --output /dev/null --write-out '%{http_code}' --insecure \
    --request POST "${REST_ENTRY}/appmesh/app/dexuser/enable" \
    --header "Authorization: Bearer ${APPMESH_BEARER_TOKEN:-}")
[ "${CODE}" = "403" ] || { echo "FAIL: enable returned ${CODE}, want 403"; exit 1; }

echo "== delete-user removes the identity and the binding =="
REMOVED=$("${LAUNCHER}" delete-user "${TEST_EMAIL}")
[ "${REMOVED}" = "${PRINCIPAL}" ] || { echo "FAIL: delete-user reported a different Principal ID"; exit 1; }
if grep -F "    ${PRINCIPAL}:" "${POLICY}" >/dev/null; then
    echo "FAIL: role binding still present in ${POLICY}"
    exit 1
fi
[ "$(login "${TEST_EMAIL}" "${TEST_PASSWORD}")" = "401" ] || { echo "FAIL: the deleted user can still sign in"; exit 1; }

echo "== deleting an unknown user fails =="
if "${LAUNCHER}" delete-user nobody@appmesh.local 2>/dev/null; then
    echo "FAIL: delete-user accepted an unknown user"
    exit 1
fi

echo "PASS: administration UI and user management verified"
