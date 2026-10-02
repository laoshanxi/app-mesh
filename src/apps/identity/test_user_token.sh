#!/usr/bin/env bash
################################################################################
# Smoke test for the user-token launcher action (appmesh-auth.sh). Runs the
# real launcher against a throwaway APPMESH_HOME with a PATH-injected fake
# curl that answers the token endpoint with a canned grant response, so no
# installed package or live Dex is needed. Covers: default output (access
# token only, byte-identical), --with-refresh printing the full JSON token
# set, and the guard for deployments with refresh tokens disabled.
################################################################################
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAUNCHER=${LAUNCHER:-"${SCRIPT_DIR}/appmesh-auth.sh"}

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

export APPMESH_HOME="${TMP}/root"
mkdir -p "${APPMESH_HOME}/work/config"

STUB_BIN="${TMP}/bin"
mkdir -p "${STUB_BIN}"
cat >"${STUB_BIN}/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" >"${CURL_STUB_ARGS:?}"
printf '%s' '{"access_token":"stub-access.jwt","refresh_token":"stub-refresh-token","expires_in":3600,"token_type":"Bearer","id_token":"stub-id.jwt"}'
STUB
chmod 755 "${STUB_BIN}/curl"
export CURL_STUB_ARGS="${TMP}/curl-args"
export PATH="${STUB_BIN}:${PATH}"

PASSWORD="ci-user-token-pw"
ACCESS_TOKEN="stub-access.jwt"
REFRESH_TOKEN="stub-refresh-token"

run_user_token() {
    printf '%s' "${PASSWORD}" | bash "${LAUNCHER}" user-token "$@"
}

echo "== default prints only the access token =="
OUTPUT=$(run_user_token)
[ "${OUTPUT}" = "${ACCESS_TOKEN}" ] || { echo "FAIL: default output was '${OUTPUT}', want '${ACCESS_TOKEN}'"; exit 1; }
grep -F 'scope=openid audience:server:client_id:appmesh-api' "${CURL_STUB_ARGS}" >/dev/null \
    || { echo "FAIL: default grant scope mismatch"; exit 1; }
if grep -F 'offline_access' "${CURL_STUB_ARGS}" >/dev/null; then
    echo "FAIL: default grant unexpectedly requested offline_access"
    exit 1
fi

echo "== --with-refresh prints the full JSON token set =="
OUTPUT=$(run_user_token --with-refresh)
EXPECTED="{\"access_token\":\"${ACCESS_TOKEN}\",\"refresh_token\":\"${REFRESH_TOKEN}\",\"expires_in\":3600,\"token_type\":\"Bearer\"}"
[ "${OUTPUT}" = "${EXPECTED}" ] || { echo "FAIL: token set output was '${OUTPUT}', want '${EXPECTED}'"; exit 1; }
grep -F 'scope=openid audience:server:client_id:appmesh-api offline_access' "${CURL_STUB_ARGS}" >/dev/null \
    || { echo "FAIL: --with-refresh grant did not request offline_access"; exit 1; }

echo "== username and flag combine in either order =="
OUTPUT=$(run_user_token someone@appmesh.local --with-refresh)
[ "${OUTPUT}" = "${EXPECTED}" ] || { echo "FAIL: reordered arguments broke --with-refresh"; exit 1; }
grep -F 'username=someone@appmesh.local' "${CURL_STUB_ARGS}" >/dev/null \
    || { echo "FAIL: username was not forwarded"; exit 1; }

echo "== disabled refresh tokens reject --with-refresh (environment) =="
if printf '%s' "${PASSWORD}" | APPMESH_AUTH_REFRESH_TOKEN=off bash "${LAUNCHER}" user-token --with-refresh 2>"${TMP}/err"; then
    echo "FAIL: --with-refresh succeeded with refresh tokens disabled"
    exit 1
fi
grep -F 'disabled for this deployment' "${TMP}/err" >/dev/null \
    || { echo "FAIL: guard message unclear: $(cat "${TMP}/err")"; exit 1; }

echo "== disabled refresh tokens reject --with-refresh (oidc.yaml) =="
printf 'refresh_token: false\n' >"${APPMESH_HOME}/work/config/oidc.yaml"
if run_user_token --with-refresh 2>"${TMP}/err"; then
    echo "FAIL: --with-refresh succeeded with oidc.yaml refresh_token: false"
    exit 1
fi
grep -F 'disabled for this deployment' "${TMP}/err" >/dev/null \
    || { echo "FAIL: guard message unclear: $(cat "${TMP}/err")"; exit 1; }
rm -f "${APPMESH_HOME}/work/config/oidc.yaml"

echo "== default output is unaffected when refresh tokens are disabled =="
OUTPUT=$(printf '%s' "${PASSWORD}" | APPMESH_AUTH_REFRESH_TOKEN=false bash "${LAUNCHER}" user-token)
[ "${OUTPUT}" = "${ACCESS_TOKEN}" ] || { echo "FAIL: default output changed with refresh disabled"; exit 1; }

echo "== invalid APPMESH_AUTH_REFRESH_TOKEN value fails validation =="
if printf '%s' "${PASSWORD}" | APPMESH_AUTH_REFRESH_TOKEN=maybe bash "${LAUNCHER}" user-token --with-refresh 2>"${TMP}/err"; then
    echo "FAIL: invalid APPMESH_AUTH_REFRESH_TOKEN was accepted"
    exit 1
fi
grep -F 'must be true or false' "${TMP}/err" >/dev/null \
    || { echo "FAIL: validation message unclear: $(cat "${TMP}/err")"; exit 1; }

echo "== unknown flags are rejected =="
if run_user_token --bogus 2>"${TMP}/err"; then
    echo "FAIL: an unknown flag was accepted"
    exit 1
fi
grep -F 'usage: appmesh-auth.sh user-token' "${TMP}/err" >/dev/null \
    || { echo "FAIL: unknown flag did not print the action usage"; exit 1; }

echo "== a token response without refresh_token fails under --with-refresh =="
cat >"${STUB_BIN}/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" >"${CURL_STUB_ARGS:?}"
printf '%s' '{"access_token":"stub-access.jwt","expires_in":3600,"token_type":"Bearer"}'
STUB
chmod 755 "${STUB_BIN}/curl"
if run_user_token --with-refresh 2>"${TMP}/err"; then
    echo "FAIL: --with-refresh accepted a grant response without refresh_token"
    exit 1
fi
grep -F 'no refresh_token' "${TMP}/err" >/dev/null \
    || { echo "FAIL: missing-refresh message unclear: $(cat "${TMP}/err")"; exit 1; }

echo "PASS: user-token token set behavior verified"
