#!/usr/bin/env bash
set -euo pipefail

umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APPMESH_ROOT=${APPMESH_HOME:-$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)}
AUTH_STATE_DIR="${APPMESH_ROOT}/work/auth"
AUTH_SECRET_DIR="${AUTH_STATE_DIR}/secrets"
AUTH_STACK_CONFIG="${APPMESH_ROOT}/work/config/auth-stack.yaml"
OIDC_CONFIG="${APPMESH_ROOT}/work/config/oidc.yaml"
DEX_CONFIG_TEMPLATE="${APPMESH_ROOT}/config/dex.yaml"
DEX_RUNTIME_CONFIG="${AUTH_STATE_DIR}/dex/dex.yaml"
DEX_INITIAL_CREDENTIALS="${AUTH_SECRET_DIR}/initial-admin-credentials"
LEGACY_INITIAL_CREDENTIALS="${AUTH_SECRET_DIR}/dex-initial-admin-credentials"
DEX_INITIAL_CREDENTIAL_MARKER="${AUTH_SECRET_DIR}/dex-initial-admin-initialized"
DEX_GUEST_CREDENTIALS="${AUTH_SECRET_DIR}/initial-viewer-credentials"
LEGACY_GUEST_CREDENTIALS="${AUTH_SECRET_DIR}/dex-initial-guest-credentials"
DEX_GUEST_CREDENTIAL_MARKER="${AUTH_SECRET_DIR}/dex-initial-guest-initialized"
DEX_AUTOMATION_CLIENT_FILE="${AUTH_SECRET_DIR}/automation-client"
AUTHORIZATION_TEMPLATE="${APPMESH_ROOT}/config/authorization.yaml"
AUTHORIZATION_RUNTIME="${APPMESH_ROOT}/work/config/authorization.yaml"
PASSHASH_HELPER="${APPMESH_ROOT}/bin/passhash"
# Dex administration web UI binary (the fork's examples/example-app), run by
# the dexuser System App through the admin-ui action below.
ADMIN_UI_BIN="${APPMESH_ROOT}/bin/dexuser"
# Mutual-TLS material for the Dex administrative gRPC listener. The launcher
# enables that listener only when the server certificate, its key, and the
# client authority all exist.
AUTH_TLS_DIR="${APPMESH_ROOT}/ssl"
AUTH_GRPC_TLS_CERT="${AUTH_TLS_DIR}/server.pem"
AUTH_GRPC_TLS_KEY="${AUTH_TLS_DIR}/server-key.pem"
AUTH_GRPC_TLS_CLIENT_CA="${AUTH_TLS_DIR}/ca.pem"
AUTH_GRPC_CLIENT_CERT="${AUTH_TLS_DIR}/client.pem"
AUTH_GRPC_CLIENT_KEY="${AUTH_TLS_DIR}/client-key.pem"
readonly DEX_INITIAL_ADMIN_EMAIL="admin@appmesh.local"
readonly DEX_INITIAL_ADMIN_USERNAME="admin"
# Confidential client_credentials client for CI/unattended automation. Its
# subject is derived from this id, so the App Mesh Principal is stable across
# secret regeneration.
readonly DEX_AUTOMATION_CLIENT_ID="appmesh-automation"
readonly DEX_AUTOMATION_SUBJECT="ChJhcHBtZXNoLWF1dG9tYXRpb24"
readonly DEX_AUTOMATION_ROLE="appmesh-maintenance"
# Stable OIDC subject for this packaged bootstrap identity. It is deliberately
# not an Engine role binding; first-admin enrollment binds the verified tuple.
readonly DEX_INITIAL_ADMIN_USER_ID="2d1c8c38-3898-4c89-a78b-3caa42f203c1"
# Packaged read-only viewer identity. Bootstrap seeds its Principal for the
# configured issuer and retires the factory-default-issuer binding left by
# older templates. Its password is generated once; rotate/forget remain
# administrator-only operations.
readonly DEX_INITIAL_GUEST_EMAIL="guest@appmesh.local"
readonly DEX_INITIAL_GUEST_USERNAME="guest"
readonly DEX_INITIAL_GUEST_USER_ID="93ad39b4-eb6f-4945-97a1-3366451867fb"
readonly DEX_INITIAL_GUEST_SUBJECT="CiQ5M2FkMzliNC1lYjZmLTQ5NDUtOTdhMS0zMzY2NDUxODY3ZmISBWxvY2Fs"
# Issuer the packaged template historically hardcoded for the guest binding.
readonly DEX_FACTORY_DEFAULT_ISSUER="http://127.0.0.1:6062/auth"

AUTH_MODE=${APPMESH_AUTH_MODE:-builtin}
case "${AUTH_MODE}" in
    builtin|external) ;;
    *) echo "invalid APPMESH_AUTH_MODE" >&2; exit 2 ;;
esac

if [[ ! -f "${AUTH_STACK_CONFIG}" ]]; then
    AUTH_STACK_CONFIG="${APPMESH_ROOT}/config/auth-stack.yaml"
fi
if [[ ! -f "${OIDC_CONFIG}" ]]; then
    OIDC_CONFIG="${APPMESH_ROOT}/config/oidc.yaml"
fi
DAEMON_CONFIG="${APPMESH_ROOT}/work/config/config.yaml"
if [[ ! -f "${DAEMON_CONFIG}" ]]; then
    DAEMON_CONFIG="${APPMESH_ROOT}/config/config.yaml"
fi

config_value() {
    yaml_value "${AUTH_STACK_CONFIG}" "$1" "$2"
}

oidc_value() {
    yaml_value "${OIDC_CONFIG}" "$1" "$2"
}

yaml_value() {
    local file=$1
    local key=$2
    local fallback=$3
    local value
    [[ -f "${file}" ]] || {
        printf '%s' "${fallback}"
        return
    }
    # mawk 1.3.3 has no POSIX character classes; use plain space/tab.
    value=$(awk -v wanted="${key}:" '$1 == wanted { $1=""; sub(/^[ \t]+/, ""); gsub(/^"|"$/, ""); print; exit }' "${file}")
    if [[ -n "${value}" ]]; then
        printf '%s' "${value}"
    else
        printf '%s' "${fallback}"
    fi
}

oidc_auth_value() {
    local key=$1
    local fallback=$2
    local value
    value=$(oidc_value "${key}" '')
    if [[ -n "${value}" ]]; then
        printf '%s' "${value}"
    else
        printf '%s' "${fallback}"
    fi
}

AUTH_ROLE=${APPMESH_AUTH_ROLE:-$(config_value role standalone)}
case "${AUTH_ROLE}" in
    standalone|owner|follower) ;;
    *) echo "invalid AuthStack.role" >&2; exit 2 ;;
esac

is_auth_owner() {
    [[ "${AUTH_ROLE}" == "standalone" || "${AUTH_ROLE}" == "owner" ]]
}

is_builtin_auth() {
    [[ "${AUTH_MODE}" == "builtin" ]]
}

# GNU stat and BSD stat (macOS) use different format switches. Probe the
# dialect once and map the GNU formats used in this script.
STAT_DIALECT=unknown
stat_fmt() {
    local format=$1
    local file=$2
    if [[ "${STAT_DIALECT}" == "unknown" ]]; then
        if stat -c '%u' / >/dev/null 2>&1; then
            STAT_DIALECT=gnu
        else
            STAT_DIALECT=bsd
        fi
    fi
    if [[ "${STAT_DIALECT}" == "gnu" ]]; then
        stat -c "${format}" "${file}"
        return
    fi
    case "${format}" in
        '%u:%g:%a') stat -f '%u:%g:%Lp' "${file}" ;;
        '%u:%g') stat -f '%u:%g' "${file}" ;;
        '%h') stat -f '%l' "${file}" ;;
        *) echo "unsupported stat format: ${format}" >&2; return 1 ;;
    esac
}

hold_system_app() {
    # A packaged System App may remain enabled in an immutable image even when
    # runtime mode is external/follower. Stay healthy and inert instead of
    # exiting into the Engine's restart policy; never initialize local state.
    trap 'exit 0' INT TERM
    while :; do
        sleep 3600
    done
}

private_file_metadata() {
    local file=$1
    [[ ! -L "${file}" && -f "${file}" ]] || {
        echo "authentication state is not a regular file: ${file}" >&2
        return 1
    }
    local metadata
    metadata=$(stat_fmt '%u:%g:%a' "${file}") || return 1
    [[ "${metadata##*:}" == "600" ]] || {
        echo "authentication state must have mode 0600: ${file}" >&2
        return 1
    }
    local directory_owner
    directory_owner=$(stat_fmt '%u:%g' "$(dirname "${file}")") || return 1
    [[ "${metadata%:*}" == "${directory_owner}" ]] || {
        echo "authentication state owner must match its private directory: ${file}" >&2
        return 1
    }
    [[ "$(stat_fmt '%h' "${file}")" == "1" ]] || {
        echo "authentication state must not have additional hard links: ${file}" >&2
        return 1
    }
    printf '%s' "${metadata%:*}"
}

credential_value() {
    local file=$1
    local key=$2
    awk -F= -v wanted="${key}" '$1 == wanted {sub(/^[^=]*=/, ""); print; found=1; exit} END {if (!found) exit 1}' "${file}"
}

automation_client_value() {
    local key=$1
    awk -F= -v wanted="${key}" '$1 == wanted {sub(/^[^=]*=/, ""); print; found=1; exit} END {if (!found) exit 1}' "${DEX_AUTOMATION_CLIENT_FILE}"
}

valid_automation_secret() {
    [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

validate_automation_client() {
    private_file_metadata "${DEX_AUTOMATION_CLIENT_FILE}" >/dev/null
    [[ "$(automation_client_value client_id)" == "${DEX_AUTOMATION_CLIENT_ID}" ]] || {
        echo "automation client credential file has an unexpected client_id" >&2
        return 1
    }
    valid_automation_secret "$(automation_client_value secret)" || {
        echo "automation client secret is invalid" >&2
        return 1
    }
}

# Create the machine client credential once and reuse it on every later start;
# an existing secret is never rotated, so automation deployments keep working
# across restarts and upgrades.
ensure_automation_client() {
    if [[ -e "${DEX_AUTOMATION_CLIENT_FILE}" || -L "${DEX_AUTOMATION_CLIENT_FILE}" ]]; then
        validate_automation_client
        return
    fi
    local secret owner temporary
    secret=$(openssl rand -hex 32) || {
        echo "failed to generate automation client secret" >&2
        return 1
    }
    owner=$(stat_fmt '%u:%g' "${AUTH_SECRET_DIR}") || return 1
    temporary=$(mktemp "${AUTH_SECRET_DIR}/.automation-client.XXXXXX") || return 1
    chmod 600 "${temporary}"
    chown "${owner}" "${temporary}"
    {
        printf 'client_id=%s\n' "${DEX_AUTOMATION_CLIENT_ID}"
        printf 'secret=%s\n' "${secret}"
    } >"${temporary}"
    [[ ! -L "${DEX_AUTOMATION_CLIENT_FILE}" ]] || {
        rm -f "${temporary}"
        echo "refusing symbolic-link automation client credential file" >&2
        return 1
    }
    mv -f "${temporary}" "${DEX_AUTOMATION_CLIENT_FILE}"
    chmod 600 "${DEX_AUTOMATION_CLIENT_FILE}"
    validate_automation_client
    secret=""
}

stable_principal_id() {
    local issuer=$1
    local subject=$2
    local digest
    digest=$(
        { printf '%s' "${issuer}"; printf '\0'; printf '%s' "${subject}"; } |
            openssl dgst -sha256 | awk '{print $NF}'
    )
    [[ "${digest}" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
    printf 'oidc:%s' "$(printf '%s' "${digest}" | tr 'A-F' 'a-f')"
}

seed_builtin_principals() {
    [[ -f "${AUTHORIZATION_TEMPLATE}" ]] || {
        echo "authorization template is unavailable: ${AUTHORIZATION_TEMPLATE}" >&2
        return 1
    }
    [[ ! -L "${AUTHORIZATION_RUNTIME}" ]] || {
        echo "refusing symbolic-link authorization policy: ${AUTHORIZATION_RUNTIME}" >&2
        return 1
    }

    local issuer issuer_yaml automation_id guest_id guest_name_yaml guest_email_yaml source temporary
    local retired_id="" stripped=""
    local add_automation=1 add_guest=1 add_role=1
    issuer=${APPMESH_AUTH_ISSUER:-$(oidc_value issuer http://127.0.0.1:6062/auth)}
    issuer_yaml=$(yaml_quote "${issuer}") || return 1
    guest_name_yaml=$(yaml_quote "${DEX_INITIAL_GUEST_USERNAME}") || return 1
    guest_email_yaml=$(yaml_quote "${DEX_INITIAL_GUEST_EMAIL}") || return 1
    automation_id=$(stable_principal_id "${issuer}" "${DEX_AUTOMATION_SUBJECT}") || {
        echo "failed to derive the automation Principal ID" >&2
        return 1
    }
    guest_id=$(stable_principal_id "${issuer}" "${DEX_INITIAL_GUEST_SUBJECT}") || {
        echo "failed to derive the guest Principal ID" >&2
        return 1
    }

    install -d -m 700 "$(dirname "${AUTHORIZATION_RUNTIME}")"
    source=${AUTHORIZATION_RUNTIME}
    if [[ ! -e "${source}" ]]; then
        source=${AUTHORIZATION_TEMPLATE}
    elif [[ ! -f "${source}" ]]; then
        echo "authorization runtime policy is not a regular file: ${source}" >&2
        return 1
    fi

    grep -Fqx "    ${automation_id}:" "${source}" && add_automation=0
    grep -Fqx "    ${guest_id}:" "${source}" && add_guest=0
    grep -Fqx "    ${DEX_AUTOMATION_ROLE}:" "${source}" && add_role=0
    # A policy from an older template can carry the guest bound to the factory
    # default issuer. With a different configured issuer that binding can never
    # authenticate and only duplicates the identity in the principal list.
    if [[ "${issuer}" != "${DEX_FACTORY_DEFAULT_ISSUER}" ]]; then
        retired_id=$(stable_principal_id "${DEX_FACTORY_DEFAULT_ISSUER}" "${DEX_INITIAL_GUEST_SUBJECT}") || return 1
        grep -Fqx "    ${retired_id}:" "${source}" || retired_id=""
    fi
    if [[ "${source}" == "${AUTHORIZATION_RUNTIME}" &&
        ${add_automation} -eq 0 && ${add_guest} -eq 0 && ${add_role} -eq 0 && -z "${retired_id}" ]]; then
        return 0
    fi

    if [[ -n "${retired_id}" ]]; then
        stripped=$(mktemp "${AUTHORIZATION_RUNTIME}.XXXXXX") || return 1
        chmod 600 "${stripped}"
        # Drop the retired entry and the comment lines describing it.
        if ! awk -v retired_id="${retired_id}" '
            $0 == "    " retired_id ":" { dropping = 1; n = 0; next }
            dropping {
                if ($0 ~ /^      / || $0 == "") next
                dropping = 0
            }
            /^    #/ { comments[n++] = $0; next }
            {
                for (i = 0; i < n; i++) print comments[i]
                n = 0
                print
            }
            END { for (i = 0; i < n; i++) print comments[i] }
        ' "${source}" >"${stripped}"; then
            rm -f "${stripped}"
            echo "failed to retire the factory-default guest binding" >&2
            return 1
        fi
        source=${stripped}
    fi

    temporary=$(mktemp "${AUTHORIZATION_RUNTIME}.XXXXXX") || return 1
    chmod 600 "${temporary}"
    if ! awk \
        -v add_automation="${add_automation}" \
        -v add_guest="${add_guest}" \
        -v add_role="${add_role}" \
        -v automation_id="${automation_id}" \
        -v guest_id="${guest_id}" \
        -v issuer="${issuer_yaml}" \
        -v automation_subject="${DEX_AUTOMATION_SUBJECT}" \
        -v guest_subject="${DEX_INITIAL_GUEST_SUBJECT}" \
        -v guest_name="${guest_name_yaml}" \
        -v guest_email="${guest_email_yaml}" \
        -v role="${DEX_AUTOMATION_ROLE}" '
            $0 == "  principals:" && (add_automation == 1 || add_guest == 1) {
                print
                if (add_automation == 1) {
                    print "    " automation_id ":"
                    print "      kind: service"
                    print "      issuer: " issuer
                    print "      subject: " automation_subject
                    print "      status: active"
                    print "      execution_user: \"\""
                    print "      roles: [" role "]"
                    automation_added = 1
                }
                if (add_guest == 1) {
                    print "    " guest_id ":"
                    print "      kind: user"
                    print "      issuer: " issuer
                    print "      subject: " guest_subject
                    print "      display_name: " guest_name
                    print "      email: " guest_email
                    print "      status: active"
                    print "      execution_user: \"\""
                    print "      roles: [appmesh-viewer]"
                    guest_added = 1
                }
                next
            }
            $0 == "  roles:" && add_role == 1 {
                print
                print "    " role ":"
                print "      - app-control"
                print "      - app-manage-all"
                print "      - app-view-all"
                print "      - host-resource-view"
                role_added = 1
                next
            }
            { print }
            END {
                if ((add_automation == 1 && automation_added != 1) ||
                    (add_guest == 1 && guest_added != 1) ||
                    (add_role == 1 && role_added != 1))
                    exit 42
            }
        ' "${source}" >"${temporary}"; then
        rm -f "${temporary}" "${stripped}"
        echo "authorization policy has no mergeable principals/roles sections; preserving it unchanged" >&2
        return 1
    fi
    mv "${temporary}" "${AUTHORIZATION_RUNTIME}"
    chmod 600 "${AUTHORIZATION_RUNTIME}"
    rm -f "${stripped}"
    echo "Seeded missing built-in authorization bindings for issuer ${issuer}" >&2
}

# Deployments without refresh tokens drop the refresh_token grant from the
# Dex grant types (render_dex_config) and reject user-token --with-refresh;
# sessions then end at access-token expiry. The Engine reads the same setting
# to advertise "refresh_token" in the auth config. Exit status: 0 when refresh
# tokens are disabled, 1 when enabled, 2 when the setting is invalid.
refresh_tokens_disabled() {
    local refresh_token_value
    refresh_token_value="${APPMESH_AUTH_REFRESH_TOKEN:-$(oidc_value refresh_token true)}"
    # Lowercase first: the Engine compares case-insensitively, so a mixed-case
    # value would otherwise disable the advertised flow on one side only.
    refresh_token_value="$(printf '%s' "${refresh_token_value}" | tr '[:upper:]' '[:lower:]')"
    case "${refresh_token_value}" in
        0|false|off|disabled) return 0 ;;
        1|true) return 1 ;;
        # Accept the same value set as the Engine (OidcTokenVerifier.cpp).
        *)
            echo "APPMESH_AUTH_REFRESH_TOKEN must be true or false" >&2
            return 2
            ;;
    esac
}

request_automation_token() {
    is_builtin_auth && is_auth_owner || {
        echo "the automation token is available only from the built-in auth owner" >&2
        return 1
    }
    validate_automation_client

    local access_url tls_verify ca_path client_secret response token
    access_url=${APPMESH_AUTH_ACCESS_URL:-$(oidc_auth_value access_url http://127.0.0.1:6062/auth)}
    tls_verify=${APPMESH_AUTH_TLS_VERIFY:-$(oidc_auth_value tls_verify true)}
    ca_path=${APPMESH_AUTH_CA_PATH:-$(oidc_auth_value ca_path '')}
    client_secret=$(automation_client_value secret)

    local curl_args=(--fail --silent --show-error --connect-timeout 2 --max-time 8 --request POST)
    case "${tls_verify}" in false|FALSE|False|0) curl_args+=(--insecure) ;; esac
    if [[ -n "${ca_path}" ]]; then
        if [[ -f "${ca_path}" ]]; then
            curl_args+=(--cacert "${ca_path}")
        elif [[ -d "${ca_path}" ]]; then
            curl_args+=(--capath "${ca_path}")
        fi
    fi

    response=$(
        printf 'grant_type=client_credentials&client_id=%s&client_secret=%s&scope=audience%%3Aserver%%3Aclient_id%%3Aappmesh-api' \
            "${DEX_AUTOMATION_CLIENT_ID}" "${client_secret}" |
            curl "${curl_args[@]}" --header 'Content-Type: application/x-www-form-urlencoded' \
                --data-binary @- --url "${access_url%/}/token"
    ) || return 1
    client_secret=""
    token=$(printf '%s' "${response}" |
        sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._~-]*\)".*/\1/p')
    response=""
    [[ -n "${token}" ]] || {
        echo "The token response has no access_token" >&2
        return 1
    }
    printf '%s' "${token}"
}

# Password grant for a human identity (administrator permissions). The password
# comes from standard input, never from argv/environment; only the access token
# is printed, so the result can go straight into APPMESH_BEARER_TOKEN. With
# with_refresh=1 (the --with-refresh flag) the grant also requests
# offline_access and the full token set is printed as JSON for SDK use; the
# refresh token reaches stdout only under that explicit flag.
request_user_token() {
    is_builtin_auth && is_auth_owner || {
        echo "the user token is available only from the built-in auth owner" >&2
        return 1
    }
    local username=${1:-${DEX_INITIAL_ADMIN_EMAIL}}
    local with_refresh=${2:-0}
    local scope="openid audience:server:client_id:appmesh-api"
    if [[ "${with_refresh}" == 1 ]]; then
        # Fail fast (before the password read) when the deployment issues no
        # refresh tokens, instead of silently returning a set without one.
        local refresh_status=0
        refresh_tokens_disabled || refresh_status=$?
        case ${refresh_status} in
            0)
                echo "Refresh tokens are disabled for this deployment (APPMESH_AUTH_REFRESH_TOKEN / oidc.yaml refresh_token); user-token --with-refresh is unavailable" >&2
                return 1
                ;;
            1) ;;
            *) return 1 ;;
        esac
        scope="${scope} offline_access"
    fi
    local password
    IFS= read -r password || [[ -n "${password}" ]] || {
        echo "Provide the password on standard input" >&2
        return 1
    }
    if IFS= read -r _; then
        echo "The password must be a single line" >&2
        return 1
    fi
    [[ -n "${password}" ]] || {
        echo "The password must not be empty" >&2
        return 1
    }

    local access_url tls_verify ca_path response token
    access_url=${APPMESH_AUTH_ACCESS_URL:-$(oidc_auth_value access_url http://127.0.0.1:6062/auth)}
    tls_verify=${APPMESH_AUTH_TLS_VERIFY:-$(oidc_auth_value tls_verify true)}
    ca_path=${APPMESH_AUTH_CA_PATH:-$(oidc_auth_value ca_path '')}

    local curl_args=(--fail --silent --show-error --connect-timeout 2 --max-time 8 --request POST)
    case "${tls_verify}" in false|FALSE|False|0) curl_args+=(--insecure) ;; esac
    if [[ -n "${ca_path}" ]]; then
        if [[ -f "${ca_path}" ]]; then
            curl_args+=(--cacert "${ca_path}")
        elif [[ -d "${ca_path}" ]]; then
            curl_args+=(--capath "${ca_path}")
        fi
    fi

    response=$(
        curl "${curl_args[@]}" --user "appmesh-cli:" \
            --data-urlencode "grant_type=password" \
            --data-urlencode "username=${username}" \
            --data-urlencode "password=${password}" \
            --data-urlencode "scope=${scope}" \
            --url "${access_url%/}/token"
    ) || return 1
    password=""
    token=$(printf '%s' "${response}" |
        sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._~-]*\)".*/\1/p')
    [[ -n "${token}" ]] || {
        response=""
        echo "The token response has no access_token" >&2
        return 1
    }
    if [[ "${with_refresh}" == 1 ]]; then
        local refresh_token expires_in
        refresh_token=$(printf '%s' "${response}" |
            sed -n 's/.*"refresh_token"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._~-]*\)".*/\1/p')
        expires_in=$(printf '%s' "${response}" |
            sed -n 's/.*"expires_in"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
        response=""
        [[ -n "${refresh_token}" ]] || {
            echo "The token response has no refresh_token" >&2
            return 1
        }
        printf '{"access_token":"%s","refresh_token":"%s","expires_in":%s,"token_type":"Bearer"}' \
            "${token}" "${refresh_token}" "${expires_in:-0}"
        return
    fi
    response=""
    printf '%s' "${token}"
}

valid_bcrypt_hash() {
    [[ "$1" =~ ^\$2[aby]\$10\$[./A-Za-z0-9]{53}$ ]]
}

validate_initial_credentials() {
    local file=$1
    local expected_email=$2
    local expected_username=$3
    local expected_user_id=$4
    local label=$5
    private_file_metadata "${file}" >/dev/null
    local email username user_id password_hash
    email=$(credential_value "${file}" email) || return 1
    username=$(credential_value "${file}" username) || return 1
    user_id=$(credential_value "${file}" user_id) || return 1
    password_hash=$(credential_value "${file}" password_hash) || return 1
    [[ "${email}" == "${expected_email}" && \
       "${username}" == "${expected_username}" && \
       "${user_id}" == "${expected_user_id}" ]] || {
        echo "The initial ${label} identity is invalid" >&2
        return 1
    }
    valid_bcrypt_hash "${password_hash}" || {
        echo "The initial ${label} password hash is invalid" >&2
        return 1
    }
}

validate_admin_credentials() {
    validate_initial_credentials "${DEX_INITIAL_CREDENTIALS}" \
        "${DEX_INITIAL_ADMIN_EMAIL}" "${DEX_INITIAL_ADMIN_USERNAME}" \
        "${DEX_INITIAL_ADMIN_USER_ID}" administrator
}

validate_guest_credentials() {
    validate_initial_credentials "${DEX_GUEST_CREDENTIALS}" \
        "${DEX_INITIAL_GUEST_EMAIL}" "${DEX_INITIAL_GUEST_USERNAME}" \
        "${DEX_INITIAL_GUEST_USER_ID}" guest
}

publish_initial_credential_marker() {
    local marker_file=$1
    local temporary_name=$2
    if [[ -e "${marker_file}" || -L "${marker_file}" ]]; then
        private_file_metadata "${marker_file}" >/dev/null
        return
    fi
    local temporary owner
    owner=$(stat_fmt '%u:%g' "${AUTH_SECRET_DIR}") || return 1
    temporary=$(mktemp "${AUTH_SECRET_DIR}/${temporary_name}.XXXXXX") || return 1
    chmod 600 "${temporary}"
    chown "${owner}" "${temporary}"
    printf '%s\n' initialized >"${temporary}"
    if ! ln "${temporary}" "${marker_file}" 2>/dev/null; then
        [[ ! -L "${marker_file}" && -f "${marker_file}" ]] || {
            rm -f "${temporary}"
            echo "failed to publish the initial credential marker" >&2
            return 1
        }
    fi
    rm -f "${temporary}"
    private_file_metadata "${marker_file}" >/dev/null
}

write_initial_credentials() {
    local file=$1
    local email=$2
    local username=$3
    local user_id=$4
    local label=$5
    local password=$6
    local include_password=${7:-yes}
    local temporary hash_file password_hash owner

    [[ ! -L "${PASSHASH_HELPER}" && -f "${PASSHASH_HELPER}" && -x "${PASSHASH_HELPER}" ]] || {
        echo "The passhash helper is unavailable" >&2
        return 1
    }
    if [[ -e "${file}" || -L "${file}" ]]; then
        private_file_metadata "${file}" >/dev/null
    fi
    owner=$(stat_fmt '%u:%g' "${AUTH_SECRET_DIR}") || return 1
    hash_file=$(mktemp "${AUTH_SECRET_DIR}/.passhash.XXXXXX") || return 1
    chmod 600 "${hash_file}"
    if ! printf '%s\n' "${password}" | "${PASSHASH_HELPER}" >"${hash_file}"; then
        rm -f "${hash_file}"
        echo "failed to hash the initial ${label} password" >&2
        return 1
    fi
    IFS= read -r password_hash <"${hash_file}"
    rm -f "${hash_file}"
    valid_bcrypt_hash "${password_hash}" || {
        echo "The passhash helper returned an invalid hash" >&2
        return 1
    }

    temporary=$(mktemp "${AUTH_SECRET_DIR}/.dex-initial-credential.XXXXXX") || return 1
    chmod 600 "${temporary}"
    chown "${owner}" "${temporary}"
    {
        printf 'username=%s\n' "${username}"
        printf 'email=%s\n' "${email}"
        printf 'user_id=%s\n' "${user_id}"
        printf 'password_hash=%s\n' "${password_hash}"
        if [[ "${include_password}" == "yes" ]]; then
            printf 'password=%s\n' "${password}"
        fi
    } >"${temporary}"
    [[ ! -L "${file}" ]] || {
        rm -f "${temporary}"
        echo "refusing a symbolic-link initial credential file" >&2
        return 1
    }
    mv -f "${temporary}" "${file}"
    chmod 600 "${file}"
    password=""
    password_hash=""
}

ensure_initial_credentials() {
    local file=$1
    local marker_file=$2
    local email=$3
    local username=$4
    local user_id=$5
    local label=$6
    local temporary_name=$7
    if [[ -e "${file}" || -L "${file}" ]]; then
        validate_initial_credentials "${file}" "${email}" "${username}" "${user_id}" "${label}"
        publish_initial_credential_marker "${marker_file}" "${temporary_name}"
        return
    fi
    if [[ -e "${marker_file}" || -L "${marker_file}" ]]; then
        private_file_metadata "${marker_file}" >/dev/null
        echo "The initial ${label} credential was removed. rotate-initial-password can create an administrator replacement." >&2
        return 1
    fi
    local password
    password=$(openssl rand -hex 24) || {
        echo "failed to generate the initial ${label} password" >&2
        return 1
    }
    write_initial_credentials "${file}" "${email}" "${username}" "${user_id}" "${label}" "${password}" yes
    publish_initial_credential_marker "${marker_file}" "${temporary_name}"
    password=""
}

ensure_admin_credentials() {
    ensure_initial_credentials "${DEX_INITIAL_CREDENTIALS}" "${DEX_INITIAL_CREDENTIAL_MARKER}" \
        "${DEX_INITIAL_ADMIN_EMAIL}" "${DEX_INITIAL_ADMIN_USERNAME}" \
        "${DEX_INITIAL_ADMIN_USER_ID}" administrator .dex-initialized
}

ensure_guest_credentials() {
    ensure_initial_credentials "${DEX_GUEST_CREDENTIALS}" "${DEX_GUEST_CREDENTIAL_MARKER}" \
        "${DEX_INITIAL_GUEST_EMAIL}" "${DEX_INITIAL_GUEST_USERNAME}" \
        "${DEX_INITIAL_GUEST_USER_ID}" guest .dex-guest-initialized
}

rotate_initial_credentials() {
    prepare_owner_directories
    local password
    password=$(openssl rand -hex 24) || {
        echo "failed to generate the initial administrator password" >&2
        return 1
    }
    write_initial_credentials "${DEX_INITIAL_CREDENTIALS}" \
        "${DEX_INITIAL_ADMIN_EMAIL}" "${DEX_INITIAL_ADMIN_USERNAME}" \
        "${DEX_INITIAL_ADMIN_USER_ID}" administrator "${password}" yes
    publish_initial_credential_marker "${DEX_INITIAL_CREDENTIAL_MARKER}" .dex-initialized
    password=""
    echo "The initial administrator password was rotated. Run print-initial-password to read it, then restart App Mesh." >&2
}

# Administrator-chosen password instead of a generated one. The password comes
# from standard input (never argv/environment, which leak into ps, docker
# inspect, and CI logs) and goes through the same write path as bootstrap and
# rotate, so file metadata and hash validation stay identical.
set_initial_password() {
    local password
    IFS= read -r password || [[ -n "${password}" ]] || {
        echo "Provide the initial administrator password on standard input" >&2
        return 1
    }
    if IFS= read -r _; then
        echo "The initial administrator password must be a single line" >&2
        return 1
    fi
    [[ -n "${password}" ]] || {
        echo "The initial administrator password must not be empty" >&2
        return 1
    }
    # bcrypt rejects inputs past 72 bytes; fail early with a clear message.
    if (( $(printf '%s' "${password}" | LC_ALL=C wc -c) > 72 )); then
        echo "The initial administrator password must be at most 72 bytes" >&2
        return 1
    fi
    prepare_owner_directories
    write_initial_credentials "${DEX_INITIAL_CREDENTIALS}" \
        "${DEX_INITIAL_ADMIN_EMAIL}" "${DEX_INITIAL_ADMIN_USERNAME}" \
        "${DEX_INITIAL_ADMIN_USER_ID}" administrator "${password}" yes
    publish_initial_credential_marker "${DEX_INITIAL_CREDENTIAL_MARKER}" .dex-initialized
    password=""
    echo "The initial administrator password was updated. Restart App Mesh to apply it." >&2
}

print_initial_password() {
    # Read-only helper for first login: emit the bootstrap password. The
    # plaintext stays absent after forget-initial-password; rotating creates one.
    validate_admin_credentials || return 1
    local password
    if ! password=$(credential_value "${DEX_INITIAL_CREDENTIALS}" password); then
        echo "The initial administrator password is not recoverable. rotate-initial-password can create a new one." >&2
        return 1
    fi
    printf '%s\n' "${password}"
}

forget_initial_password() {
    bootstrap_owner
    validate_admin_credentials
    local password_hash owner temporary
    password_hash=$(credential_value "${DEX_INITIAL_CREDENTIALS}" password_hash)
    owner=$(private_file_metadata "${DEX_INITIAL_CREDENTIALS}")
    temporary=$(mktemp "${AUTH_SECRET_DIR}/.dex-initial-admin.XXXXXX") || return 1
    chmod 600 "${temporary}"
    chown "${owner}" "${temporary}"
    {
        printf 'username=%s\n' "${DEX_INITIAL_ADMIN_USERNAME}"
        printf 'email=%s\n' "${DEX_INITIAL_ADMIN_EMAIL}"
        printf 'user_id=%s\n' "${DEX_INITIAL_ADMIN_USER_ID}"
        printf 'password_hash=%s\n' "${password_hash}"
    } >"${temporary}"
    mv -f "${temporary}" "${DEX_INITIAL_CREDENTIALS}"
    chmod 600 "${DEX_INITIAL_CREDENTIALS}"
    password_hash=""
    echo "Removed the initial administrator plaintext password. The existing password hash remains configured." >&2
}

# Serve the Dex administration web UI (bin/dexuser, built from the fork's
# examples/example-app). It talks to the Dex administrative gRPC API over
# mutual TLS, so it requires the same TLS material that gates the gRPC listener
# in render_dex_config. The UI has no authentication of its own and therefore
# listens on loopback only.
admin_ui() {
    [[ ! -L "${ADMIN_UI_BIN}" && -f "${ADMIN_UI_BIN}" && -x "${ADMIN_UI_BIN}" ]] || {
        echo "The administration UI is unavailable: ${ADMIN_UI_BIN}" >&2
        return 1
    }
    if [[ ! -f "${AUTH_GRPC_TLS_CERT}" || ! -f "${AUTH_GRPC_TLS_KEY}" || \
        ! -f "${AUTH_GRPC_TLS_CLIENT_CA}" || ! -f "${AUTH_GRPC_CLIENT_CERT}" || \
        ! -f "${AUTH_GRPC_CLIENT_KEY}" ]]; then
        echo "The administration UI is unavailable because the TLS material is incomplete in ${AUTH_TLS_DIR}" >&2
        return 1
    fi
    local listen issuer grpc_listen
    listen=${APPMESH_AUTH_ADMIN_LISTEN:-127.0.0.1:6064}
    issuer=${APPMESH_AUTH_ISSUER:-$(oidc_value issuer http://127.0.0.1:6062/auth)}
    grpc_listen=${APPMESH_AUTH_GRPC_LISTEN:-127.0.0.1:5557}
    # dexuser authentication contract: the runtime issuer it must validate
    # sessions against, the same value rendered into dex.yaml above. Audience
    # (appmesh-api) and session TTL keep dexuser defaults unless the operator
    # exports APP_MESH_DEXUSER_AUDIENCE / APP_MESH_DEXUSER_SESSION_TTL himself.
    export APP_MESH_DEXUSER_ISSUER="${issuer}"
    exec "${ADMIN_UI_BIN}" \
        --listen "http://${listen}" \
        --issuer "${issuer}" \
        --grpc-addr "${grpc_listen}" \
        --grpc-ca "${AUTH_GRPC_TLS_CLIENT_CA}" \
        --grpc-client-cert "${AUTH_GRPC_CLIENT_CERT}" \
        --grpc-client-key "${AUTH_GRPC_CLIENT_KEY}"
}

# The container entrypoint and the service environment file disable the UI
# with APPMESH_AUTH_ADMIN_UI=off; the dexuser App then stays up but serves
# nothing, like the identity App does in external authentication mode.
admin_ui_disabled() {
    case "${APPMESH_AUTH_ADMIN_UI:-on}" in
        off|OFF|false|0|disabled) return 0 ;;
        *) return 1 ;;
    esac
}

admin_ui_health() {
    local listen
    listen=${APPMESH_AUTH_ADMIN_LISTEN:-127.0.0.1:6064}
    exec curl --fail --silent --show-error --max-time 2 "http://${listen}/"
}

# The authorization policy a write must target: the runtime copy when it
# exists, the packaged template otherwise.
authorization_policy_source() {
    if [[ -e "${AUTHORIZATION_RUNTIME}" ]]; then
        [[ ! -L "${AUTHORIZATION_RUNTIME}" && -f "${AUTHORIZATION_RUNTIME}" ]] || {
            echo "authorization runtime policy is not a regular file: ${AUTHORIZATION_RUNTIME}" >&2
            return 1
        }
        printf '%s' "${AUTHORIZATION_RUNTIME}"
        return 0
    fi
    [[ -f "${AUTHORIZATION_TEMPLATE}" ]] || {
        echo "authorization template is unavailable: ${AUTHORIZATION_TEMPLATE}" >&2
        return 1
    }
    printf '%s' "${AUTHORIZATION_TEMPLATE}"
}

# An undefined role makes the Engine reject the whole policy, so every caller
# checks before it writes. Principal keys share the four-space indent of role
# names, so the match is scoped to the roles section.
policy_defines_role() {
    local source
    source=$(authorization_policy_source) || return 1
    awk -v role="$1" '
        $0 == "  roles:" { in_roles = 1; next }
        /^  [^ ]/ { in_roles = 0 }
        in_roles && $0 == "    " role ":" { found = 1 }
        END { exit(found == 1 ? 0 : 1) }
    ' "${source}"
}

# Bind one Principal to one role in the authorization policy. The Engine owns
# this file and rewrites it on every administrative change, so a binding that
# is written while the Engine runs can be lost.
bind_principal() {
    local principal_id=$1
    local issuer=$2
    local subject=$3
    local role=$4
    local source
    source=$(authorization_policy_source) || return 1
    policy_defines_role "${role}" || {
        echo "The authorization policy does not define the role ${role}" >&2
        return 1
    }
    if grep -Fqx "    ${principal_id}:" "${source}"; then
        echo "The authorization policy already lists ${principal_id}" >&2
        return 0
    fi
    install -d -m 700 "$(dirname "${AUTHORIZATION_RUNTIME}")"
    local issuer_yaml temporary
    issuer_yaml=$(yaml_quote "${issuer}") || return 1
    temporary=$(mktemp "${AUTHORIZATION_RUNTIME}.XXXXXX") || return 1
    chmod 600 "${temporary}"
    if ! awk \
        -v principal_id="${principal_id}" \
        -v issuer="${issuer_yaml}" \
        -v subject="${subject}" \
        -v role="${role}" '
            $0 == "  principals:" {
                print
                print "    " principal_id ":"
                print "      kind: user"
                print "      issuer: " issuer
                print "      subject: " subject
                print "      status: active"
                print "      execution_user: \"\""
                print "      roles: [" role "]"
                added = 1
                next
            }
            { print }
            END { if (added != 1) exit 42 }
        ' "${source}" >"${temporary}"; then
        rm -f "${temporary}"
        echo "authorization policy has no principals section; preserving it unchanged" >&2
        return 1
    fi
    mv "${temporary}" "${AUTHORIZATION_RUNTIME}"
    chmod 600 "${AUTHORIZATION_RUNTIME}"
}

# Remove one Principal from the authorization policy. It reports success when
# the policy does not list the Principal, because the caller only needs the
# entry to be absent.
unbind_principal() {
    local principal_id=$1
    local source
    source=$(authorization_policy_source) || return 1
    if ! grep -Fqx "    ${principal_id}:" "${source}"; then
        echo "The authorization policy does not list ${principal_id}" >&2
        return 0
    fi
    install -d -m 700 "$(dirname "${AUTHORIZATION_RUNTIME}")"
    local temporary
    temporary=$(mktemp "${AUTHORIZATION_RUNTIME}.XXXXXX") || return 1
    chmod 600 "${temporary}"
    # A Principal is its own line plus the six-space fields below it. The next
    # four-space key ends the block.
    if ! awk -v principal_id="${principal_id}" '
            $0 == "    " principal_id ":" { removing = 1; removed = 1; next }
            removing && /^      / { next }
            removing { removing = 0 }
            { print }
            END { exit(removed == 1 ? 0 : 42) }
        ' "${source}" >"${temporary}"; then
        rm -f "${temporary}"
        echo "authorization policy does not contain the Principal ${principal_id}" >&2
        return 1
    fi
    mv "${temporary}" "${AUTHORIZATION_RUNTIME}"
    chmod 600 "${AUTHORIZATION_RUNTIME}"
}

# OIDC subject for a local password user: base64url_raw of the IDTokenSubject
# protobuf (field 1 user_id, field 2 connector id "local"), mirroring Dex's
# GenSubject. add-user generates a UUID, but delete-user recovers the identifier
# from the administration UI, where the form takes free text. Encode the length
# prefix instead of assuming it, or the subject of any other identifier is
# wrong and the Principal it names is not the one Dex issues.
oidc_subject_for_user_id() {
    local user_id=$1 length remaining byte prefix=""
    length=$(printf '%s' "${user_id}" | LC_ALL=C wc -c)
    remaining=${length}
    # A protobuf length is a varint: seven bits per byte, high bit set while
    # more bytes follow.
    while ((remaining > 127)); do
        printf -v byte '\\x%02x' "$((remaining & 127 | 128))"
        prefix+="${byte}"
        remaining=$((remaining >> 7))
    done
    printf -v byte '\\x%02x' "${remaining}"
    prefix+="${byte}"
    printf "\x0a${prefix}%s\x12\x05local" "${user_id}" |
        openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# POST one form to the administration UI (the dexuser System App, loopback
# only). The UI answers every administrative write with a redirect: ?notice=
# on success and ?error= on failure, so the Location header carries the result.
admin_ui_post() {
    local path=$1
    shift
    local listen headers location detail
    listen=${APPMESH_AUTH_ADMIN_LISTEN:-127.0.0.1:6064}
    if ! headers=$(curl --silent --show-error --max-time 10 --request POST \
        --output /dev/null --dump-header - \
        "http://${listen}${path}" "$@"); then
        echo "The administration UI is not reachable at http://${listen}; the dexuser System App must be running (see APPMESH_AUTH_ADMIN_UI)" >&2
        return 1
    fi
    location=$(printf '%s\n' "${headers}" | sed -n 's/^[Ll]ocation:[[:space:]]*//p' | tr -d '\r' | tail -n 1)
    case "${location}" in
        *error=*)
            detail=${location##*error=}
            detail=${detail//+/ }
            detail=$(printf '%b' "${detail//%/\\x}")
            echo "The administration UI rejected the request: ${detail}" >&2
            return 1
            ;;
    esac
}

# Create a Dex password user through the administration UI and bind its App
# Mesh Principal. The password comes from standard input, like
# set-initial-password: argv and the environment leak into ps, docker inspect,
# and CI logs. The Principal ID is written to standard output; the report goes
# to standard error.
add_user() {
    local email=$1
    local role=${2:-appmesh-viewer}
    [[ -n "${email}" ]] || {
        echo "usage: appmesh-auth.sh add-user <email> [role]" >&2
        return 1
    }
    # Dex compares static emails case-insensitively, so this guard does too.
    # Otherwise a mixed-case address reaches Dex and fails with its own error.
    local email_lower
    email_lower=$(printf '%s' "${email}" | tr '[:upper:]' '[:lower:]')
    case "${email_lower}" in
        "${DEX_INITIAL_ADMIN_EMAIL}"|"${DEX_INITIAL_GUEST_EMAIL}")
            # Dex serves these from its static list, which is read-only
            # through the administrative API.
            echo "The ${email} identity is a static entry in the authentication configuration. Dex cannot change it through the administrative API." >&2
            return 1
            ;;
    esac
    # A malformed address would create a stray identity, because Dex keys
    # password users by email. Reject it before creation.
    case "${email}" in
        ?*@?*) ;;
        *)
            echo "The user address must be an email address: ${email}" >&2
            return 1
            ;;
    esac
    # Check the role before the user is created. A half-done operation would
    # leave an identity in Dex that no policy authorizes.
    policy_defines_role "${role}" || {
        echo "The authorization policy does not define the role ${role}" >&2
        return 1
    }

    local password
    IFS= read -r password || [[ -n "${password}" ]] || {
        echo "Provide the user password on standard input" >&2
        return 1
    }
    if IFS= read -r _; then
        echo "The user password must be a single line" >&2
        return 1
    fi
    [[ -n "${password}" ]] || {
        echo "The user password must not be empty" >&2
        return 1
    }
    # bcrypt rejects inputs past 72 bytes; fail early with a clear message.
    if (( $(printf '%s' "${password}" | LC_ALL=C wc -c) > 72 )); then
        echo "The user password must be at most 72 bytes" >&2
        return 1
    fi

    prepare_owner_directories
    local random_hex user_id username
    random_hex=$(openssl rand -hex 16) || return 1
    user_id="${random_hex:0:8}-${random_hex:8:4}-${random_hex:12:4}-${random_hex:16:4}-${random_hex:20:12}"
    username=${email%%@*}

    # The UI hashes the password itself; hand it over through a private file so
    # it never appears in a process argument list.
    local password_file
    password_file=$(mktemp "${AUTH_SECRET_DIR}/.add-user.XXXXXX") || return 1
    chmod 600 "${password_file}"
    printf '%s' "${password}" >"${password_file}"
    password=""
    local ui_result
    if ! ui_result=$(admin_ui_post "/admin/password/create" \
        --data-urlencode "email=${email}" \
        --data-urlencode "username=${username}" \
        --data-urlencode "user_id=${user_id}" \
        --data-urlencode "password@${password_file}" 2>&1); then
        rm -f "${password_file}"
        printf '%s\n' "${ui_result}" >&2
        # An existing identity keeps its original user ID, so the Principal ID
        # cannot be derived here; report the case instead of printing a wrong one.
        case "${ui_result}" in
            *"already exists"*)
                echo "Bind the role to the Principal that identity already uses:" >&2
                echo "  POST /appmesh/principal/<principal-id>  {\"roles\": [\"${role}\"]}" >&2
                ;;
        esac
        return 1
    fi
    rm -f "${password_file}"

    local issuer subject principal_id
    issuer=${APPMESH_AUTH_ISSUER:-$(oidc_value issuer http://127.0.0.1:6062/auth)}
    subject=$(oidc_subject_for_user_id "${user_id}")
    principal_id=$(stable_principal_id "${issuer}" "${subject}") || {
        echo "failed to derive the Principal ID" >&2
        return 1
    }
    bind_principal "${principal_id}" "${issuer}" "${subject}" "${role}" || return 1

    echo "Created the Dex password user ${email}" >&2
    echo "  user_id:      ${user_id}" >&2
    echo "  OIDC subject: ${subject}" >&2
    echo "  Principal ID: ${principal_id}" >&2
    echo "  role:         ${role}" >&2

    local engine_state=unknown
    if command -v pgrep >/dev/null 2>&1; then
        if pgrep -x appmesh >/dev/null 2>&1; then
            engine_state=running
        else
            engine_state=stopped
        fi
    fi
    if [[ "${engine_state}" != "stopped" ]]; then
        echo "Note: a running Engine adopts this binding on the user's first request. If the user has already authenticated before, the Engine holds a role-less record; apply the role through the REST API while the Engine is ${engine_state}:" >&2
        echo "  POST /appmesh/principal/${principal_id}  {\"roles\": [\"${role}\"]}" >&2
    fi
    echo "${principal_id}"
}

# Remove a Dex password user through the administration UI and unbind its App
# Mesh Principal. The Principal ID is written to standard output when known;
# the report goes to standard error.
delete_user() {
    local email=$1
    [[ -n "${email}" ]] || {
        echo "usage: appmesh-auth.sh delete-user <email>" >&2
        return 1
    }
    # Dex compares static emails case-insensitively, so this guard does too.
    local email_lower
    email_lower=$(printf '%s' "${email}" | tr '[:upper:]' '[:lower:]')
    case "${email_lower}" in
        "${DEX_INITIAL_ADMIN_EMAIL}"|"${DEX_INITIAL_GUEST_EMAIL}")
            echo "The ${email} identity is a static entry in the authentication configuration. Dex cannot delete it through the administrative API." >&2
            return 1
            ;;
    esac

    # The Principal binding keys on the OIDC subject, which embeds the user_id.
    # Recover it from the UI password list before the entry disappears; the
    # column layout mirrors the fork's admin.html passwords table.
    local listen list_page user_id=""
    listen=${APPMESH_AUTH_ADMIN_LISTEN:-127.0.0.1:6064}
    if ! list_page=$(curl --fail --silent --show-error --max-time 10 \
        "http://${listen}/admin?section=passwords"); then
        echo "The administration UI is not reachable at http://${listen}; the dexuser System App must be running (see APPMESH_AUTH_ADMIN_UI)" >&2
        return 1
    fi
    user_id=$(printf '%s\n' "${list_page}" |
        { grep -F -A2 "<td class=\"mono\">${email}</td>" || true; } |
        sed -n 's/.*<td class="mono small">\([^<]*\)<\/td>.*/\1/p' |
        head -n 1)

    local issuer subject principal_id=""
    if [[ -n "${user_id}" ]]; then
        issuer=${APPMESH_AUTH_ISSUER:-$(oidc_value issuer http://127.0.0.1:6062/auth)}
        subject=$(oidc_subject_for_user_id "${user_id}")
        principal_id=$(stable_principal_id "${issuer}" "${subject}") || principal_id=""
    fi

    admin_ui_post "/admin/password/delete" --data-urlencode "email=${email}" || return 1

    if [[ -n "${principal_id}" ]]; then
        unbind_principal "${principal_id}" || true
    fi

    echo "Removed the Dex password user ${email}" >&2
    if [[ -n "${user_id}" ]]; then
        echo "  user_id:      ${user_id}" >&2
    fi
    if [[ -n "${principal_id}" ]]; then
        echo "  Principal ID: ${principal_id}" >&2
    else
        echo "  The user identifier is unknown, so no Principal record was removed." >&2
    fi

    local engine_state=unknown
    if command -v pgrep >/dev/null 2>&1; then
        if pgrep -x appmesh >/dev/null 2>&1; then
            engine_state=running
        else
            engine_state=stopped
        fi
    fi
    if [[ -n "${principal_id}" && "${engine_state}" != "stopped" ]]; then
        echo "Warning: the Engine owns the authorization policy and rewrites it from memory. Remove the Principal through the REST API when the Engine is ${engine_state}:" >&2
        echo "  DELETE /appmesh/principal/${principal_id}" >&2
    fi
    [[ -n "${principal_id}" ]] && echo "${principal_id}"
    return 0
}

yaml_quote() {
    local value=$1
    case "${value}" in
        *$'\n'*|*$'\r'*)
            echo "Authentication configuration values must not contain newlines" >&2
            return 1
            ;;
    esac
    value=${value//\'/\'\'}
    printf "'%s'" "${value}"
}

# Single web redirect URI: <origin of browser_entry>/oauth/callback. An empty
# browser_entry derives the daemon's own REST listener, scheme included, so a
# plaintext listener registers http:// and Dex does not reject the redirect.
derive_web_redirect_uri() {
    local browser_entry=${APPMESH_AUTH_BROWSER_ENTRY:-$(oidc_value browser_entry "")}
    if [[ -z "${browser_entry}" ]]; then
        local address=${APPMESH_REST_RestListenAddress:-$(yaml_value "${DAEMON_CONFIG}" RestListenAddress 127.0.0.1)}
        local port=${APPMESH_REST_RestListenPort:-$(yaml_value "${DAEMON_CONFIG}" RestListenPort 6060)}
        local ssl=${APPMESH_REST_SSL_SSLEnabled:-$(yaml_value "${DAEMON_CONFIG}" SSLEnabled true)}
        # Mirror the daemon's env coercion: TLS stays on only for exact "true" or a positive number.
        local scheme=http
        case "${ssl}" in
            true) scheme=https ;;
            *[!0-9]*) ;;
            *) [ "${ssl:-0}" -gt 0 ] && scheme=https ;;
        esac
        browser_entry="${scheme}://${address}:${port}"
    fi
    local scheme=${browser_entry%%://*}
    [[ "${scheme}" != "${browser_entry}" ]] || {
        echo "browser_entry must be an absolute http(s) URL: ${browser_entry}" >&2
        return 1
    }
    local rest=${browser_entry#*://}
    printf '%s://%s/oauth/callback' "${scheme}" "${rest%%[/?#]*}"
}

render_dex_config() {
    [[ -f "${DEX_CONFIG_TEMPLATE}" ]] || {
        echo "The authentication configuration template is unavailable: ${DEX_CONFIG_TEMPLATE}" >&2
        return 1
    }

    local issuer=${APPMESH_AUTH_ISSUER:-$(oidc_value issuer http://127.0.0.1:6062/auth)}
    local listen=${APPMESH_AUTH_LISTEN:-$(config_value listen 127.0.0.1:6062)}
    local telemetry_listen=${APPMESH_AUTH_TELEMETRY_LISTEN:-$(config_value telemetry_listen 127.0.0.1:6063)}
    local web_redirect_uri
    web_redirect_uri=$(derive_web_redirect_uri) || return 1
    validate_admin_credentials
    validate_guest_credentials
    ensure_automation_client
    local password_hash guest_password_hash automation_secret
    password_hash=$(credential_value "${DEX_INITIAL_CREDENTIALS}" password_hash)
    guest_password_hash=$(credential_value "${DEX_GUEST_CREDENTIALS}" password_hash)
    automation_secret=$(automation_client_value secret)
    # The administrative gRPC listener is optional. It is enabled only when the
    # mutual-TLS material is present, because Dex refuses to start when a
    # configured certificate file is missing and the authentication service
    # gates every sign-in.
    local grpc_enabled=0 grpc_skip=0 grpc_listen
    grpc_listen=${APPMESH_AUTH_GRPC_LISTEN:-127.0.0.1:5557}
    if [[ -f "${AUTH_GRPC_TLS_CERT}" && -f "${AUTH_GRPC_TLS_KEY}" && \
        -f "${AUTH_GRPC_TLS_CLIENT_CA}" ]]; then
        grpc_enabled=1
    fi
    # Pure PKCE deployments drop the resource-owner password grant from the Dex
    # grant types; the Engine reads the same setting to advertise the flows.
    # The password database stays enabled, so browser sign-in keeps working.
    local password_flow_disabled=0 grant_types_rendered=0 password_flow_value
    password_flow_value="${APPMESH_AUTH_PASSWORD_FLOW:-$(oidc_value password_flow true)}"
    # Lowercase first: the Engine compares case-insensitively, so a mixed-case
    # value would otherwise disable the advertised flow on one side only.
    password_flow_value="$(printf '%s' "${password_flow_value}" | tr '[:upper:]' '[:lower:]')"
    case "${password_flow_value}" in
        0|false|off|disabled) password_flow_disabled=1 ;;
        1|true) ;;
        # Accept the same value set as the Engine (OidcTokenVerifier.cpp).
        *)
            echo "APPMESH_AUTH_PASSWORD_FLOW must be true or false" >&2
            return 1
            ;;
    esac
    # Deployments without refresh tokens drop the refresh_token grant from the
    # Dex grant types; refresh_tokens_disabled reads the deployment setting.
    local refresh_token_disabled=0 refresh_token_status=0
    refresh_tokens_disabled || refresh_token_status=$?
    case ${refresh_token_status} in
        0) refresh_token_disabled=1 ;;
        1) ;;
        *) return 1 ;;
    esac
    # Absolute cap of a refresh-token chain (Dex expiry.refreshTokens
    # absoluteLifetime); rotation does not extend it. Dex enforces it alone.
    local refresh_max_lifetime absolute_lifetime_rendered=0
    refresh_max_lifetime="${APPMESH_AUTH_REFRESH_TOKEN_MAX_LIFETIME:-$(oidc_value refresh_token_max_lifetime 168h)}"
    if [[ ! "${refresh_max_lifetime}" =~ ^[0-9]+(s|m|h)$ ]]; then
        echo "APPMESH_AUTH_REFRESH_TOKEN_MAX_LIFETIME must be a duration like 30m or 168h" >&2
        return 1
    fi
    yaml_quote "${refresh_max_lifetime}" >/dev/null
    local public_value
    for public_value in \
        "${issuer}" "${listen}" "${telemetry_listen}" "${web_redirect_uri}" \
        "${DEX_INITIAL_ADMIN_EMAIL}" "${DEX_INITIAL_ADMIN_USERNAME}" \
        "${DEX_INITIAL_ADMIN_USER_ID}" "${password_hash}" \
        "${DEX_INITIAL_GUEST_EMAIL}" "${DEX_INITIAL_GUEST_USERNAME}" \
        "${DEX_INITIAL_GUEST_USER_ID}" "${guest_password_hash}" \
        "${automation_secret}" "${grpc_listen}" \
        "${AUTH_STATE_DIR}/dex/dex.db"; do
        yaml_quote "${public_value}" >/dev/null
    done
    if [[ ${grpc_enabled} -eq 1 ]]; then
        for public_value in \
            "${AUTH_GRPC_TLS_CERT}" "${AUTH_GRPC_TLS_KEY}" "${AUTH_GRPC_TLS_CLIENT_CA}"; do
            yaml_quote "${public_value}" >/dev/null
        done
    fi
    local temporary
    temporary=$(mktemp "${DEX_RUNTIME_CONFIG}.XXXXXX")
    chmod 600 "${temporary}"

    local line
    while IFS= read -r line || [[ -n "${line}" ]]; do
        case "${line}" in
            "# __APPMESH_AUTH_GRPC_BEGIN__")
                # Control markers, not configuration: never emit them, because
                # the final check rejects any unresolved marker text.
                [[ ${grpc_enabled} -eq 1 ]] || grpc_skip=1
                continue
                ;;
            "# __APPMESH_AUTH_GRPC_END__")
                grpc_skip=0
                continue
                ;;
        esac
        [[ ${grpc_skip} -eq 0 ]] || continue
        case "${line}" in
            "issuer: __APPMESH_AUTH_ISSUER__")
                printf 'issuer: %s\n' "$(yaml_quote "${issuer}")"
                ;;
            "    file: __APPMESH_AUTH_STORAGE_PATH__")
                printf '    file: %s\n' "$(yaml_quote "${AUTH_STATE_DIR}/dex/dex.db")"
                ;;
            "  http: __APPMESH_AUTH_LISTEN__")
                printf '  http: %s\n' "$(yaml_quote "${listen}")"
                ;;
            "  http: __APPMESH_AUTH_TELEMETRY_LISTEN__")
                printf '  http: %s\n' "$(yaml_quote "${telemetry_listen}")"
                ;;
            "    redirectURIs: [__APPMESH_AUTH_WEB_CALLBACK__]")
                printf '    redirectURIs: [%s]\n' "$(yaml_quote "${web_redirect_uri}")"
                ;;
            "  - email: __APPMESH_AUTH_INITIAL_ADMIN_EMAIL__")
                printf '  - email: %s\n' "$(yaml_quote "${DEX_INITIAL_ADMIN_EMAIL}")"
                ;;
            "    hash: __APPMESH_AUTH_INITIAL_ADMIN_PASSWORD_HASH__")
                printf '    hash: %s\n' "$(yaml_quote "${password_hash}")"
                ;;
            "    username: __APPMESH_AUTH_INITIAL_ADMIN_USERNAME__")
                printf '    username: %s\n' "$(yaml_quote "${DEX_INITIAL_ADMIN_USERNAME}")"
                ;;
            "    userID: __APPMESH_AUTH_INITIAL_ADMIN_USER_ID__")
                printf '    userID: %s\n' "$(yaml_quote "${DEX_INITIAL_ADMIN_USER_ID}")"
                ;;
            "  - email: __APPMESH_AUTH_INITIAL_GUEST_EMAIL__")
                printf '  - email: %s\n' "$(yaml_quote "${DEX_INITIAL_GUEST_EMAIL}")"
                ;;
            "    hash: __APPMESH_AUTH_INITIAL_GUEST_PASSWORD_HASH__")
                printf '    hash: %s\n' "$(yaml_quote "${guest_password_hash}")"
                ;;
            "    username: __APPMESH_AUTH_INITIAL_GUEST_USERNAME__")
                printf '    username: %s\n' "$(yaml_quote "${DEX_INITIAL_GUEST_USERNAME}")"
                ;;
            "    userID: __APPMESH_AUTH_INITIAL_GUEST_USER_ID__")
                printf '    userID: %s\n' "$(yaml_quote "${DEX_INITIAL_GUEST_USER_ID}")"
                ;;
            "    secret: __APPMESH_AUTH_AUTOMATION_SECRET__")
                printf '    secret: %s\n' "$(yaml_quote "${automation_secret}")"
                ;;
            "  addr: __APPMESH_AUTH_GRPC_LISTEN__")
                printf '  addr: %s\n' "$(yaml_quote "${grpc_listen}")"
                ;;
            "  tlsCert: __APPMESH_AUTH_GRPC_TLS_CERT__")
                printf '  tlsCert: %s\n' "$(yaml_quote "${AUTH_GRPC_TLS_CERT}")"
                ;;
            "  tlsKey: __APPMESH_AUTH_GRPC_TLS_KEY__")
                printf '  tlsKey: %s\n' "$(yaml_quote "${AUTH_GRPC_TLS_KEY}")"
                ;;
            "  tlsClientCA: __APPMESH_AUTH_GRPC_TLS_CLIENT_CA__")
                printf '  tlsClientCA: %s\n' "$(yaml_quote "${AUTH_GRPC_TLS_CLIENT_CA}")"
                ;;
            '  grantTypes: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "password", "client_credentials"]')
                grant_types_rendered=1
                if [[ ${password_flow_disabled} -eq 1 && ${refresh_token_disabled} -eq 1 ]]; then
                    printf '  grantTypes: ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code", "client_credentials"]\n'
                elif [[ ${password_flow_disabled} -eq 1 ]]; then
                    printf '  grantTypes: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "client_credentials"]\n'
                elif [[ ${refresh_token_disabled} -eq 1 ]]; then
                    printf '  grantTypes: ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code", "password", "client_credentials"]\n'
                else
                    printf '%s\n' "${line}"
                fi
                ;;
            "    absoluteLifetime: 168h")
                absolute_lifetime_rendered=1
                printf '    absoluteLifetime: %s\n' "$(yaml_quote "${refresh_max_lifetime}")"
                ;;
            *)
                printf '%s\n' "${line}"
                ;;
        esac
    done < "${DEX_CONFIG_TEMPLATE}" > "${temporary}"

    if grep -q '__APPMESH_' "${temporary}"; then
        rm -f "${temporary}"
        echo "The authentication configuration template contains an unresolved marker" >&2
        return 1
    fi
    # A template drift must never silently keep a grant the operator disabled.
    if [[ ${password_flow_disabled} -eq 1 && ${grant_types_rendered} -eq 0 ]]; then
        rm -f "${temporary}"
        echo "The authentication configuration template grantTypes line does not match; cannot drop the password grant" >&2
        return 1
    fi
    if [[ ${refresh_token_disabled} -eq 1 && ${grant_types_rendered} -eq 0 ]]; then
        rm -f "${temporary}"
        echo "The authentication configuration template grantTypes line does not match; cannot drop the refresh_token grant" >&2
        return 1
    fi
    if [[ "${refresh_max_lifetime}" != "168h" && ${absolute_lifetime_rendered} -eq 0 ]]; then
        rm -f "${temporary}"
        echo "The authentication configuration template absoluteLifetime line does not match; cannot set the refresh-token maximum lifetime" >&2
        return 1
    fi
    mv -f "${temporary}" "${DEX_RUNTIME_CONFIG}"
    chmod 600 "${DEX_RUNTIME_CONFIG}"
    password_hash=""
    guest_password_hash=""
    automation_secret=""
}

prepare_owner_directories() {
    local directory
    for directory in "${AUTH_STATE_DIR}" "${AUTH_SECRET_DIR}" "${AUTH_STATE_DIR}/dex"; do
        [[ ! -L "${directory}" ]] || {
            echo "refusing symbolic-link authentication state directory: ${directory}" >&2
            return 1
        }
    done
    install -d -m 700 \
        "${AUTH_STATE_DIR}" \
        "${AUTH_SECRET_DIR}" \
        "${AUTH_STATE_DIR}/dex"
}

migrate_legacy_credential() {
    local legacy=$1
    local current=$2
    if [[ -f "${legacy}" && ! -e "${current}" ]]; then
        [[ ! -L "${legacy}" ]] || {
            echo "refusing symbolic-link legacy credential: ${legacy}" >&2
            return 1
        }
        mv "${legacy}" "${current}"
    fi
}

bootstrap_owner() {
    prepare_owner_directories
    migrate_legacy_credential "${LEGACY_INITIAL_CREDENTIALS}" "${DEX_INITIAL_CREDENTIALS}"
    migrate_legacy_credential "${LEGACY_GUEST_CREDENTIALS}" "${DEX_GUEST_CREDENTIALS}"
    ensure_admin_credentials
    ensure_guest_credentials
    ensure_automation_client
    seed_builtin_principals
    ensure_replication_follower_tokens

    local ready_file="${AUTH_STATE_DIR}/bootstrap.ready"
    local temporary owner
    if [[ -e "${ready_file}" || -L "${ready_file}" ]]; then
        private_file_metadata "${ready_file}" >/dev/null
        return
    fi
    owner=$(stat_fmt '%u:%g' "${AUTH_STATE_DIR}") || return 1
    temporary=$(mktemp "${AUTH_STATE_DIR}/.bootstrap-ready.XXXXXX") || return 1
    chmod 600 "${temporary}"
    chown "${owner}" "${temporary}"
    printf '%s\n' ready >"${temporary}"
    if ! ln "${temporary}" "${ready_file}" 2>/dev/null; then
        [[ ! -L "${ready_file}" && -f "${ready_file}" ]] || {
            rm -f "${temporary}"
            echo "failed to publish authentication bootstrap marker" >&2
            return 1
        }
    fi
    rm -f "${temporary}"
    private_file_metadata "${ready_file}" >/dev/null
}

prepare_dex_config() {
    # Render deployment settings and the persisted bcrypt value into a private
    # runtime file. The plaintext password is never materialized in Dex YAML.
    render_dex_config
}

# --- Cluster replication tokens (per follower, individually revocable) ------
# Two interchangeable sources, selected by environment:
#   file  (default): the accept list holds one bearer per line with an
#          optional label; distribution is a projected token file.
#   vault (real secrets service): the accepted per-follower tokens live in
#          Vault KV v2 (secret/appmesh/replication/<label>). Issuing and
#          revoking are KV operations against the component itself, every
#          change lands in the Vault audit log, and both engine sides read
#          live values: the owner lists per request, the follower reads its
#          own entry per pull. Rotation propagates without any restart.
replication_token_file() {
    echo "${APPMESH_AUTH_REPLICATION_TOKEN_FILE:-${AUTH_STATE_DIR}/replication/replication-token}"
}

replication_vault_addr() {
    # The Vault tooling is opt-in: it activates only when the deployment
    # selected the secrets-service source AND named an address — an empty
    # address resolves to the file source, the same silent fallback the
    # engine's AuthReplicator applies.
    [ "${APPMESH_AUTH_REPLICATION_TOKEN_SOURCE:-file}" = "vault" ] || return 1
    [ -n "${APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR:-}" ] || return 1
    echo "${APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR}"
}

replication_vault_kv_path() {
    echo "secret/data/${APPMESH_REPLICATION_VAULT_KV_PATH:-appmesh/replication}"
}

replication_vault_meta_path() {
    echo "secret/metadata/${APPMESH_REPLICATION_VAULT_KV_PATH:-appmesh/replication}"
}

vault_curl() {
    # vault_curl <ADDR> <TOKEN> <METHOD> <PATH> [JSON_BODY] — one bounded
    # curl shared by both Vault helpers: timeouts keep a network black hole
    # failing fast instead of hanging bootstrap, and the token rides in a
    # header file so it never appears in a process listing. Fails on a
    # transport error, on HTTP >= 400, and on a Vault error envelope (a JSON
    # errors array that is present and non-empty — Vault answers a missing KV
    # key with 404 and {"errors":[]}, which is a miss, not an outage). The
    # exit code separates the miss: 2 for HTTP 404, 1 for any other failure,
    # so callers can tell "no such entry" from "Vault is broken".
    # APPMESH_VAULT_CACERT (a PEM file) makes https:// addresses verify
    # against a private CA; the same variable drives the engine's VaultClient.
    local addr=$1 token=$2 method=$3 path=$4 body=${5:-} out status rc header ca
    header=$(mktemp) || return 1
    printf 'X-Vault-Token: %s\n' "${token}" >"${header}"
    ca=""
    if [ -n "${APPMESH_VAULT_CACERT:-}" ]; then
        [ -f "${APPMESH_VAULT_CACERT}" ] || {
            echo "APPMESH_VAULT_CACERT is not a readable file: ${APPMESH_VAULT_CACERT}" >&2
            rm -f "${header}"
            return 1
        }
        ca="--cacert ${APPMESH_VAULT_CACERT}"
    fi
    if [ -n "${body}" ]; then
        out=$(curl -sS ${ca} --connect-timeout 3 --max-time 10 -X "${method}" -H @"${header}" \
            -H 'Content-Type: application/json' -d "${body}" -w '\n%{http_code}' "${addr}${path}" 2>&1)
    else
        out=$(curl -sS ${ca} --connect-timeout 3 --max-time 10 -X "${method}" -H @"${header}" \
            -w '\n%{http_code}' "${addr}${path}" 2>&1)
    fi
    rc=$?
    rm -f "${header}"
    [ "${rc}" -eq 0 ] || { echo "${out}" >&2; return 1; }
    status=${out##*$'\n'}
    out=${out%$'\n'*}
    if [ "${status}" -ge 400 ] 2>/dev/null; then
        # A miss (404) stays quiet: existence probes are routine.
        [ "${status}" -eq 404 ] && return 2
        echo "${out}" >&2
        return 1
    fi
    if ! printf '%s' "${out}" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
errors = data.get("errors") if isinstance(data, dict) else None
sys.exit(1 if isinstance(errors, list) and errors else 0)' 2>/dev/null; then
        echo "${out}" >&2
        return 1
    fi
    printf '%s' "${out}"
}

vault_api() {
    # vault_api <METHOD> <PATH> [JSON_BODY] — prints the response body and
    # fails on a Vault error envelope or a transport failure. The credential
    # is the owner's service token: one line, like the engine's VaultClient
    # resolves it (two-line AppRole pairs are parsed by vault_tls_token).
    local token
    token=$(sed -n '1p' "${APPMESH_AUTH_REPLICATION_TOKEN_VAULT_TOKEN_FILE:?vault token file unset}" 2>/dev/null) || {
        echo "The Vault token file is not readable" >&2
        return 1
    }
    vault_curl "${APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR}" "${token}" "$@"
}

validate_replication_label() {
    case "${1:-}" in
        ''|*[!A-Za-z0-9._-]*)
            echo "The follower label may only use letters, digits, '.', '_' or '-'" >&2
            return 1
            ;;
    esac
}

issue_replication_token() {
    validate_replication_label "${1:-}" || return 1
    local token payload
    if replication_vault_addr >/dev/null; then
        # A revoked label stays revoked: the tombstone written at revocation
        # blocks this path too, not only the bootstrap.
        if vault_api GET "/v1/$(replication_vault_kv_path)/$1.revoked" >/dev/null 2>&1; then
            echo "Follower <$1> is revoked; delete the tombstone first (replication-token-restore $1)" >&2
            return 1
        fi
        token=$(openssl rand -hex 32) || { echo "Could not generate a token" >&2; return 1; }
        payload=$(python3 -c 'import json,sys;print(json.dumps({"data":{"token":sys.argv[1]}}))' "${token}") || return 1
        # KV v2 put on an existing key is the rotation; the follower reads the
        # new value on its next pull. A fresh label also needs its policy,
        # AppRole and delivered credential — the same chain the bootstrap
        # builds (a bare KV entry alone serves no new follower).
        vault_api PUT "/v1/$(replication_vault_kv_path)/$1" "${payload}" >/dev/null || return 1
        local dir
        dir=$(dirname "$(replication_token_file)")
        mkdir -p "${dir}"
        ensure_replication_vault_token "$1" "${dir}" || return 1
        echo "${token}"
        return 0
    fi
    token=$(openssl rand -hex 32) || { echo "Could not generate a token" >&2; return 1; }
    local file slot rotate
    file=$(replication_token_file)
    mkdir -p "$(dirname "${file}")"
    slot="$(dirname "${file}")/$1.token"
    rotate=0
    [ -f "${slot}" ] && rotate=1
    if [ "${rotate}" -eq 0 ] && [ -f "${file}" ] &&
        awk -v n="$1" 'NF >= 2 && $2 == n { found = 1 } END { exit !found }' "${file}"; then
        echo "A replication token labeled <${1}> already exists; revoke it first" >&2
        return 1
    fi
    if [ "${rotate}" -eq 1 ]; then
        # Rotation: replace the accept line and rewrite the follower's file in
        # place; the follower re-reads its token on the next pull.
        local tmp="${file}.tmp.$$"
        awk -v n="$1" '!(NF >= 2 && $2 == n)' "${file}" > "${tmp}" || { rm -f "${tmp}"; return 1; }
        chmod 600 "${tmp}"
        mv "${tmp}" "${file}"
    fi
    printf '%s %s\n' "${token}" "$1" >> "${file}"
    if [ "${rotate}" -eq 1 ]; then
        printf '%s\n' "${token}" > "${slot}"
        chmod 600 "${slot}"
        echo "Rotated the replication token for <${1}>" >&2
    fi
    chmod 600 "${file}"
    echo "${token}" # shown exactly once; the label stays in the file for audit
}

revoke_replication_token() {
    validate_replication_label "${1:-}" || return 1
    if replication_vault_addr >/dev/null; then
        # Persistent revocation, not a bare KV DELETE (a soft delete the next
        # bootstrap would undo by re-issuing): a tombstone entry checked
        # before any issuance, the accepted token deleted, the follower's
        # AppRole and its policy destroyed. The tombstone lands first — a
        # revoke interrupted mid-way then leaves a still-working follower
        # (rerun to finish) instead of one that resurrects on restart.
        local dir payload
        dir=$(dirname "$(replication_token_file)")
        payload=$(python3 -c 'import json,time;print(json.dumps({"data":{"revoked_at":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}))') || return 1
        vault_api PUT "/v1/$(replication_vault_kv_path)/$1.revoked" "${payload}" >/dev/null ||
            { echo "Could not write the revocation tombstone for <${1}> in Vault (check Vault reachability and the owner credential)" >&2; return 1; }
        # Exit code 2 (HTTP 404) from the data delete means the entry never
        # existed; anything else is a broken Vault or owner credential.
        local del_rc=0
        vault_api DELETE "/v1/$(replication_vault_kv_path)/$1" >/dev/null 2>&1 || del_rc=$?
        case "${del_rc}" in
            0|2) ;;
            *) echo "Could not revoke replication token <${1}> in Vault (check Vault reachability and the owner credential)" >&2; return 1 ;;
        esac
        # The machine identity dies with the role: a delivered credential
        # (role_id + secret_id file a follower still holds) can no longer log
        # in, and the policy it referenced is gone too.
        vault_api DELETE "/v1/auth/approle/role/appmesh-follower-$1" >/dev/null 2>&1 || true
        vault_api DELETE "/v1/sys/policies/acl/appmesh-follower-$1" >/dev/null 2>&1 || true
        # Remove the credential file when this master's replication directory
        # is writable (the compose topology mounts it read-write); a follower
        # holding a copy is stranded safely — the AppRole is destroyed and
        # the tombstone blocks every re-issue.
        rm -f "${dir}/$1.vault-token" 2>/dev/null || true
        echo "Revoked replication token <$1> in Vault; its next pull is rejected"
        echo "To re-enable: replication-token-restore $1" >&2
        return 0
    fi
    local file tmp slot
    file=$(replication_token_file)
    [ -f "${file}" ] || { echo "No replication token file at <${file}>" >&2; return 1; }
    tmp="${file}.tmp.$$"
    if ! awk -v n="$1" '!(NF >= 2 && $2 == n)' "${file}" > "${tmp}"; then
        rm -f "${tmp}"
        return 1
    fi
    if [ "$(wc -l < "${file}")" -eq "$(wc -l < "${tmp}")" ]; then
        rm -f "${tmp}"
        echo "No replication token labeled <${1}>" >&2
        return 1
    fi
    chmod 600 "${tmp}"
    mv "${tmp}" "${file}"
    # Truncate (not delete) a provisioned slot: an empty file stays "present"
    # so bootstrap provisioning does not silently re-enable the follower. To
    # re-enable, rotate with: replication-token <label> (or delete the slot
    # file and restart the owner bootstrap).
    slot="$(dirname "${file}")/$1.token"
    [ -f "${slot}" ] && : > "${slot}" && chmod 600 "${slot}"
    echo "Revoked replication token <${1}>; its next pull is rejected"
}

# Undo a Vault revocation (the file source has no tombstone; rotate instead).
# Deletes the tombstone and re-runs the bootstrap chain; the follower must
# receive the new credential file before it pulls again.
restore_replication_token() {
    validate_replication_label "${1:-}" || return 1
    replication_vault_addr >/dev/null || {
        echo "The file source keeps no tombstone: rotate with replication-token <${1}>" >&2
        return 1
    }
    local rc=0
    vault_api DELETE "/v1/$(replication_vault_kv_path)/$1.revoked" >/dev/null 2>&1 || rc=$?
    [ "${rc}" -eq 2 ] && { echo "No revocation tombstone for <${1}>" >&2; return 1; }
    [ "${rc}" -eq 0 ] || { echo "Could not delete the tombstone for <${1}> in Vault" >&2; return 1; }
    local dir
    dir=$(dirname "$(replication_token_file)")
    mkdir -p "${dir}"
    ensure_replication_vault_token "$1" "${dir}" || return 1
    echo "Re-enabled follower <${1}>: a fresh token, AppRole and credential file are issued" >&2
    echo "Recreate (or re-deliver credentials to) the follower so it picks up the new file" >&2
}

list_replication_tokens() {
    if replication_vault_addr >/dev/null; then
        # An empty KV store answers the metadata list with 404: that is "no
        # entries", not an outage. Any other failure propagates — a broken
        # Vault must not exit 0 behind an empty listing.
        local body rc=0
        body=$(vault_api GET "/v1/$(replication_vault_meta_path)?list=true") || rc=$?
        case "${rc}" in
            0) ;;
            2) return 0 ;;
            *) return 1 ;;
        esac
        printf '%s' "${body}" | python3 -c '
import sys, json
for key in json.load(sys.stdin)["data"]["keys"]:
    label = key.rstrip("/")
    print(label + " (revoked)" if label.endswith(".revoked") else label)'
        return 0
    fi
    local file
    file=$(replication_token_file)
    [ -f "${file}" ] || { echo "(no replication token file)" >&2; return 0; }
    awk 'NF && $1 !~ /^#/ { print (NF >= 2 ? $2 : "shared") }' "${file}"
}

# Provision per-follower replication tokens for the declared follower set
# (APPMESH_AUTH_REPLICATION_FOLLOWERS, space or comma separated). Idempotent:
# an existing token is never regenerated; rotation is a deliberate
# replication-token re-issue.
ensure_replication_follower_tokens() {
    local followers=${APPMESH_AUTH_REPLICATION_FOLLOWERS:-}
    [ -n "${followers}" ] || return 0
    local label dir
    dir="$(dirname "$(replication_token_file)")"
    mkdir -p "${dir}"
    followers=${followers//,/ }
    # Word-split without globbing: a label carrying '*' must stay a label.
    printf '%s\n' "${followers}" | tr -s ' \t' '\n' | while IFS= read -r label; do
        [ -n "${label}" ] || continue
        validate_replication_label "${label}" || exit 1
        if replication_vault_addr >/dev/null; then
            ensure_replication_vault_token "${label}" "${dir}" || exit 1
        else
            ensure_replication_file_token "${label}" "${dir}" || exit 1
        fi
    done
}

# File source: one single-token file per follower, registered as a labeled
# line in the accept list (projected-secret pattern; read-only mounts).
ensure_replication_file_token() {
    local label=$1 dir=$2 token
    [ -f "${dir}/${label}.token" ] && return 0
    token=$(openssl rand -hex 32) || { echo "Could not generate a replication token" >&2; return 1; }
    printf '%s %s\n' "${token}" "${label}" >> "$(replication_token_file)"
    printf '%s\n' "${token}" > "${dir}/${label}.token"
    chmod 600 "$(replication_token_file)" "${dir}/${label}.token"
    echo "Issued the replication token for follower <${label}>" >&2
}

# Vault source: the KV entry is the accepted token. The follower's machine
# identity is an AppRole (role_id + one secret_id), the standard Vault
# issuance for non-human callers: the engine logs in for a fresh client token
# on every pull, and the role's policy can read its own KV entry only. The
# credential file is the single bootstrap secret delivered through the volume.
ensure_replication_vault_token() {
    local label=$1 dir=$2 token payload policy role role_id secret_id
    # Revocation is persistent: the tombstone entry (written before the KV
    # delete at revoke time) survives restarts, so a bootstrap never
    # re-issues a revoked follower. "Never issued" (404, no tombstone) is
    # the only path that auto-issues. Undo: replication-token-restore.
    if vault_api GET "/v1/$(replication_vault_kv_path)/${label}.revoked" >/dev/null 2>&1; then
        echo "Skipping follower <${label}>: revoked (tombstone at $(replication_vault_kv_path)/${label}.revoked)" >&2
        return 0
    fi
    if ! vault_api GET "/v1/$(replication_vault_kv_path)/${label}" >/dev/null 2>&1; then
        token=$(openssl rand -hex 32) || return 1
        payload=$(python3 -c 'import json,sys;print(json.dumps({"data":{"token":sys.argv[1]}}))' "${token}") || return 1
        vault_api PUT "/v1/$(replication_vault_kv_path)/${label}" "${payload}" >/dev/null || return 1
        echo "Issued the Vault replication token for follower <${label}>" >&2
    fi
    # The policy is rewritten on every bootstrap (a delivered credential does
    # not stop the rewrite: that is exactly how a follower provisioned before
    # the PKI source gains its pki/issue path). A policy upsert invalidates
    # nothing; the KV path follows APPMESH_REPLICATION_VAULT_KV_PATH like
    # every other reader. The role is created once and never replaced: a PUT
    # would mint a new role_id and silently invalidate every delivered
    # credential. Changing a role is an explicit operator action.
    policy=$(
        python3 - "${label}" "$(ssl_vault_pki_role)" "$(replication_vault_kv_path)" <<'PY'
import json, sys
label, role, kv = sys.argv[1], sys.argv[2], sys.argv[3]
rules = (
    f'path "{kv}/{label}" {{ capabilities = ["read"] }}\n'
    f'path "pki/issue/{role}" {{ capabilities = ["create", "update"] }}'
)
print(json.dumps({"policy": rules}))
PY
    ) || return 1
    vault_api PUT "/v1/sys/policies/acl/appmesh-follower-${label}" "${policy}" >/dev/null || return 1
    if ! vault_api GET "/v1/auth/approle/role/appmesh-follower-${label}/role-id" >/dev/null 2>&1; then
        # Every pull mints a fresh token through this role, so the tokens stay
        # use-bounded and short-lived: a login per pull cycle would otherwise
        # accumulate month-long tokens in the token table (a pull needs at
        # most three calls: its KV read and two PKI issues).
        role=$(python3 - "${label}" <<'PY'
import json, sys
print(json.dumps({"token_policies": ["appmesh-follower-" + sys.argv[1]], "token_ttl": "1h", "token_num_uses": 10}))
PY
        ) || return 1
        vault_api PUT "/v1/auth/approle/role/appmesh-follower-${label}" "${role}" >/dev/null || return 1
    fi
    # A delivered credential is final: re-issuing would rewrite the AppRole
    # (PUT replaces the role and invalidates every delivered secret_id) while
    # the follower keeps the old file. Rotate explicitly instead.
    [ -f "${dir}/${label}.vault-token" ] && return 0
    # Field order in Vault's JSON is not contractual (secret_id_accessor
    # sorts before secret_id); parse it properly instead of positional awk.
    role_id=$(vault_api GET "/v1/auth/approle/role/appmesh-follower-${label}/role-id" |
        python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["role_id"])') || return 1
    secret_id=$(vault_api POST "/v1/auth/approle/role/appmesh-follower-${label}/secret-id" '{}' |
        python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["secret_id"])') || return 1
    printf '%s\n%s\n' "${role_id}" "${secret_id}" > "${dir}/${label}.vault-token"
    chmod 600 "${dir}/${label}.vault-token"
    echo "Issued the AppRole Vault access for follower <${label}>" >&2
}


# --- Cluster TLS material (central issuance through the Vault PKI) ----------
# Two interchangeable sources, selected by APPMESH_SSL_SOURCE exactly like the
# replication tokens above:
#   file  (default): each node self-signs its six-file set (docker entrypoint
#          / setup.sh) and the compose cluster shares the owner CA by volume.
#   vault (real PKI): one cluster CA lives in the Vault PKI engine and signs
#          every node's leaf certificates — owner and followers alike — so any
#          node verifies any peer. The CA private key never leaves Vault:
#          this path writes the five daemon-consumed files and no ca-key.pem.
# Issuing and renewing are operator actions (bootstrap, tls-renew); the engine
# only ever consumes files and serves new material after a restart.
ssl_vault_addr() {
    # Opt-in like the replication tooling: it activates only when the
    # deployment selected the central source. The address defaults to the
    # replication deployment's Vault when no dedicated one was pinned.
    [ "${APPMESH_SSL_SOURCE:-file}" = "vault" ] || return 1
    echo "${APPMESH_SSL_VAULT_ADDR:-${APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR:-}}"
}

ssl_vault_token_file() {
    echo "${APPMESH_SSL_VAULT_TOKEN_FILE:-${APPMESH_AUTH_REPLICATION_TOKEN_VAULT_TOKEN_FILE:-}}"
}

ssl_vault_pki_role() {
    echo "${APPMESH_SSL_VAULT_PKI_ROLE:-appmesh-node}"
}

vault_tls_api() {
    # vault_tls_api <ADDR> <TOKEN> <METHOD> <PATH> [JSON_BODY] — the PKI
    # companion of vault_api, parametrized on address and token so one helper
    # serves the owner's service token and the follower AppRole logins.
    vault_curl "$@"
}

vault_tls_token() {
    # Resolve the bootstrap credential exactly like the engine's VaultClient:
    # one line is a static service token (the owner's); a non-empty second
    # line is an AppRole (role_id, secret_id) whose login mints a fresh client
    # token. A lone trailing newline stays the one-line form.
    local addr=$1 file token secret_id payload
    file=$(ssl_vault_token_file)
    [ -n "${file}" ] && [ -f "${file}" ] || {
        echo "The Vault token file for TLS is unavailable: ${file:-unset}" >&2
        return 1
    }
    token=$(sed -n '1p' "${file}")
    secret_id=$(sed -n '2p' "${file}")
    if [ -n "$(printf '%s' "${secret_id}" | tr -d '[:space:]')" ]; then
        payload=$(printf '%s\n%s\n' "${token}" "${secret_id}" |
            python3 -c 'import json,sys;print(json.dumps(dict(zip(("role_id", "secret_id"), sys.stdin.read().splitlines()))))') || return 1
        token=$(vault_tls_api "${addr}" "" POST /v1/auth/approle/login "${payload}" |
            python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"]["client_token"])') || return 1
    fi
    [ -n "${token}" ] || { echo "The Vault credential for TLS is empty" >&2; return 1; }
    printf '%s' "${token}"
}

tls_trusts_vault_ca() {
    # True when the five daemon-consumed files are complete, the installed
    # ca.pem is byte-identical to the argument CA, and both leaves chain to
    # it. Material from any other origin — a previous self-signed set, a
    # replaced CA, a bootstrap interrupted between the CA and leaf writes —
    # fails and is re-issued: the check doubles as the migration path from
    # the file source and as the self-heal for a half-written set (peers
    # verify against the installed ca.pem, so leaves that chain to the
    # fetched CA but not to the installed one are not good enough).
    local ca_file=$1 leaf
    for leaf in ca.pem server.pem server-key.pem client.pem client-key.pem; do
        [ -f "${AUTH_TLS_DIR}/${leaf}" ] || return 1
    done
    cmp -s "${ca_file}" "${AUTH_TLS_DIR}/ca.pem" || return 1
    openssl verify -CAfile "${ca_file}" \
        "${AUTH_TLS_DIR}/server.pem" "${AUTH_TLS_DIR}/client.pem" >/dev/null 2>&1
}

issue_vault_certificate() {
    # POST pki/issue/<role> for one leaf; prints the Vault response. Empty SAN
    # lists are omitted rather than sent as empty strings; the API takes DNS
    # names as alt_names and addresses as ip_sans (unknown fields are ignored
    # silently, so a wrong name means a silently missing SAN).
    local addr=$1 token=$2 role=$3 common_name=$4 dns=$5 ips=$6 payload
    payload=$(python3 -c '
import json, sys
payload = {"common_name": sys.argv[1]}
if sys.argv[2]:
    payload["alt_names"] = sys.argv[2]
if sys.argv[3]:
    payload["ip_sans"] = sys.argv[3]
print(json.dumps(payload))' "${common_name}" "${dns}" "${ips}") || return 1
    vault_tls_api "${addr}" "${token}" POST "/v1/pki/issue/${role}" "${payload}"
}

write_vault_leaf() {
    # Atomically install one issued pair: certificate 644, private key 600.
    # The Vault response arrives on stdin — the private key never sits in a
    # process's argv. The paths are argv (not secret), so the program itself
    # rides a -c string and stdin stays the data channel.
    local cert_path=$1 key_path=$2
    python3 -c '
import json, os, sys
data = json.load(sys.stdin)["data"]
for path, field, mode in ((sys.argv[1], "certificate", 0o644), (sys.argv[2], "private_key", 0o600)):
    temporary = path + ".tmp"
    with open(temporary, "w") as handle:
        handle.write(data[field])
    os.chmod(temporary, mode)
    os.replace(temporary, path)
' "${cert_path}" "${key_path}"
}

provision_tls_vault() {
    local force=${1:-0}
    local addr role token temporary sans san_dns san_ip common_name response server_response leaf
    addr=$(ssl_vault_addr) || return 1
    [ -n "${addr}" ] || { echo "The Vault address for TLS is unset" >&2; return 1; }
    role=$(ssl_vault_pki_role)
    token=$(vault_tls_token "${addr}") || return 1

    [ ! -L "${AUTH_TLS_DIR}" ] || { echo "refusing symbolic-link TLS directory: ${AUTH_TLS_DIR}" >&2; return 1; }
    install -d -m 700 "${AUTH_TLS_DIR}"
    for leaf in ca.pem server.pem server-key.pem client.pem client-key.pem; do
        [ ! -L "${AUTH_TLS_DIR}/${leaf}" ] || {
            echo "refusing symbolic-link TLS material: ${AUTH_TLS_DIR}/${leaf}" >&2
            return 1
        }
    done
    temporary="${AUTH_TLS_DIR}/.vault-ca.$$"
    rm -f "${temporary}"

    # The trust anchor: the root certificate, or the issuing chain when an
    # operator layers an intermediate CA on the engine.
    vault_tls_api "${addr}" "" GET /v1/pki/cert/ca |
        python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["certificate"])' \
        >"${temporary}" || { rm -f "${temporary}"; return 1; }
    if [ "${force}" -eq 0 ] && tls_trusts_vault_ca "${temporary}"; then
        rm -f "${temporary}"
        return 0
    fi

    # Same name coverage as the self-signed generator: hostname, FQDN, local
    # addresses and the APPMESH_SSL_EXTRA_SAN peers, split the way the Vault
    # API wants them (alt_names takes DNS names, ip_names takes addresses).
    [ -x "${APPMESH_ROOT}/ssl/generate_ssl_cert.sh" ] || {
        echo "The SAN listing tool is unavailable: ${APPMESH_ROOT}/ssl/generate_ssl_cert.sh" >&2
        rm -f "${temporary}"
        return 1
    }
    sans=$("${APPMESH_ROOT}/ssl/generate_ssl_cert.sh" --san-list) || { rm -f "${temporary}"; return 1; }
    san_dns=$(printf '%s\n' "${sans}" | sed -n '1p')
    san_ip=$(printf '%s\n' "${sans}" | sed -n '2p')
    common_name=$(hostname 2>/dev/null) || common_name=""
    [ -n "${common_name}" ] && [ "${#common_name}" -le 64 ] || common_name="AppMesh-Server"
    # Vault PKI rejects underscore hostnames as common_name once the issuing
    # role enforces hostnames; the hyphenated form is the same node under
    # the alias the overlay already dials.
    common_name=${common_name//_/-}

    # Both leaves are issued before any file changes: a failure mid-way must
    # not leave a half-replaced set. The CA lands first: an interruption then
    # leaves new CA + old leaves, which the next bootstrap detects (the
    # installed ca.pem no longer matches, the leaves no longer chain) and
    # re-issues — leaves-first would strand old CA + new leaves, a state the
    # trust check could not see. An existing ca.pem is rewritten in place
    # (same inode): the compose topology projects exactly that file into the
    # followers and the MCP service.
    response=$(issue_vault_certificate "${addr}" "${token}" "${role}" \
        "${common_name}" "${san_dns}" "${san_ip}") || { rm -f "${temporary}"; return 1; }
    server_response=${response}
    response=$(issue_vault_certificate "${addr}" "${token}" "${role}" \
        "appmesh-client" "${san_dns}" "${san_ip}") || { rm -f "${temporary}"; return 1; }
    if [ -f "${AUTH_TLS_DIR}/ca.pem" ]; then
        cat "${temporary}" >"${AUTH_TLS_DIR}/ca.pem" || { rm -f "${temporary}"; return 1; }
        rm -f "${temporary}"
    else
        chmod 644 "${temporary}"
        mv -f "${temporary}" "${AUTH_TLS_DIR}/ca.pem" || return 1
    fi
    printf '%s' "${server_response}" | write_vault_leaf "${AUTH_TLS_DIR}/server.pem" "${AUTH_TLS_DIR}/server-key.pem" || return 1
    printf '%s' "${response}" | write_vault_leaf "${AUTH_TLS_DIR}/client.pem" "${AUTH_TLS_DIR}/client-key.pem" || return 1
    # A stale signing key from the file source has no business here: this
    # node's certificates are issued by Vault, never locally.
    rm -f "${AUTH_TLS_DIR}/ca-key.pem"
    echo "Issued the TLS certificates for <${common_name}> from the Vault PKI" >&2
}

ensure_tls_material() {
    # Bootstrap hook on every node: central issuance when the deployment
    # selected the Vault PKI source; the file source self-signs in the docker
    # entrypoint / setup and needs nothing here.
    ssl_vault_addr >/dev/null || return 0
    provision_tls_vault 0
}


action=${1:-}
case "${action}" in
    bootstrap)
        # One-shot install-time initialization (setup.sh / docker entrypoint).
        # The `dex` subcommand re-runs both steps idempotently on every start,
        # so this only pre-creates the credentials and runtime configuration.
        if is_builtin_auth && is_auth_owner; then
            bootstrap_owner
            prepare_dex_config
            echo "App Mesh authentication state initialized" >&2
        fi
        # Every node — owner and followers — provisions its TLS material
        # before the daemon starts; the file source self-signs instead.
        ensure_tls_material
        ;;
    service|dex)
        if ! is_builtin_auth || ! is_auth_owner; then
            hold_system_app
        fi
        bootstrap_owner
        prepare_dex_config
        export DEX_CLIENT_CREDENTIAL_GRANT_ENABLED_BY_DEFAULT=true
        exec "${APPMESH_ROOT}/bin/dex" serve "${DEX_RUNTIME_CONFIG}"
        ;;
    service-health|dex-health)
        if ! is_builtin_auth || ! is_auth_owner; then
            exit 0
        fi
        telemetry_listen=${APPMESH_AUTH_TELEMETRY_LISTEN:-$(config_value telemetry_listen 127.0.0.1:6063)}
        exec curl --fail --silent --show-error --max-time 2 "http://${telemetry_listen}/healthz"
        ;;
    automation-token)
        request_automation_token
        ;;
    user-token)
        is_builtin_auth || { echo "The user token is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "The user token is managed only on the authentication owner" >&2; exit 1; }
        user_token_name=
        user_token_with_refresh=0
        for user_token_arg in "${@:2}"; do
            case "${user_token_arg}" in
                --with-refresh) user_token_with_refresh=1 ;;
                -*)
                    echo "usage: appmesh-auth.sh user-token [--with-refresh] [username]" >&2
                    exit 2
                    ;;
                *)
                    [[ -z "${user_token_name}" ]] || {
                        echo "usage: appmesh-auth.sh user-token [--with-refresh] [username]" >&2
                        exit 2
                    }
                    user_token_name=${user_token_arg}
                    ;;
            esac
        done
        request_user_token "${user_token_name}" "${user_token_with_refresh}"
        ;;
    print-initial-password)
        is_builtin_auth || { echo "The initial password is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "The initial password is managed only on the authentication owner" >&2; exit 1; }
        print_initial_password
        ;;
    rotate-initial-password)
        is_builtin_auth || { echo "The initial password is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "The initial password is managed only on the authentication owner" >&2; exit 1; }
        rotate_initial_credentials
        ;;
    set-initial-password)
        is_builtin_auth || { echo "The initial password is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "The initial password is managed only on the authentication owner" >&2; exit 1; }
        set_initial_password
        ;;
    forget-initial-password)
        is_builtin_auth || { echo "The initial password is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "The initial password is managed only on the authentication owner" >&2; exit 1; }
        forget_initial_password
        ;;
    admin-ui)
        if ! is_builtin_auth || ! is_auth_owner || admin_ui_disabled; then
            hold_system_app
        fi
        admin_ui
        ;;
    admin-ui-health)
        if ! is_builtin_auth || ! is_auth_owner || admin_ui_disabled; then
            exit 0
        fi
        admin_ui_health
        ;;
    add-user)
        is_builtin_auth || { echo "The user management API is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "Users are managed only on the authentication owner" >&2; exit 1; }
        add_user "${2:-}" "${3:-}"
        ;;
    replication-token)
        is_auth_owner || { echo "Replication tokens are managed only on the authentication owner" >&2; exit 1; }
        issue_replication_token "${2:-}"
        ;;
    replication-token-revoke)
        is_auth_owner || { echo "Replication tokens are managed only on the authentication owner" >&2; exit 1; }
        revoke_replication_token "${2:-}"
        ;;
    replication-token-restore)
        is_auth_owner || { echo "Replication tokens are managed only on the authentication owner" >&2; exit 1; }
        restore_replication_token "${2:-}"
        ;;
    replication-token-list)
        is_auth_owner || { echo "Replication tokens are managed only on the authentication owner" >&2; exit 1; }
        list_replication_tokens
        ;;
    tls-renew)
        ssl_vault_addr >/dev/null || {
            echo "TLS renewal requires the Vault PKI source (APPMESH_SSL_SOURCE=vault)" >&2
            exit 1
        }
        provision_tls_vault 1
        echo "TLS certificates re-issued; restart the daemon to serve them" >&2
        ;;
    delete-user)
        is_builtin_auth || { echo "The user management API is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "Users are managed only on the authentication owner" >&2; exit 1; }
        delete_user "${2:-}"
        ;;
    *)
        echo "usage: appmesh-auth.sh {bootstrap|service|service-health|admin-ui|admin-ui-health|automation-token|user-token|print-initial-password|rotate-initial-password|set-initial-password|forget-initial-password|add-user|delete-user|replication-token|replication-token-revoke|replication-token-restore|replication-token-list|tls-renew}" >&2
        echo "  user-token [--with-refresh] [username]  print the password-grant access token; --with-refresh adds offline_access and prints the full JSON token set for SDK use" >&2
        echo "  replication-token <label>  issue a per-follower replication token (printed once); revoke with replication-token-revoke <label>; undo a Vault revocation with replication-token-restore <label>" >&2
        echo "  tls-renew  re-issue this node's TLS certificates from the Vault PKI, then restart the daemon to serve them" >&2
        exit 2
        ;;
esac
