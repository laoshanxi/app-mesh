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
DEX_PASSWORD_HASH_HELPER="${APPMESH_ROOT}/bin/password-hash"
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
# configured issuer (the packaged authorization.yaml already covers the factory
# default). Its password is generated once; rotate/forget remain administrator-
# only operations.
readonly DEX_INITIAL_GUEST_EMAIL="guest@appmesh.local"
readonly DEX_INITIAL_GUEST_USERNAME="guest"
readonly DEX_INITIAL_GUEST_USER_ID="93ad39b4-eb6f-4945-97a1-3366451867fb"
readonly DEX_INITIAL_GUEST_SUBJECT="CiQ5M2FkMzliNC1lYjZmLTQ5NDUtOTdhMS0zMzY2NDUxODY3ZmISBWxvY2Fs"

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

config_value() {
    local key=$1
    local fallback=$2
    local value
    value=$(awk -v wanted="${key}:" '$1 == wanted { $1=""; sub(/^[[:space:]]+/, ""); gsub(/^"|"$/, ""); print; exit }' "${AUTH_STACK_CONFIG}")
    if [[ -n "${value}" ]]; then
        printf '%s' "${value}"
    else
        printf '%s' "${fallback}"
    fi
}

oidc_value() {
    local key=$1
    local fallback=$2
    local value
    value=$(awk -v wanted="${key}:" '$1 == wanted { $1=""; sub(/^[[:space:]]+/, ""); gsub(/^"|"$/, ""); print; exit }' "${OIDC_CONFIG}")
    if [[ -n "${value}" ]]; then
        printf '%s' "${value}"
    else
        printf '%s' "${fallback}"
    fi
}

oidc_auth_value() {
    local key=$1
    local legacy_key=$2
    local fallback=$3
    local value
    value=$(oidc_value "${key}" '')
    if [[ -n "${value}" ]]; then
        printf '%s' "${value}"
    else
        oidc_value "${legacy_key}" "${fallback}"
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

    local issuer issuer_yaml automation_id guest_id source temporary
    local add_automation=1 add_guest=1 add_role=1
    issuer=${APPMESH_AUTH_ISSUER:-${APPMESH_DEX_ISSUER:-$(oidc_value issuer http://127.0.0.1:6062/auth)}}
    issuer_yaml=$(yaml_quote "${issuer}") || return 1
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
    if [[ "${source}" == "${AUTHORIZATION_RUNTIME}" &&
        ${add_automation} -eq 0 && ${add_guest} -eq 0 && ${add_role} -eq 0 ]]; then
        return 0
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
        rm -f "${temporary}"
        echo "authorization policy has no mergeable principals/roles sections; preserving it unchanged" >&2
        return 1
    fi
    mv "${temporary}" "${AUTHORIZATION_RUNTIME}"
    chmod 600 "${AUTHORIZATION_RUNTIME}"
    echo "Seeded missing built-in authorization bindings for issuer ${issuer}" >&2
}

request_automation_token() {
    is_builtin_auth && is_auth_owner || {
        echo "the automation token is available only from the built-in auth owner" >&2
        return 1
    }
    validate_automation_client

    local access_url tls_verify ca_path client_secret response token
    access_url=${APPMESH_AUTH_ACCESS_URL:-${APPMESH_DEX_ACCESS_URL:-$(oidc_auth_value access_url dex_access_url http://127.0.0.1:6062/auth)}}
    tls_verify=${APPMESH_AUTH_TLS_VERIFY:-${APPMESH_DEX_TLS_VERIFY:-$(oidc_auth_value tls_verify dex_tls_verify true)}}
    ca_path=${APPMESH_AUTH_CA_PATH:-${APPMESH_DEX_CA_PATH:-$(oidc_auth_value ca_path dex_ca_path '')}}
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

valid_bcrypt_hash() {
    [[ "$1" =~ ^\$2a\$10\$[./A-Za-z0-9]{53}$ ]]
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

    [[ ! -L "${DEX_PASSWORD_HASH_HELPER}" && -f "${DEX_PASSWORD_HASH_HELPER}" && -x "${DEX_PASSWORD_HASH_HELPER}" ]] || {
        echo "The password-hash helper is unavailable" >&2
        return 1
    }
    if [[ -e "${file}" || -L "${file}" ]]; then
        private_file_metadata "${file}" >/dev/null
    fi
    owner=$(stat_fmt '%u:%g' "${AUTH_SECRET_DIR}") || return 1
    hash_file=$(mktemp "${AUTH_SECRET_DIR}/.dex-password-hash.XXXXXX") || return 1
    chmod 600 "${hash_file}"
    if ! printf '%s\n' "${password}" | "${DEX_PASSWORD_HASH_HELPER}" >"${hash_file}"; then
        rm -f "${hash_file}"
        echo "failed to hash the initial ${label} password" >&2
        return 1
    fi
    IFS= read -r password_hash <"${hash_file}"
    rm -f "${hash_file}"
    valid_bcrypt_hash "${password_hash}" || {
        echo "The password-hash helper returned an invalid hash" >&2
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

render_dex_config() {
    [[ -f "${DEX_CONFIG_TEMPLATE}" ]] || {
        echo "The authentication configuration template is unavailable: ${DEX_CONFIG_TEMPLATE}" >&2
        return 1
    }

    local issuer=${APPMESH_AUTH_ISSUER:-${APPMESH_DEX_ISSUER:-$(oidc_value issuer http://127.0.0.1:6062/auth)}}
    local listen=${APPMESH_AUTH_DEX_LISTEN:-$(config_value dex_listen 127.0.0.1:6062)}
    local telemetry_listen=${APPMESH_AUTH_DEX_TELEMETRY_LISTEN:-$(config_value dex_telemetry_listen 127.0.0.1:6063)}
    local web_callback
    web_callback=$(config_value web_callback https://127.0.0.1:6060/oauth/callback)
    validate_admin_credentials
    validate_guest_credentials
    ensure_automation_client
    local password_hash guest_password_hash automation_secret
    password_hash=$(credential_value "${DEX_INITIAL_CREDENTIALS}" password_hash)
    guest_password_hash=$(credential_value "${DEX_GUEST_CREDENTIALS}" password_hash)
    automation_secret=$(automation_client_value secret)
    local public_value
    for public_value in \
        "${issuer}" "${listen}" "${telemetry_listen}" "${web_callback}" \
        "${DEX_INITIAL_ADMIN_EMAIL}" "${DEX_INITIAL_ADMIN_USERNAME}" \
        "${DEX_INITIAL_ADMIN_USER_ID}" "${password_hash}" \
        "${DEX_INITIAL_GUEST_EMAIL}" "${DEX_INITIAL_GUEST_USERNAME}" \
        "${DEX_INITIAL_GUEST_USER_ID}" "${guest_password_hash}" \
        "${automation_secret}" \
        "${AUTH_STATE_DIR}/dex/dex.db"; do
        yaml_quote "${public_value}" >/dev/null
    done
    local temporary
    temporary=$(mktemp "${DEX_RUNTIME_CONFIG}.XXXXXX")
    chmod 600 "${temporary}"

    local line
    while IFS= read -r line || [[ -n "${line}" ]]; do
        case "${line}" in
            "issuer: __APPMESH_DEX_ISSUER__")
                printf 'issuer: %s\n' "$(yaml_quote "${issuer}")"
                ;;
            "    file: __APPMESH_DEX_STORAGE_PATH__")
                printf '    file: %s\n' "$(yaml_quote "${AUTH_STATE_DIR}/dex/dex.db")"
                ;;
            "  http: __APPMESH_DEX_LISTEN__")
                printf '  http: %s\n' "$(yaml_quote "${listen}")"
                ;;
            "  http: __APPMESH_DEX_TELEMETRY_LISTEN__")
                printf '  http: %s\n' "$(yaml_quote "${telemetry_listen}")"
                ;;
            "    redirectURIs: [__APPMESH_DEX_WEB_CALLBACK__]")
                printf '    redirectURIs: [%s]\n' "$(yaml_quote "${web_callback}")"
                ;;
            "  - email: __APPMESH_DEX_INITIAL_ADMIN_EMAIL__")
                printf '  - email: %s\n' "$(yaml_quote "${DEX_INITIAL_ADMIN_EMAIL}")"
                ;;
            "    hash: __APPMESH_DEX_INITIAL_ADMIN_PASSWORD_HASH__")
                printf '    hash: %s\n' "$(yaml_quote "${password_hash}")"
                ;;
            "    username: __APPMESH_DEX_INITIAL_ADMIN_USERNAME__")
                printf '    username: %s\n' "$(yaml_quote "${DEX_INITIAL_ADMIN_USERNAME}")"
                ;;
            "    userID: __APPMESH_DEX_INITIAL_ADMIN_USER_ID__")
                printf '    userID: %s\n' "$(yaml_quote "${DEX_INITIAL_ADMIN_USER_ID}")"
                ;;
            "  - email: __APPMESH_DEX_INITIAL_GUEST_EMAIL__")
                printf '  - email: %s\n' "$(yaml_quote "${DEX_INITIAL_GUEST_EMAIL}")"
                ;;
            "    hash: __APPMESH_DEX_INITIAL_GUEST_PASSWORD_HASH__")
                printf '    hash: %s\n' "$(yaml_quote "${guest_password_hash}")"
                ;;
            "    username: __APPMESH_DEX_INITIAL_GUEST_USERNAME__")
                printf '    username: %s\n' "$(yaml_quote "${DEX_INITIAL_GUEST_USERNAME}")"
                ;;
            "    userID: __APPMESH_DEX_INITIAL_GUEST_USER_ID__")
                printf '    userID: %s\n' "$(yaml_quote "${DEX_INITIAL_GUEST_USER_ID}")"
                ;;
            "    secret: __APPMESH_DEX_AUTOMATION_SECRET__")
                printf '    secret: %s\n' "$(yaml_quote "${automation_secret}")"
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
        dex_telemetry_listen=${APPMESH_AUTH_DEX_TELEMETRY_LISTEN:-$(config_value dex_telemetry_listen 127.0.0.1:6063)}
        exec curl --fail --silent --show-error --max-time 2 "http://${dex_telemetry_listen}/healthz"
        ;;
    automation-token)
        request_automation_token
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
    forget-initial-password)
        is_builtin_auth || { echo "The initial password is unavailable in external authentication mode" >&2; exit 1; }
        is_auth_owner || { echo "The initial password is managed only on the authentication owner" >&2; exit 1; }
        forget_initial_password
        ;;
    *)
        echo "usage: appmesh-auth.sh {bootstrap|service|service-health|automation-token|print-initial-password|rotate-initial-password|forget-initial-password}" >&2
        exit 2
        ;;
esac
