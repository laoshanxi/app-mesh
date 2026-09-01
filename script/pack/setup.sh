#!/usr/bin/env bash

################################################################################
# Setup script for App Mesh
# Supports: Linux (systemd, sysvinit) and macOS (launchd)
# Purpose: Register and set up system files for initialization after installation
################################################################################

set -e # Exit on error
# set -u # Exit on undefined variables

# Constants and paths
readonly PROG_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/.." && pwd -P)"
if [[ "$(uname)" == "Darwin" ]]; then
    readonly BASH_COMPLETION_DIR="$(brew --prefix 2>/dev/null || echo /opt/homebrew)/etc/bash_completion.d"
else
    # Prefer modern path, fallback to legacy
    if [[ -d /usr/share/bash-completion/completions ]]; then
        readonly BASH_COMPLETION_DIR="/usr/share/bash-completion/completions"
    else
        readonly BASH_COMPLETION_DIR="/etc/bash_completion.d"
    fi
fi
readonly BASH_COMPLETION_PATH="$BASH_COMPLETION_DIR/appm"
readonly APPM_SOFTLINK=/usr/local/bin/appm
readonly INITD_SOFTLINK=/etc/init.d/appmesh
readonly SYSTEMD_FILE=/etc/systemd/system/appmesh.service
readonly LAUNCHD_FILE=/Library/LaunchDaemons/com.laoshanxi.appmesh.plist
readonly ENV_FILE="$PROG_HOME/appmesh.default"
readonly SECRET_MASTER_KEY_FILE="${PROG_HOME}/work/auth/secrets/secret-master-key"
readonly WORKFLOW_TEMPLATE="${PROG_HOME}/config/templates/workflow.yaml"
readonly WORKFLOW_APP="${PROG_HOME}/work/apps/workflow.yaml"
readonly WORKFLOW_INIT_MARKER="${PROG_HOME}/work/.workflow_initialized"
readonly WORKFLOW_BASELINE="${PROG_HOME}/work/.workflow_builtin_template.yaml"
readonly WORKFLOW_DISABLED_APP="${WORKFLOW_APP}.builtin-disabled"
readonly AUTH_LAUNCHER="${PROG_HOME}/script/appmesh-auth.sh"
readonly AUTH_APP_NAMES=(identity)

AUTH_ACCESS_URL_EXPLICIT=0
AUTH_ISSUER_EXPLICIT=0
AUTH_BROWSER_ENTRY_EXPLICIT=0
AUTH_TLS_VERIFY_EXPLICIT=0
AUTH_CA_PATH_EXPLICIT=0
AUTH_ROLE_EXPLICIT=0
PREVIOUS_AUTH_MODE=""
if [ "${APPMESH_AUTH_ACCESS_URL+x}" = x ]; then
    AUTH_ACCESS_URL_EXPLICIT=1
fi
if [ "${APPMESH_AUTH_ISSUER+x}" = x ]; then
    AUTH_ISSUER_EXPLICIT=1
fi
if [ "${APPMESH_AUTH_BROWSER_ENTRY+x}" = x ]; then
    AUTH_BROWSER_ENTRY_EXPLICIT=1
fi
if [ "${APPMESH_AUTH_TLS_VERIFY+x}" = x ]; then
    AUTH_TLS_VERIFY_EXPLICIT=1
fi
if [ "${APPMESH_AUTH_CA_PATH+x}" = x ]; then
    AUTH_CA_PATH_EXPLICIT=1
fi
if [ "${APPMESH_AUTH_ROLE+x}" = x ]; then
    AUTH_ROLE_EXPLICIT=1
fi

################################################################################
# Utility Functions
################################################################################

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO" "$@"; }
warn() { log "WARN" "$@"; }
error() { log "ERROR" "$@"; }
die() { error "$@" && exit 1; }

usage() {
    cat <<'EOF'
Usage: setup.sh [authentication options]

Authentication options (Linux/macOS):
  --auth-mode builtin|external  Select the bundled or external authentication service
  --auth-role standalone|owner|follower
                                Cluster role of the bundled authentication service.
                                owner runs the authentication service; follower joins
                                an owner and runs no local authentication service
  --oidc-issuer URL             Canonical issuer (required for external mode and follower role)
  --oidc-access-url URL         Per-node discovery/JWKS route (defaults to the issuer)
  --oidc-browser-entry URL      Browser entry that fronts the issuer path
                                (defaults to the issuer; required for the follower role)
  --oidc-tls-verify BOOL        Verify the external route certificate: true or false (default: true)
  --oidc-ca-path PATH           Optional CA file or directory for the external route
  --clear-oidc-ca               Remove a previously configured external CA path
  -h, --help                    Show this help

The equivalent non-interactive environment variables are APPMESH_AUTH_MODE,
APPMESH_AUTH_ROLE, APPMESH_AUTH_ISSUER, APPMESH_AUTH_ACCESS_URL,
APPMESH_AUTH_BROWSER_ENTRY, APPMESH_AUTH_TLS_VERIFY, and APPMESH_AUTH_CA_PATH.
They also select the settings during package installation, which runs this
script with the administrator environment. This interface never accepts user
or client passwords.
EOF
}

require_option_value() {
    local option="$1"
    local value="${2:-}"
    [ -n "$value" ] || die "Missing value for $option"
}

parse_arguments() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
        --auth-mode)
            require_option_value "$1" "${2:-}"
            export APPMESH_AUTH_MODE="$2"
            shift 2
            ;;
        --auth-mode=*) export APPMESH_AUTH_MODE="${1#*=}"; shift ;;
        --auth-role)
            require_option_value "$1" "${2:-}"
            export APPMESH_AUTH_ROLE="$2"
            AUTH_ROLE_EXPLICIT=1
            shift 2
            ;;
        --auth-role=*) export APPMESH_AUTH_ROLE="${1#*=}"; AUTH_ROLE_EXPLICIT=1; shift ;;
        --oidc-issuer)
            require_option_value "$1" "${2:-}"
            export APPMESH_AUTH_ISSUER="$2"
            AUTH_ISSUER_EXPLICIT=1
            shift 2
            ;;
        --oidc-issuer=*) export APPMESH_AUTH_ISSUER="${1#*=}"; AUTH_ISSUER_EXPLICIT=1; shift ;;
        --oidc-access-url)
            require_option_value "$1" "${2:-}"
            export APPMESH_AUTH_ACCESS_URL="$2"
            AUTH_ACCESS_URL_EXPLICIT=1
            shift 2
            ;;
        --oidc-access-url=*) export APPMESH_AUTH_ACCESS_URL="${1#*=}"; AUTH_ACCESS_URL_EXPLICIT=1; shift ;;
        --oidc-browser-entry)
            require_option_value "$1" "${2:-}"
            export APPMESH_AUTH_BROWSER_ENTRY="$2"
            AUTH_BROWSER_ENTRY_EXPLICIT=1
            shift 2
            ;;
        --oidc-browser-entry=*) export APPMESH_AUTH_BROWSER_ENTRY="${1#*=}"; AUTH_BROWSER_ENTRY_EXPLICIT=1; shift ;;
        --oidc-tls-verify)
            require_option_value "$1" "${2:-}"
            export APPMESH_AUTH_TLS_VERIFY="$2"
            AUTH_TLS_VERIFY_EXPLICIT=1
            shift 2
            ;;
        --oidc-tls-verify=*) export APPMESH_AUTH_TLS_VERIFY="${1#*=}"; AUTH_TLS_VERIFY_EXPLICIT=1; shift ;;
        --oidc-ca-path)
            require_option_value "$1" "${2:-}"
            export APPMESH_AUTH_CA_PATH="$2"
            AUTH_CA_PATH_EXPLICIT=1
            shift 2
            ;;
        --oidc-ca-path=*) export APPMESH_AUTH_CA_PATH="${1#*=}"; AUTH_CA_PATH_EXPLICIT=1; shift ;;
        --clear-oidc-ca)
            export APPMESH_AUTH_CA_PATH=""
            AUTH_CA_PATH_EXPLICIT=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "Unknown setup option: $1" ;;
        esac
    done
}

get_os_type() {
    case "$(uname)" in
    "Darwin") echo "macos" ;;
    "Linux")
        if [ -f /etc/os-release ]; then
            # shellcheck source=/dev/null
            . /etc/os-release
            echo "$ID"
        elif [ -f /etc/redhat-release ]; then
            echo "rhel"
        elif [ -f /etc/debian_version ]; then
            echo "debian"
        else
            echo "unknown"
        fi
        ;;
    *) echo "unknown" ;;
    esac
}

detect_init_system() {
    case "$(uname)" in
    "Darwin") echo "launchd" ;;
    "Linux")
        if command -v systemctl >/dev/null 2>&1 && systemctl list-units >/dev/null 2>&1; then
            echo "systemd"
        else
            echo "init"
        fi
        ;;
    *) echo "unknown" ;;
    esac
}

################################################################################
# Path and Environment Setup Functions
################################################################################

update_appmesh_paths() {
    local appmesh_dir="$PROG_HOME"
    local input_file_path="$1"

    [ ! -f "$input_file_path" ] && die "Input file '$input_file_path' does not exist."

    # Normalize paths for consistency
    appmesh_dir=$(realpath "$appmesh_dir")
    input_file_path=$(realpath "$input_file_path")

    # Ensure appmesh_dir ends with "/appmesh"
    [[ ! "$appmesh_dir" =~ /appmesh$ ]] && die "App Mesh dir must end with '/appmesh'. Current value: '$appmesh_dir'."

    # Escape special characters in the appmesh directory for use in sed
    local escaped_appmesh_dir=$(echo "$appmesh_dir" | sed 's/\//\\\//g')
    local temp_file=$(mktemp)

    # Replace paths matching the pattern ending with 'appmesh/'
    sed -e "s|/[[:alnum:]/]*appmesh/|$escaped_appmesh_dir/|g" "$input_file_path" >"$temp_file"

    if ! cmp -s "$input_file_path" "$temp_file"; then
        mv "$temp_file" "$input_file_path"
        info "File '$input_file_path' updated successfully with the new directory: '$appmesh_dir'."
    else
        rm "$temp_file"
    fi
    return 0
}

clean_environment() {
    mkdir -p "${PROG_HOME}/work"

    # Stop existing service
    info "Stopping existing service if running..."
    if [ -f "$SYSTEMD_FILE" ]; then
        systemctl stop appmesh 2>/dev/null || true
        # Older installed units used KillMode=process. Explicitly terminate all
        # remaining cgroup members before changing auth mode or package files.
        systemctl kill --kill-whom=all --signal=TERM appmesh 2>/dev/null || true
        sleep 2
        systemctl kill --kill-whom=all --signal=KILL appmesh 2>/dev/null || true
    elif [ -f "$INITD_SOFTLINK" ]; then
        service appmesh stop 2>/dev/null || true
        sleep 2
    elif [ -f "$LAUNCHD_FILE" ]; then
        launchctl unload -w "$LAUNCHD_FILE" 2>/dev/null || true
        sleep 2
    fi

    # Clean work directory for fresh install
    if [ "${APPMESH_FRESH_INSTALL:-}" = "Y" ]; then
        find "${PROG_HOME}/work" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
        info "Work directory cleaned for fresh installation"
    fi
}

remove_obsolete_auth_app_definition() {
    local obsolete_file="${PROG_HOME}/apps/auth-dex.yaml"

    [ -e "$obsolete_file" ] || [ -L "$obsolete_file" ] || return 0
    [ ! -L "$obsolete_file" ] || die "Refusing symbolic-link application definition: $obsolete_file"
    [ -f "$obsolete_file" ] || die "Obsolete application definition is not a regular file: $obsolete_file"
    grep -Eq '^name:[[:space:]]*auth-dex[[:space:]]*$' "$obsolete_file" || \
        die "Refusing to remove an unrecognized application definition: $obsolete_file"
    grep -Eq '^owner_principal_id:[[:space:]]*system:appmesh[[:space:]]*$' "$obsolete_file" || \
        die "Refusing to remove an unrecognized application definition: $obsolete_file"
    grep -Eq '^system:[[:space:]]*true[[:space:]]*$' "$obsolete_file" || \
        die "Refusing to remove an unrecognized application definition: $obsolete_file"

    rm -f -- "$obsolete_file"
    info "Removed an obsolete bundled authentication application definition"
}

# Bundled System Apps renamed in one release keep their state across an upgrade:
# the definition in apps/ and the persisted copy in work/apps/ move to the new
# name. When both names exist, the old copy is removed only after it is
# validated as the bundled definition.
migrate_renamed_bundled_apps() {
    local pair
    local old_name
    local new_name
    local dir
    local old_file
    local new_file

    for pair in "auth-service:identity" "pytask:py-task" "pyexec:py-exec"; do
        old_name="${pair%%:*}"
        new_name="${pair#*:}"
        for dir in "${PROG_HOME}/apps" "${PROG_HOME}/work/apps"; do
            old_file="${dir}/${old_name}.yaml"
            new_file="${dir}/${new_name}.yaml"
            [ -e "$old_file" ] || continue
            [ ! -L "$old_file" ] || die "Refusing symbolic-link application definition: $old_file"
            [ -f "$old_file" ] || die "Renamed application definition is not a regular file: $old_file"
            grep -Eq "^name:[[:space:]]*${old_name}[[:space:]]*$" "$old_file" || \
                die "Refusing to migrate an unrecognized application definition: $old_file"
            grep -Eq '^owner_principal_id:[[:space:]]*system:appmesh[[:space:]]*$' "$old_file" || \
                die "Refusing to migrate an unrecognized application definition: $old_file"
            grep -Eq '^system:[[:space:]]*true[[:space:]]*$' "$old_file" || \
                die "Refusing to migrate an unrecognized application definition: $old_file"
            if [ -e "$new_file" ]; then
                rm -f -- "$old_file"
                info "Removed the superseded <${old_name}> application definition (${dir})"
            else
                mv -- "$old_file" "$new_file"
                info "Renamed the bundled application <${old_name}> to <${new_name}> (${dir})"
            fi
        done
    done
}

write_env_entry() {
    local target="$1"
    local name="$2"
    local value="$3"
    local filtered=""

    case "$name" in
    "" | [0-9]* | *[!a-zA-Z0-9_]*) die "Invalid environment variable name: $name" ;;
    esac

    filtered=$(mktemp "${target}.filter.XXXXXX") || die "Failed to create temporary environment file"
    chmod 600 "$filtered"
    if [ -s "$target" ]; then
        awk -v key="$name" 'substr($0, 1, length(key) + 1) != key "=" { print }' "$target" >"$filtered"
    fi
    printf '%s=%s\n' "$name" "$value" >>"$filtered"
    mv "$filtered" "$target"
}

remove_env_entry() {
    local target="$1"
    local name="$2"
    local filtered=""

    filtered=$(mktemp "${target}.filter.XXXXXX") || die "Failed to create temporary environment file"
    chmod 600 "$filtered"
    if [ -s "$target" ]; then
        awk -v key="$name" 'substr($0, 1, length(key) + 1) != key "=" { print }' "$target" >"$filtered"
    fi
    mv "$filtered" "$target"
}

read_env_entry() {
    local name="$1"
    awk -v key="$name" '
        substr($0, 1, length(key) + 1) == key "=" {
            value = substr($0, length(key) + 2)
            found = 1
        }
        END {
            if (found) print value
            else exit 1
        }
    ' "$ENV_FILE"
}

validate_oidc_url() {
    local name="$1"
    local value="$2"
    if [[ ! "$value" =~ ^https?://(\[[0-9A-Fa-f:.]+\]|[^/:?\#[:space:]@]+)(:[0-9]+)?(/[^?\#[:space:]]*)?$ ]]; then
        die "$name must be an absolute HTTP(S) URL without credentials, query, fragment, or whitespace"
    fi
}

normalize_tls_verify() {
    case "$1" in
    true | TRUE | True | 1) printf '%s' true ;;
    false | FALSE | False | 0) printf '%s' false ;;
    *) die "APPMESH_AUTH_TLS_VERIFY must be true or false" ;;
    esac
}

# A node that verifies against a remote authentication service must reach the
# advertised browser entry. The check uses the configured TLS posture.
verify_auth_entry_reachable() {
    local url="$1"
    local tls_verify="$2"
    local ca_path="$3"
    command -v curl >/dev/null 2>&1 || {
        error "curl is not available; skipped the authentication entry reachability check: $url"
        return 0
    }
    local curl_args=(--fail --silent --show-error --connect-timeout 5 --max-time 15 --output /dev/null)
    case "$tls_verify" in
    false | FALSE | False | 0) curl_args+=(--insecure) ;;
    esac
    if [ -n "$ca_path" ]; then
        if [ -d "$ca_path" ]; then
            curl_args+=(--capath "$ca_path")
        else
            curl_args+=(--cacert "$ca_path")
        fi
    fi
    curl "${curl_args[@]}" "$url" ||
        die "The authentication entry is not reachable: $url. Check the address and the network, then run setup again."
}

set_auth_app_status() {
    local status="$1"
    local app_name=""
    local app_file=""
    local app_tmp=""

    for app_name in "${AUTH_APP_NAMES[@]}"; do
        app_file="${PROG_HOME}/apps/${app_name}.yaml"
        [ -f "$app_file" ] || die "Bundled authentication App definition not found: $app_file"
        grep -q '^status:' "$app_file" || die "Bundled authentication App has no status field: $app_file"
        app_tmp=$(mktemp "${app_file}.XXXXXX") || die "Failed to create temporary App definition"
        awk -v status="$status" '/^status:/ { print "status: " status; next } { print }' "$app_file" >"$app_tmp"
        chmod 644 "$app_tmp"
        mv "$app_tmp" "$app_file"
    done
}

configure_authentication() {
    # The bundled auth runtime and System Apps ship on Linux and macOS. Other
    # platforms retain their existing externally managed issuer setup.
    case "$(uname)" in
    Linux | Darwin) ;;
    *) return 0 ;;
    esac

    local mode=""
    local issuer=""
    local access_url=""
    local browser_entry=""
    local tls_verify=""
    local ca_path=""

    mode=$(read_env_entry APPMESH_AUTH_MODE 2>/dev/null || true)
    mode=${mode:-builtin}
    case "$mode" in
    builtin | external) ;;
    *) die "APPMESH_AUTH_MODE must be builtin or external" ;;
    esac
    write_env_entry "$ENV_FILE" APPMESH_AUTH_MODE "$mode"

    # Cluster role of the bundled authentication service. setup_env_file() has
    # already persisted any explicitly passed or preserved APPMESH_AUTH_ROLE;
    # without a selection the packaged auth-stack.yaml default applies. The
    # package post-install runs this script with the administrator environment,
    # so APPMESH_AUTH_ROLE also selects the role at dpkg/rpm install time.
    local role=""
    role=$(read_env_entry APPMESH_AUTH_ROLE 2>/dev/null || true)
    if [ -n "$role" ]; then
        case "$role" in
        standalone | owner | follower) ;;
        *) die "APPMESH_AUTH_ROLE must be standalone, owner, or follower" ;;
        esac
        if [ "$mode" = "external" ]; then
            if [ "$AUTH_ROLE_EXPLICIT" -eq 1 ]; then
                die "--auth-role requires builtin mode; external mode runs no local authentication service"
            fi
            # A stale role selection from a previous builtin installation is
            # meaningless in external mode; drop it instead of failing upgrade.
            remove_env_entry "$ENV_FILE" APPMESH_AUTH_ROLE
            role=""
            info "Removed the stale authentication role selection for external mode."
        else
            info "Authentication role set to ${role}."
        fi
    fi

    issuer=$(read_env_entry APPMESH_AUTH_ISSUER 2>/dev/null || true)
    access_url=$(read_env_entry APPMESH_AUTH_ACCESS_URL 2>/dev/null || true)
    browser_entry=$(read_env_entry APPMESH_AUTH_BROWSER_ENTRY 2>/dev/null || true)
    tls_verify=$(read_env_entry APPMESH_AUTH_TLS_VERIFY 2>/dev/null || true)
    ca_path=$(read_env_entry APPMESH_AUTH_CA_PATH 2>/dev/null || true)

    if [ "$mode" = "external" ]; then
        if [ "$PREVIOUS_AUTH_MODE" != "external" ] && [ "$AUTH_ISSUER_EXPLICIT" -ne 1 ]; then
            die "Changing to external authentication requires --oidc-issuer or APPMESH_AUTH_ISSUER"
        fi
        # Do not silently carry built-in routing/TLS state into a different
        # issuer deployment. Explicit values in this invocation still win;
        # repeated external-mode setup preserves the established selection.
        if [ "$PREVIOUS_AUTH_MODE" != "external" ]; then
            [ "$AUTH_ACCESS_URL_EXPLICIT" -eq 1 ] || access_url=""
            [ "$AUTH_BROWSER_ENTRY_EXPLICIT" -eq 1 ] || browser_entry=""
            [ "$AUTH_TLS_VERIFY_EXPLICIT" -eq 1 ] || tls_verify=""
            [ "$AUTH_CA_PATH_EXPLICIT" -eq 1 ] || ca_path=""
        fi
        [ -n "$issuer" ] || die "External authentication requires --oidc-issuer or APPMESH_AUTH_ISSUER"
        access_url=${access_url:-$issuer}
        browser_entry=${browser_entry:-$issuer}
        tls_verify=$(normalize_tls_verify "${tls_verify:-true}")
        validate_oidc_url APPMESH_AUTH_ISSUER "$issuer"
        validate_oidc_url APPMESH_AUTH_ACCESS_URL "$access_url"
        validate_oidc_url APPMESH_AUTH_BROWSER_ENTRY "$browser_entry"
        if [ -n "$ca_path" ]; then
            [[ "$ca_path" = /* ]] || die "APPMESH_AUTH_CA_PATH must be an absolute path"
            [ -e "$ca_path" ] || die "APPMESH_AUTH_CA_PATH does not exist: $ca_path"
        fi
        write_env_entry "$ENV_FILE" APPMESH_AUTH_ISSUER "$issuer"
        write_env_entry "$ENV_FILE" APPMESH_AUTH_ACCESS_URL "$access_url"
        write_env_entry "$ENV_FILE" APPMESH_AUTH_BROWSER_ENTRY "$browser_entry"
        write_env_entry "$ENV_FILE" APPMESH_AUTH_TLS_VERIFY "$tls_verify"
        if [ -n "$ca_path" ]; then
            write_env_entry "$ENV_FILE" APPMESH_AUTH_CA_PATH "$ca_path"
        elif [ "$AUTH_CA_PATH_EXPLICIT" -eq 1 ] || [ "$PREVIOUS_AUTH_MODE" != "external" ]; then
            remove_env_entry "$ENV_FILE" APPMESH_AUTH_CA_PATH
        fi
        set_auth_app_status 0
        info "Authentication mode set to external. The bundled authentication service is disabled."
        # The whole configuration is persisted above, so a failed check keeps the
        # selection and a repeated setup re-runs only the check.
        verify_auth_entry_reachable "$browser_entry" "$tls_verify" "$ca_path"
    else
        # Changing from external mode discards external-only routing/TLS state
        # unless this invocation supplies a replacement. The canonical issuer is
        # retained: it may be the public URL of the newly local service behind an
        # ingress.
        if [ "$PREVIOUS_AUTH_MODE" = "external" ]; then
            if [ "$AUTH_ACCESS_URL_EXPLICIT" -eq 0 ]; then
                remove_env_entry "$ENV_FILE" APPMESH_AUTH_ACCESS_URL
                access_url=""
            fi
            if [ "$AUTH_TLS_VERIFY_EXPLICIT" -eq 0 ]; then
                remove_env_entry "$ENV_FILE" APPMESH_AUTH_TLS_VERIFY
                tls_verify=""
            fi
            if [ "$AUTH_CA_PATH_EXPLICIT" -eq 0 ]; then
                remove_env_entry "$ENV_FILE" APPMESH_AUTH_CA_PATH
                ca_path=""
            fi
        elif [ "$AUTH_CA_PATH_EXPLICIT" -eq 1 ] && [ -z "$ca_path" ]; then
            remove_env_entry "$ENV_FILE" APPMESH_AUTH_CA_PATH
        fi
        [ -z "$issuer" ] || validate_oidc_url APPMESH_AUTH_ISSUER "$issuer"
        [ -z "$access_url" ] || validate_oidc_url APPMESH_AUTH_ACCESS_URL "$access_url"
        [ -z "$browser_entry" ] || validate_oidc_url APPMESH_AUTH_BROWSER_ENTRY "$browser_entry"
        [ -z "$tls_verify" ] || normalize_tls_verify "$tls_verify" >/dev/null
        if [ "$role" = "follower" ]; then
            # A follower runs no local authentication service. It must carry the
            # owner's canonical issuer and a route to it; without an explicit
            # access route the owner issuer itself is the route.
            [ -n "$issuer" ] || die "Follower role requires --oidc-issuer or APPMESH_AUTH_ISSUER of the authentication owner"
            # The owner issuer is an internal route that a browser cannot reach;
            # only the owner's browser entry fronts the issuer path.
            [ -n "$browser_entry" ] || die "Follower role requires --oidc-browser-entry or APPMESH_AUTH_BROWSER_ENTRY of the authentication owner"
            access_url=${access_url:-$issuer}
            write_env_entry "$ENV_FILE" APPMESH_AUTH_ACCESS_URL "$access_url"
            write_env_entry "$ENV_FILE" APPMESH_AUTH_BROWSER_ENTRY "$browser_entry"
            verify_auth_entry_reachable "$browser_entry" "${tls_verify:-true}" "$ca_path"
            info "This node joins the authentication owner at ${issuer}."
        fi
        set_auth_app_status 1
        info "Authentication mode set to builtin. The bundled authentication service is enabled."
        # Without the launcher installed, the authentication App self-bootstraps instead.
        if [ -x "$AUTH_LAUNCHER" ]; then
            APPMESH_AUTH_MODE="$mode" \
                APPMESH_AUTH_ROLE="$role" \
                APPMESH_AUTH_ISSUER="${issuer:-http://127.0.0.1:6062/auth}" \
                APPMESH_AUTH_ACCESS_URL="${access_url:-http://127.0.0.1:6062/auth}" \
                APPMESH_AUTH_BROWSER_ENTRY="$browser_entry" \
                APPMESH_AUTH_TLS_VERIFY="${tls_verify:-true}" \
                APPMESH_AUTH_CA_PATH="$ca_path" \
                "$AUTH_LAUNCHER" bootstrap || die "Authentication bootstrap failed"
        fi
    fi
    chmod 600 "$ENV_FILE"
}

setup_env_file() {
    info "Setting up environment file at $ENV_FILE"
    [ -L "$ENV_FILE" ] && die "Refusing symbolic-link environment file: $ENV_FILE"

    local env_tmp=""
    local assignment=""
    local name=""
    local value=""
    env_tmp=$(mktemp "${ENV_FILE}.XXXXXX") || die "Failed to create temporary environment file"
    chmod 600 "$env_tmp"

    # Preserve service configuration across upgrades.
    if [ "${APPMESH_FRESH_INSTALL:-}" != "Y" ] && [ -f "$ENV_FILE" ]; then
        [ -r "$ENV_FILE" ] || die "Existing environment file is not readable: $ENV_FILE"
        while IFS= read -r assignment || [ -n "$assignment" ]; do
            case "$assignment" in
            "" | \#*) continue ;;
            *=*)
                name="${assignment%%=*}"
                value="${assignment#*=}"
                [ "$name" != "APPMESH_SECRET_MASTER_KEY" ] || \
                    die "APPMESH_SECRET_MASTER_KEY is not supported; use the owner-only master-key file"
                write_env_entry "$env_tmp" "$name" "$value"
                ;;
            *) die "Invalid environment entry in $ENV_FILE" ;;
            esac
        done <"$ENV_FILE"
    fi

    # Locale setup
    if locale -a 2>/dev/null | grep -iE "^(en_US\.(utf8|UTF-8))$" >/dev/null; then
        write_env_entry "$env_tmp" "LANG" "en_US.UTF-8"
        write_env_entry "$env_tmp" "LC_ALL" "en_US.UTF-8"
        info "Locale set to [en_US.UTF-8]"
    else
        error "Failed to set default locale [en_US.UTF-8], not available"
    fi

    # Current installer values override preserved values.
    while IFS= read -r assignment || [ -n "$assignment" ]; do
        name="${assignment%%=*}"
        value="${assignment#*=}"
        [ "$name" != "APPMESH_SECRET_MASTER_KEY" ] || \
            die "APPMESH_SECRET_MASTER_KEY is not supported; use the owner-only master-key file"
        info "Applying environment variable: $name"
        write_env_entry "$env_tmp" "$name" "$value"
    done < <(printenv | grep '^APPMESH_')

    # Default execution user setup
    if [ -n "${APPMESH_BaseConfig_DefaultExecUser:-}" ] && [ "$APPMESH_BaseConfig_DefaultExecUser" != "root" ]; then
        info "DefaultExecUser set to: $APPMESH_BaseConfig_DefaultExecUser"
    fi

    mv "$env_tmp" "$ENV_FILE"
    # setup_permissions() keeps this root-owned; the service manager reads it.
    chmod 600 "$ENV_FILE"

    # Restore the persisted service identity before regenerating definitions.
    for name in APPMESH_DAEMON_EXEC_USER APPMESH_DAEMON_EXEC_USER_GROUP; do
        if value=$(read_env_entry "$name"); then
            printf -v "$name" '%s' "$value"
            export "$name"
        fi
    done
}

provision_secret_master_key() {
    local secret_dir=""
    local key_tmp=""

    secret_dir=$(dirname "$SECRET_MASTER_KEY_FILE")
    [ -L "$secret_dir" ] && die "Refusing symbolic-link runtime secret directory: $secret_dir"
    install -d -m 700 "$secret_dir"

    [ -L "$SECRET_MASTER_KEY_FILE" ] && \
        die "Refusing symbolic-link SecretProtector master key: $SECRET_MASTER_KEY_FILE"
    if [ -e "$SECRET_MASTER_KEY_FILE" ]; then
        [ -f "$SECRET_MASTER_KEY_FILE" ] || \
            die "SecretProtector master key is not a regular file: $SECRET_MASTER_KEY_FILE"
        chmod 600 "$SECRET_MASTER_KEY_FILE"
        info "Preserving existing SecretProtector master key"
    else
        command -v openssl >/dev/null 2>&1 || \
            die "OpenSSL is required to provision the SecretProtector master key"
        key_tmp=$(mktemp "${SECRET_MASTER_KEY_FILE}.XXXXXX") || \
            die "Failed to create temporary SecretProtector master key"
        chmod 600 "$key_tmp"
        if ! openssl rand -base64 32 >"$key_tmp"; then
            rm -f "$key_tmp"
            die "Failed to generate SecretProtector master key"
        fi
        # A hard-link publish is atomic and does not replace a key concurrently
        # created by another setup process.
        if ln "$key_tmp" "$SECRET_MASTER_KEY_FILE" 2>/dev/null; then
            info "Provisioned SecretProtector master key"
        elif [ ! -f "$SECRET_MASTER_KEY_FILE" ] || [ -L "$SECRET_MASTER_KEY_FILE" ]; then
            rm -f "$key_tmp"
            die "Failed to atomically publish SecretProtector master key"
        fi
        rm -f "$key_tmp"
    fi
    write_env_entry "$ENV_FILE" APPMESH_SECRET_MASTER_KEY_FILE "$SECRET_MASTER_KEY_FILE"
    chmod 600 "$ENV_FILE"
}

prepare_workflow_app() {
    # The launcher only execs the workflow binary; authentication mode does not affect
    # registration because Workflow is no longer an OAuth service client.
    # Platforms without the Linux launcher must not auto-register this App.
    if [ ! -x "$AUTH_LAUNCHER" ]; then
        info "Bundled authentication runtime is not installed; skipping the default workflow App"
        return
    fi

    [ -f "$WORKFLOW_TEMPLATE" ] || die "Workflow App template not found: $WORKFLOW_TEMPLATE"

    # Runtime definitions are operator state. Only initialize a missing one.
    if [ -f "$WORKFLOW_APP" ]; then
        info "Preserving existing workflow App definition at $WORKFLOW_APP"
        if cmp -s "$WORKFLOW_APP" "$WORKFLOW_TEMPLATE"; then
            cp "$WORKFLOW_TEMPLATE" "$WORKFLOW_BASELINE"
            chmod 600 "$WORKFLOW_BASELINE"
        fi
        touch "$WORKFLOW_INIT_MARKER"
        chmod 600 "$WORKFLOW_INIT_MARKER"
        return
    fi
    if [ -f "$WORKFLOW_DISABLED_APP" ]; then
        # Migrate state left by installers that disabled Workflow together with
        # local authentication service. The current template is mode-independent.
        mv -f "$WORKFLOW_DISABLED_APP" "$WORKFLOW_APP"
        cp "$WORKFLOW_TEMPLATE" "$WORKFLOW_APP"
        chmod 600 "$WORKFLOW_APP"
        cp "$WORKFLOW_TEMPLATE" "$WORKFLOW_BASELINE"
        chmod 600 "$WORKFLOW_BASELINE"
        touch "$WORKFLOW_INIT_MARKER"
        chmod 600 "$WORKFLOW_INIT_MARKER"
        info "Restored the mode-independent bundled workflow App at $WORKFLOW_APP"
        return
    fi
    if [ -f "$WORKFLOW_INIT_MARKER" ]; then
        info "Preserving intentionally absent workflow App definition"
        return
    fi
    mkdir -p "$(dirname "$WORKFLOW_APP")"
    cp "$WORKFLOW_TEMPLATE" "$WORKFLOW_APP"
    chmod 600 "$WORKFLOW_APP"
    cp "$WORKFLOW_TEMPLATE" "$WORKFLOW_BASELINE"
    chmod 600 "$WORKFLOW_BASELINE"
    touch "$WORKFLOW_INIT_MARKER"
    chmod 600 "$WORKFLOW_INIT_MARKER"
    info "Installed default workflow App definition at $WORKFLOW_APP"
}

################################################################################
# Service Installation Functions
################################################################################

setup_service() {
    local init_system=$(detect_init_system)

    case "$init_system" in
    "systemd") install_systemd_service ;;
    "launchd") install_launchd_service ;;
    *) install_initd_service ;;
    esac

    # Install bash completion
    if [ -d "$BASH_COMPLETION_DIR" ]; then
        rm -f "$BASH_COMPLETION_PATH" && cp "${PROG_HOME}/script/bash_completion.sh" "$BASH_COMPLETION_PATH"
        info "Bash completion script installed at $BASH_COMPLETION_PATH"
    else
        error "$BASH_COMPLETION_DIR not found. Skipping bash completion installation"
    fi

    # Create appm symlink
    rm -f "$APPM_SOFTLINK" && ln -sf "${PROG_HOME}/bin/appm" "$APPM_SOFTLINK"
    info "Symlink for appm created at $APPM_SOFTLINK"

}

install_systemd_service() {
    info "Installing systemd service at $SYSTEMD_FILE"
    local service_template="${PROG_HOME}/script/appmesh.systemd.service"

    [ ! -f "$service_template" ] && {
        info "Service template not found: $service_template"
        return 1
    }

    update_appmesh_paths "${PROG_HOME}/script/appmesh.systemd.service"
    rm -f "$SYSTEMD_FILE" && cp "$service_template" "$SYSTEMD_FILE"

    if [ -n "${APPMESH_DAEMON_EXEC_USER:-}" ]; then
        sed -i "s/^User=.*/User=${APPMESH_DAEMON_EXEC_USER}/" "$SYSTEMD_FILE"
        info "Service user set to: ${APPMESH_DAEMON_EXEC_USER}"
    fi

    if [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP:-}" ]; then
        sed -i "s/^Group=.*/Group=${APPMESH_DAEMON_EXEC_USER_GROUP}/" "$SYSTEMD_FILE"
        info "Service group set to: ${APPMESH_DAEMON_EXEC_USER_GROUP}"
    fi

    rm -f "${SYSTEMD_FILE}.bak"
    systemctl daemon-reload
}

install_launchd_service() {
    info "Installing launchd service at $LAUNCHD_FILE"
    local service_template="${PROG_HOME}/script/appmesh.launchd.plist"

    [ ! -f "$service_template" ] && die "Service template not found: $service_template"

    update_appmesh_paths "${PROG_HOME}/script/appmesh.launchd.plist"

    # Keep the LaunchDaemon definition root-owned.
    rm -f "$LAUNCHD_FILE" && cp "$service_template" "$LAUNCHD_FILE"

    # Render the env file into launchd's native dictionary without eval.
    local assignment=""
    local name=""
    local value=""
    while IFS= read -r assignment || [ -n "$assignment" ]; do
        case "$assignment" in
        "" | \#*) continue ;;
        *=*)
            name="${assignment%%=*}"
            value="${assignment#*=}"
            case "$name" in
            "" | [0-9]* | *[!a-zA-Z0-9_]*) die "Invalid environment entry in $ENV_FILE" ;;
            esac
            if plutil -extract "EnvironmentVariables.${name}" raw "$LAUNCHD_FILE" >/dev/null 2>&1; then
                plutil -replace "EnvironmentVariables.${name}" -string "$value" "$LAUNCHD_FILE"
            else
                plutil -insert "EnvironmentVariables.${name}" -string "$value" "$LAUNCHD_FILE"
            fi
            ;;
        *) die "Invalid environment entry in $ENV_FILE" ;;
        esac
    done <"$ENV_FILE"

    if [ -n "${APPMESH_DAEMON_EXEC_USER:-}" ]; then
        if plutil -extract UserName raw "$LAUNCHD_FILE" >/dev/null 2>&1; then
            plutil -replace UserName -string "$APPMESH_DAEMON_EXEC_USER" "$LAUNCHD_FILE"
        else
            plutil -insert UserName -string "$APPMESH_DAEMON_EXEC_USER" "$LAUNCHD_FILE"
        fi
        info "Service user set to: ${APPMESH_DAEMON_EXEC_USER}"
    fi

    if [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP:-}" ]; then
        if plutil -extract GroupName raw "$LAUNCHD_FILE" >/dev/null 2>&1; then
            plutil -replace GroupName -string "$APPMESH_DAEMON_EXEC_USER_GROUP" "$LAUNCHD_FILE"
        else
            plutil -insert GroupName -string "$APPMESH_DAEMON_EXEC_USER_GROUP" "$LAUNCHD_FILE"
        fi
        info "Service group set to: ${APPMESH_DAEMON_EXEC_USER_GROUP}"
    fi

    chown root:wheel "$LAUNCHD_FILE"
    chmod 600 "$LAUNCHD_FILE"

    rm -f "${LAUNCHD_FILE}.bak"

    # Remove macOS quarantine attributes
    for binary in appmesh appm agent; do
        xattr -d com.apple.quarantine "${PROG_HOME}/bin/${binary}" 2>/dev/null || true
    done

    # launchctl load -w "$LAUNCHD_FILE"
}

install_initd_service() {
    info "Installing init.d service"
    local initd_template="${PROG_HOME}/script/appmesh.initd.sh"

    [ ! -f "$initd_template" ] && die "Service template not found: $initd_template"

    rm -f "$INITD_SOFTLINK" && ln -sf "$initd_template" "$INITD_SOFTLINK"

    local os_type=$(get_os_type)
    case "$os_type" in
    "rhel" | "centos")
        command -v chkconfig >/dev/null 2>&1 && chkconfig --add appmesh
        ;;
    "debian" | "ubuntu")
        command -v update-rc.d >/dev/null 2>&1 && update-rc.d appmesh defaults
        ;;
    esac
}

################################################################################
# Additional Setup Functions
################################################################################

setup_permissions() {
    info "Setting up permissions"
    local root_group=""
    root_group=$(id -gn 0)

    # Package payload remains an administrator-controlled trust boundary. This
    # also repairs ownership left by older installers that delegated the whole
    # installation tree to the daemon account.
    find "${PROG_HOME}" -path "${PROG_HOME}/work" -prune -o -type d -exec chown "root:${root_group}" {} \;
    find "${PROG_HOME}" -path "${PROG_HOME}/work" -prune -o \
        -path "${PROG_HOME}/ssl/*" -name "*.pem" -prune -o \
        -type f -exec chown "root:${root_group}" {} \;
    find "${PROG_HOME}" -path "${PROG_HOME}/work" -prune -o -type d -exec chmod go-w {} \;
    find "${PROG_HOME}" -path "${PROG_HOME}/work" -prune -o \
        -path "${PROG_HOME}/ssl/*" -name "*.pem" -prune -o \
        -type f -exec chmod go-w {} \;

    chmod 644 "${PROG_HOME}"/config/config.yaml "${PROG_HOME}"/config/oidc.yaml
    chmod 600 "${PROG_HOME}"/config/authorization.yaml
    find "${PROG_HOME}/script" -name "*.sh" -exec chmod +x {} \;

    if [ -n "${APPMESH_DAEMON_EXEC_USER:-}" ]; then
        id -u "${APPMESH_DAEMON_EXEC_USER}" >/dev/null 2>&1 || \
            die "Configured daemon user does not exist: ${APPMESH_DAEMON_EXEC_USER}"
        local daemon_group="${APPMESH_DAEMON_EXEC_USER_GROUP:-}"
        daemon_group=${daemon_group:-$(id -gn "${APPMESH_DAEMON_EXEC_USER}")}
        local runtime_owner="${APPMESH_DAEMON_EXEC_USER}:${daemon_group}"

        # Only mutable runtime state and the PID file belong to the daemon.
        # Sensitive packaged policy stays root-owned and group-readable.
        install -d -m 750 -o "${APPMESH_DAEMON_EXEC_USER}" -g "${daemon_group}" "${PROG_HOME}/work"
        chown -R "${runtime_owner}" "${PROG_HOME}/work"
        chown "root:${daemon_group}" "${PROG_HOME}/config/authorization.yaml"
        chmod 640 "${PROG_HOME}/config/authorization.yaml"
        : > "${PROG_HOME}/appmesh.pid"
        chown "${runtime_owner}" "${PROG_HOME}/appmesh.pid"
        chmod 640 "${PROG_HOME}/appmesh.pid"
    fi
}

setup_ssl_certificates() {
    local ssl_dir="${PROG_HOME}/ssl"
    if [ "${APPMESH_FRESH_INSTALL:-}" = "Y" ] || [ ! -f "${ssl_dir}/server.pem" ]; then
        info "Generating SSL certificates"
        if [ -f "${ssl_dir}/generate_ssl_cert.sh" ]; then
            (cd "$ssl_dir" && bash generate_ssl_cert.sh)
            # Preserve the historical generated-file defaults. Existing
            # operator-provided TLS ownership and modes are never rewritten.
            find "$ssl_dir" -type f -name "*.pem" -exec chmod 644 {} \;
        else
            die "SSL certificate generation script not found"
        fi
    fi
}

# User-facing introduction. Plain echo on purpose: this block is an
# introduction, not a log entry, so it carries no timestamp prefix. Each
# platform prints only its own service commands. tee also copies the text to
# NEXT_STEPS.txt without a timestamp prefix: macOS package installs swallow
# postinstall stdout, and the file keeps the steps readable there.
print_startup_instructions() {
    local init_system
    init_system=$(detect_init_system)

    {
        echo
        echo "App Mesh installed to: $PROG_HOME"
        echo
        echo "Next steps:"
        echo "  1. Start the service"
        case "$init_system" in
        "systemd")
            echo "       sudo systemctl enable --now appmesh"
            ;;
        "launchd")
            echo "       sudo launchctl load -w $LAUNCHD_FILE"
            ;;
        *)
            echo "       sudo service appmesh start"
            ;;
        esac
        echo "  2. Sign in"
        if [ "$(read_env_entry APPMESH_AUTH_MODE 2>/dev/null || true)" = "builtin" ]; then
            if grep -q '^password=' "${PROG_HOME}/work/auth/secrets/initial-admin-credentials" 2>/dev/null; then
                echo "       sudo ${PROG_HOME}/script/appmesh-auth.sh print-initial-password"
            else
                echo "       The initial password was removed on this host. Set a new one:"
                echo "       sudo ${PROG_HOME}/script/appmesh-auth.sh rotate-initial-password, then restart appmesh"
            fi
            echo "       appm logon --username admin@appmesh.local"
        else
            echo "       appm logon --browser"
        fi
        echo
        echo "Logs: ${PROG_HOME}/work/server.log"
        echo "Docs: https://app-mesh.readthedocs.io"
        if command -v rpm >/dev/null 2>&1 && rpm -q appmesh >/dev/null 2>&1; then
            echo "Uninstall: sudo yum remove appmesh"
        elif command -v dpkg >/dev/null 2>&1 && dpkg -s appmesh >/dev/null 2>&1; then
            echo "Uninstall: sudo apt remove appmesh"
        elif [ "$init_system" = "launchd" ]; then
            echo "Uninstall:"
            echo "       sudo launchctl unload -w $LAUNCHD_FILE"
            echo "       sudo rm -rf $PROG_HOME $LAUNCHD_FILE /usr/local/bin/appm"
            echo "       sudo pkgutil --forget com.laoshanxi.appmesh"
        else
            echo "Uninstall: sudo service appmesh stop; sudo rm -rf $PROG_HOME"
        fi
        echo
    } | tee "$PROG_HOME/NEXT_STEPS.txt" || warn "Failed to write $PROG_HOME/NEXT_STEPS.txt"
    chmod 644 "$PROG_HOME/NEXT_STEPS.txt" 2>/dev/null || true
}

################################################################################
# Main Function
################################################################################
main() {
    parse_arguments "$@"

    # Check root privileges
    [[ "$(id -u)" -ne 0 ]] && die "This script must be run as root"

    if [ -f "$ENV_FILE" ]; then
        PREVIOUS_AUTH_MODE=$(read_env_entry APPMESH_AUTH_MODE 2>/dev/null || true)
    fi

    # Clean
    clean_environment
    remove_obsolete_auth_app_definition
    migrate_renamed_bundled_apps

    # Setup
    setup_env_file
    provision_secret_master_key
    configure_authentication
    setup_service
    prepare_workflow_app
    setup_permissions
    setup_ssl_certificates

    # Print instructions
    print_startup_instructions
}

# Execute main function
main "$@"
