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
readonly WORKFLOW_TEMPLATE="${PROG_HOME}/config/templates/workflow.yaml"
readonly WORKFLOW_APP="${PROG_HOME}/work/apps/workflow.yaml"
readonly WORKFLOW_INIT_MARKER="${PROG_HOME}/work/.workflow_initialized"

################################################################################
# Utility Functions
################################################################################

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO" "$@"; }
error() { log "ERROR" "$@"; }
die() { error "$@" && exit 1; }

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
        sleep 2
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
        info "Applying environment variable: $name"
        write_env_entry "$env_tmp" "$name" "$value"
    done < <(printenv | grep '^APPMESH_')

    # Default execution user setup
    if [ -n "${APPMESH_BaseConfig_DefaultExecUser:-}" ] && [ "$APPMESH_BaseConfig_DefaultExecUser" != "root" ]; then
        info "DefaultExecUser set to: $APPMESH_BaseConfig_DefaultExecUser"
    fi

    mv "$env_tmp" "$ENV_FILE"
    # setup_permissions() transfers ownership to a configured daemon user.
    chmod 600 "$ENV_FILE"

    # Restore the persisted service identity before regenerating definitions.
    for name in APPMESH_DAEMON_EXEC_USER APPMESH_DAEMON_EXEC_USER_GROUP; do
        if value=$(read_env_entry "$name"); then
            printf -v "$name" '%s' "$value"
            export "$name"
        fi
    done
}

prepare_workflow_app() {
    if [ "${APPMESH_SECURE_INSTALLATION:-N}" = "Y" ] || [ -f "${PROG_HOME}/work/.appmginit" ]; then
        # A packaged default is incompatible with appmginit credentials.
        if [ -f "$WORKFLOW_APP" ] && [ -f "$WORKFLOW_TEMPLATE" ] && cmp -s "$WORKFLOW_APP" "$WORKFLOW_TEMPLATE"; then
            local disabled_app="${WORKFLOW_APP}.disabled"
            [ -e "$disabled_app" ] && disabled_app="${disabled_app}.$(date +%s)"
            mv "$WORKFLOW_APP" "$disabled_app"
            info "Secure installation: moved the default workflow App to $disabled_app"
        fi
        info "Secure installation: workflow App was not enabled with default credentials"
        info "Provision the workflow App sec_env after the daemon starts"
        touch "$WORKFLOW_INIT_MARKER"
        chmod 600 "$WORKFLOW_INIT_MARKER"
        return
    fi

    # Runtime definitions are operator state. Only initialize a missing one.
    if [ -f "$WORKFLOW_APP" ]; then
        info "Preserving existing workflow App definition at $WORKFLOW_APP"
        touch "$WORKFLOW_INIT_MARKER"
        chmod 600 "$WORKFLOW_INIT_MARKER"
        return
    fi
    if [ -f "$WORKFLOW_INIT_MARKER" ]; then
        info "Preserving intentionally absent workflow App definition"
        return
    fi
    if [ ! -f "$WORKFLOW_TEMPLATE" ]; then
        die "Workflow App template not found: $WORKFLOW_TEMPLATE"
    fi

    mkdir -p "$(dirname "$WORKFLOW_APP")"
    cp "$WORKFLOW_TEMPLATE" "$WORKFLOW_APP"
    chmod 600 "$WORKFLOW_APP"
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

    # Initialize secure installation if needed
    if [ "${APPMESH_SECURE_INSTALLATION:-}" = "Y" ]; then
        local flag_file="${PROG_HOME}/work/.appmginit"
        if [ ! -f "$flag_file" ]; then
            info "Performing secure installation initialization"
            "$APPM_SOFTLINK" appmginit
        else
            info "Secure installation was already initialized"
        fi
    fi
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
    chmod 644 "${PROG_HOME}"/config/config.yaml "${PROG_HOME}"/config/security.yaml
    find "${PROG_HOME}/script" -name "*.sh" -exec chmod +x {} \;

    if [ -n "${APPMESH_DAEMON_EXEC_USER:-}" ]; then
        local owner="${APPMESH_DAEMON_EXEC_USER}"
        [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP:-}" ] && owner="${owner}:${APPMESH_DAEMON_EXEC_USER_GROUP}"
        chown -R "$owner" "${PROG_HOME}"
    fi
}

setup_ssl_certificates() {
    local ssl_dir="${PROG_HOME}/ssl"
    if [ "${APPMESH_FRESH_INSTALL:-}" = "Y" ] || [ ! -f "${ssl_dir}/server.pem" ]; then
        info "Generating SSL certificates"
        if [ -f "${ssl_dir}/generate_ssl_cert.sh" ]; then
            (cd "$ssl_dir" && bash generate_ssl_cert.sh)
            find "$ssl_dir" -name "*.pem" -exec chmod 644 {} \;
        else
            die "SSL certificate generation script not found"
        fi
    fi
}

print_startup_instructions() {
    info "App Mesh installation completed successfully. Installed to: $PROG_HOME"
    local init_system=$(detect_init_system)

    info "Startup Instructions:"
    case "$init_system" in
    "systemd")
        info "  To enable App Mesh to start on boot and start it immediately:"
        info "    sudo systemctl enable appmesh"
        info "    sudo systemctl start appmesh"
        ;;
    "launchd")
        info "  To load the App Mesh service using launchd:"
        info "    sudo launchctl load -w $LAUNCHD_FILE"
        info "  Alternatively, to manually start the service:"
        info "    sudo bash ${PROG_HOME}/script/appmesh.initd.sh start"
        ;;
    *)
        info "  To enable and start App Mesh service on init.d systems:"
        info "    sudo update-rc.d appmesh defaults"
        info "    sudo service appmesh start"
        ;;
    esac
}

################################################################################
# Main Function
################################################################################
main() {
    # Check root privileges
    [[ "$(id -u)" -ne 0 ]] && die "This script must be run as root"

    # Clean
    clean_environment

    # Setup
    setup_env_file
    setup_service
    prepare_workflow_app
    setup_permissions
    setup_ssl_certificates

    # Print instructions
    print_startup_instructions
}

# Execute main function
main "$@"
