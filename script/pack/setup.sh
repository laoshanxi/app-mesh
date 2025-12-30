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
[[ "$(uname)" == "Darwin" ]] && readonly BASH_COMPLETION_DIR="/opt/homebrew/etc/bash_completion.d" || readonly BASH_COMPLETION_DIR="/usr/share/bash-completion/completions"
readonly BASH_COMPLETION_PATH="$BASH_COMPLETION_DIR/appc"
readonly APPC_SOFTLINK=/usr/local/bin/appc
readonly INITD_SOFTLINK=/etc/init.d/appmesh
readonly SYSTEMD_FILE=/etc/systemd/system/appmesh.service
readonly LAUNCHD_FILE=/Library/LaunchDaemons/com.appmesh.appmesh.plist
readonly ENV_FILE="$PROG_HOME/appmesh.default"

################################################################################
# Utility Functions
################################################################################

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
error() { log "ERROR $@"; }
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
        rm -rf "${PROG_HOME}/work/"* "${PROG_HOME}/work/".* 2>/dev/null || true
        info "Work directory cleaned for fresh installation"
    fi
}

setup_env_file() {
    info "Setting up environment file at $ENV_FILE"
    : >$ENV_FILE

    # Locale setup
    if locale -a 2>/dev/null | grep -iE "^(en_US\.(utf8|UTF-8))$" >/dev/null; then
        {
            echo "LANG=en_US.UTF-8"
            echo "LC_ALL=en_US.UTF-8"
        } >>"$ENV_FILE"
        info "Locale set to [en_US.UTF-8]"
    else
        error "Failed to set default locale [en_US.UTF-8], not available"
    fi

    # AppMesh environment variables
    printenv | grep '^APPMESH_' | while read -r var; do
        info "Applying environment variable: $var"
        echo "$var" >>"$ENV_FILE"
    done

    # Default execution user setup
    if [ -n "${APPMESH_BaseConfig_DefaultExecUser:-}" ] && [ "$APPMESH_BaseConfig_DefaultExecUser" != "root" ]; then
        echo "APPMESH_BaseConfig_DefaultExecUser=${APPMESH_BaseConfig_DefaultExecUser}" >>"$ENV_FILE"
        info "DefaultExecUser set to: $APPMESH_BaseConfig_DefaultExecUser"
    fi

    chmod 644 "$ENV_FILE"
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

    # Create appc symlink
    rm -f "$APPC_SOFTLINK" && ln -sf "${PROG_HOME}/bin/appc" "$APPC_SOFTLINK"
    info "Symlink for appc created at $APPC_SOFTLINK"

    # Initialize secure installation if needed
    if [ "${APPMESH_SECURE_INSTALLATION:-}" = "Y" ]; then
        info "Performing secure installation initialization"
        "$APPC_SOFTLINK" appmginit
    fi
}

install_systemd_service() {
    info "Installing systemd service at $SYSTEMD_FILE"
    local service_template="${PROG_HOME}/script/appmesh.systemd.service"

    [ ! -f "$service_template" ] && {
        info "Service template not found: $service_template"
        return 1
    }

    update_appmesh_paths ${PROG_HOME}/script/appmesh.systemd.service
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

    update_appmesh_paths ${PROG_HOME}/script/appmesh.launchd.plist

    chown root:wheel "$service_template"
    chmod 644 "$service_template"
    rm -f "$LAUNCHD_FILE" && ln -sf "$service_template" "$LAUNCHD_FILE"

     if [ -n "${APPMESH_DAEMON_EXEC_USER:-}" ]; then
        sed -i '' "s/<key>UserName<\/key>\n\t<string>.*<\/string>/<key>UserName<\/key>\n\t<string>${APPMESH_DAEMON_EXEC_USER}<\/string>/" "$LAUNCHD_FILE"
        info "Service user set to: ${APPMESH_DAEMON_EXEC_USER}"
    fi

    rm -f "${LAUNCHD_FILE}.bak"

    # Remove macOS quarantine attributes
    for binary in appsvc appc agent; do
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
    setup_permissions
    setup_ssl_certificates

    # Print instructions
    print_startup_instructions
}

# Execute main function
main "$@"
