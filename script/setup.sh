#!/usr/bin/env bash

################################################################################
# Setup script for App Mesh
# Supports: Linux (systemd, sysvinit) and macOS (launchd)
# Purpose: Register and set up system files for initialization after installation
################################################################################

set -e # Exit on error

# Constants and paths
readonly PROG_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/.." && pwd -P)"
[[ "$(uname)" == "Darwin" ]] && readonly BASH_COMPLETION_DIR="/opt/homebrew/etc/bash_completion.d" || readonly BASH_COMPLETION_DIR="/usr/share/bash-completion/completions"
readonly BASH_COMPLETION_SOFTLINK="$BASH_COMPLETION_DIR/appc"
readonly APPC_SOFTLINK=/usr/local/bin/appc
readonly INITD_SOFTLINK=/etc/init.d/appmesh
readonly SYSTEMD_FILE=/etc/systemd/system/appmesh.service
readonly LAUNCHD_FILE=/Library/LaunchDaemons/com.appmesh.appmesh.plist
readonly ENV_FILE="$PROG_HOME/appmesh.default"

################################################################################
# Utility Functions
################################################################################

log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
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

    [ ! -f "$input_file_path" ] && {
        log "Error: Input file '$input_file_path' does not exist."
        return 1
    }

    # Normalize paths for consistency
    appmesh_dir=$(realpath "$appmesh_dir")
    input_file_path=$(realpath "$input_file_path")

    # Ensure appmesh_dir ends with "/appmesh"
    [[ ! "$appmesh_dir" =~ /appmesh$ ]] && {
        log "Error: home dir must end with '/appmesh'. Current value: '$appmesh_dir'."
        return 1
    }

    # Escape special characters in the appmesh directory for use in sed
    local escaped_appmesh_dir=$(echo "$appmesh_dir" | sed 's/\//\\\//g')
    local temp_file=$(mktemp)

    # Replace paths matching the pattern ending with 'appmesh/'
    sed -e "s|/[[:alnum:]/]*appmesh/|$escaped_appmesh_dir/|g" "$input_file_path" >"$temp_file"

    if ! cmp -s "$input_file_path" "$temp_file"; then
        mv "$temp_file" "$input_file_path"
        log "File '$input_file_path' updated successfully with the new directory: '$appmesh_dir'."
    else
        rm "$temp_file"
    fi
    return 0
}

setup_env_file() {
    log "Setting up environment file at $ENV_FILE"
    : >$ENV_FILE

    # Locale setup
    if locale -a 2>/dev/null | grep -iE "^(en_US\.(utf8|UTF-8))$" >/dev/null; then
        {
            echo "LANG=en_US.UTF-8"
            echo "LC_ALL=en_US.UTF-8"
        } >>"$ENV_FILE"
        log "Locale set to [en_US.UTF-8]"
    else
        log "Warning: Failed to set default locale [en_US.UTF-8], not available"
    fi

    # Library path setup
    local lib_path="${PROG_HOME}/lib64"
    if [ -d "$lib_path" ]; then
        if [ -n "$LD_LIBRARY_PATH" ]; then
            echo "LD_LIBRARY_PATH=${lib_path}:${LD_LIBRARY_PATH}" >>"$ENV_FILE"
        else
            echo "LD_LIBRARY_PATH=${lib_path}" >>"$ENV_FILE"
        fi
    fi

    # AppMesh environment variables
    printenv | grep '^APPMESH_' | while read -r var; do
        log "Applying environment variable: $var"
        echo "$var" >>"$ENV_FILE"
    done

    # Default execution user setup
    if [ -n "$APPMESH_BaseConfig_DefaultExecUser" ] && [ "$APPMESH_BaseConfig_DefaultExecUser" != "root" ]; then
        echo "APPMESH_BaseConfig_DefaultExecUser=${APPMESH_BaseConfig_DefaultExecUser}" >>"$ENV_FILE"
        log "DefaultExecUser set to: $APPMESH_BaseConfig_DefaultExecUser"
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
}

install_systemd_service() {
    log "Installing systemd service at $SYSTEMD_FILE"
    local service_template="${PROG_HOME}/script/appmesh.systemd.service"

    [ ! -f "$service_template" ] && {
        log "Service template not found: $service_template"
        return 1
    }

    update_appmesh_paths ${PROG_HOME}/script/appmesh.systemd.service
    rm -f "$SYSTEMD_FILE" && ln -sf "$service_template" "$SYSTEMD_FILE"

    if [ -n "${APPMESH_DAEMON_EXEC_USER}" ]; then
        sed -i.bak "s/^User=.*/User=${APPMESH_DAEMON_EXEC_USER}/" "$SYSTEMD_FILE"
        log "Service user set to: ${APPMESH_DAEMON_EXEC_USER}"
    fi

    if [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP}" ]; then
        sed -i.bak "s/^Group=.*/Group=${APPMESH_DAEMON_EXEC_USER_GROUP}/" "$SYSTEMD_FILE"
        log "Service group set to: ${APPMESH_DAEMON_EXEC_USER_GROUP}"
    fi

    rm -f "${SYSTEMD_FILE}.bak"
    systemctl daemon-reload
}

install_launchd_service() {
    log "Installing launchd service at $LAUNCHD_FILE"
    local service_template="${PROG_HOME}/script/appmesh.launchd.plist"

    [ ! -f "$service_template" ] && {
        log "Service template not found: $service_template"
        return 1
    }

    update_appmesh_paths ${PROG_HOME}/script/appmesh.launchd.plist

    chown root:wheel "$service_template"
    chmod 644 "$service_template"
    rm -f "$LAUNCHD_FILE" && ln -sf "$service_template" "$LAUNCHD_FILE"

    if [ -n "${APPMESH_DAEMON_EXEC_USER}" ]; then
        sed -i.bak "s/<key>UserName<\/key>\n\t<string>.*<\/string>/<key>UserName<\/key>\n\t<string>${APPMESH_DAEMON_EXEC_USER}<\/string>/" "$LAUNCHD_FILE"
        log "Service user set to: ${APPMESH_DAEMON_EXEC_USER}"
    fi

    rm -f "${LAUNCHD_FILE}.bak"

    # Remove macOS quarantine attributes
    for binary in appsvc appc agent; do
        xattr -d com.apple.quarantine "${PROG_HOME}/bin/${binary}" 2>/dev/null || true
    done

    # launchctl load -w "$LAUNCHD_FILE"
}

install_initd_service() {
    log "Installing init.d service"
    local initd_template="${PROG_HOME}/script/appmesh.initd.sh"

    [ ! -f "$initd_template" ] && {
        log "Service template not found: $initd_template"
        return 1
    }

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
    log "Setting up permissions"
    chmod 644 "${PROG_HOME}"/config.yaml "${PROG_HOME}"/security.yaml
    find "${PROG_HOME}/script" -name "*.sh" -exec chmod +x {} \;

    if [ -n "${APPMESH_DAEMON_EXEC_USER}" ]; then
        local owner="${APPMESH_DAEMON_EXEC_USER}"
        [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP}" ] && owner="${owner}:${APPMESH_DAEMON_EXEC_USER_GROUP}"
    fi
}

setup_ssl_certificates() {
    local ssl_dir="${PROG_HOME}/ssl"
    if [ "$APPMESH_FRESH_INSTALL" = "Y" ] || [ ! -f "${ssl_dir}/server.pem" ]; then
        log "Generating SSL certificates"
        if [ -f "${ssl_dir}/generate_ssl_cert.sh" ]; then
            (cd "$ssl_dir" && bash generate_ssl_cert.sh)
            find "$ssl_dir" -name "*.pem" -exec chmod 644 {} \;
        else
            log "SSL certificate generation script not found"
            return 1
        fi
    fi
}

print_startup_instructions() {
    local init_system=$(detect_init_system)

    log "Startup Instructions:"
    case "$init_system" in
    "systemd")
        log "  To enable App Mesh to start on boot and start it immediately:"
        log "    sudo systemctl enable appmesh"
        log "    sudo systemctl start appmesh"
        ;;
    "launchd")
        log "  To load the App Mesh service using launchd:"
        log "    sudo launchctl load -w $LAUNCHD_FILE"
        log "  Alternatively, to manually start the service:"
        log "    sudo bash ${PROG_HOME}/script/appmesh.initd.sh start"
        ;;
    *)
        log "  To enable and start App Mesh service on init.d systems:"
        log "    sudo update-rc.d appmesh defaults"
        log "    sudo service appmesh start"
        ;;
    esac
}

################################################################################
# Main Function
################################################################################

main() {
    # Check for root privileges
    if [ "$(id -u)" -ne 0 ]; then
        log "This script must be run as root"
        exit 1
    fi

    mkdir -p "${PROG_HOME}/work"

    # Stop existing service
    log "Stopping existing service if running..."
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
    if [ "$APPMESH_FRESH_INSTALL" = "Y" ]; then
        rm -rf "${PROG_HOME}/work/"* "${PROG_HOME}/work/".* 2>/dev/null || true
        log "Work directory cleaned for fresh installation"
    fi

    # Setup components
    setup_env_file
    setup_service
    setup_permissions
    setup_ssl_certificates

    # Install bash completion
    if [ -d "$BASH_COMPLETION_DIR" ]; then
        rm -f "$BASH_COMPLETION_SOFTLINK" && ln -sf "${PROG_HOME}/script/bash_completion.sh" "$BASH_COMPLETION_SOFTLINK"
        log "Bash completion script installed at $BASH_COMPLETION_SOFTLINK"
    else
        log "Warning: $BASH_COMPLETION_DIR not found. Skipping bash completion installation"
    fi

    # Create appc symlink
    rm -f "$APPC_SOFTLINK" && ln -sf "${PROG_HOME}/script/appc.sh" "$APPC_SOFTLINK"
    log "Symlink for appc created at $APPC_SOFTLINK"

    # Initialize secure installation if needed
    if [ "$APPMESH_SECURE_INSTALLATION" = "Y" ]; then
        log "Performing secure installation initialization"
        "$APPC_SOFTLINK" appmginit
    fi

    log "App Mesh installation completed successfully. Installed to: $PROG_HOME"
    print_startup_instructions
}

main "$@"
