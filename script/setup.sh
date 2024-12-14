#!/usr/bin/env bash

################################################################################
## Register and set up system files for initialization after installation
################################################################################

# HOME path
export PROG_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/.." && pwd -P)"

# Soft links
readonly BASH_COMPLETION_DIR=/usr/share/bash-completion/completions
readonly BASH_COMPLETION_SOFTLINK="$BASH_COMPLETION_DIR/appc"
readonly APPC_SOFTLINK=/usr/bin/appc
readonly INITD_SOFTLINK=/etc/init.d/appmesh

# Target files
readonly SYSTEMD_FILE=/etc/systemd/system/appmesh.service
readonly ENV_FILE="$PROG_HOME/appmesh.default"

log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

# Detect OS type and version
get_os_type() {
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
}

setup_environment_file() {

    log "Setting up environment file at $ENV_FILE"
    : >$ENV_FILE

    # Set locale with better compatibility
    if locale -a 2>/dev/null | grep -iE "^(en_US\.(utf8|UTF-8))$" >/dev/null; then
        {
            echo "LANG=en_US.UTF-8"
            echo "LC_ALL=en_US.UTF-8"
        } >>"$ENV_FILE"
        log "Locale set to [en_US.UTF-8]"
    else
        log "Warning: Failed to set default locale [en_US.UTF-8], not available"
    fi

    # Set LD_LIBRARY_PATH with path validation
    local lib_path="${PROG_HOME}/lib64"
    if [ -d "$lib_path" ]; then
        if [ -n "$LD_LIBRARY_PATH" ]; then
            echo "LD_LIBRARY_PATH=${lib_path}:${LD_LIBRARY_PATH}" >>"$ENV_FILE"
        else
            echo "LD_LIBRARY_PATH=${lib_path}" >>"$ENV_FILE"
        fi
    fi

    # Export APPMESH environment variables: env | grep '^APPMESH_' | sort >> "$ENV_FILE"
    printenv | grep '^APPMESH_' | while read -r var; do
        log "Applying environment variable: $var"
        echo "$var" >>"$ENV_FILE"
    done

    # Handle default execution user
    # set default execute user to current user
    #if [ -z "$APPMESH_BaseConfig_DefaultExecUser" ]; then
    #	APPMESH_BaseConfig_DefaultExecUser="${SUDO_USER:-$LOGNAME}"
    #fi
    if [ -n "$APPMESH_BaseConfig_DefaultExecUser" ] && [ "$APPMESH_BaseConfig_DefaultExecUser" != "root" ]; then
        echo "APPMESH_BaseConfig_DefaultExecUser=${APPMESH_BaseConfig_DefaultExecUser}" >>"$ENV_FILE"
        log "DefaultExecUser set to: $APPMESH_BaseConfig_DefaultExecUser"
    fi

    chmod 644 "$ENV_FILE"
}

detect_init_system() {
    # Original detection for non-container environments
    if command -v systemctl >/dev/null 2>&1 && systemctl list-units >/dev/null 2>&1; then
        echo "systemd"
    else
        echo "init"
    fi
}

setup_service() {
    local init_system
    init_system=$(detect_init_system)

    case "$init_system" in
    systemd)
        install_systemd_service
        ;;
    *)
        install_initd_service
        ;;
    esac
}

install_systemd_service() {
    log "Installing systemd service at $SYSTEMD_FILE"
    local service_template="${PROG_HOME}/script/appmesh.systemd.service"

    if [ ! -f "$service_template" ]; then
        log "Service template not found: $service_template"
        return 1
    fi

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

install_initd_service() {
    log "Installing init.d service"
    local initd_template="${PROG_HOME}/script/appmesh.initd.sh"

    if [ ! -f "$initd_template" ]; then
        log "Service template not found: $initd_template"
        return 1
    fi

    rm -f "$INITD_SOFTLINK" && ln -sf "$initd_template" "$INITD_SOFTLINK"

    local os_type
    os_type=$(get_os_type)
    if [ "$os_type" = "rhel" ] || [ "$os_type" = "centos" ]; then
        command -v chkconfig >/dev/null 2>&1 && chkconfig --add appmesh
    elif [ "$os_type" = "debian" ] || [ "$os_type" = "ubuntu" ]; then
        command -v update-rc.d >/dev/null 2>&1 && update-rc.d appmesh defaults
    fi
}

setup_permissions() {
    log "Setting up permissions"
    chmod 644 "${PROG_HOME}"/config.yaml "${PROG_HOME}"/security.yaml
    find "${PROG_HOME}/script" -name "*.sh" -exec chmod +x {} \;

    if [ -n "${APPMESH_DAEMON_EXEC_USER}" ]; then
        local owner="${APPMESH_DAEMON_EXEC_USER}"
        [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP}" ] && owner="${owner}:${APPMESH_DAEMON_EXEC_USER_GROUP}"
    fi
}

setup_ssl() {
    local ssl_dir="${PROG_HOME}/ssl"
    if [ "$APPMESH_FRESH_INSTALL" = "Y" ] || [ ! -f "${ssl_dir}/server.pem" ]; then
        log "Generating SSL certificates"
        if [ -f "${ssl_dir}/generate_ssl_cert.sh" ]; then
            (cd "$ssl_dir" && sh generate_ssl_cert.sh)
            find "$ssl_dir" -name "*.pem" -exec chmod 644 {} \;
        else
            log "SSL certificate generation script not found"
            return 1
        fi
    fi
}

print_startup_instructions() {
    local init_system
    init_system=$(detect_init_system)

    log "To start App Mesh:"
    case "$init_system" in
    systemd)
        log "  sudo systemctl enable appmesh"
        log "  sudo systemctl start appmesh"
        ;;
    sysvinit | upstart)
        log "  sudo service appmesh start"
        ;;
    esac
}

main() {
    if [ "$(id -u)" -ne 0 ]; then
        log "This script must be run as root"
        exit 1
    fi

    mkdir -p "${PROG_HOME}/work"

    # Stop existing service
    if [ -f "$SYSTEMD_FILE" ] || [ -f "$INITD_SOFTLINK" ]; then
        log "Stopping existing service"
        systemctl stop appmesh 2>/dev/null || service appmesh stop 2>/dev/null || true
        sleep 2
    fi

    # Clean work directory for fresh install
    if [ "$APPMESH_FRESH_INSTALL" = "Y" ]; then
        rm -rf "${PROG_HOME}/work/"* "${PROG_HOME}/work/".* 2>/dev/null || true
        log "Work directory cleaned for fresh installation"
    fi

    # Setup components
    setup_environment_file
    setup_service
    setup_permissions
    setup_ssl

    # Install bash completion
    if [ -d "$BASH_COMPLETION_DIR" ]; then
        rm -f "$BASH_COMPLETION_SOFTLINK" && ln -sf "${PROG_HOME}/script/bash_completion.sh" "$BASH_COMPLETION_SOFTLINK"
        log "Bash completion script successfully installed at $BASH_COMPLETION_SOFTLINK"
    else
        log "Warning: $BASH_COMPLETION_DIR directory not found. Skipping bash completion script installation"
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
