#!/usr/bin/env bash

################################################################################
## RPM/DEB post installation script file, executed during installation
################################################################################

readonly INSTALL_DIR=/opt/appmesh
readonly SOFTLINK=/usr/bin/appc
readonly BASH_COMPLETION_DIR=/usr/share/bash-completion/completions
readonly BASH_COMPLETION_FILE="$BASH_COMPLETION_DIR/appc"
readonly SYSTEMD_FILE=/etc/systemd/system/appmesh.service
readonly INITD_FILE=/etc/init.d/appmesh
readonly ENV_FILE=/etc/default/appmesh
readonly PID_DIR=/run/appmesh

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
    log "Setting up environment file at $ENV_FILE."
    mkdir -p "$(dirname "$ENV_FILE")"
    : >"$ENV_FILE"

    # Set locale with better compatibility
    if locale -a 2>/dev/null | grep -iE "^(en_US\.(utf8|UTF-8))$" >/dev/null; then
        {
            echo "LANG=en_US.UTF-8"
            echo "LC_ALL=en_US.UTF-8"
        } >>"$ENV_FILE"
        log "Locale set to [en_US.UTF-8]."
    else
        log "Warning: Failed to set default locale [en_US.UTF-8], not available."
    fi

    # Set LD_LIBRARY_PATH with path validation
    local lib_path="${INSTALL_DIR}/lib64"
    if [ -d "$lib_path" ]; then
        if [ -n "$LD_LIBRARY_PATH" ]; then
            echo "LD_LIBRARY_PATH=${lib_path}:${LD_LIBRARY_PATH}" >>"$ENV_FILE"
        else
            echo "LD_LIBRARY_PATH=${lib_path}" >>"$ENV_FILE"
        fi
    fi

    # Export APPMESH environment variables: env | grep '^APPMESH_' | sort >> "$ENV_FILE"
    printenv | grep '^APPMESH_' | while read -r var; do
        log "Applying environment variable: $var."
        echo "$var" >>"$ENV_FILE"
    done

    # Handle default execution user
    # set default execute user to current user
    #if [ -z "$APPMESH_BaseConfig_DefaultExecUser" ]; then
    #	APPMESH_BaseConfig_DefaultExecUser="${SUDO_USER:-$LOGNAME}"
    #fi
    if [ -n "$APPMESH_BaseConfig_DefaultExecUser" ] && [ "$APPMESH_BaseConfig_DefaultExecUser" != "root" ]; then
        echo "APPMESH_BaseConfig_DefaultExecUser=${APPMESH_BaseConfig_DefaultExecUser}" >>"$ENV_FILE"
        log "DefaultExecUser set to: $APPMESH_BaseConfig_DefaultExecUser."
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
    log "Installing systemd service at $SYSTEMD_FILE."
    local service_template="${INSTALL_DIR}/script/appmesh.systemd.service"

    if [ ! -f "$service_template" ]; then
        log "Service template not found: $service_template"
        return 1
    fi

    cp -f "$service_template" "$SYSTEMD_FILE"
    chmod 644 "$SYSTEMD_FILE"

    if [ -n "${APPMESH_DAEMON_EXEC_USER}" ]; then
        sed -i.bak "s/^User=.*/User=${APPMESH_DAEMON_EXEC_USER}/" "$SYSTEMD_FILE"
        log "Service user set to: ${APPMESH_DAEMON_EXEC_USER}."
    fi

    if [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP}" ]; then
        sed -i.bak "s/^Group=.*/Group=${APPMESH_DAEMON_EXEC_USER_GROUP}/" "$SYSTEMD_FILE"
        log "Service group set to: ${APPMESH_DAEMON_EXEC_USER_GROUP}."
    fi

    rm -f "${SYSTEMD_FILE}.bak"
    systemctl daemon-reload
}

install_initd_service() {
    log "Installing init.d service"
    local initd_template="${INSTALL_DIR}/script/appmesh.initd.sh"

    if [ ! -f "$initd_template" ]; then
        log "Service template not found: $initd_template"
        return 1
    fi

    cp -f "$initd_template" "$INITD_FILE"
    chmod 755 "$INITD_FILE"

    local os_type
    os_type=$(get_os_type)
    if [ "$os_type" = "rhel" ] || [ "$os_type" = "centos" ]; then
        command -v chkconfig >/dev/null 2>&1 && chkconfig --add appmesh
    elif [ "$os_type" = "debian" ] || [ "$os_type" = "ubuntu" ]; then
        command -v update-rc.d >/dev/null 2>&1 && update-rc.d appmesh defaults
    fi
}

setup_permissions() {
    log "Setting up permissions."
    chmod 644 "${INSTALL_DIR}"/config.yaml "${INSTALL_DIR}"/security.yaml
    find "${INSTALL_DIR}/script" -name "*.sh" -exec chmod +x {} \;

    if [ -n "${APPMESH_DAEMON_EXEC_USER}" ]; then
        local owner="${APPMESH_DAEMON_EXEC_USER}"
        [ -n "${APPMESH_DAEMON_EXEC_USER_GROUP}" ] && owner="${owner}:${APPMESH_DAEMON_EXEC_USER_GROUP}"
        chown -R "$owner" "${INSTALL_DIR}" "${PID_DIR}"
    fi
}

setup_ssl() {
    local ssl_dir="${INSTALL_DIR}/ssl"
    if [ "$APPMESH_FRESH_INSTALL" = "Y" ] || [ ! -f "${ssl_dir}/server.pem" ]; then
        log "Generating SSL certificates"
        if [ -f "${ssl_dir}/ssl_cert_generate.sh" ]; then
            (cd "$ssl_dir" && sh ssl_cert_generate.sh)
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

    mkdir -p "${INSTALL_DIR}/work"
    mkdir -p "$PID_DIR"

    # Stop existing service
    if [ -f "$SYSTEMD_FILE" ] || [ -f "$INITD_FILE" ]; then
        log "Stopping existing service"
        systemctl stop appmesh 2>/dev/null || service appmesh stop 2>/dev/null || true
        sleep 2
    fi

    # Clean work directory for fresh install
    if [ "$APPMESH_FRESH_INSTALL" = "Y" ]; then
        rm -rf "${INSTALL_DIR}/work/"* "${INSTALL_DIR}/work/".* 2>/dev/null || true
        log "Work directory cleaned for fresh installation."
    fi

    # Setup components
    setup_environment_file
    setup_service
    setup_permissions
    setup_ssl

    # Install bash completion
    if [ -d "$BASH_COMPLETION_DIR" ]; then
        cp -f "${INSTALL_DIR}/script/bash_completion.sh" "$BASH_COMPLETION_FILE"
        chmod 644 "$BASH_COMPLETION_FILE"
        log "Bash completion script successfully installed at $BASH_COMPLETION_FILE."
    else
        log "Warning: $BASH_COMPLETION_DIR directory not found. Skipping bash completion script installation."
    fi

    # Create appc symlink
    ln -sf "${INSTALL_DIR}/script/appc.sh" "$SOFTLINK"
    log "Symlink for appc created at $SOFTLINK."

    # Initialize secure installation if needed
    if [ "$APPMESH_SECURE_INSTALLATION" = "Y" ]; then
        log "Performing secure installation initialization."
        "$SOFTLINK" appmginit
    fi

    log "App Mesh installation completed successfully. Installed to: $INSTALL_DIR."
    print_startup_instructions
}

main "$@"
