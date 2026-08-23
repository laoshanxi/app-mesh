#!/usr/bin/env bash

################################################################################
# RPM/DEB/PKG Pre-Uninstallation Script
# Purpose: Stop non-system applications without changing their persisted state,
# then stop the App Mesh service (and its protected System Apps) last.
################################################################################

set +e # Authentication/daemon failures must never block package removal.
set -u

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO" "$@"; }
error() { log "ERROR" "$@"; }

detect_os() {
    case "$(uname -s)" in
    Darwin*) echo "macos" ;;
    Linux*) echo "linux" ;;
    *) echo "unknown" ;;
    esac
}

find_install_dir() {
    local install_path=""
    local requested_path=""
    if [ "$(detect_os)" = "macos" ] && [ -n "${2:-}" ]; then
        requested_path="$2"
    elif [ -n "${RPM_INSTALL_PREFIX:-}" ]; then
        requested_path="$RPM_INSTALL_PREFIX"
    elif [ -n "${PROMPT_INSTALL_PATH:-}" ] && [ "$PROMPT_INSTALL_PATH" != "1" ]; then
        requested_path="$PROMPT_INSTALL_PATH"
    fi
    if [ -n "$requested_path" ]; then
        requested_path=${requested_path%/}
        if [ -x "${requested_path}/bin/appm" ]; then
            printf '%s\n' "$requested_path"
            return
        elif [ -x "${requested_path}/appmesh/bin/appm" ]; then
            printf '%s\n' "${requested_path}/appmesh"
            return
        fi
    fi

    if [ "$(detect_os)" = "macos" ]; then
        local launchd_file="/Library/LaunchDaemons/com.laoshanxi.appmesh.plist"
        if [ -f "$launchd_file" ]; then
            install_path=$(plutil -extract WorkingDirectory raw "$launchd_file" 2>/dev/null || true)
        fi
    elif [ -f /etc/systemd/system/appmesh.service ]; then
        install_path=$(sed -n 's/^WorkingDirectory=//p' /etc/systemd/system/appmesh.service | tail -n 1)
    elif [ -e /etc/init.d/appmesh ]; then
        local initd_script=""
        initd_script=$(readlink /etc/init.d/appmesh 2>/dev/null || true)
        case "$initd_script" in
        /*) ;;
        "") initd_script=/etc/init.d/appmesh ;;
        *) initd_script="/etc/init.d/${initd_script}" ;;
        esac
        install_path=$(cd "$(dirname "$initd_script")/.." 2>/dev/null && pwd -P)
        [ -x "${install_path}/bin/appm" ] || install_path=""
    fi
    if [ -n "$install_path" ] && [ -d "$install_path" ]; then
        printf '%s\n' "$install_path"
    else
        printf '%s\n' /opt/appmesh
    fi
}

load_auth_environment() {
    local env_file="${INSTALL_DIR}/appmesh.default"
    local assignment=""
    local name=""
    [ -r "$env_file" ] || return 0
    while IFS= read -r assignment || [ -n "$assignment" ]; do
        case "$assignment" in
        "" | \#*) continue ;;
        *=*)
            name=${assignment%%=*}
            case "$name" in
            APPMESH_AUTH_MODE | APPMESH_AUTH_ROLE | APPMESH_AUTH_ISSUER | \
                APPMESH_AUTH_ACCESS_URL | APPMESH_AUTH_TLS_VERIFY | APPMESH_AUTH_CA_PATH | \
                APPMESH_DEX_ISSUER | APPMESH_DEX_ACCESS_URL | APPMESH_DEX_TLS_VERIFY | APPMESH_DEX_CA_PATH)
                export "$assignment"
                ;;
            esac
            ;;
        esac
    done <"$env_file"
}

backup_applications() {
    [ -d "$APPS_DIR" ] || return 0
    find "$APPS_DIR" -mindepth 1 -maxdepth 1 -print -quit | grep -q . || return 0
    BACKUP_DIR=$(mktemp -d "${INSTALL_DIR}/work/.apps_backup.XXXXXX") || {
        error "Cannot back up application definitions; skipping authenticated disable"
        return 1
    }
    cp -Rp "${APPS_DIR}/." "$BACKUP_DIR/" || {
        error "Cannot back up application definitions; skipping authenticated disable"
        rm -rf "$BACKUP_DIR"
        BACKUP_DIR=""
        return 1
    }
}

restore_applications() {
    [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ] || return 0
    cp -Rp "${BACKUP_DIR}/." "$APPS_DIR/" || error "Failed to restore application definitions"
    rm -rf "$BACKUP_DIR"
    BACKUP_DIR=""
}

disable_applications() {
    [ -x "$APPM_BIN" ] || {
        error "appm is unavailable; skipping application disable"
        return 0
    }
    local token=""
    local auth_launcher="${INSTALL_DIR}/script/appmesh-auth.sh"
    [ -x "$auth_launcher" ] || {
        error "Authentication launcher is unavailable; continuing with service stop"
        return 0
    }
    load_auth_environment
    token=$(APPMESH_HOME="$INSTALL_DIR" "$auth_launcher" automation-token) || {
        error "Bundled authentication credentials are unavailable. Continuing with service stop."
        return 0
    }
    [ -n "$token" ] || {
        error "The bundled authentication service did not return an access token. Continuing with service stop."
        return 0
    }
    backup_applications || return 0
    trap restore_applications EXIT
    trap 'exit 1' HUP INT TERM
    info "Disabling all non-system applications"
    APPMESH_BEARER_TOKEN="$token" "$APPM_BIN" disable --all || \
        error "Failed to disable all applications; continuing with service stop"
    token=""
    restore_applications
    trap - EXIT HUP INT TERM
}

stop_systemd_service() {
    if [ -f /etc/systemd/system/appmesh.service ]; then
        info "Stopping systemd service"
        systemctl stop appmesh 2>/dev/null || error "Failed to stop appmesh service"
    fi
}

stop_initd_service() {
    if [ -f /etc/init.d/appmesh ]; then
        info "Stopping init.d service"
        service appmesh stop 2>/dev/null || error "Failed to stop appmesh service"
    fi
}

stop_launchd_service() {
    local launchd_file="/Library/LaunchDaemons/com.laoshanxi.appmesh.plist"
    if [ -f "$launchd_file" ]; then
        info "Stopping launchd service"
        launchctl unload "$launchd_file" 2>/dev/null || error "Failed to unload com.laoshanxi.appmesh service"
    fi
}

main() {
    INSTALL_DIR=$(find_install_dir "$@")
    APPM_BIN="${INSTALL_DIR}/bin/appm"
    APPS_DIR="${INSTALL_DIR}/work/apps"
    BACKUP_DIR=""

    disable_applications

    # The daemon shuts down protected System Apps in reverse startup order, so
    # the bundled issuer remains available through the token/disable phase.
    case "$(detect_os)" in
    macos) stop_launchd_service ;;
    linux)
        stop_systemd_service
        stop_initd_service
        ;;
    *) error "Unsupported operating system, skipping service stop" ;;
    esac

    info "Pre-uninstallation preparation completed"
}

main "$@"
