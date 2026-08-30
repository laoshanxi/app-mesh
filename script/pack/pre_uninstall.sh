#!/usr/bin/env bash

################################################################################
# RPM/DEB/PKG Pre-Uninstallation Script
# Purpose: Stop the App Mesh service before package files are removed.
# Service deregistration and file cleanup belong to post_uninstall.sh.
# Usage: Automatically executed before package uninstallation.
# Supports: Linux (systemd, init.d) and macOS (launchd)
################################################################################

set +e # Allow script to continue on errors
set -u # Exit on undefined variables

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

stop_systemd_service() {
    if [[ -f /etc/systemd/system/appmesh.service ]]; then
        info "Stopping systemd service"
        systemctl stop appmesh 2>/dev/null || error "Failed to stop appmesh service"
    fi
}

stop_initd_service() {
    if [[ -f /etc/init.d/appmesh ]]; then
        info "Stopping init.d service"
        service appmesh stop 2>/dev/null || error "Failed to stop appmesh service"
    fi
}

stop_launchd_service() {
    local launchd_file="/Library/LaunchDaemons/com.laoshanxi.appmesh.plist"
    if [[ -f "$launchd_file" ]]; then
        info "Stopping launchd service"
        launchctl unload "$launchd_file" 2>/dev/null || error "Failed to unload com.laoshanxi.appmesh service"
    fi
}

################################################################################
# Main Function
################################################################################
main() {
    info "Stopping App Mesh service before uninstallation"

    case "$(detect_os)" in
    macos)
        stop_launchd_service
        ;;
    linux)
        stop_systemd_service
        stop_initd_service
        ;;
    *)
        error "Unsupported operating system, skipping service stop"
        ;;
    esac

    info "Pre-uninstallation preparation completed"
}

# Execute main function
main
