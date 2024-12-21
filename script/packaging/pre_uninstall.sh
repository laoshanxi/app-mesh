#!/usr/bin/env bash

################################################################################
# RPM/DEB Pre-Uninstallation Script
# Purpose: Prepare system for package removal by stopping applications and
# preserving their configurations.
# Usage: Automatically executed before package uninstallation.
################################################################################

readonly INSTALL_DIR=/opt/appmesh
readonly APPC_BIN=/usr/local/bin/appc
readonly APPS_DIR=/opt/appmesh/work/apps
readonly BACKUP_DIR=/opt/appmesh/work/.apps_backup

set +e # Allow script to continue on errors
set -u # Exit on undefined variables

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
error() { log "ERROR $@"; }
die() { error "$@" && exit 1; }

backup_configurations() {
	if [ -d "$APPS_DIR" ] && [ "$(ls -A "$APPS_DIR" 2>/dev/null)" ]; then
		info "Creating backup of application configurations"
		cp -rf "$APPS_DIR" "$BACKUP_DIR"
	fi
}

stop_applications() {
	info "Stopping all active applications"

	if [ -e "$APPC_BIN" ]; then
		if [ -n "${SUDO_USER:-}" ]; then
			sudo -u "$SUDO_USER" "$APPC_BIN" disable --all
		else
			"$APPC_BIN" disable --all
		fi
	else
		error "$APPC_BIN not found"
	fi
}

restore_configurations() {
	if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
		info "Restoring application configurations"
		rm -rf "${APPS_DIR:?}"/*
		mv -f "${BACKUP_DIR}"/* "${APPS_DIR}/"
		rm -rf "$BACKUP_DIR"
	fi
}

################################################################################
# Main Function
################################################################################
main() {
	# Backup existing configurations
	backup_configurations

	# Stop all applications
	stop_applications

	# Restore configurations from backup
	restore_configurations

	info "Pre-uninstallation preparation completed"
}

# Execute main function
main
