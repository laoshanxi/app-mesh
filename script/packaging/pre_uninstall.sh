#!/usr/bin/env bash

################################################################################
# RPM Pre-Uninstallation Script
# Purpose: Prepare system for package removal by stopping applications and
# preserving their configurations.
# Usage: Automatically executed before package uninstallation.
################################################################################

readonly INSTALL_DIR=/opt/appmesh
readonly APPC_BIN=/usr/local/bin/appc
readonly APPS_DIR=/opt/appmesh/work/apps
readonly BACKUP_DIR=/opt/appmesh/work/.apps_backup

# Allow script to continue on errors
set +e

# Exit on undefined variables
set -u

log() {
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

backup_configurations() {
	if [ -d "$APPS_DIR" ] && [ "$(ls -A "$APPS_DIR" 2>/dev/null)" ]; then
		log "Creating backup of application configurations"
		cp -rf "$APPS_DIR" "$BACKUP_DIR"
	fi
}

stop_applications() {
	log "Stopping all active applications"

	if [ -e "$APPC_BIN" ]; then
		if [ -n "${SUDO_USER:-}" ]; then
			sudo -u "$SUDO_USER" "$APPC_BIN" disable --all
		else
			"$APPC_BIN" disable --all
		fi
	else
		log "Warning: $APPC_BIN not found"
	fi

}

restore_configurations() {
	if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
		log "Restoring application configurations"
		rm -rf "${APPS_DIR:?}"/*
		mv -f "${BACKUP_DIR}"/* "${APPS_DIR}/"
		rm -rf "$BACKUP_DIR"
	fi
}

main() {

	# Backup existing configurations
	backup_configurations

	# Stop all applications
	stop_applications

	# Restore configurations from backup
	restore_configurations

	log "Pre-uninstallation preparation completed"
}

# Execute main function
main
