#!/usr/bin/env bash

################################################################################
# RPM Pre-Uninstallation Script
# Purpose: Prepare system for package removal by stopping applications and
# preserving their configurations.
# Usage: Automatically executed before package uninstallation.
################################################################################

readonly INSTALL_DIR=/opt/appmesh
readonly APPC_BIN=/opt/appmesh/bin/appc
readonly APPS_DIR=/opt/appmesh/work/apps
readonly BACKUP_DIR=/opt/appmesh/work/.apps_backup

export LD_LIBRARY_PATH="/opt/appmesh/lib64:$LD_LIBRARY_PATH"

# Allow script to continue on errors
set +e

# Function to log timestamped messages
log() {
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] $@"
}

# Create backup of application configurations
if [ -d "$APPS_DIR" ] && [ "$(ls -A "$APPS_DIR" 2>/dev/null)" ]; then
	log "Creating backup of application configurations"
	cp -rf "$APPS_DIR" "$BACKUP_DIR"
fi

# Stop all active applications
# "$APPC_BIN" ls -l | awk '{if (NR>1){cmd="$APPC_BIN disable -n "$2;print(cmd);system(cmd)}}'
log "Stopping all active applications"
if [ -n "$SUDO_USER" ]; then
	sudo -u "$SUDO_USER" "$APPC_BIN" disable --all
else
	"$APPC_BIN" disable --all
fi

# Restore application configurations from backup
if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
	log "Restoring application configurations"
	rm -rf "${APPS_DIR}"/*
	mv -f "${BACKUP_DIR}"/* "${APPS_DIR}/"
	rm -rf "$BACKUP_DIR"
fi

log "Pre-uninstallation preparation completed successfully"
