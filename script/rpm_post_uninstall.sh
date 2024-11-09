#!/usr/bin/env bash

################################################################################
# RPM Post-Uninstallation Script
# Purpose: Remove App Mesh service files and clean up related files after
# package uninstallation.
# Usage: Automatically executed after package uninstallation.
################################################################################

readonly SYSTEMD_FILE="/etc/systemd/system/appmesh.service"
readonly INITD_FILE="/etc/init.d/appmesh"
readonly BASH_COMPLETION_FILE="/usr/share/bash-completion/completions/appc"
readonly SOFTLINK="/usr/bin/appc"

# Allow script to continue on errors
set +e

# Function to log timestamped messages
log() {
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] $@"
}

# Remove systemd service if it exists
if [ -f "$SYSTEMD_FILE" ]; then
	log "Removing systemd service"
	if ! systemctl stop appmesh; then
		log "Warning: Failed to stop appmesh service"
	fi
	if ! systemctl disable appmesh; then
		log "Warning: Failed to disable appmesh service"
	fi
	rm -f "$SYSTEMD_FILE"
	systemctl daemon-reload
fi

# Remove init.d service if it exists
if [ -f "$INITD_FILE" ]; then
	log "Removing init.d service"
	if ! service appmesh stop; then
		log "Warning: Failed to stop appmesh service"
	fi
	rm -f "$INITD_FILE"
fi

# Remove bash completion file
if [ -f "$BASH_COMPLETION_FILE" ]; then
	log "Removing bash completion file"
	rm -f "$BASH_COMPLETION_FILE"
fi

# Remove any _appmesh_ temporary files from the actual user's home directory
log "Cleaning up temporary files"
if [ -n "$SUDO_USER" ]; then
	sudo -u "$SUDO_USER" rm -f "/home/$SUDO_USER"/._appmesh_*
else
	rm -f "$HOME"/._appmesh_*
fi

# Remove binary file
if [ -L "$SOFTLINK" ]; then
	log "Removing symbolic link to binary"
	rm -f "$SOFTLINK"
fi

log "Post-uninstallation cleanup completed successfully"
