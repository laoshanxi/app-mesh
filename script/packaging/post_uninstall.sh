#!/usr/bin/env bash

################################################################################
# RPM/DEB Post-Uninstallation Script
# Purpose: Remove App Mesh service files and clean up related files after
# package uninstallation.
# Usage: Automatically executed after package uninstallation.
################################################################################

[[ "$(uname)" == "Darwin" ]] && readonly BASH_COMPLETION_DIR="/opt/homebrew/etc/bash_completion.d" || readonly BASH_COMPLETION_DIR="/usr/share/bash-completion/completions"
readonly BASH_COMPLETION_SOFTLINK="${BASH_COMPLETION_DIR}/appc"
readonly SYSTEMD_FILE="/etc/systemd/system/appmesh.service"
readonly INITD_FILE="/etc/init.d/appmesh"
readonly APPC_SOFTLINK="/usr/local/bin/appc"

set +e # Allow script to continue on errors
set -u # Exit on undefined variables

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
error() { log "ERROR $@"; }
die() { error "$@" && exit 1; }

cleanup_systemd_service() {
	if [[ -f "$SYSTEMD_FILE" ]]; then
		info "Removing systemd service"
		if ! systemctl stop appmesh 2>/dev/null; then
			error "Failed to stop appmesh service"
		fi
		if ! systemctl disable appmesh 2>/dev/null; then
			error "Failed to disable appmesh service"
		fi
		rm -f "$SYSTEMD_FILE"
		systemctl daemon-reload
	fi
}

cleanup_initd_service() {
	if [[ -f "$INITD_FILE" ]]; then
		info "Removing init.d service"
		if ! service appmesh stop 2>/dev/null; then
			error "Failed to stop appmesh service"
		fi
		rm -f "$INITD_FILE"
	fi
}

cleanup_bash_completion() {
	if [[ -f "$BASH_COMPLETION_SOFTLINK" ]]; then
		info "Removing bash completion file"
		rm -f "$BASH_COMPLETION_SOFTLINK"
	fi
}

cleanup_temp_files() {
	info "Cleaning up temporary files"
	local user_home

	if [[ -n "${SUDO_USER:-}" ]]; then
		user_home="/home/$SUDO_USER"
		sudo -u "$SUDO_USER" rm -f "${user_home}"/.appmesh.*
	else
		user_home="$HOME"
		rm -f "${user_home}"/.appmesh.*
	fi
}

cleanup_binary() {
	if [[ -L "$APPC_SOFTLINK" ]]; then
		info "Removing symbolic link to binary"
		rm -f "$APPC_SOFTLINK"
	fi
}

################################################################################
# Main Function
################################################################################
main() {
	info "Starting post-uninstallation cleanup"

	cleanup_systemd_service
	cleanup_initd_service
	cleanup_bash_completion
	cleanup_temp_files
	cleanup_binary

	info "Post-uninstallation cleanup completed successfully"
}

# Execute main function
main
