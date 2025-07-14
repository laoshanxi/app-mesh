#!/usr/bin/env bash

################################################################################
# RPM/DEB/PKG Post-Uninstallation Script
# Purpose: Remove App Mesh service files and clean up related files after
# package uninstallation.
# Usage: Automatically executed after package uninstallation.
# Supports: Linux (systemd/init.d) and macOS (launchd)
################################################################################

set +e # Allow script to continue on errors
set -u # Exit on undefined variables

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
error() { log "ERROR $@"; }
die() { error "$@" && exit 1; }

# Detect operating system
detect_os() {
	case "$(uname -s)" in
	Darwin*) echo "macos" ;;
	Linux*) echo "linux" ;;
	*) echo "unknown" ;;
	esac
}

# Platform-specific variables
setup_platform_vars() {
	local os_type=$(detect_os)

	if [[ "$os_type" == "macos" ]]; then
		# macOS specific paths
		readonly BASH_COMPLETION_DIR="/opt/homebrew/etc/bash_completion.d"
		readonly LAUNCHD_FILE="/Library/LaunchDaemons/com.laoshanxi.appmesh.plist"
		readonly SERVICE_NAME="com.laoshanxi.appmesh"
		# Define empty Linux variables to avoid undefined variable errors
		readonly SYSTEMD_FILE=""
		readonly INITD_FILE=""
	else
		# Linux specific paths
		readonly BASH_COMPLETION_DIR="/usr/share/bash-completion/completions"
		readonly SYSTEMD_FILE="/etc/systemd/system/appmesh.service"
		readonly INITD_FILE="/etc/init.d/appmesh"
		readonly SERVICE_NAME="appmesh"
		# Define empty macOS variables to avoid undefined variable errors
		readonly LAUNCHD_FILE=""
	fi

	readonly BASH_COMPLETION_PATH="${BASH_COMPLETION_DIR}/appc"
	readonly APPC_SOFTLINK="/usr/local/bin/appc"
}

cleanup_linux_systemd_service() {
	[[ -z "$SYSTEMD_FILE" ]] && return 0

	if [[ -f "$SYSTEMD_FILE" ]]; then
		info "Removing systemd service"
		if ! systemctl stop "$SERVICE_NAME" 2>/dev/null; then
			error "Failed to stop $SERVICE_NAME service"
		fi
		if ! systemctl disable "$SERVICE_NAME" 2>/dev/null; then
			error "Failed to disable $SERVICE_NAME service"
		fi
		rm -f "$SYSTEMD_FILE"
		systemctl daemon-reload
	fi
}

cleanup_linux_initd_service() {
	[[ -z "$INITD_FILE" ]] && return 0

	if [[ -f "$INITD_FILE" ]]; then
		info "Removing init.d service"
		if ! service "$SERVICE_NAME" stop 2>/dev/null; then
			error "Failed to stop $SERVICE_NAME service"
		fi
		rm -f "$INITD_FILE"
	fi
}

cleanup_macos_launchd_service() {
	[[ -z "$LAUNCHD_FILE" ]] && return 0

	if [[ -f "$LAUNCHD_FILE" ]]; then
		info "Removing launchd service"
		if ! launchctl unload "$LAUNCHD_FILE" 2>/dev/null; then
			error "Failed to unload $SERVICE_NAME service"
		fi
		rm -f "$LAUNCHD_FILE"
	fi

	# Also check user-specific LaunchAgents (if any)
	local user_launchd_dir="/Users/${SUDO_USER:-$USER}/Library/LaunchAgents"
	local user_launchd_file="${user_launchd_dir}/${SERVICE_NAME}.plist"
	if [[ -f "$user_launchd_file" ]]; then
		info "Removing user-specific launchd service"
		if [[ -n "${SUDO_USER:-}" ]]; then
			sudo -u "$SUDO_USER" launchctl unload "$user_launchd_file" 2>/dev/null || true
		else
			launchctl unload "$user_launchd_file" 2>/dev/null || true
		fi
		rm -f "$user_launchd_file"
	fi
}

cleanup_service() {
	local os_type=$(detect_os)

	if [[ "$os_type" == "macos" ]]; then
		cleanup_macos_launchd_service
	else
		cleanup_linux_systemd_service
		cleanup_linux_initd_service
	fi
}

cleanup_bash_completion() {
	if [[ -f "$BASH_COMPLETION_PATH" ]]; then
		info "Removing bash completion file"
		rm -f "$BASH_COMPLETION_PATH"
	fi
}

cleanup_temp_files() {
	info "Cleaning up temporary files"
	local user_home
	local os_type=$(detect_os)

	if [[ -n "${SUDO_USER:-}" ]]; then
		if [[ "$os_type" == "macos" ]]; then
			user_home="/Users/$SUDO_USER"
		else
			user_home="/home/$SUDO_USER"
		fi
		sudo -u "$SUDO_USER" rm -f "${user_home}"/.appmesh.* 2>/dev/null || true
	else
		user_home="$HOME"
		rm -f "${user_home}"/.appmesh.* 2>/dev/null || true
	fi
}

cleanup_binary() {
	if [[ -L "$APPC_SOFTLINK" ]]; then
		info "Removing symbolic link to binary"
		rm -f "$APPC_SOFTLINK"
	fi
}

cleanup_macos_specific() {
	local os_type=$(detect_os)

	if [[ "$os_type" == "macos" ]]; then
		# Remove any macOS-specific files or configurations
		info "Performing macOS-specific cleanup"

		# Remove any potential .DS_Store files
		find /opt/appmesh -name ".DS_Store" -delete 2>/dev/null || true

		# Remove any potential extended attributes
		xattr -rc /opt/appmesh 2>/dev/null || true
	fi
}

################################################################################
# Main Function
################################################################################
main() {
	info "Starting post-uninstallation cleanup"

	setup_platform_vars

	cleanup_service

	cleanup_bash_completion

	# cleanup_temp_files

	cleanup_binary

	cleanup_macos_specific

	info "Post-uninstallation cleanup completed successfully"
}

# Execute main function
main
