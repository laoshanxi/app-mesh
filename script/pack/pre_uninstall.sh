#!/usr/bin/env bash

################################################################################
# RPM/DEB/PKG Pre-Uninstallation Script
# Purpose: Prepare system for package removal by stopping applications and
# preserving their configurations.
# Usage: Automatically executed before package uninstallation.
# Supports: Linux and macOS
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

# Find the actual installation directory
find_install_dir() {
	local default_install_dir="/opt/appmesh"
	local os_type=$(detect_os)
	local install_path=""

	# Try to find the installation directory by checking service files
	if [[ "$os_type" == "macos" ]]; then
		local launchd_file="/Library/LaunchDaemons/com.laoshanxi.appmesh.plist"
		if [[ -f "$launchd_file" ]]; then
			# Use more robust method to extract path from plist
			install_path=$(plutil -extract ProgramArguments.0 raw "$launchd_file" 2>/dev/null | xargs dirname | xargs dirname 2>/dev/null || echo "")
			if [[ -n "$install_path" && -d "$install_path" ]]; then
				echo "$install_path"
				return
			fi
		fi
	else
		local systemd_file="/etc/systemd/system/appmesh.service"
		if [[ -f "$systemd_file" ]]; then
			# Extract installation path from systemd service file
			install_path=$(grep "^WorkingDirectory=" "$systemd_file" | cut -d'=' -f2 | tr -d ' ')
			if [[ -n "$install_path" && -d "$install_path" ]]; then
				echo "$install_path"
				return
			fi
		fi
	fi

	# Fallback to default if service files don't exist or don't contain path info
	echo "$default_install_dir"
}

# Setup platform-specific variables
setup_platform_vars() {
	readonly INSTALL_DIR=$(find_install_dir)
	readonly APPC_BIN="${INSTALL_DIR}/bin/appc"
	readonly APPS_DIR="${INSTALL_DIR}/work/apps"
	readonly BACKUP_DIR="${INSTALL_DIR}/work/.apps_backup"
}

backup_configurations() {
	if [[ -d "$APPS_DIR" ]] && [[ -n "$(ls -A "$APPS_DIR" 2>/dev/null)" ]]; then
		info "Creating backup of application configurations"
		mkdir -p "$(dirname "$BACKUP_DIR")"
		# Use platform-appropriate copy command for better Linux compatibility
		local os_type=$(detect_os)
		if [[ "$os_type" == "linux" ]]; then
			# Use -rf for Linux to maintain Version 1 behavior
			cp -rf "$APPS_DIR" "$BACKUP_DIR"
		else
			# Use -R for macOS
			cp -R "$APPS_DIR" "$BACKUP_DIR"
		fi
	fi
}

stop_applications() {
	info "Stopping all active applications"

	# Stop applications with appropriate user context
	if [[ -n "${SUDO_USER:-}" ]]; then
		sudo -u "$SUDO_USER" "$APPC_BIN" disable --all
	else
		"$APPC_BIN" disable --all
	fi
}

restore_configurations() {
	if [[ -d "$BACKUP_DIR" ]] && [[ -n "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
		info "Restoring application configurations"

		# Ensure apps directory exists
		mkdir -p "$APPS_DIR"
		# Clear existing configurations
		rm -rf "${APPS_DIR:?}"/*
		# Restore from backup
		mv -f "${BACKUP_DIR}"/* "${APPS_DIR}/"
		# Clean up backup directory
		rm -rf "$BACKUP_DIR"
	fi
}

################################################################################
# Main Function
################################################################################
main() {
	info "Starting pre-uninstallation preparation"

	# Setup platform-specific variables
	setup_platform_vars

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
