#!/usr/bin/env bash
################################################################################
# App Mesh Entrypoint Script
# Initializes the App Mesh service (appsvc) for init.d or as a Docker entrypoint.
################################################################################

set -e # Exit on error
set -u # Exit on undefined variables

# Environment Variables
export PROG_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/.." && pwd -P)"
export PROGRAM="${PROG_HOME}/bin/appsvc"

# Function: Logging Utility
log() {
	local level="$1"
	local message="$2"
	local timestamp

	# Fallback chain for timestamp generation
	timestamp=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%d %H:%M:%S%z' 2>/dev/null || printf '%(%Y-%m-%d %H:%M:%S)T')

	printf '%s [%s]: %s\n' "$timestamp" "$level" "$message"

	# Use logger only if available
	if command -v logger >/dev/null 2>&1; then
		logger -t "appmesh" "$level" "$message"
	fi
}
info() { log "INFO" "$@"; }
warn() { log "ERROR" "$@"; }
die() { error "$@" && exit 1; }

# Function: Check Required Dependencies
check_dependencies() {
	local missing_deps=0
	local required_commands="touch mkdir chmod"

	for cmd in $required_commands; do
		if ! command -v "$cmd" >/dev/null 2>&1; then
			warn "Required command not found: $cmd"
			((missing_deps++))
		fi
	done

	if [ "$missing_deps" -ne 0 ]; then
		die "Missing required dependencies. Please install them first."
	fi
}

# Function: Change to Program Directory
initialize_directory() {
	if [ ! -d "${PROG_HOME}" ]; then
		die "Program directory ${PROG_HOME} does not exist"
	fi

	cd "${PROG_HOME}" || {
		die "Failed to change directory to ${PROG_HOME}"
	}
}

# Function: Prepare and register the initial app
prepare_app_start() {
	if [ $# -gt 0 ]; then
		# Check if the first argument is "appc"
		if [ "$1" = "appc" ]; then
			shift
			info "Executing native command: $*"
			exec "$@"
		else
			# Register as long-running app with escaped command
			local yaml_file="${PROG_HOME}/work/apps/start_app.yaml"
			local command="$*"

			# Ensure work/apps directory exists
			mkdir -p "${PROG_HOME}/work/apps"

			# Create YAML with proper escaping
			{
				printf '%s\n' "name: start_app"
				printf '%s\n' "command: |"
				printf '  %s\n' "$command"
			} >"$yaml_file"

			chmod 600 "$yaml_file"
			info "Registered long-running application command in $yaml_file"
		fi
	fi
}

# Function: Secure Installation Check
secure_installation_check() {
	if [ "${APPMESH_SECURE_INSTALLATION:-N}" = "Y" ]; then
		local flag_file="${PROG_HOME}/work/.appmginit"

		# Ensure work directory exists
		mkdir -p "${PROG_HOME}/work"

		if [ ! -f "$flag_file" ]; then
			info "Initializing secure installation"
			"${PROG_HOME}/bin/appc" appmginit
			touch "$flag_file" && chmod 600 "$flag_file"
		fi
	fi
}

################################################################################
# Main Script Execution
################################################################################

check_dependencies
initialize_directory
prepare_app_start "$@"
secure_installation_check

info "Starting App Mesh service: $PROGRAM"
exec "$PROGRAM"
