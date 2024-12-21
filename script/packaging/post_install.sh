#!/usr/bin/env bash

################################################################################
## RPM/DEB post installation script file, executed during installation
################################################################################

set -u # Exit on undefined variables

readonly DEFAULT_INSTALL_PATH="/opt/appmesh"
readonly FORBIDDEN_PATHS=("/bin" "/sbin" "/etc" "/lib" "/lib32" "/lib64" "/usr" "/var" "/boot" "/root" "/media" "/tmp" "/proc" "/sys" "/dev" "/System" "/Library" "/Applications" "/Volumes" "/Network" "/lost+found")
declare TARGET_INSTALL_PATH="$DEFAULT_INSTALL_PATH"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
error() { log "ERROR $@"; }
die() { error "$@" && exit 1; }

is_valid_path() {
    # Resolve the real path
    local path=$(realpath "$1")

    # Ensure path is directory
    if [[ ! -d "$path" ]]; then
        return 1
    fi

    # Root path check
    if [[ "$path" == "/" ]]; then
        return 1
    fi

    for forbidden in "${FORBIDDEN_PATHS[@]}"; do
        if [[ "$path" == "$forbidden" || "$path" == "$forbidden/"* ]]; then
            return 1
        fi
    done

    return 0
}

validate_install_path() {
    local install_path=$(realpath "$1")

    # Empty path check
    if [[ -z "$install_path" ]]; then
        die "Installation path cannot be empty"
    fi

    # Forbidden path check
    if ! is_valid_path "$install_path"; then
        die "Installation to $install_path is not allowed. Please choose a different path"
    fi

    # Writable path check
    if ! [[ -w "$(dirname "$install_path")" ]]; then
        die "Directory $(dirname "$install_path") is not writable"
    fi
}

process_installation_path() {
    if [[ -n "${PROMPT_INSTALL_PATH:-}" ]]; then
        if [[ "$PROMPT_INSTALL_PATH" == "1" ]]; then
            # Interactive prompt for custom installation directory
            read -r -p "Enter installation path [${DEFAULT_INSTALL_PATH}]: " USER_INPUT_PATH
            TARGET_INSTALL_PATH="${USER_INPUT_PATH:-$DEFAULT_INSTALL_PATH}"
        else
            # Use the provided value as the installation directory
            TARGET_INSTALL_PATH="$PROMPT_INSTALL_PATH"
        fi
    fi

    TARGET_INSTALL_PATH="$(realpath "$TARGET_INSTALL_PATH")"
    validate_install_path "$TARGET_INSTALL_PATH"
}

setup_installation() {
    local source_path=$(realpath "$DEFAULT_INSTALL_PATH")
    local target_path="$TARGET_INSTALL_PATH"

    # Ensure target path ends with "appmesh"
    [[ "$(basename "$target_path")" != "appmesh" ]] && target_path="$target_path/appmesh"

    # Create target directory
    mkdir -p "$target_path" || die "Failed to create directory: $target_path"
    info "Installing to: $target_path"

    # Copy files if paths differ
    if [[ "$source_path" != "$target_path" ]]; then
        info "Moving files from $source_path to $target_path"
        cp -rf "$source_path"/* "$target_path"/ || die "Failed to copy files from $source_path to $target_path"
        rm -rf "$source_path"

        # Update systemd service file
        local service_file="$target_path/script/appmesh.systemd.service"
        sed -i "s|/opt/appmesh|$target_path|g" "$service_file" || die "Failed to update service file: $service_file"
    fi
}

run_setup_script() {
    local setup_script="$TARGET_INSTALL_PATH/script/setup.sh"
    info "Executing setup script: $setup_script"
    bash "$setup_script"
}

################################################################################
# Main Function
################################################################################
main() {
    info "Starting post installation"

    # Read and validate installation path
    process_installation_path

    # Install to target path
    setup_installation

    # Run setup.sh
    run_setup_script
}

# Execute main function
main
