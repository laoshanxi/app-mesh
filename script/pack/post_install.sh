#!/usr/bin/env bash

################################################################################
## RPM/DEB/PKG Post-installation script
## Handles: Native Relocation (MacOS/RPM) and Manual Relocation (DEB)
################################################################################

set -u # Exit on undefined variables

# The fixed path where the package payload was originally built to go
readonly BUILT_IN_PREFIX="/opt/appmesh"

# Default target is the built-in prefix, unless detected otherwise
declare TARGET_INSTALL_PATH="$BUILT_IN_PREFIX"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
info() { log "INFO $@"; }
die() { log "ERROR $@" && exit 1; }

detect_os() {
    case "$(uname -s)" in
    Darwin*) echo "macos" ;;
    Linux*) echo "linux" ;;
    *) echo "unknown" ;;
    esac
}

# Cross-platform realpath function
get_realpath() {
    local path="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath "$path" 2>/dev/null || echo "$path"
    elif command -v readlink >/dev/null 2>&1; then
        local resolved
        resolved=$(readlink -f "$path" 2>/dev/null) && echo "$resolved" && return
        # Fallback for macOS
        if [[ "$(detect_os)" == "macos" ]]; then
            python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$path" 2>/dev/null || echo "$path"
        else
            echo "$path"
        fi
    else
        if [[ "$path" == /* ]]; then
            echo "$path"
        else
            echo "$(pwd)/$path"
        fi
    fi
}

# 1. Detect where the user/installer WANTS the files
determine_target_path() {
    local os_type
    os_type=$(detect_os)

    # PRIORITY 1: MacOS Native Installer Destination
    # The macOS installer passes the destination path as the $2 argument to this script
    if [[ "$os_type" == "macos" ]] && [[ -n "${2:-}" ]]; then
        TARGET_INSTALL_PATH="$2"
        info "MacOS Installer requested install to: $TARGET_INSTALL_PATH"
        return
    fi

    # PRIORITY 2: RPM Native Relocation
    # RPM sets RPM_INSTALL_PREFIX environment variable if --prefix or --relocate is used
    if [[ -n "${RPM_INSTALL_PREFIX:-}" ]]; then
        TARGET_INSTALL_PATH="$RPM_INSTALL_PREFIX"
        info "RPM Relocation detected at: $TARGET_INSTALL_PATH"
        return
    fi

    # PRIORITY 3: Manual Environment Variable (User Override)
    # Useful for DEB packages or manual script runs
    if [[ -n "${PROMPT_INSTALL_PATH:-}" ]] && [[ "$PROMPT_INSTALL_PATH" != "1" ]]; then
        TARGET_INSTALL_PATH="$PROMPT_INSTALL_PATH"
        info "Environment variable requested install to: $TARGET_INSTALL_PATH"
        return
    fi

    # PRIORITY 4: Interactive Prompt (Only if explicitly enabled)
    if [[ "${PROMPT_INSTALL_PATH:-}" == "1" ]]; then
        read -r -p "Enter installation path [${BUILT_IN_PREFIX}]: " USER_INPUT
        TARGET_INSTALL_PATH="${USER_INPUT:-$BUILT_IN_PREFIX}"
    fi
}

# 2. Handle the files (Move if necessary, or just verify)
finalize_files() {
    local os_type
    os_type=$(detect_os)

    # Normalize paths (remove trailing slashes)
    TARGET_INSTALL_PATH="${TARGET_INSTALL_PATH%/}"
    local built_in_normalized="${BUILT_IN_PREFIX%/}"

    # Resolve to absolute path
    TARGET_INSTALL_PATH=$(get_realpath "$TARGET_INSTALL_PATH")

    # Only append /appmesh if files don't exist at the target and we're doing manual relocation
    # Native relocation (RPM/MacOS) installs directly to the target path
    if [[ "$(basename "$TARGET_INSTALL_PATH")" != "appmesh" ]] && [[ ! -d "$TARGET_INSTALL_PATH/bin" ]]; then
        TARGET_INSTALL_PATH="$TARGET_INSTALL_PATH/appmesh"
    fi

    info "Finalizing installation at: $TARGET_INSTALL_PATH"

    # If target == built-in, nothing to relocate
    if [[ "$TARGET_INSTALL_PATH" == "$built_in_normalized" ]]; then
        info "Installing to default location, no relocation needed."
        return
    fi

    # CASE A: Native Relocation Happened (RPM/MacOS)
    # The files are ALREADY at $TARGET_INSTALL_PATH because the installer put them there.
    if [[ -d "$TARGET_INSTALL_PATH/bin" ]]; then
        info "Files found at target. Native relocation successful."
        # Clean up built-in path if it exists and is different
        if [[ -d "$built_in_normalized" ]] && [[ "$TARGET_INSTALL_PATH" != "$built_in_normalized" ]]; then
            info "Cleaning up original path: $built_in_normalized"
            rm -rf "$built_in_normalized"
        fi

    # CASE B: Manual Relocation Needed (DEB or Custom Move)
    # The files are at $BUILT_IN_PREFIX, but user wants them at $TARGET_INSTALL_PATH.
    elif [[ -d "$built_in_normalized/bin" ]]; then
        info "Moving files from $built_in_normalized to $TARGET_INSTALL_PATH"
        
        # Create target directory
        mkdir -p "$TARGET_INSTALL_PATH" || die "Failed to create directory: $TARGET_INSTALL_PATH"
        
        # Copy files then remove source (safer than mv for cross-filesystem)
        if [[ "$os_type" == "macos" ]]; then
            cp -R "$built_in_normalized"/* "$TARGET_INSTALL_PATH"/ || die "Failed to copy files"
        else
            cp -rf "$built_in_normalized"/* "$TARGET_INSTALL_PATH"/ || die "Failed to copy files"
        fi
        rm -rf "$built_in_normalized"
    else
        die "Cannot find installation files at $TARGET_INSTALL_PATH or $built_in_normalized"
    fi

    # Update Service Files with the REAL path
    update_service_paths "$TARGET_INSTALL_PATH"
}

update_service_paths() {
    local install_path="$1"
    local os_type
    os_type=$(detect_os)

    info "Updating service configuration paths..."

    if [[ "$os_type" == "macos" ]]; then
        local plist="$install_path/script/appmesh.launchd.plist"
        if [[ -f "$plist" ]]; then
            info "Patching macOS plist: $plist"
            # Use | as delimiter to avoid escaping issues with paths
            sed -i '' "s|/opt/appmesh|$install_path|g" "$plist" || die "Failed to update plist: $plist"
        fi
    else
        local service="$install_path/script/appmesh.systemd.service"
        if [[ -f "$service" ]]; then
            info "Patching systemd service: $service"
            # Use | as delimiter to avoid escaping issues with paths
            sed -i "s|/opt/appmesh|$install_path|g" "$service" || die "Failed to update service: $service"
        fi
    fi
}

run_setup() {
    local setup_script="$TARGET_INSTALL_PATH/script/setup.sh"
    if [[ -f "$setup_script" ]]; then
        info "Executing setup script: $setup_script"
        if [[ -x /usr/bin/bash ]]; then
            /usr/bin/bash "$setup_script"
        elif [[ -x /bin/bash ]]; then
            /bin/bash "$setup_script"
        else
            bash "$setup_script"
        fi
    else
        info "Setup script not found at $setup_script, skipping."
    fi
}

main() {
    info "Starting post installation"
    determine_target_path "$@"
    finalize_files
    run_setup
    info "Post-install complete."
}

# Execute main function
main "$@"
