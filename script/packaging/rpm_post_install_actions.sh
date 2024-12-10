#!/usr/bin/env bash

################################################################################
## RPM/DEB post installation script file, executed during installation
################################################################################

# Default installation path
readonly DEFAULT_INSTALL_PATH="/opt/appmesh"
readonly FORBIDDEN_PATHS=("/bin", "/sbin", "/etc", "/lib", "/lib64", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/System", "/Library", "/Applications")
TARGET_INSTALL_PATH="$DEFAULT_INSTALL_PATH"

log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

function is_forbidden_path {
    local path="$1"
    for forbidden in "${FORBIDDEN_PATHS[@]}"; do
        if [[ "$path" == "/" ]]; then
            return 0 # true
        fi
        if [[ "$path" == "$forbidden" || "$path" == "$forbidden/"* ]]; then
            return 0 # true
        fi
    done
    return 1 # false
}

# Determine installation path
if [ -n "$PROMPT_INSTALL_PATH" ]; then
    if [ "$PROMPT_INSTALL_PATH" = "1" ]; then
        # Interactive prompt for custom installation directory
        read -p "Enter installation path [${DEFAULT_INSTALL_PATH}]: " USER_INPUT_PATH
        TARGET_INSTALL_PATH="${USER_INPUT_PATH:-$DEFAULT_INSTALL_PATH}"
    else
        # Use the provided value as the installation directory
        TARGET_INSTALL_PATH="$PROMPT_INSTALL_PATH"
    fi
fi
TARGET_INSTALL_PATH="$(realpath "$TARGET_INSTALL_PATH")"

if is_forbidden_path "$TARGET_INSTALL_PATH"; then
    echo "Error: Installation to $TARGET_INSTALL_PATH is not allowed. Please choose a different path."
    exit 1
fi

log "Installing to: $TARGET_INSTALL_PATH"

# Validate and resolve absolute paths for source and target directories
SOURCE_REALPATH=$(realpath "$DEFAULT_INSTALL_PATH")
TARGET_REALPATH=$(realpath "$TARGET_INSTALL_PATH")

# Check if target path already ends with "appmesh"
if [[ "$(basename "$TARGET_REALPATH")" != "appmesh" ]]; then
    TARGET_REALPATH="$TARGET_REALPATH/appmesh"
fi

# Ensure the parent directory of the target path exists
mkdir -p "$TARGET_REALPATH"

# Move source directory to target path if they differ
if [ "$SOURCE_REALPATH" != "$TARGET_REALPATH" ]; then
    log "Moving $SOURCE_REALPATH to $TARGET_REALPATH"
    cp -rf "$SOURCE_REALPATH"/* "$TARGET_REALPATH"/ || {
        log "Error: Failed to move $SOURCE_REALPATH to $TARGET_REALPATH."
        exit 1
    }
    rm -rf "$SOURCE_REALPATH"
    sed -i "s|/opt/appmesh|$TARGET_REALPATH|g" $TARGET_REALPATH/script/appmesh.systemd.service
fi

# Execute setup script
SETUP_SCRIPT="$TARGET_REALPATH/script/setup.sh"
log "Executing setup script: $SETUP_SCRIPT"
bash "$SETUP_SCRIPT"
