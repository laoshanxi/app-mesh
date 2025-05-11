#!/bin/bash

set -euo pipefail

# Configuration
readonly SCAN_DIR="nfpm_home/lib64"
readonly OUTPUT_DIR="nfpm_home"
readonly PACKAGE_LIST_FILE="dependency_list.txt"
readonly DPKG_STATUS_FILE="/var/lib/dpkg/status"
readonly DPKG_INFO_DIR="/var/lib/dpkg/info"
readonly TEMP_STATUS_FILE=$(mktemp)

cleanup() {
    rm -f "$TEMP_STATUS_FILE"
}
trap cleanup EXIT

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Find executable files and shared libraries
find_binaries() {
    local scan_dir="$1"
    local -a binaries=()

    [[ -d "$scan_dir" ]] || error_exit "Directory $scan_dir does not exist"

    log "Scanning directory: $scan_dir"

    while IFS= read -r -d '' file; do
        if [[ -x "$file" || "$file" == *.so* ]]; then
            binaries+=("$(basename "$file")")
        fi
    done < <(find "$scan_dir" -type f -print0)

    [[ ${#binaries[@]} -gt 0 ]] || error_exit "No binaries found in $scan_dir"

    log "Found ${#binaries[@]} binaries"
    printf '%s\n' "${binaries[@]}"
}

# Find package for a single binary using multiple methods
find_package_for_binary() {
    local binary="$1"
    local package=""

    # Try exact filename match
    package=$(dpkg -S "$binary" 2>/dev/null | head -1 | cut -d: -f1 || true)

    # Try wildcard pattern if exact match failed
    if [[ -z "$package" ]]; then
        package=$(dpkg -S "*/$binary" 2>/dev/null | head -1 | cut -d: -f1 || true)
    fi

    # Try finding full path then package lookup
    if [[ -z "$package" ]]; then
        local full_path
        full_path=$(which "$binary" 2>/dev/null || true)
        if [[ -n "$full_path" ]]; then
            package=$(dpkg -S "$full_path" 2>/dev/null | head -1 | cut -d: -f1 || true)
        fi
    fi

    echo "$package"
}

# Find packages for all binaries
find_packages() {
    local -a binaries=("$@")
    local -a packages=()
    local package

    log "Looking up packages for ${#binaries[@]} binaries..."

    for binary in "${binaries[@]}"; do
        package=$(find_package_for_binary "$binary")

        if [[ -n "$package" ]]; then
            packages+=("$package")
            log "Found package for $binary: $package"
        else
            log "Warning: No package found for binary: $binary"
        fi
    done

    [[ ${#packages[@]} -gt 0 ]] || error_exit "No packages found for any binaries"

    printf '%s\n' "${packages[@]}"
}

# Create deduplicated package list
create_package_list() {
    local -a packages=("$@")
    local -a dedup_packages

    log "Creating deduplicated package list..."
    readarray -t dedup_packages < <(printf '%s\n' "${packages[@]}" | sort -u)

    printf '%s\n' "${dedup_packages[@]}" >"$PACKAGE_LIST_FILE"
    log "Wrote ${#dedup_packages[@]} packages to $PACKAGE_LIST_FILE"
}

# Update dpkg database
update_dpkg_database() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    log "Filtering dpkg database..."
    if ! python3 "$script_dir/syft_dpkg_filter.py" "$DPKG_STATUS_FILE" "$TEMP_STATUS_FILE" "$PACKAGE_LIST_FILE"; then
        error_exit "Failed to filter dpkg database"
    fi

    # Prepare target directory structure
    mkdir -p "$OUTPUT_DIR/var/lib/dpkg"

    # Copy dpkg structure and update status file
    cp -rf --parents /var/lib/dpkg "$OUTPUT_DIR/" || true
    if ! cp "$TEMP_STATUS_FILE" "$OUTPUT_DIR/var/lib/dpkg/status"; then
        error_exit "Failed to update status file"
    fi

    log "Updated dpkg status file"
}

# Copy package info files
copy_package_info() {
    local target_info_dir="$OUTPUT_DIR/var/lib/dpkg/info"

    log "Setting up package info directory..."
    rm -rf "$target_info_dir"
    mkdir -p "$target_info_dir"

    log "Copying package info files..."
    while IFS= read -r package; do
        if compgen -G "$DPKG_INFO_DIR/${package}*" >/dev/null 2>&1; then
            cp "$DPKG_INFO_DIR/${package}"* "$target_info_dir/"
            log "Copied info for package: $package"
        else
            log "Warning: No info files found for package: $package"
        fi
    done <"$PACKAGE_LIST_FILE"

    log "Package info setup completed"
}

# Main execution
main() {
    log "Starting dependency extraction process..."

    # Find binaries in the scan directory
    readarray -t binaries < <(find_binaries "$SCAN_DIR")

    # Find packages for the binaries
    readarray -t packages < <(find_packages "${binaries[@]}")

    # Create deduplicated package list
    create_package_list "${packages[@]}"

    # Update dpkg database
    update_dpkg_database

    # Copy package info files
    copy_package_info

    log "Process completed successfully"
}

# Run main function
main "$@"
