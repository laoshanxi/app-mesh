#!/usr/bin/env bash
################################################################################
# OpenSSL Installation & Upgrade Script
# Supported distributions: SUSE, CentOS, Ubuntu, RHEL
# Purpose: Production-grade OpenSSL deployment with security considerations
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Configuration
OPENSSL_VERSION="3.0.15"
OPENSSL_INSTALL_DIR="/usr/local/ssl"
OPENSSL_SOURCE="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_SHA256="23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533"

# Logging setup
log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

error() {
  log "ERROR: $*" >&2
  exit 1
}

check_prerequisites() {
  local missing_deps=()
  for cmd in wget tar make gcc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_deps+=("$cmd")
    fi
  done

  if ((${#missing_deps[@]} > 0)); then
    log "Missing required tools: ${missing_deps[*]}"
    install_dependencies
  fi
}

install_dependencies() {
  if command -v zypper >/dev/null 2>&1; then
    # SUSE
    log "Installing dependencies using zypper..."
    zypper --non-interactive install gcc make wget tar zlib-devel perl-core
  elif command -v yum >/dev/null 2>&1; then
    # CentOS/RHEL
    rhel_version=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/')
    if [[ $rhel_version = "7" ]]; then
      cp -a /etc/yum.repos.d /etc/yum.repos.d.backup
      rm -f /etc/yum.repos.d/*.repo
      curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
      yum clean all
      yum makecache
    fi
    if [[ $rhel_version = "8" ]]; then
      sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-*
      sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
    fi
    log "Installing dependencies using yum..."
    yum install -y gcc make wget tar zlib-devel perl-core
  elif command -v apt-get >/dev/null 2>&1; then
    # Ubuntu/Debian
    log "Installing dependencies using apt..."
    apt-get update
    apt-get install -y gcc make wget tar zlib1g-dev perl
  else
    error "Unsupported package manager. Please install dependencies manually."
  fi
}

verify_current_version() {
  if command -v openssl >/dev/null 2>&1; then
    local current_version
    current_version=$(openssl version | cut -d' ' -f2)
    log "Current OpenSSL version: $current_version"
    log "Target OpenSSL version: $OPENSSL_VERSION"
  fi
}

backup_existing_openssl() {
  if [ -f "/usr/bin/openssl" ]; then
    log "Backing up existing OpenSSL binary..."
    mv "/usr/bin/openssl" "/usr/bin/openssl.bak.$(date +%Y%m%d)"
  fi
}

download_and_verify_openssl() {
  local tempdir
  tempdir=$(mktemp -d)
  cd "$tempdir"

  log "Downloading OpenSSL ${OPENSSL_VERSION}..."
  wget --quiet --backups=1 --tries=5 --no-check-certificate "$OPENSSL_SOURCE" || error "Failed to download OpenSSL"

  log "Verifying download integrity..."
  echo "$OPENSSL_SHA256 openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c || error "SHA256 verification failed"

  tar xzf "openssl-${OPENSSL_VERSION}.tar.gz" >/dev/null
  cd "openssl-${OPENSSL_VERSION}"
}

compile_and_install_openssl() {
  log "Configuring OpenSSL..."
  ./config --prefix="$OPENSSL_INSTALL_DIR" \
    --openssldir="$OPENSSL_INSTALL_DIR" \
    --libdir=lib \
    shared \
    zlib \
    enable-fips \
    -Wl,-rpath,"$OPENSSL_INSTALL_DIR/lib" ||
    error "Configuration failed"

  log "Compiling OpenSSL..."
  make -j"$(($(nproc) / 2))" >/dev/null || error "Compilation failed"

  # log "Running tests..."
  # make test || error "Tests failed"

  log "Installing OpenSSL..."
  make install_sw >/dev/null || error "Installation failed"
}

setup_system_links() {
  log "Setting up system links and configurations..."

  # Create symbolic links
  ln -sf "$OPENSSL_INSTALL_DIR/bin/openssl" "/usr/bin/openssl"

  # Setup library paths
  echo "$OPENSSL_INSTALL_DIR/lib" >"/etc/ld.so.conf.d/openssl.conf"
  ldconfig

  # Verify installation
  log "Verifying installation..."
  "$OPENSSL_INSTALL_DIR/bin/openssl" version -a || error "Installation verification failed"
}

cleanup_temp_files() {
  if [ -n "${tempdir:-}" ]; then
    log "Cleaning up temporary files..."
    rm -rf "$tempdir"
  fi
}

main() {
  log "Starting OpenSSL installation process..."

  check_prerequisites
  verify_current_version
  backup_existing_openssl
  download_and_verify_openssl
  compile_and_install_openssl
  setup_system_links
  cleanup_temp_files

  log "OpenSSL $OPENSSL_VERSION installation completed successfully"
}

trap cleanup_temp_files EXIT
main "$@"
