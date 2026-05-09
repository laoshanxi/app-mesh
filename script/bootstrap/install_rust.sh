#!/bin/bash
set -e

if command -v cargo >/dev/null 2>&1; then
    rustup update stable
    echo "Rust already installed: $(rustc --version)"
    exit 0
fi

# Rust needs a C linker (cc/gcc) to link compiled crates
if ! command -v cc >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y gcc
    elif command -v yum >/dev/null 2>&1; then
        yum install -y gcc
    fi
fi

RUST_ARCH=$(uname -m)
case "$RUST_ARCH" in
    x86_64)  RUST_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64) RUST_ARCH="aarch64-unknown-linux-gnu" ;;
    armv7l)  RUST_ARCH="armv7-unknown-linux-gnueabihf" ;;
    *)       echo "Unsupported architecture: $RUST_ARCH" >&2; exit 1 ;;
esac

wget -q --no-check-certificate -O /tmp/rustup-init "https://static.rust-lang.org/rustup/dist/${RUST_ARCH}/rustup-init"
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --default-toolchain stable --no-modify-path
rm -f /tmp/rustup-init
export PATH="$HOME/.cargo/bin:$PATH"
ln -sf "$HOME/.cargo/bin/rustc" /usr/local/bin/rustc
ln -sf "$HOME/.cargo/bin/cargo" /usr/local/bin/cargo
ln -sf "$HOME/.cargo/bin/rustup" /usr/local/bin/rustup
echo "Rust installed: $(rustc --version)"
