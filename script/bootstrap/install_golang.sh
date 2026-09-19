#!/bin/bash
set -e

GO_VER=1.27.1

# keep a system Go that is newer than (or equal to) the pinned version
installed_ver=$(go version 2>/dev/null | sed -n 's/.*go\([0-9]*\.[0-9]*\(\.[0-9]*\)\{0,1\}\).*/\1/p')
if [ -n "$installed_ver" ] && [ "$installed_ver" = "$(printf '%s\n' "$GO_VER" "$installed_ver" | sort -V | tail -1)" ]; then
    echo "Go already installed (>= ${GO_VER}): $(go version)"
    exit 0
fi

GO_ARCH=$(uname -m)
case "$GO_ARCH" in
    x86_64)  GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    armv7l)  GO_ARCH="armv6l" ;;
    *)       echo "Unsupported architecture: $GO_ARCH" >&2; exit 1 ;;
esac

wget -q --no-check-certificate "https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm -f /tmp/go.tar.gz
ln -sf /usr/local/go/bin/go /usr/bin/go
echo "Go installed: $(go version)"
