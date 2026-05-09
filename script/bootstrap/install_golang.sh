#!/bin/bash
set -e

GO_VER=1.25.10

if command -v go >/dev/null 2>&1 && go version | grep -q "go${GO_VER}"; then
    echo "Go already installed: $(go version)"
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
