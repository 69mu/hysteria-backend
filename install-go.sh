#!/bin/bash
set -euo pipefail

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  GOARCH="amd64" ;;
  aarch64) GOARCH="arm64" ;;
  armv6l)  GOARCH="armv6l" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Fetching latest Go version..."
LATEST=$(curl -fsSL https://go.dev/VERSION?m=text | head -1)
echo "Latest version: $LATEST"

TARBALL="${LATEST}.linux-${GOARCH}.tar.gz"
URL="https://go.dev/dl/${TARBALL}"

echo "Downloading $URL ..."
curl -fsSL -o "/tmp/${TARBALL}" "$URL"

echo "Installing to /usr/local/go ..."
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "/tmp/${TARBALL}"
rm -f "/tmp/${TARBALL}"

# Add to PATH in ~/.bashrc if not already present.
if ! grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null; then
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  echo "Added /usr/local/go/bin to ~/.bashrc"
else
  echo "/usr/local/go/bin already in ~/.bashrc"
fi

export PATH=$PATH:/usr/local/go/bin
echo "Installed: $(go version)"
