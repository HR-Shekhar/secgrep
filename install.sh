#!/usr/bin/env bash
# Install the latest secgrep release binary for macOS or Linux.
# Usage:
#   curl -sSL https://raw.githubusercontent.com/HR-Shekhar/secgrep/main/install.sh | bash
set -e

REPO="HR-Shekhar/secgrep"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64)
        PLATFORM="linux-x86_64"
        ;;
      *)
        echo "error: unsupported Linux CPU '${ARCH}'. Only x86_64 is published."
        echo "Build from source: cargo install --git https://github.com/${REPO}.git"
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64)
        PLATFORM="darwin-arm64"
        ;;
      *)
        PLATFORM="darwin-x86_64"
        ;;
    esac
    ;;
  *)
    echo "error: this installer supports macOS and Linux only."
    echo "On Windows, download secgrep-windows-x86_64.exe from:"
    echo "  https://github.com/${REPO}/releases/latest"
    exit 1
    ;;
esac

ASSET="secgrep-${PLATFORM}"
TMP="$(mktemp)"
echo "Downloading ${ASSET}..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "$TMP"
chmod +x "$TMP"

if [ "$OS" = "Darwin" ]; then
  # Unsigned binary may be quarantined after download.
  xattr -d com.apple.quarantine "$TMP" 2>/dev/null || true
fi

echo "Installing to /usr/local/bin/secgrep (may ask for your password)..."
sudo mv "$TMP" /usr/local/bin/secgrep

echo ""
echo "Installed secgrep successfully."
echo "Try it: secgrep scan ."
echo "Help:   secgrep --help"
