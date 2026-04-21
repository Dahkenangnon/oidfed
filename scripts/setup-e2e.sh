#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/.certs"
CERT_FILE="$CERT_DIR/ofed.pem"
KEY_FILE="$CERT_DIR/ofed-key.pem"

# Skip if certs already exist
if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
  echo "E2E certificates already exist in $CERT_DIR — skipping."
  echo "To regenerate, delete .certs/ and re-run this script."
  exit 0
fi

# 1. Check for mkcert
if ! command -v mkcert &>/dev/null; then
  echo "mkcert is not installed."
  echo ""
  echo "Install it for your platform:"
  echo "  macOS:         brew install mkcert"
  echo "  Ubuntu/Debian: sudo apt-get install mkcert libnss3-tools"
  echo "  Fedora:        sudo dnf install mkcert nss-tools"
  echo "  Arch:          sudo pacman -S mkcert nss"
  echo "  Other:         https://github.com/FiloSottile/mkcert#installation"
  echo ""
  echo "Note: libnss3-tools (or nss-tools) is needed for Firefox to trust the CA."
  exit 1
fi

# 2. Install local CA
mkcert -install

# 3. Generate certificates
mkdir -p "$CERT_DIR"
mkcert \
  -cert-file "$CERT_FILE" \
  -key-file "$KEY_FILE" \
  "*.ofed.test" localhost 127.0.0.1 ::1

# 4. Write CA root path
mkcert -CAROOT > "$CERT_DIR/ca-path.txt"

# 5. Add .certs/ to .gitignore if not present
GITIGNORE="$(cd "$(dirname "$0")/.." && pwd)/.gitignore"
if ! grep -qxF '.certs/' "$GITIGNORE" 2>/dev/null; then
  echo '.certs/' >> "$GITIGNORE"
fi

echo ""
echo "E2E certificates generated in $CERT_DIR"
echo "CA root: $(cat "$CERT_DIR/ca-path.txt")"
