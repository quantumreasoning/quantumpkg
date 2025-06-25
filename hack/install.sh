#!/usr/bin/env sh
set -e

info()    { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
success() { printf "\033[1;32m[SUCCESS]\033[0m %s\n" "$*"; }
warn()    { printf "\033[1;33m[WARN]\033[0m %s\n" "$*" >&2; }
error()   { printf "\033[1;31m[ERROR]\033[0m %s\n" "$*" >&2; exit 1; }

# ----------------------
# Argument parsing
# ----------------------
VERSION="latest"

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -v, --version VERSION   Install specific release (e.g. 1.4.0 or v1.4.0).
  -h, --help              Show this help and exit.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -v|--version)
      [ -n "$2" ] || { error "--version requires an argument"; }
      VERSION="$2"; shift 2 ;;
    --version=*)
      VERSION="${1#*=}"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    --) shift; break ;;
    *)
      error "Unknown option: $1" ;;
  esac
done

# Normalize tag: prepend 'v' if user omitted it
if [ "$VERSION" != "latest" ]; then
  case "$VERSION" in
    v*) TAG="$VERSION" ;;
    *)  TAG="v$VERSION" ;;
  esac
else
  TAG="latest"
fi

# ----------------------
# Prerequisite commands
# ----------------------
for cmd in uname mktemp tar sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || error "Required command '$cmd' not found."
done

# Detect download tool
if command -v curl >/dev/null 2>&1; then
  download() { curl -fsSL -o "$1" "$2"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget -qO "$1" "$2"; }
else
  error "Neither curl nor wget is available."
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  i386|i686) ARCH="i386" ;;
  *) error "Unsupported architecture: $ARCH" ;;
esac

TAR_FILE="quantumpkg-$OS-$ARCH.tar.gz"
CHECKSUM_FILE="quantumpkg-checksums.txt"

if [ "$TAG" = "latest" ]; then
  BASE_URL="https://github.com/quantumreasoning/quantumpkg/releases/latest/download"
else
  BASE_URL="https://github.com/quantumreasoning/quantumpkg/releases/download/$TAG"
fi

TMPDIR=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

info "Installing quantumpkg version: $TAG"
info "Downloading $TAR_FILE..."

download "$TMPDIR/$TAR_FILE" "https://gitverse.ru/api/attachments/cc46a633-32f0-4d46-9e38-d7c6077348dd" || error "Failed to download $TAR_FILE"

info "Downloading checksums..."
download "$TMPDIR/$CHECKSUM_FILE" "$BASE_URL/$CHECKSUM_FILE" || error "Failed to download $CHECKSUM_FILE"

EXPECTED_SUM=$(grep "  $TAR_FILE" "$TMPDIR/$CHECKSUM_FILE" | awk '{print $1}')
[ -n "$EXPECTED_SUM" ] || error "Checksum not found for $TAR_FILE"

ACTUAL_SUM=$(sha256sum "$TMPDIR/$TAR_FILE" | awk '{print $1}')

if [ "$EXPECTED_SUM" != "$ACTUAL_SUM" ]; then
  error "Checksum verification failed!\nExpected: $EXPECTED_SUM\nActual:   $ACTUAL_SUM"
fi

success "Checksum verified."

info "Extracting..."
tar -xzf "$TMPDIR/$TAR_FILE" -C "$TMPDIR"

[ -f "$TMPDIR/quantumpkg" ] || error "Binary 'quantumpkg' not found in archive."

chmod +x "$TMPDIR/quantumpkg"

# Determine install dir
if [ "$(id -u)" = "0" ] || [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not in your PATH." ;;
  esac
fi

INSTALL_PATH="$INSTALL_DIR/quantumpkg"

mv "$TMPDIR/quantumpkg" "$INSTALL_PATH"

success "quantumpkg installed successfully at $INSTALL_PATH"
info "Run 'quantumpkg --help' to get started."
