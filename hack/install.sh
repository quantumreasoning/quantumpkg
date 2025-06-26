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


TAR_FILE="quantumpkg-linux-amd64.tar.gz"



TMPDIR=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

info "Installing quantumpkg"
info "Downloading $TAR_FILE..."

download "$TMPDIR/$TAR_FILE" "https://gitverse.ru/api/attachments/cc46a633-32f0-4d46-9e38-d7c6077348dd" || error "Failed to download $TAR_FILE"


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
