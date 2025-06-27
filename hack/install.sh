#!/usr/bin/env sh
set -e

info()    { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
success() { printf "\033[1;32m[SUCCESS]\033[0m %s\n" "$*"; }
warn()    { printf "\033[1;33m[WARN]\033[0m %s\n" "$*" >&2; }
error()   { printf "\033[1;31m[ERROR]\033[0m %s\n" "$*" >&2; exit 1; }

TAR_FILE="cozypkg-linux-amd64.tar.gz"

info "Installing quantumpkg"
info "Downloading TAR_FILE..."

# wget -O "$TAR_FILE" "https://gitverse.ru/api/attachments/cc46a633-32f0-4d46-9e38-d7c6077348dd" || error "Failed to download $TAR_FILE"
wget -O "$TAR_FILE" "https://github.com/cozystack/cozypkg/releases/download/v1.1.0/cozypkg-linux-amd64.tar.gz" || error "Failed to download $TAR_FILE"

info "Extracting..."
tar -xzf "$TAR_FILE"
mv "cozypkg" "quantumpkg"
chmod +x "quantumpkg"

mv "quantumpkg" "/usr/local/bin/quantumpkg"

success "quantumpkg installed successfully"
info "Run 'quantumpkg --help' to get started."
