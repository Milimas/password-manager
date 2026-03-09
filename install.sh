#!/usr/bin/env bash
# VaultC — install / update script
# Usage: ./install.sh [--prefix /usr]
set -euo pipefail

PREFIX="${1:-/usr}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$REPO_DIR/build-release"

echo "==> VaultC install script"
echo "    Repo   : $REPO_DIR"
echo "    Prefix : $PREFIX"
echo ""

# ── 1. Build ────────────────────────────────────────────────────────────────
echo "==> Configuring Release build..."
cmake -B "$BUILD_DIR" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$PREFIX" \
      -S "$REPO_DIR" \
      -Wno-dev \
      2>&1 | grep -E "(libcurl|libsodium|SQLite|GTK4|Configuring|error)" || true

echo "==> Building..."
cmake --build "$BUILD_DIR" -- -j"$(nproc)"

# ── 2. Run tests before installing ─────────────────────────────────────────
echo "==> Running test suite..."
if ! (cd "$BUILD_DIR" && ctest --output-on-failure -Q); then
    echo ""
    echo "ERROR: Tests failed — aborting install."
    echo "       Run 'cd $BUILD_DIR && ctest --output-on-failure' for details."
    exit 1
fi
echo "    All tests passed."

# ── 3. Install ──────────────────────────────────────────────────────────────
echo "==> Installing to $PREFIX (may require sudo)..."
sudo cmake --install "$BUILD_DIR" --prefix "$PREFIX"

# ── 4. Update system caches ─────────────────────────────────────────────────
echo "==> Updating system caches..."
sudo gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true
sudo update-desktop-database "$PREFIX/share/applications"        2>/dev/null || true
sudo update-mime-database "$PREFIX/share/mime"                   2>/dev/null || true

# ── 5. Verify ───────────────────────────────────────────────────────────────
INSTALLED="$PREFIX/bin/vaultc"
if [[ -x "$INSTALLED" ]]; then
    echo ""
    echo "✓ VaultC installed successfully → $INSTALLED"
else
    echo ""
    echo "WARNING: binary not found at $INSTALLED after install."
    exit 1
fi
