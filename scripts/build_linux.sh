#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
cd "$ROOT_DIR"

VENV_PYTHON=".venv/bin/python"
LAUNCHER="cli.py"
DIST_DIR="dist"
APP_NAME="omni-scan"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "[!] Local Python virtual environment not found. Run ./install.sh first."
    exit 1
fi

echo "[*] Building standalone Linux binary with PyInstaller..."
"$VENV_PYTHON" -m pip install --upgrade pyinstaller

ARGS=(
    --onefile
    --windowed
    --name "$APP_NAME"
    --distpath "$DIST_DIR/linux"
    --workpath build/linux
    --specpath build/linux
    "$LAUNCHER"
)

"$VENV_PYTHON" -m PyInstaller "${ARGS[@]}"

if [ -f "$DIST_DIR/linux/$APP_NAME" ]; then
    chmod +x "$DIST_DIR/linux/$APP_NAME"
    echo "[+] Linux build complete: $DIST_DIR/linux/$APP_NAME"
else
    echo "[!] Linux build failed."
    exit 1
fi
