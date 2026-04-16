#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Installing pip dependencies..."
pip install -r "$SCRIPT_DIR/requirements.txt"

echo "[*] Installing r2flutch agent dependencies..."
(cd "$SCRIPT_DIR/r2flutch/agent" && npm install)

echo "[*] Building r2flutch agent..."
(cd "$SCRIPT_DIR/r2flutch/agent" && npm run build)

echo "[*] Installing r2flutch package..."
pip install "$SCRIPT_DIR"

echo "[✓] Installation complete. Run 'r2flutch -h' to get started."
