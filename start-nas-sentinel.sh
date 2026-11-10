#!/usr/bin/env bash
# NAS Sentinel One-Click Launcher for Linux / macOS
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/nas-sentinel"

echo "============================================================"
echo "  Starting NAS Sentinel Server (Linux / macOS)..."
echo "  Dashboard URL: http://127.0.0.1:8088"
echo "  API token: printed below / written to data/api_token.txt"
echo "  Paste the token in the browser auth gate (Bearer auth)."
echo "============================================================"

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Please install Python 3.8+."
    exit 1
fi

# Launch server
python3 server.py &
SERVER_PID=$!
echo "[OK] Server started in background (PID: $SERVER_PID)"
echo "To stop: kill $SERVER_PID"

# Open browser if possible
sleep 1
if command -v xdg-open &>/dev/null; then
    xdg-open "http://127.0.0.1:8088" &>/dev/null || true
elif command -v open &>/dev/null; then
    open "http://127.0.0.1:8088" &>/dev/null || true
fi
