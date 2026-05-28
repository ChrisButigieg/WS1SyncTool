#!/bin/bash
# WS1 UEM Sync Tool — start script

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Create venv if needed
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment…"
  python3 -m venv .venv
fi

source .venv/bin/activate

# Install deps
pip install -q -r requirements.txt

echo ""
echo "╔══════════════════════════════════════╗"
echo "║      WS1 UEM Sync Tool               ║"
echo "║  Open: http://localhost:5000         ║"
echo "╚══════════════════════════════════════╝"
echo ""

python app.py
