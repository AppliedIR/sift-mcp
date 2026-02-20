#!/usr/bin/env bash
#
# setup.sh - Setup sift-mcp for standalone use
#
# Usage: ./setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Setting up sift-mcp..."

# Check Python version
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
required="3.10"
if [ "$(printf '%s\n' "$required" "$python_version" | sort -V | head -n1)" != "$required" ]; then
    echo "Error: Python 3.10+ required (found $python_version)"
    exit 1
fi

# Create virtual environment
if [[ ! -d ".venv" ]]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
else
    echo "Virtual environment exists."
fi

# Install dependencies
echo "Installing dependencies..."
.venv/bin/pip install --upgrade pip || { echo "Error: pip upgrade failed"; exit 1; }
.venv/bin/pip install -e . || { echo "Error: dependency installation failed"; exit 1; }

# Verify installation
echo "Verifying installation..."
.venv/bin/python -c "from sift_mcp.server import create_server; print('OK')"

echo ""
echo "Setup complete!"
echo "Add this server to your MCP client configuration."
echo "See README.md for configuration details."
