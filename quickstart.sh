#!/usr/bin/env bash
#
# quickstart.sh — AIIR Platform Quick Start
#
# One command to go from zero to a working AIIR platform.
# Runs setup-sift.sh with quick tier (includes CLI + client config).
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh | bash
#
set -euo pipefail

curl -sSL "https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/setup-sift.sh" \
    | bash -s -- --quick -y

echo ""
echo "Quick start complete. Restart your shell, then: aiir setup test"
echo ""
