#!/usr/bin/env bash
#
# quickstart.sh — AIIR Platform Quick Start
#
# One command to go from zero to a working AIIR platform.
# Downloads setup-sift.sh and runs it with quick tier. Prompts for
# examiner identity and LLM client selection.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh -o /tmp/aiir-quickstart.sh && bash /tmp/aiir-quickstart.sh
#
set -euo pipefail

SETUP_SCRIPT=$(mktemp /tmp/aiir-setup-XXXXXX.sh)
trap 'rm -f "$SETUP_SCRIPT"' EXIT

curl -sSL "https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/setup-sift.sh" \
    -o "$SETUP_SCRIPT"

bash "$SETUP_SCRIPT" --quick "$@"

echo ""
echo "Quick start complete. Restart your shell, then: aiir setup test"
echo ""
