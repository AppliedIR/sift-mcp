#!/usr/bin/env bash
#
# quickstart.sh — Valhuntir Platform Quick Start
#
# One command to go from zero to a working Valhuntir platform.
# Auto-selects quick tier. Prompts for examiner identity and LLM client.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh -o /tmp/vhir-quickstart.sh && bash /tmp/vhir-quickstart.sh
#
set -euo pipefail

SETUP_SCRIPT=$(mktemp /tmp/vhir-setup-XXXXXX.sh)
trap 'rm -f "$SETUP_SCRIPT"' EXIT

curl -fsSL "https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/setup-sift.sh" \
    -o "$SETUP_SCRIPT"

bash "$SETUP_SCRIPT" --quick "$@"
