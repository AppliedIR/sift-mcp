#!/usr/bin/env bash
#
# quickstart.sh — AIIR Platform Quick Start
#
# Downloads and runs both installers: sift-install.sh (quick tier) + aiir-install.sh.
# One command to go from zero to a working AIIR platform.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh | bash
#
set -euo pipefail

BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR — Quick Start${NC}"
echo -e "${BOLD}  Applied Incident Investigation and Response${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

SIFT_URL="https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/sift-install.sh"
AIIR_URL="https://raw.githubusercontent.com/AppliedIR/aiir/main/aiir-install.sh"

echo "This will install the AIIR platform (quick tier) and the aiir CLI."
echo ""

# Step 1: SIFT platform (quick tier, non-interactive)
echo -e "${BOLD}--- Step 1: SIFT Platform ---${NC}"
echo ""
curl -sSL "$SIFT_URL" | bash -s -- --quick -y

# Step 2: aiir CLI (non-interactive — stdin is the curl pipe, not a terminal)
echo ""
echo -e "${BOLD}--- Step 2: aiir CLI ---${NC}"
echo ""
curl -sSL "$AIIR_URL" | bash -s -- -y

echo ""
echo -e "${BOLD}Quick start complete.${NC}"
echo ""
echo "Gateway:  http://127.0.0.1:4508"
echo ""
echo "Next steps:"
echo "  1. Restart your shell (or: source ~/.bashrc)"
echo "  2. Configure your LLM client:   aiir setup client"
echo "  3. Verify installation:          aiir setup test"
echo ""
echo "Examiner identity was set to your OS username during install."
echo "To change it:  aiir config --examiner <name>"
echo ""
