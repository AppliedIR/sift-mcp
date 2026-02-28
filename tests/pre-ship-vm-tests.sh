#!/usr/bin/env bash
# Pre-ship VM tests for forensic controls scoping fix
# Run on SIFT VM with gateway running and Claude Code installed
#
# Tests:
#   1. Does Claude Code preserve pre-existing ~/.claude.json on startup?
#   2. Does "type": "http" work in ~/.claude.json global mcpServers?
#   3. Does "type": "streamable-http" work in ~/.claude.json global mcpServers?
#
# Usage: bash pre-ship-vm-tests.sh

set -euo pipefail

CLAUDE_JSON="$HOME/.claude.json"
BACKUP="$HOME/.claude.json.pre-ship-backup"
GATEWAY_YAML="$HOME/.aiir/gateway.yaml"
RESULTS=()

# --- Helpers ---

pass() { RESULTS+=("PASS: $1"); echo "  ✓ PASS: $1"; }
fail() { RESULTS+=("FAIL: $1"); echo "  ✗ FAIL: $1"; }
info() { echo "  → $1"; }

add_mcp_entry() {
    local name="$1" type="$2" token="$3"
    python3 << PYEOF
import json
p = "$CLAUDE_JSON"
try:
    with open(p) as f: data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}
data.setdefault("mcpServers", {})["$name"] = {
    "type": "$type",
    "url": "http://localhost:4508/mcp/forensic-mcp",
    "headers": {"Authorization": "Bearer $token"}
}
with open(p, "w") as f: json.dump(data, f, indent=2)
PYEOF
}

remove_mcp_entry() {
    local name="$1"
    python3 << PYEOF
import json
p = "$CLAUDE_JSON"
with open(p) as f: data = json.load(f)
data.get("mcpServers", {}).pop("$name", None)
with open(p, "w") as f: json.dump(data, f, indent=2)
PYEOF
}

entry_exists() {
    local name="$1"
    python3 -c "
import json
with open('$CLAUDE_JSON') as f: data = json.load(f)
entry = data.get('mcpServers', {}).get('$name')
if entry:
    print('EXISTS')
    print(f'  type: {entry.get(\"type\")}')
    print(f'  url: {entry.get(\"url\")}')
else:
    print('MISSING')
"
}

check_mcp_connects() {
    local name="$1"
    info "Launching Claude Code from /tmp to test MCP connection..."
    info "Asking Claude to call forensic-mcp tools via entry '$name'"

    local output
    output=$(cd /tmp && claude -p \
        "Check if you have an MCP server named '$name' available. Try to call get_investigation_status or list tools from it. Report: CONNECTED if it works, FAILED if it doesn't. Be brief — one word answer with any error." \
        2>&1) || true

    echo "  Claude response: $output"

    if echo "$output" | grep -qi "CONNECTED\|available\|tools\|status\|investigation"; then
        return 0
    else
        return 1
    fi
}

# --- Pre-flight ---

echo ""
echo "=== Pre-ship VM Tests ==="
echo ""

if ! command -v claude &>/dev/null; then
    echo "ERROR: claude not on PATH. Install Claude Code first."
    exit 1
fi

if [ ! -f "$GATEWAY_YAML" ]; then
    echo "ERROR: $GATEWAY_YAML not found. Run on SIFT VM with gateway configured."
    exit 1
fi

# Extract gateway token
TOKEN=$(python3 -c "
import yaml
with open('$GATEWAY_YAML') as f: gw = yaml.safe_load(f)
print(gw.get('auth', {}).get('token', ''))
")

if [ -z "$TOKEN" ]; then
    echo "ERROR: Could not extract gateway token from $GATEWAY_YAML"
    exit 1
fi

info "Gateway token: ${TOKEN:0:10}..."
info "Backing up $CLAUDE_JSON"
cp "$CLAUDE_JSON" "$BACKUP" 2>/dev/null || info "No existing .claude.json to back up"

echo ""
echo "--- Test 1: First-Launch Preservation ---"
echo ""
info "Adding test mcpServers entry to ~/.claude.json"

add_mcp_entry "aiir-preservation-test" "http" "test_token_preservation_check"

BEFORE=$(entry_exists "aiir-preservation-test")
info "Before Claude launch: $BEFORE"

info "Launching Claude Code (non-interactive, single prompt)..."
(cd /tmp && claude -p "Respond with exactly: OK" 2>&1) || true

AFTER=$(entry_exists "aiir-preservation-test")
info "After Claude launch: $AFTER"

if echo "$AFTER" | grep -q "EXISTS"; then
    pass "~/.claude.json mcpServers preserved after Claude Code startup"
else
    fail "~/.claude.json mcpServers LOST after Claude Code startup"
    info "Check if ~/.claude.json.backup was created by Claude Code"
    ls -la "$HOME/.claude.json.backup"* 2>/dev/null || info "No backups found"
fi

remove_mcp_entry "aiir-preservation-test"

echo ""
echo "--- Test 2: MCP type 'http' in global scope ---"
echo ""
info "Adding forensic-mcp entry with type=http to ~/.claude.json"

add_mcp_entry "aiir-type-test-http" "http" "$TOKEN"
info "Entry added:"
entry_exists "aiir-type-test-http"

if check_mcp_connects "aiir-type-test-http"; then
    pass "type=http works in ~/.claude.json global mcpServers"
else
    fail "type=http does NOT work in ~/.claude.json global mcpServers"
fi

remove_mcp_entry "aiir-type-test-http"

echo ""
echo "--- Test 3: MCP type 'streamable-http' in global scope ---"
echo ""
info "Adding forensic-mcp entry with type=streamable-http to ~/.claude.json"

add_mcp_entry "aiir-type-test-shttp" "streamable-http" "$TOKEN"
info "Entry added:"
entry_exists "aiir-type-test-shttp"

if check_mcp_connects "aiir-type-test-shttp"; then
    pass "type=streamable-http works in ~/.claude.json global mcpServers"
else
    fail "type=streamable-http does NOT work in ~/.claude.json global mcpServers"
fi

remove_mcp_entry "aiir-type-test-shttp"

# --- Restore and Report ---

echo ""
echo "--- Cleanup ---"
echo ""

if [ -f "$BACKUP" ]; then
    cp "$BACKUP" "$CLAUDE_JSON"
    rm "$BACKUP"
    info "Restored ~/.claude.json from backup"
else
    info "No backup to restore"
fi

echo ""
echo "==============================="
echo "  RESULTS SUMMARY"
echo "==============================="
echo ""

PASS_COUNT=0
FAIL_COUNT=0
for r in "${RESULTS[@]}"; do
    echo "  $r"
    if [[ "$r" == PASS* ]]; then ((PASS_COUNT++)); fi
    if [[ "$r" == FAIL* ]]; then ((FAIL_COUNT++)); fi
done

echo ""
echo "  Total: $((PASS_COUNT + FAIL_COUNT)) tests, $PASS_COUNT passed, $FAIL_COUNT failed"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "  ACTION REQUIRED:"
    for r in "${RESULTS[@]}"; do
        if [[ "$r" == FAIL* ]]; then
            case "$r" in
                *preserved*|*LOST*)
                    echo "  - Preservation failed: installer must run AFTER first Claude Code launch"
                    echo "    This changes installation ordering in the spec."
                    ;;
                *http\ works*|*http\ does*)
                    echo "  - type=http failed: cannot use 'http' for global MCP entries"
                    ;;
                *streamable-http\ works*|*streamable-http\ does*)
                    echo "  - type=streamable-http failed: cannot use 'streamable-http' for global MCP entries"
                    ;;
            esac
        fi
    done
    if echo "${RESULTS[*]}" | grep -q "FAIL.*http.*FAIL.*streamable"; then
        echo ""
        echo "  BLOCKING: Neither type works in global scope."
        echo "  The ~/.claude.json approach for global MCP may not be viable."
    fi
    echo ""
    exit 1
fi

echo "  All tests passed. Spec approach is confirmed viable."
echo "  Dev can proceed with implementation."
echo ""
exit 0
