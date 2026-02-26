#!/usr/bin/env bash
# PreToolUse hook — block Bash writes to case data files.
# Reads JSON from stdin (Claude Code hook protocol).
# Filename-based matching. Does not require an active case.

set -euo pipefail

# Read JSON from stdin
INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
[ "$TOOL_NAME" = "Bash" ] || exit 0

CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
[ -n "$CMD" ] || exit 0

# CWD == HOME warning (not a block).
# Reminds examiner to launch from a case directory.
if [ "$PWD" = "$HOME" ]; then
    echo "WARNING: Running from home directory. Case work should"
    echo "be launched from a case directory for full protection."
    echo "  cd ~/cases/INC-2026-001 && claude"
fi

PROTECTED="findings\.json|timeline\.json|approvals\.jsonl|todos\.json|CASE\.yaml|actions\.jsonl"

# Block redirections, tee, cp, mv targeting protected files
if echo "$CMD" | grep -qEi "(>|>>|tee\s|cp\s|mv\s).*($PROTECTED)"; then
    echo "Blocked: direct writes to case data files. Use MCP tools."
    exit 2
fi

# Block chmod on protected files (prevents chmod 644 bypass of L5)
if echo "$CMD" | grep -qEi "chmod.*($PROTECTED)"; then
    echo "Blocked: permission changes on case data files."
    exit 2
fi

exit 0
