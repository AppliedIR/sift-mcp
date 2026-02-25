#!/bin/sh
# PostToolUse hook: audit Bash commands to the active case audit trail.
# Receives JSON on stdin from Claude Code. Never exits 2 (would block).
set -e

# 1. Read active case directory
ACTIVE_CASE_FILE="$HOME/.aiir/active_case"
if [ ! -f "$ACTIVE_CASE_FILE" ]; then
    exit 0
fi
CASE_DIR=$(cat "$ACTIVE_CASE_FILE" 2>/dev/null)
if [ -z "$CASE_DIR" ]; then
    exit 0
fi
# If not absolute path, skip (legacy bare ID without cases dir)
case "$CASE_DIR" in
    /*) ;;
    *) exit 0 ;;
esac
if [ ! -d "$CASE_DIR" ]; then
    exit 0
fi

# 2. Examiner identity
EXAMINER="${AIIR_EXAMINER:-$(whoami)}"

# 3. Read stdin and parse via Python one-liner
INPUT=$(cat)
PARSED=$(printf '%s' "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ti = d.get('tool_input', {})
    cmd = ti.get('command', '')
    resp = str(d.get('tool_response', ''))
    tuid = d.get('tool_use_id', '')
    sid = d.get('session_id', '')
    cwd = ti.get('cwd', '')
    print(json.dumps({'command': cmd, 'tool_response': resp, 'tool_use_id': tuid, 'session_id': sid, 'cwd': cwd}))
except Exception:
    print('{}')
" 2>/dev/null) || PARSED="{}"

COMMAND=$(printf '%s' "$PARSED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command',''))" 2>/dev/null) || COMMAND=""
if [ -z "$COMMAND" ]; then
    exit 0
fi

# 4. Ensure audit directory exists
AUDIT_DIR="$CASE_DIR/audit"
mkdir -p "$AUDIT_DIR" 2>/dev/null || exit 0

AUDIT_FILE="$AUDIT_DIR/claude-code.jsonl"

# 5. Generate evidence_id with sequence number
SEQ=1
if [ -f "$AUDIT_FILE" ]; then
    EXISTING=$(grep -c '"hook-' "$AUDIT_FILE" 2>/dev/null) || EXISTING=0
    SEQ=$((EXISTING + 1))
fi
TODAY=$(date -u +%Y%m%d)
EVIDENCE_ID="hook-${EXAMINER}-${TODAY}-$(printf '%03d' "$SEQ")"

# 6. Compute SHA-256 of command + output
TOOL_RESPONSE=$(printf '%s' "$PARSED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_response',''))" 2>/dev/null) || TOOL_RESPONSE=""
HASH_INPUT="${COMMAND}${TOOL_RESPONSE}"
OUTPUT_HASH=$(printf '%s' "$HASH_INPUT" | sha256sum | cut -d' ' -f1 2>/dev/null) || OUTPUT_HASH=""

# 7. Build and write audit entry
TOOL_USE_ID=$(printf '%s' "$PARSED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_use_id',''))" 2>/dev/null) || TOOL_USE_ID=""
SESSION_ID=$(printf '%s' "$PARSED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null) || SESSION_ID=""
CWD=$(printf '%s' "$PARSED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cwd',''))" 2>/dev/null) || CWD=""
OUTPUT_BYTES=$(printf '%s' "$TOOL_RESPONSE" | wc -c 2>/dev/null) || OUTPUT_BYTES=0

# Truncate output to 2000 chars for excerpt
OUTPUT_EXCERPT=$(printf '%s' "$TOOL_RESPONSE" | head -c 2000 2>/dev/null) || OUTPUT_EXCERPT=""

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 -c "
import json, sys
entry = {
    'ts': '$TS',
    'source': 'claude-code-hook',
    'tool_use_id': sys.argv[1],
    'evidence_id': sys.argv[2],
    'command': sys.argv[3],
    'output_hash': sys.argv[4],
    'output_excerpt': sys.argv[5][:2000],
    'output_bytes': int(sys.argv[6]),
    'cwd': sys.argv[7],
    'session_id': sys.argv[8],
}
print(json.dumps(entry))
" "$TOOL_USE_ID" "$EVIDENCE_ID" "$COMMAND" "$OUTPUT_HASH" "$OUTPUT_EXCERPT" "$OUTPUT_BYTES" "$CWD" "$SESSION_ID" >> "$AUDIT_FILE" 2>/dev/null || true

exit 0
