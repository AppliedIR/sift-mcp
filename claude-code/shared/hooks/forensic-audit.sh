#!/bin/sh
# PostToolUse hook: audit Bash commands to the active case audit trail. Also
# registered for PostToolUseFailure (a command that failed: the entry says
# "failed" with the error) and PermissionDenied (a call the permission mode
# refused: "denied" with the reason).
# With --client codex (Codex's managed hooks): entries carry "client": "codex",
# "event" ("shell" or "apply_patch") and "outside_case" when the session runs
# outside the active case, and each run also records Codex's write_stdin text
# (codex-stdin-capture.sh), which no hook sees.
# Receives JSON on stdin from Claude Code. Never exits 2 (would block).
set -e
CLIENT=claude-code
if [ "$1" = "--client" ] && [ -n "$2" ]; then CLIENT=$2; fi

# 1. Read active case directory
# Priority: VHIR_CASE_DIR env var > ~/.vhir/active_case file
if [ -n "$VHIR_CASE_DIR" ] && [ -d "$VHIR_CASE_DIR" ]; then
    CASE_DIR="$VHIR_CASE_DIR"
else
    ACTIVE_CASE_FILE="$HOME/.vhir/active_case"
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
fi

# 2. Examiner identity
EXAMINER="${VHIR_EXAMINER:-$(whoami)}"

# 3. Read stdin and parse via Python one-liner
INPUT=$(cat)
PARSED=$(printf '%s' "$INPUT" | python3 -I -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ti = d.get('tool_input', {})
    cmd = ti.get('command', '')
    resp = str(d.get('tool_response', ''))
    tuid = d.get('tool_use_id', '')
    sid = d.get('session_id', '')
    cwd = d.get('cwd', '')  # Claude Code sends it at the top level
    event = d.get('hook_event_name', '')
    tool = d.get('tool_name', '')
    error = str(d.get('error', ''))
    reason = str(d.get('reason', ''))
    print(json.dumps({'command': cmd, 'tool_response': resp, 'tool_use_id': tuid, 'session_id': sid, 'cwd': cwd,
                      'event': event, 'error': error, 'reason': reason, 'tool': tool}))
except Exception:
    print('{}')
" 2>/dev/null) || PARSED="{}"

COMMAND=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('command',''))" 2>/dev/null) || COMMAND=""
if [ -z "$COMMAND" ]; then
    exit 0
fi

# 4. Ensure audit directory exists
if [ -n "$VHIR_AUDIT_DIR" ] && [ -d "$VHIR_AUDIT_DIR" ]; then
    AUDIT_DIR="$VHIR_AUDIT_DIR"
else
    AUDIT_DIR="$CASE_DIR/audit"
fi
mkdir -p "$AUDIT_DIR" 2>/dev/null || exit 0

AUDIT_FILE="$AUDIT_DIR/claude-code.jsonl"

# 5. Generate audit_id with sequence number
SEQ=1
if [ -f "$AUDIT_FILE" ]; then
    EXISTING=$(grep -c '"hook-' "$AUDIT_FILE" 2>/dev/null) || EXISTING=0
    SEQ=$((EXISTING + 1))
fi
TODAY=$(date -u +%Y%m%d)
EVIDENCE_ID="hook-${EXAMINER}-${TODAY}-$(printf '%03d' "$SEQ")"

# 6. Compute SHA-256 of command + output
TOOL_RESPONSE=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('tool_response',''))" 2>/dev/null) || TOOL_RESPONSE=""
HASH_INPUT="${COMMAND}${TOOL_RESPONSE}"
if command -v sha256sum >/dev/null 2>&1; then
    OUTPUT_HASH=$(printf '%s' "$HASH_INPUT" | sha256sum | cut -d' ' -f1 2>/dev/null) || OUTPUT_HASH=""
elif command -v shasum >/dev/null 2>&1; then
    OUTPUT_HASH=$(printf '%s' "$HASH_INPUT" | shasum -a 256 | cut -d' ' -f1 2>/dev/null) || OUTPUT_HASH=""
else
    OUTPUT_HASH=""
fi

# 7. Build and write audit entry
TOOL_USE_ID=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('tool_use_id',''))" 2>/dev/null) || TOOL_USE_ID=""
SESSION_ID=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null) || SESSION_ID=""
CWD=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('cwd',''))" 2>/dev/null) || CWD=""
OUTPUT_BYTES=$(printf '%s' "$TOOL_RESPONSE" | wc -c 2>/dev/null) || OUTPUT_BYTES=0
EVENT=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('event',''))" 2>/dev/null) || EVENT=""
ERROR=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null) || ERROR=""
REASON=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('reason',''))" 2>/dev/null) || REASON=""
TOOL=$(printf '%s' "$PARSED" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('tool',''))" 2>/dev/null) || TOOL=""

# Truncate output to 2000 chars for excerpt
OUTPUT_EXCERPT=$(printf '%s' "$TOOL_RESPONSE" | head -c 2000 2>/dev/null) || OUTPUT_EXCERPT=""

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 -I -c "
import json, sys
entry = {
    'ts': '$TS',
    'source': 'claude-code-hook',
    'tool_use_id': sys.argv[1],
    'audit_id': sys.argv[2],
    'command': sys.argv[3],
    'output_hash': sys.argv[4],
    'output_excerpt': sys.argv[5][:2000],
    'output_bytes': int(sys.argv[6]),
    'cwd': sys.argv[7],
    'session_id': sys.argv[8],
}
if sys.argv[9] == 'PostToolUseFailure':
    entry.update(event='failed', error=sys.argv[10][:2000])
elif sys.argv[9] == 'PermissionDenied':
    entry.update(event='denied', denial_reason=sys.argv[11][:2000])
if sys.argv[12] == 'codex':
    import os
    entry.update(client='codex', event='apply_patch' if sys.argv[13] == 'apply_patch' else 'shell')
    case = os.path.realpath(sys.argv[14])
    if sys.argv[7] and not (os.path.realpath(sys.argv[7]) + '/').startswith(case + '/'):
        entry['outside_case'] = True
print(json.dumps(entry))
" "$TOOL_USE_ID" "$EVIDENCE_ID" "$COMMAND" "$OUTPUT_HASH" "$OUTPUT_EXCERPT" "$OUTPUT_BYTES" "$CWD" "$SESSION_ID" "$EVENT" "$ERROR" "$REASON" "$CLIENT" "$TOOL" "$CASE_DIR" >> "$AUDIT_FILE" 2>/dev/null || true

# Codex: the write_stdin text typed since the last capture (a session killed
# before its Stop hook loses none of it)
if [ "$CLIENT" = codex ]; then
    printf '%s' "$INPUT" | bash "$(dirname "$0")/codex-stdin-capture.sh" >/dev/null 2>&1 || true
fi

exit 0
