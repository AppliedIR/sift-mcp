#!/usr/bin/env bash
#
# PreToolUse hook: Protect case data from destructive Bash commands.
#
# Allows destructive commands (rm, rmdir, mv) only when ALL target paths
# resolve to whitelisted directories (.outputs/, extractions/, /tmp/).
# Blocks targeting case roots, protected case files, or the cases dir.
#
# Fail-closed: if a path can't be resolved, block.
#
set -euo pipefail

# Only intercept Bash tool calls
TOOL_NAME="${TOOL_NAME:-}"
if [[ "$TOOL_NAME" != "Bash" ]]; then
    exit 0
fi

# Read the command from stdin (Claude Code passes tool input as JSON)
INPUT=$(cat)
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command',''))" 2>/dev/null || echo "")

if [[ -z "$COMMAND" ]]; then
    exit 0
fi

# Resolve cases directory
CASES_DIR="${VHIR_CASES_DIR:-$HOME/cases}"
CASES_DIR_RESOLVED=$(realpath "$CASES_DIR" 2>/dev/null || echo "$CASES_DIR")

# Protected file basenames within any case directory
PROTECTED_FILES=(
    "findings.json" "timeline.json" "evidence.json" "todos.json"
    "iocs.json" "approvals.jsonl" "CASE.yaml" "pending-reviews.json"
    "pending-reviews.processing"
)
PROTECTED_DIRS=("audit" "examiners")

# Allowed directories within case dirs (LLM output workspace)
ALLOWED_DIRS=(".outputs" "extractions")

# Extract the base command (first word, handle pipes by checking first segment)
BASE_CMD=$(echo "$COMMAND" | sed 's/|.*//' | awk '{print $1}' | sed 's|.*/||')

# Only check destructive commands
case "$BASE_CMD" in
    rm|rmdir|shred)
        ;;
    mv)
        ;;
    find)
        # Only if -delete is in the command
        if ! echo "$COMMAND" | grep -qE '\-delete|\-exec\s+rm'; then
            exit 0
        fi
        ;;
    *)
        exit 0
        ;;
esac

# Extract path arguments (skip flags for rm/rmdir, handle mv source)
get_path_args() {
    local cmd="$1"
    local base="$2"

    if [[ "$base" == "mv" ]]; then
        # For mv, check ALL path args (both sources and destination).
        # Moving FROM a protected path is destructive (removes source).
        # Moving TO a protected file overwrites it.
        local args=()
        for arg in $cmd; do
            if [[ "$arg" == "mv" ]]; then continue; fi
            if [[ "$arg" == -* ]]; then continue; fi
            args+=("$arg")
        done
        echo "${args[@]}"
    elif [[ "$base" == "find" ]]; then
        # For find, the first non-flag arg is the search root
        for arg in $cmd; do
            if [[ "$arg" == "find" ]]; then continue; fi
            if [[ "$arg" == -* ]]; then break; fi
            echo "$arg"
            break
        done
    else
        # rm/rmdir/shred: all non-flag args after --
        local past_dashdash=false
        for arg in $cmd; do
            if [[ "$arg" == "$base" ]]; then continue; fi
            if [[ "$arg" == "--" ]]; then past_dashdash=true; continue; fi
            if [[ "$arg" == -* ]] && ! $past_dashdash; then continue; fi
            echo "$arg"
        done
    fi
}

is_in_allowed_dir() {
    local path="$1"
    for allowed in "${ALLOWED_DIRS[@]}"; do
        if echo "$path" | grep -q "/$allowed/\|/$allowed$"; then
            return 0
        fi
    done
    # /tmp/ is always allowed
    if [[ "$path" == /tmp/* ]]; then
        return 0
    fi
    return 1
}

is_protected_file() {
    local path="$1"
    local basename=$(basename "$path")
    for pf in "${PROTECTED_FILES[@]}"; do
        if [[ "$basename" == "$pf" ]]; then
            return 0
        fi
    done
    for pd in "${PROTECTED_DIRS[@]}"; do
        if echo "$path" | grep -q "/$pd/\|/$pd$"; then
            return 0
        fi
    done
    return 1
}

is_case_path() {
    local path="$1"
    if [[ "$path" == "$CASES_DIR_RESOLVED" ]] || \
       [[ "$path" == "$CASES_DIR_RESOLVED/"* ]]; then
        return 0
    fi
    return 1
}

# Check each path argument
BLOCKED=false
BLOCKED_PATH=""

# Get first pipe segment only
FIRST_SEGMENT=$(echo "$COMMAND" | sed 's/|.*//')

for arg in $(get_path_args "$FIRST_SEGMENT" "$BASE_CMD"); do
    # Expand ~ manually
    arg="${arg/#\~/$HOME}"

    # Try to resolve. If resolution fails and path looks like it could
    # be in cases dir, block (fail closed).
    resolved=$(realpath "$arg" 2>/dev/null || echo "")
    if [[ -z "$resolved" ]]; then
        # Can't resolve — check if the literal path starts with cases dir
        if [[ "$arg" == "$CASES_DIR"* ]] || [[ "$arg" == "$CASES_DIR_RESOLVED"* ]]; then
            BLOCKED=true
            BLOCKED_PATH="$arg (could not resolve, matches cases directory)"
            break
        fi
        continue
    fi

    # Block: cases root itself
    if [[ "$resolved" == "$CASES_DIR_RESOLVED" ]]; then
        BLOCKED=true
        BLOCKED_PATH="$resolved (cases root directory)"
        break
    fi

    # Not in cases dir at all — allow
    if ! is_case_path "$resolved"; then
        continue
    fi

    # In cases dir — check if in allowed subdirectory
    if is_in_allowed_dir "$resolved"; then
        continue
    fi

    # In cases dir, not in allowed dir — check if it's a case root
    # (one level below cases dir)
    local_path="${resolved#$CASES_DIR_RESOLVED/}"
    if [[ "$local_path" != */* ]]; then
        # Direct child of cases dir = case root
        BLOCKED=true
        BLOCKED_PATH="$resolved (case root directory)"
        break
    fi

    # Deeper path — check if it's a protected file/dir
    if is_protected_file "$resolved"; then
        BLOCKED=true
        BLOCKED_PATH="$resolved (protected case data)"
        break
    fi

    # In case dir, not allowed, not explicitly protected — block (fail closed)
    BLOCKED=true
    BLOCKED_PATH="$resolved (case data — not in allowed directory)"
    break
done

if $BLOCKED; then
    echo "BLOCKED: Destructive command targeting protected case data."
    echo "  Path: $BLOCKED_PATH"
    echo ""
    echo "  Case data is protected. Options:"
    echo "  - Target .outputs/ or extractions/ for cleanup"
    echo "  - Use 'vhir case delete' to remove a case (with backup)"
    echo "  - Use 'vhir case close' before deletion"
    exit 2
fi

# Warn (but don't block) when forensic tools are run via Bash instead of MCP.
# These tools have MCP equivalents (run_command) that provide provenance tracking.
FORENSIC_PATTERNS="rip\.pl|strings |7z |qemu-nbd|mount.*nbd|fls |mmls |icat |mactime |vol -f |bulk_extractor|AmcacheParser|PECmd|MFTECmd|EvtxECmd|RECmd|hayabusa|log2timeline|psort"
if echo "$COMMAND" | grep -qiE "$FORENSIC_PATTERNS"; then
    echo "NOTE: Forensic tool detected in Bash. Use run_command on sift-mcp for provenance tracking. Call log_external_action afterward if you proceed via Bash." >&2
fi

exit 0
