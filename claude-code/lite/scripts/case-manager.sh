#!/usr/bin/env bash
# case-manager.sh — Deterministic case management for AIIR Lite.
# Called by the /case skill. All file operations happen here so the
# LLM never writes state files, directories, or CASE.yaml directly.
set -euo pipefail

STATE_FILE="$HOME/.aiir/active_case"
CASES_DIR="$PWD/cases"
TEMPLATES_DIR="$CASES_DIR/.templates"

# ── helpers ──────────────────────────────────────────────────────────

_die() { echo "$1" >&2; exit 1; }

_validate_name() {
    local name="$1"
    if [[ ! "$name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]]; then
        _die "Invalid case name: $name (alphanumeric, hyphens, underscores only)"
    fi
}

_read_yaml_field() {
    # Read a YAML field from a simple key: value file.
    # Matches the field name anchored at start of line. For indented
    # sub-keys (e.g. under paths:), pass the leading spaces as part
    # of the field name: _read_yaml_field "$f" "  evidence"
    # This is safe because the script controls the YAML format (heredoc).
    local file="$1" field="$2"
    sed -n "s/^${field}: *//p" "$file" 2>/dev/null || echo ""
}

_read_active_path() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE" 2>/dev/null
    fi
}

# ── init ─────────────────────────────────────────────────────────────

_cmd_init() {
    local name="" description=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --description)
                description="${2:-}"
                shift 2
                ;;
            *)
                if [[ -z "$name" ]]; then
                    name="$1"
                    shift
                else
                    _die "Unexpected argument: $1"
                fi
                ;;
        esac
    done

    [[ -n "$name" ]] || _die "Usage: case-manager.sh init <name> [--description \"text\"]"
    _validate_name "$name"

    local case_dir="$CASES_DIR/$name"
    [[ ! -d "$case_dir" ]] || _die "Case already exists: $name"

    # Create directory structure
    mkdir -p "$case_dir"/{evidence,extractions,audit,reports}

    # Copy templates and replace placeholders
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if [[ -d "$TEMPLATES_DIR" ]]; then
        for tmpl in "$TEMPLATES_DIR"/*.md; do
            [[ -f "$tmpl" ]] || continue
            local base
            base=$(basename "$tmpl")
            sed -e "s/\[CASE_NAME\]/$name/g" -e "s/\[DATE\]/$ts/g" \
                "$tmpl" > "$case_dir/reports/$base"
        done
    fi

    # Write CASE.yaml via heredoc
    # Single-quote description for YAML safety (# in value would be parsed as comment)
    local yaml_desc="${description//\'/\'\'}"
    cat > "$case_dir/CASE.yaml" << EOF
name: $name
description: '$yaml_desc'
status: open
created: $ts
paths:
  evidence: cases/$name/evidence/
  extracted: cases/$name/extractions/
  reports: cases/$name/reports/
EOF

    # Write state file
    mkdir -p "$(dirname "$STATE_FILE")"
    printf '%s\n' "$PWD/cases/$name" > "$STATE_FILE"

    echo "Created case: $name"
    echo "Path: $PWD/cases/$name"
    echo "Status: open"
    echo "Active case set."
}

# ── open ─────────────────────────────────────────────────────────────

_cmd_open() {
    local name="${1:-}"
    [[ -n "$name" ]] || _die "Usage: case-manager.sh open <name>"

    local case_dir="$CASES_DIR/$name"
    local yaml="$case_dir/CASE.yaml"
    [[ -f "$yaml" ]] || _die "Case not found: $name (no CASE.yaml)"

    # Write state file
    mkdir -p "$(dirname "$STATE_FILE")"
    printf '%s\n' "$PWD/cases/$name" > "$STATE_FILE"

    # Read fields and display
    local desc status created ev_path ex_path rp_path
    desc=$(_read_yaml_field "$yaml" "description")
    status=$(_read_yaml_field "$yaml" "status")
    created=$(_read_yaml_field "$yaml" "created")
    ev_path=$(_read_yaml_field "$yaml" "  evidence")
    ex_path=$(_read_yaml_field "$yaml" "  extracted")
    rp_path=$(_read_yaml_field "$yaml" "  reports")

    echo "Active case: $name"
    echo "Description: $desc"
    echo "Status: $status"
    echo "Created: $created"
    echo "Evidence: $ev_path"
    echo "Extractions: $ex_path"
    echo "Reports: $rp_path"
}

# ── status ───────────────────────────────────────────────────────────

_cmd_status() {
    local active_path
    active_path=$(_read_active_path)

    if [[ -z "$active_path" ]]; then
        echo "No active case."
        return 0
    fi

    # Validate path
    case "$active_path" in
        /*) ;;
        *)
            rm -f "$STATE_FILE"
            echo "Stale active case removed (not absolute path)."
            echo "No active case."
            return 0
            ;;
    esac

    if [[ ! -d "$active_path" ]]; then
        rm -f "$STATE_FILE"
        echo "Stale active case removed (directory missing)."
        echo "No active case."
        return 0
    fi

    local yaml="$active_path/CASE.yaml"
    if [[ ! -f "$yaml" ]]; then
        rm -f "$STATE_FILE"
        echo "Stale active case removed (no CASE.yaml)."
        echo "No active case."
        return 0
    fi

    local name
    name=$(basename "$active_path")

    local desc status created ev_path ex_path rp_path
    desc=$(_read_yaml_field "$yaml" "description")
    status=$(_read_yaml_field "$yaml" "status")
    created=$(_read_yaml_field "$yaml" "created")
    ev_path=$(_read_yaml_field "$yaml" "  evidence")
    ex_path=$(_read_yaml_field "$yaml" "  extracted")
    rp_path=$(_read_yaml_field "$yaml" "  reports")

    echo "Active case: $name"
    echo "Description: $desc"
    echo "Status: $status"
    echo "Created: $created"
    echo "Evidence: $ev_path"
    echo "Extractions: $ex_path"
    echo "Reports: $rp_path"
}

# ── list ─────────────────────────────────────────────────────────────

_cmd_list() {
    local active_path
    active_path=$(_read_active_path)

    local found=0
    local lines=()

    for yaml in "$CASES_DIR"/*/CASE.yaml; do
        [[ -f "$yaml" ]] || continue
        local case_dir
        case_dir=$(dirname "$yaml")
        local name
        name=$(basename "$case_dir")
        [[ "$name" != ".templates" ]] || continue

        local status created desc marker
        status=$(_read_yaml_field "$yaml" "status")
        created=$(_read_yaml_field "$yaml" "created")
        desc=$(_read_yaml_field "$yaml" "description")

        # Truncate description to 40 chars
        if [[ ${#desc} -gt 40 ]]; then
            desc="${desc:0:37}..."
        fi

        # Extract date portion from ISO timestamp for display
        local display_date="${created:0:10}"

        # Mark active case
        if [[ "$PWD/cases/$name" = "$active_path" ]]; then
            marker="*"
        else
            marker=" "
        fi

        lines+=("$(printf '%s %-24s %-8s %-12s %s' "$marker" "$name" "$status" "$display_date" "$desc")")
        found=1
    done

    if [[ "$found" -eq 0 ]]; then
        echo "No cases found."
        return 0
    fi

    for line in "${lines[@]}"; do
        echo "$line"
    done
}

# ── close ────────────────────────────────────────────────────────────

_cmd_close() {
    local name="${1:-}"

    # If no name, derive from active case
    if [[ -z "$name" ]]; then
        local active_path
        active_path=$(_read_active_path)
        [[ -n "$active_path" ]] || _die "No active case and no case name provided."
        name=$(basename "$active_path")
    fi

    local case_dir="$CASES_DIR/$name"
    local yaml="$case_dir/CASE.yaml"
    [[ -f "$yaml" ]] || _die "Case not found: $name (no CASE.yaml)"

    # Check not already closed
    local current_status
    current_status=$(_read_yaml_field "$yaml" "status")
    [[ "$current_status" != "closed" ]] || _die "Case already closed: $name"

    # Update status
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    sed -i "s/^status: .*$/status: closed/" "$yaml"
    echo "closed: $ts" >> "$yaml"

    # Only clear state file if this case matches active case
    local active_path
    active_path=$(_read_active_path)
    if [[ "$active_path" = "$PWD/cases/$name" ]]; then
        rm -f "$STATE_FILE"
        echo "Closed case: $name"
        echo "Active case cleared."
    else
        echo "Closed case: $name"
    fi
}

# ── dispatch ─────────────────────────────────────────────────────────

action="${1:-}"
shift || true

case "$action" in
    init)   _cmd_init "$@" ;;
    open)   _cmd_open "$@" ;;
    status) _cmd_status "$@" ;;
    list)   _cmd_list "$@" ;;
    close)  _cmd_close "$@" ;;
    -h|--help)
        echo "Usage: case-manager.sh <init|open|status|list|close> [args...]"
        echo ""
        echo "Actions:"
        echo "  init   <name> [--description \"text\"]  Create a new case"
        echo "  open   <name>                          Set active case"
        echo "  status                                 Show active case"
        echo "  list                                   List all cases"
        echo "  close  [name]                          Close a case"
        exit 0
        ;;
    *)
        echo "Usage: case-manager.sh <init|open|status|list|close> [args...]" >&2
        exit 1
        ;;
esac
