#!/usr/bin/env bash
# SessionStart hook — warn if not launched from a case directory.

if [ -f "CASE.yaml" ]; then
    exit 0
fi

VHIR_HOME="${VHIR_HOME:-$HOME/.vhir}"
CASES_DIR="${VHIR_CASES_DIR:-$HOME/cases}"
ACTIVE_CASE=""
if [ -f "$VHIR_HOME/active_case" ]; then
    ACTIVE_CASE=$(cat "$VHIR_HOME/active_case" 2>/dev/null)
fi

if [ -n "$ACTIVE_CASE" ] && [ -d "$ACTIVE_CASE" ]; then
    # Unquoted EOF — $ACTIVE_CASE expanded (content is a path we wrote)
    cat <<EOF
WARNING: Not in a case directory (no CASE.yaml found).

Launching from outside a case directory bypasses case isolation.

Your active case is: $ACTIVE_CASE

Please close this session and relaunch from the case directory:

  cd $ACTIVE_CASE
  claude

EOF
else
    # Unquoted EOF — $CASES_DIR expanded (VHIR_CASES_DIR or ~/cases)
    cat <<EOF
WARNING: Not in a case directory (no CASE.yaml found).

Launching from outside a case directory bypasses case isolation.

To fix, close this session and either:

  1. Launch from an existing case:
     cd $CASES_DIR/<case-id>
     claude

  2. Create a new case first:
     vhir case init <case-id>
     cd $CASES_DIR/<case-id>
     claude

EOF
fi
