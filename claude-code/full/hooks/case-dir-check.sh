#!/usr/bin/env bash
# SessionStart hook — warn if not launched from a case directory.

if [ -f "CASE.yaml" ]; then
    exit 0
fi

VHIR_HOME="${VHIR_HOME:-$HOME/.vhir}"
ACTIVE_CASE=""
if [ -f "$VHIR_HOME/active_case" ]; then
    ACTIVE_CASE=$(cat "$VHIR_HOME/active_case" 2>/dev/null)
fi

if [ -n "$ACTIVE_CASE" ] && [ -d "$ACTIVE_CASE" ]; then
    cat <<EOF
WARNING: Not in a case directory (no CASE.yaml found).

The sandbox restricts all commands to the current directory tree.
Launching from outside a case directory bypasses case isolation.

Your active case is: $ACTIVE_CASE

Please close this session and relaunch from the case directory:

  cd $ACTIVE_CASE
  claude

EOF
else
    cat <<EOF
WARNING: Not in a case directory (no CASE.yaml found).

The sandbox restricts all commands to the current directory tree.
Launching from outside a case directory bypasses case isolation.

To fix, close this session and either:

  1. Launch from an existing case:
     cd ~/.vhir/cases/<case-id>
     claude

  2. Create a new case first:
     vhir case init <case-id>
     cd ~/.vhir/cases/<case-id>
     claude

EOF
fi
