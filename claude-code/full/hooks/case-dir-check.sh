#!/usr/bin/env bash
# SessionStart hook — warn if not launched from a case directory.
# The sandbox scopes commands to the working directory tree.

if [ -f "CASE.yaml" ]; then
    exit 0
fi

cat <<'EOF'
WARNING: Not in a case directory (no CASE.yaml found).

The sandbox restricts all commands to the current directory tree.
Launching from outside a case directory bypasses case isolation.

Fix: exit, cd into a case directory, and relaunch.
EOF
