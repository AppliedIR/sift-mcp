"""setup-sift.sh --manual-start over an install that turned auto-start on.

The unit an earlier install enabled still starts the gateway at the next
boot: --manual-start says so, and how to turn it off, and changes nothing.
Only the gateway-start block runs, with stub curl and systemctl; nothing is
installed or started.
"""

import subprocess
from pathlib import Path

import pytest

TEXT = (Path(__file__).resolve().parents[1] / "setup-sift.sh").read_text()
START = "# Check if gateway is already running"
END = "# Phase 13b"
PROLOGUE = (
    "set -euo pipefail\n"
    'info() { echo "[INFO] $*"; }; ok() { echo "[OK] $*"; }; warn() { echo "[WARN] $*"; }\n'
    "prompt() { echo 1; }\n"
    "MODE=recommended; AUTO_YES=true\n"
    'GATEWAY_START="$HOME/.vhir/start-gateway.sh"; GATEWAY_PORT=4508\n'
    'VENV_DIR="$HOME/venv"; GATEWAY_CONFIG="$HOME/.vhir/gateway.yaml"\n'
    'EXAMINER_NAME=examiner; CASE_DIR="$HOME/cases"\n'
    'HEALTH_URL="https://127.0.0.1:4508/health"; CURL_EXTRA="-k"\n'
)


def _run(tmp_path, enabled, health):
    """Run the block with --manual-start; returns its output and the
    systemctl calls it made."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stubs = {
        "curl": f"exit {0 if health else 7}",
        "systemctl": (
            f'echo "$*" >> "{tmp_path}/systemctl"\n'
            '[[ "$*" == *is-enabled* ]] || exit 0\n'
            + ("echo enabled; exit 0" if enabled else "echo disabled; exit 1")
        ),
        "loginctl": "exit 0",
    }
    for name, body in stubs.items():
        (bin_ / name).write_text(f"#!/bin/bash\n{body}\n")
        (bin_ / name).chmod(0o755)
    script = tmp_path / "block.sh"
    script.write_text(
        PROLOGUE + "MANUAL_START=true\n" + TEXT[TEXT.index(START) : TEXT.index(END)]
    )
    p = subprocess.run(
        ["/bin/bash", str(script)],
        env={"PATH": f"{bin_}:/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    calls = tmp_path / "systemctl"
    return (
        p.returncode,
        p.stdout + p.stderr,
        (calls.read_text().splitlines() if calls.exists() else []),
    )


@pytest.mark.parametrize("health", [True, False], ids=["running", "not-running"])
def test_an_enabled_unit_is_named_with_how_to_turn_it_off(tmp_path, health):
    rc, out, calls = _run(tmp_path, enabled=True, health=health)
    assert rc == 0, out
    said = [
        s
        for s in out.splitlines()
        if s.startswith("[WARN] ") and "systemctl --user disable vhir-gateway" in s
    ]
    assert len(said) == 1 and "auto-start" in said[0].lower(), out
    # warn only: nothing turned off, stopped or started
    assert [c for c in calls if "is-enabled" not in c] == [], calls


@pytest.mark.parametrize("health", [True, False], ids=["running", "not-running"])
def test_with_no_enabled_unit_nothing_is_said(tmp_path, health):
    rc, out, calls = _run(tmp_path, enabled=False, health=health)
    assert rc == 0, out
    assert "systemctl --user disable" not in out
    assert "[WARN]" not in out
    assert [c for c in calls if "is-enabled" not in c] == [], calls
