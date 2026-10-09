"""setup-sift.sh's signing-key step.

`vhir config --upgrade-key` says where the examiner stands: with a signing key
it prints the fingerprint and changes nothing; with a 0.6 password it
upgrades it; with none it says "No passphrase for ...", and only then does
the installer run --setup-password. These run the installer's own step text
with `vhir` replaced by a recorder, never the installer itself.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
STEP = SCRIPT[
    SCRIPT.index("# --- Signing passphrase and key ---") : SCRIPT.index(
        "# =============================================================================\n# Phase 7"
    )
]


def _run(tmp_path, upgrade_out: str, upgrade_rc: int, interactive: bool = True):
    bindir = tmp_path / "venv" / "bin"
    bindir.mkdir(parents=True)
    log = tmp_path / "calls"
    (bindir / "vhir").write_text(
        "#!/bin/bash\n"
        f'echo "$*" >> "{log}"\n'
        'if [[ "$*" == "config --upgrade-key" ]]; then\n'
        f"  printf '%s\\n' {upgrade_out!r} >&2\n"
        f"  exit {upgrade_rc}\n"
        "fi\n"
        "exit 0\n"
    )
    (bindir / "vhir").chmod(0o755)
    step = STEP.replace("if [[ -t 0 ]] && ! $AUTO_YES; then", "if $INTERACTIVE; then")
    script = (
        "set -euo pipefail\n"
        'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }; warn() { echo "WARN $*"; }\n'
        f'VENV_DIR="{tmp_path / "venv"}"\n'
        f"INTERACTIVE={'true' if interactive else 'false'}\n" + step
    )
    p = subprocess.run(
        ["bash", "-c", script],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "TMPDIR": str(tmp_path)},
        capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
    )  # fmt: skip
    calls = log.read_text().splitlines() if log.exists() else []
    return p, calls


def test_no_credential_runs_setup(tmp_path):
    p, calls = _run(
        tmp_path, "No passphrase for steve; run `vhir config --setup-password`.", 1
    )
    assert p.returncode == 0, p.stderr
    assert calls == ["config --upgrade-key", "config --setup-password"]
    assert "Minimum 8 characters; 15 or more recommended." in p.stdout
    assert "re-sign" not in p.stdout


def test_a_signing_key_is_reported_and_setup_never_runs(tmp_path):
    p, calls = _run(
        tmp_path,
        "steve already has a signing key.\nSigning key fingerprint: SHA256:x",
        0,
    )
    assert calls == ["config --upgrade-key"]
    assert "Signing key fingerprint: SHA256:x" in p.stdout


@pytest.mark.parametrize("message", ["Incorrect passphrase.", "No passphrase was set."])
def test_a_failed_upgrade_says_how_to_retry_and_never_runs_setup(tmp_path, message):
    p, calls = _run(tmp_path, message, 1)
    assert calls == ["config --upgrade-key"]
    assert "Run it later with: vhir config --upgrade-key" in p.stdout


def test_non_interactive_runs_neither(tmp_path):
    p, calls = _run(tmp_path, "", 0, interactive=False)
    assert calls == [] and "vhir config --upgrade-key" in p.stdout


def test_the_old_false_text_is_gone():
    assert "re-sign all previously approved findings" not in SCRIPT
    assert "HMAC" not in SCRIPT
