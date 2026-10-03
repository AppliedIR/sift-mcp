"""setup-sift.sh lets vhir setup client ask only the user at a terminal.

vhir asks before changing a user's own Claude files, and only when stdin is
a terminal. The installer ran it with -y and stdin inherited (under
`curl | bash`, the script itself). Now -y gives it /dev/null (no consent),
and otherwise it gets the installer's terminal. "Forensic controls deployed
globally" is printed only when vhir setup client reports it applied them.
The blocks are taken from the script and run under its own shell options
with a stub vhir.
"""

import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
# From the optional comment through the call's failure warning.
_call = SCRIPT.index('"$VENV_DIR/bin/vhir" setup client')
_start = SCRIPT.rfind("# vhir asks before changing", 0, _call)
_start = _start if _start != -1 else SCRIPT.rfind("\n", 0, _call) + 1
_end = SCRIPT.index("\n", SCRIPT.index("Client configuration failed", _call)) + 1
_end += 3 if SCRIPT.startswith("fi\n", _end) else 0
CLIENT = SCRIPT[_start:_end]
MESSAGE = re.search(r"# Global deployment message.*?\nfi\n", SCRIPT, re.S).group(0)


def _bash(snippet, home, stdin=None, **env):
    prologue = 'set -euo pipefail\nwarn() { echo "WARN $*"; }\nBOLD=; NC=\n'
    return subprocess.run(
        ["bash", "-c", prologue + snippet],
        env={"PATH": "/usr/bin:/bin", "HOME": str(home), **env},
        stdin=stdin,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture
def stub(tmp_path):
    def make(says="", rc=0):
        vhir = tmp_path / "venv" / "bin" / "vhir"
        vhir.parent.mkdir(parents=True, exist_ok=True)
        vhir.write_text(
            f'#!/bin/bash\necho "STDIN=$(readlink /proc/self/fd/0)"\necho "{says}"\nexit {rc}\n'
        )
        vhir.chmod(0o755)
        tty = tmp_path / "fake-tty"
        tty.write_text("")
        return tty

    return make


def _install(tmp_path, tty, auto_yes="false", read_from=None):
    env = dict(
        AUTO_YES=auto_yes,
        READ_FROM=read_from or str(tty),
        VENV_DIR=str(tmp_path / "venv"),
        CLIENT="claude-code",
        SIFT_URL="http://x",
    )
    with open(tty) as terminal:  # the installer's own stdin is the terminal
        return _bash(CLIENT + MESSAGE, tmp_path, stdin=terminal, **env)


@pytest.mark.parametrize(
    "auto_yes,read_from,expected",
    [
        ("true", None, "/dev/null"),
        ("false", None, "TTY"),
        ("false", "/nonexistent", "/dev/null"),
    ],
    ids=["-y", "terminal", "no-terminal"],
)
def test_client_setup_gets_a_terminal_only_without_y(
    stub, tmp_path, auto_yes, read_from, expected
):
    tty = stub()
    out = _install(tmp_path, tty, auto_yes, read_from)
    assert f"STDIN={tty if expected == 'TTY' else expected}" in out, out


def test_deployed_message_when_vhir_applied_the_controls(stub, tmp_path):
    out = _install(tmp_path, stub("  Forensic controls deployed:"))
    assert "Forensic controls deployed globally." in out


def test_no_deployed_message_when_vhir_kept_the_users_settings(stub, tmp_path):
    # the user's kept settings.json still names the hook; that's not "deployed"
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text('{"x": "forensic-audit.sh"}')
    out = _install(tmp_path, stub("  Forensic controls NOT applied to settings.json"))
    assert "Forensic controls deployed globally." not in out


def test_a_failed_client_setup_warns_and_the_install_goes_on(stub, tmp_path):
    out = _install(tmp_path, stub(rc=1))
    assert "WARN Client configuration failed" in out
    assert "Forensic controls deployed globally." not in out


def test_only_vhirs_own_status_line_counts(stub, tmp_path):
    out = _install(
        tmp_path, stub("  NOTE: Forensic controls deployed: none, see above")
    )
    assert "Forensic controls deployed globally." not in out
