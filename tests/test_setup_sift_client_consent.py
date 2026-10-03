"""setup-sift.sh lets vhir setup client ask only the user at a terminal.

vhir asks before changing a user's own Claude files, and only when stdin is
a terminal. The installer ran it with -y and stdin inherited (under
`curl | bash`, the script itself). Now -y gives it /dev/null (no consent),
and otherwise it gets the installer's terminal. "Forensic controls deployed
globally" is printed only if ~/.claude/settings.json really has the hook.
The two blocks are taken from the script and run with a stub vhir.
"""

import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
# From the optional comment through the call's `|| warn` line.
CLIENT = re.search(
    r"(?:# vhir asks before changing.*?)?"
    r"\"\$VENV_DIR/bin/vhir\" setup client.*?\|\| warn [^\n]*\n",
    SCRIPT,
    re.S,
).group(0)
MESSAGE = re.search(r"# Global deployment message.*?\nfi\n", SCRIPT, re.S).group(0)


def _bash(snippet, home, stdin=None, **env):
    return subprocess.run(
        ["bash", "-c", 'warn() { echo "WARN $*"; }\n' + snippet],
        env={"PATH": "/usr/bin:/bin", "HOME": str(home), **env},
        stdin=stdin,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture
def stub(tmp_path):
    vhir = tmp_path / "venv" / "bin" / "vhir"
    vhir.parent.mkdir(parents=True)
    vhir.write_text('#!/bin/bash\necho "STDIN=$(readlink /proc/self/fd/0)"\n')
    vhir.chmod(0o755)
    return tmp_path


@pytest.mark.parametrize(
    "auto_yes,read_from,expected",
    [
        ("true", "TTY", "/dev/null"),
        ("false", "TTY", "TTY"),
        ("false", "/nonexistent", "/dev/null"),
    ],
    ids=["-y", "terminal", "no-terminal"],
)
def test_client_setup_gets_a_terminal_only_without_y(
    stub, auto_yes, read_from, expected
):
    tty = stub / "fake-tty"
    tty.write_text("")
    with open(tty) as terminal:  # the installer's own stdin is the terminal
        out = _bash(
            CLIENT,
            stub,
            stdin=terminal,
            AUTO_YES=auto_yes,
            READ_FROM=str(tty) if read_from == "TTY" else read_from,
            VENV_DIR=str(stub / "venv"),
            CLIENT="claude-code",
            SIFT_URL="http://x",
        )
    assert f"STDIN={tty if expected == 'TTY' else expected}" in out, out


@pytest.mark.parametrize("has_hook", [True, False])
def test_deployed_message_only_when_the_hook_is_in_settings(tmp_path, has_hook):
    claude = tmp_path / ".claude"
    claude.mkdir()
    hooks = '{"hooks": {"PostToolUse": [{"command": "/x/forensic-audit.sh"}]}}'
    (claude / "settings.json").write_text(hooks if has_hook else "{}")
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"forensic-mcp": {}}}')
    out = _bash("BOLD=; NC=\n" + MESSAGE, tmp_path)
    assert ("Forensic controls deployed globally." in out) is has_hook
