"""setup-sift.sh offers Codex and refuses Claude Desktop.

Only the client block runs, in a scratch HOME; nothing is installed.
"""

import subprocess
from pathlib import Path

import pytest

TEXT = (Path(__file__).resolve().parents[1] / "setup-sift.sh").read_text()
START = "# Prompt for client if not set via --client flag"
END = "# vhir setup client -y changes the user's own Claude files"
PROLOGUE = (
    "set -euo pipefail\nRED=; NC=\n"
    'err() { echo "ERROR $*"; }\nprompt() { echo "$CHOICE"; }\n'
)


def _run(tmp_path, client="", choice="1", auto="false"):
    block = TEXT[TEXT.index(START) : TEXT.index(END)]
    script = tmp_path / "block.sh"
    script.write_text(
        PROLOGUE
        + f'CLIENT="{client}"\nAUTO_YES={auto}\n'
        + block
        + 'echo "CLIENT=$CLIENT"\n'
    )
    p = subprocess.run(
        ["/bin/bash", str(script)],
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "CHOICE": choice},
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.returncode, p.stdout + p.stderr


@pytest.mark.parametrize("choice,client", [("1", "claude-code"), ("2", "codex"),
                                           ("3", "librechat"), ("4", "other")])  # fmt: skip
def test_the_menu_offers_codex_and_no_desktop(tmp_path, choice, client):
    rc, out = _run(tmp_path, choice=choice)
    assert rc == 0 and f"CLIENT={client}" in out, out
    assert "Claude Desktop" not in out


def test_claude_desktop_is_refused_with_the_way_forward(tmp_path):
    rc, out = _run(tmp_path, client="claude-desktop")
    assert rc == 1
    assert "Claude Desktop is no longer supported" in out and "--client=codex" in out
    assert "CLIENT=" not in out
