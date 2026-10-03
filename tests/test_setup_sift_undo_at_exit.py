"""setup-sift.sh repeats vhir's undo block as its last output.

When `vhir setup client -y` changes the user's own Claude files it prints the
commands that undo it, but the installer's summary followed and scrolled them
away. The installer keeps the block from vhir's output and prints it again
after the summary. The client block and the final block are taken from the
script and run under its own shell options with a stub vhir.
"""

import re
import subprocess
from pathlib import Path

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_call = SCRIPT.index('"$VENV_DIR/bin/vhir" setup client')
CLIENT = SCRIPT[
    SCRIPT.rfind("\nCLIENT_LOG=$(mktemp)", 0, _call) + 1 : SCRIPT.index(
        'rm -f "$CLIENT_LOG"\n', _call
    )
    + len('rm -f "$CLIENT_LOG"\n')
]
FINAL = re.search(r"# vhir's undo block, repeated.*?\nfi\n", SCRIPT, re.S).group(0)
AFTER = SCRIPT[SCRIPT.index(FINAL) + len(FINAL) :]


def _install(tmp_path, vhir_says):
    vhir = tmp_path / "venv" / "bin" / "vhir"
    vhir.parent.mkdir(parents=True, exist_ok=True)
    vhir.write_text("#!/bin/bash\ncat <<'OUT'\n" + vhir_says + "OUT\n")
    vhir.chmod(0o755)
    prologue = (
        'set -euo pipefail\nwarn() { echo "WARN $*"; }\nBOLD=; RED=; NC=\n'
        'ASK_USER_FILES=""; CLIENT_IN=/dev/null\n'
    )
    summary = 'echo "  To start an investigation:"\necho ""\n'
    return subprocess.run(
        ["bash", "-c", prologue + CLIENT + summary + FINAL],
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "VENV_DIR": str(tmp_path / "venv"),
            "CLIENT": "claude-code",
            "SIFT_URL": "http://x",
        },
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def test_the_undo_block_is_the_last_output_and_pasting_it_restores(tmp_path):
    home = tmp_path / "my home"  # a space in every path
    files = {}
    for name, old, new in (
        ("settings.json", b'{"mine": 1}\n', b'{"vhir": 1}\n'),
        (".claude.json", b'{"projects": {}}\n', b'{"mcpServers": {}}\n'),
    ):
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(new)
        bak = home / f"{name}.vhir-backup-20261003T120000Z"
        bak.write_bytes(old)
        files[path] = (bak, old)
    lines = []
    for path, (bak, _) in files.items():
        if path.name == ".claude.json":
            lines.append(
                "    # This also reverts what Claude Code saved there since;"
                " close Claude Code first."
            )
        lines.append(f"    cp -p '{bak}' '{path}'")
    block = (
        "\n  vhir setup client -y changed these files. To undo, run these in a\n"
        "  normal terminal (not inside a Claude session):\n" + "\n".join(lines) + "\n"
    )
    out = _install(tmp_path, "  Forensic controls deployed:\n" + block)
    tail = out.rstrip("\n").split("\n")
    # the header, then the block verbatim, and nothing after it
    assert tail[-len(lines) - 3] == (
        "=== Your own Claude settings were changed (backups kept) ==="
    )
    assert tail[-len(lines) - 2 :] == block.strip("\n").split("\n")
    assert out.index("To start an investigation") < out.rindex("cp -p")
    subprocess.run(["bash", "-c", "\n".join(tail[-len(lines) :])], check=True)
    for path, (_, old) in files.items():
        assert path.read_bytes() == old


def test_anchor_a_fresh_install_prints_no_block(tmp_path):
    out = _install(tmp_path, "  Forensic controls deployed:\n  Generated: x\n")
    assert "were changed" not in out and "cp -p" not in out


def test_nothing_prints_after_the_repeated_block():
    assert not re.search(r"\b(echo|printf|info|ok|warn|header)\b", AFTER), AFTER
