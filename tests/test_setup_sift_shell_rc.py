"""setup-sift.sh edits only its own lines in the shell rc, and keeps a symlinked rc a symlink.

The installer and its uninstall deleted or rewrote any line mentioning
.vhir/venv/bin, including a user's own PATH line, and `sed -i` replaced a
symlinked rc (dotfile managers) with a plain file. These run the installer's
own rc blocks (the examiner export, the PATH phase and uninstall's shell
profile step) in a scratch HOME, never the installer or a real rc.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()


def _block(start: str, end: str) -> str:
    i = SCRIPT.index(start)
    return SCRIPT[i : SCRIPT.index(end, i)]


EXAMINER = _block("# Write VHIR_EXAMINER to shell profile", "# --- Password setup ---")
PATH_PHASE = _block("# Phase 12: Add venv to PATH", "# Phase 13:")
UNINSTALL = _block("    # [5] Shell profile", "    # [6] Gateway config")

PRELUDE = """set -euo pipefail
ok() { echo "OK $*"; }; info() { echo "INFO $*"; }; warn() { echo "WARN $*"; }
prompt_yn_strict() { return 0; }  # the user's "y"
BOLD=; NC=
VENV_DIR="$HOME/.vhir/venv"
CASE_DIR="${CASE_DIR:-$HOME/cases}"
EXAMINER_NAME="${EXAMINER_NAME:-alice}"
"""

# a user's own PATH lines: one that lists other directories too, and the bare form
USER_LINE = 'export PATH="$HOME/.vhir/venv/bin:$HOME/go/bin:$PATH"'
BARE_LINE = 'export PATH="$HOME/.vhir/venv/bin:$PATH"'
OWN = ("# Valhuntir Platform", "export VHIR_EXAMINER=", "export VHIR_CASES_DIR=")


def _run(home: Path, *steps: str, **env: str) -> subprocess.CompletedProcess:
    bin_dir = home / "stub-bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "register-python-argcomplete"
    stub.write_text("#!/bin/sh\n")
    stub.chmod(0o755)
    text = {"install": EXAMINER + PATH_PHASE, "uninstall": UNINSTALL}
    out = None
    for step in steps:
        out = subprocess.run(
            ["/bin/bash", "-c", PRELUDE + text[step]],
            env={"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin", **env},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert out.returncode == 0, (step, out.stdout + out.stderr)
    return out


def _lines(path: Path) -> list[str]:
    return path.read_text().splitlines()


def _own_lines(lines: list[str]) -> list[str]:
    return [
        ln
        for ln in lines
        if ln.startswith(OWN)
        or "# vhir-path" in ln
        or "register-python-argcomplete vhir" in ln
    ]


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


def _linked_rc(home: Path, content: str) -> Path:
    target = home / "dotfiles" / "bashrc"
    target.parent.mkdir()
    target.write_text(content)
    (home / ".bashrc").symlink_to("dotfiles/bashrc")  # relative, as stow makes it
    return target


def test_a_pre_rename_install_keeps_the_users_path_lines(home):
    # the old marker and no VHIR_EXAMINER yet, so the examiner step writes the new marker
    rc = home / ".bashrc"
    rc.write_text(f"# my stuff\n# ValiHuntIR Platform\n{USER_LINE}\n{BARE_LINE}\n")
    _run(home, "install")
    lines = _lines(rc)
    assert lines.count(USER_LINE) == 1 and lines.count(BARE_LINE) == 1
    assert sum("# vhir-path" in ln for ln in lines) == 1
    assert "# ValiHuntIR Platform" not in lines


def test_uninstall_removes_only_valhuntirs_own_lines(home):
    rc = home / ".bashrc"
    rc.write_text(f"# my stuff\n{USER_LINE}\n{BARE_LINE}\n")
    _run(home, "install")
    own = "\n".join(_own_lines(_lines(rc)))
    for kind in (*OWN, "# vhir-path", "register-python-argcomplete vhir"):
        assert kind in own  # each of Valhuntir's lines is there to be removed
    _run(home, "uninstall")
    lines = _lines(rc)
    assert lines.count(USER_LINE) == 1 and lines.count(BARE_LINE) == 1
    assert _own_lines(lines) == []


def test_a_re_run_keeps_a_symlinked_rc_a_symlink(home):
    target = _linked_rc(home, "# my stuff\n")
    _run(home, "install", "install")
    assert (home / ".bashrc").is_symlink()
    assert sum("# vhir-path" in ln for ln in _lines(target)) == 1


def test_uninstall_keeps_a_symlinked_rc_a_symlink(home):
    target = _linked_rc(home, "# my stuff\n")
    _run(home, "install", "uninstall")
    assert (home / ".bashrc").is_symlink()
    assert _own_lines(_lines(target)) == [] and "# my stuff" in _lines(target)


def test_a_pre_rename_marker_behind_a_symlink_is_cleaned_in_the_target(home):
    target = _linked_rc(home, "# my stuff\n# ValiHuntIR Platform\n")
    _run(home, "install")
    assert (home / ".bashrc").is_symlink()
    assert "# ValiHuntIR Platform" not in _lines(target)


def test_anchor_a_fresh_rc_gets_the_same_lines_and_a_re_run_adds_none(home):
    rc = home / ".bashrc"
    rc.write_text('# my stuff\nalias ll="ls -l"\n')
    _run(home, "install")
    first = rc.read_text()
    venv_bin = home / ".vhir" / "venv" / "bin"
    assert first == (
        '# my stuff\nalias ll="ls -l"\n\n# Valhuntir Platform\n'
        'export VHIR_EXAMINER="alice"\n'
        f'export PATH="{venv_bin}:$PATH"  # vhir-path\n'
        f'export VHIR_CASES_DIR="{home}/cases"\n'
        'eval "$(register-python-argcomplete vhir)"\n'
    )
    _run(home, "install")
    assert rc.read_text() == first


def test_anchor_no_rc_creates_none_and_warns(home):
    out = _run(home, "install")
    assert not (home / ".bashrc").exists() and not (home / ".zshrc").exists()
    assert "WARN No .bashrc or .zshrc found" in out.stdout


# --- A user's own lines that mention VHIR_EXAMINER or VHIR_CASES_DIR -------------

USER_VHIR_LINES = {
    "VHIR_CASES_DIR": [
        "alias cases='cd \"$VHIR_CASES_DIR\"'",
        "if [ -d /srv/cases ]; then",
        "    export VHIR_CASES_DIR=/srv/cases",
        "fi",
    ],
    "VHIR_EXAMINER": [
        "alias who-ir='echo \"$VHIR_EXAMINER\"'",
        'if [ -n "${SUDO_USER:-}" ]; then',
        '    export VHIR_EXAMINER="$SUDO_USER"',
        "fi",
    ],
}


def _with_user_lines(home: Path, *names: str) -> Path:
    rc = home / ".bashrc"
    lines = ["# my stuff"] + [ln for n in names for ln in USER_VHIR_LINES[n]]
    rc.write_text("\n".join(lines) + "\n")
    return rc


def _has_block(lines: list[str], block: list[str]) -> bool:
    return any(lines[i : i + len(block)] == block for i in range(len(lines)))


@pytest.mark.parametrize(
    "name,ours",
    [
        ("VHIR_CASES_DIR", 'export VHIR_CASES_DIR="{home}/cases"'),
        ("VHIR_EXAMINER", 'export VHIR_EXAMINER="alice"'),
    ],
)
def test_a_users_lines_mentioning_a_vhir_variable_still_get_ours(home, name, ours):
    rc = _with_user_lines(home, name)
    _run(home, "install")
    lines = _lines(rc)
    assert _has_block(lines, USER_VHIR_LINES[name])  # the user's lines, unchanged
    assert ours.format(home=home) in lines  # and ours is written


def test_uninstall_removes_only_our_vhir_exports(home):
    rc = _with_user_lines(home, "VHIR_CASES_DIR", "VHIR_EXAMINER")
    _run(home, "install")
    before = _lines(rc)
    assert f'export VHIR_CASES_DIR="{home}/cases"' in before
    assert 'export VHIR_EXAMINER="alice"' in before
    _run(home, "uninstall")
    lines = _lines(rc)
    for name in USER_VHIR_LINES:
        assert _has_block(lines, USER_VHIR_LINES[name])
    assert not [ln for ln in lines if ln.startswith("export VHIR_")]
    syntax = subprocess.run(["bash", "-n", str(rc)], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr  # no if-block left with an empty body


def test_anchor_a_re_run_updates_our_exports_in_place(home):
    rc = home / ".bashrc"
    rc.write_text("# my stuff\n")
    _run(home, "install")
    _run(home, "install", EXAMINER_NAME="bob", CASE_DIR=f"{home}/other")
    lines = _lines(rc)
    assert [ln for ln in lines if ln.startswith("export VHIR_")] == [
        'export VHIR_EXAMINER="bob"',
        f'export VHIR_CASES_DIR="{home}/other"',
    ]
