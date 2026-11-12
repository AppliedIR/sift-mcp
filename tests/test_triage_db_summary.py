"""setup-sift.sh's closing summary says the triage databases are installed
only when both are there; otherwise it warns, with the download command.
(windows-triage won't start without them.) Runs the installer's own text,
with a stub venv python that prints the release file list's default DBs."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SETUP = Path(__file__).parent.parent / "setup-sift.sh"


def _summary() -> str:
    text = SETUP.read_text()
    # The summary is the last INSTALL_TRIAGE block before the last of these.
    end = text.rindex("\nif $INSTALL_RAG || $INSTALL_TRIAGE; then")
    start = text.rindex("\nif $INSTALL_TRIAGE; then\n", 0, end)
    # It checks with the setup's file-list read and presence check
    fn = text.index("\n    TRIAGE_DBS=$(")
    fn_end = text.index("\n    }\n", fn) + len("\n    }\n")
    return text[fn:fn_end] + text[start:end]


def _stub_python(tmp_path: Path) -> Path:
    """A venv python that answers only the summary's read of the release file
    list's default DBs, with the two the release fetches."""
    py = tmp_path / "venv-python"
    py.write_text(
        "#!/bin/sh\n"
        'case "$1 $2" in\n'
        '  "-c "*release_manifest*default_databases*)\n'
        '    echo "known_good.db context.db" ;;\n'
        "  *) exit 1 ;;\n"
        "esac\n"
    )
    py.chmod(0o755)
    return py


def _run_summary(db_dir: Path, venv_python: Path) -> str:
    script = "\n".join(
        [
            "set -euo pipefail",
            'ok(){ echo "[OK] $*"; }; warn(){ echo "[WARN] $*"; }',
            f'INSTALL_TRIAGE=true; DB_DIR="{db_dir}"; VENV_PYTHON="{venv_python}"',
            _summary(),
        ]
    )
    run = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    return run.stdout


@pytest.mark.parametrize(
    "dbs,installed",
    [
        ({"known_good.db": b"x", "context.db": b"x"}, True),
        ({}, False),  # the download failed
        ({"known_good.db": b"x"}, False),
        ({"known_good.db": b"x", "context.db": b""}, False),
    ],
)
def test_triage_summary_matches_the_databases(tmp_path, dbs, installed):
    db_dir = tmp_path / "data"
    db_dir.mkdir()
    for name, data in dbs.items():
        (db_dir / name).write_bytes(data)
    py = _stub_python(tmp_path)
    out = _run_summary(db_dir, py)
    command = f"{py} -m windows_triage.scripts.download_databases --dest {db_dir}"
    if installed:
        assert out.startswith("[OK] Triage databases: installed"), out
    else:
        assert "[OK]" not in out and out.startswith("[WARN] Triage databases"), out
        assert command in out


def test_without_the_venv_python_the_summary_warns_and_counts_them_missing(tmp_path):
    db_dir = tmp_path / "data"
    db_dir.mkdir()
    for name in ("known_good.db", "context.db"):
        (db_dir / name).write_bytes(b"x")
    py = tmp_path / "no-venv-python"
    out = _run_summary(db_dir, py)
    lines = out.splitlines()
    assert lines[0] == (
        f"[WARN] The triage release file list could not be read from the venv ({py});"
        " the databases count as missing"
    ), out
    assert "[OK]" not in out, out
    assert lines[1].startswith("[WARN] Triage databases: not installed"), out
    assert f"{py} -m windows_triage.scripts.download_databases --dest {db_dir}" in out
