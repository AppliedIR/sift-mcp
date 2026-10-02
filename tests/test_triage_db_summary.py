"""setup-sift.sh's closing summary says the triage databases are installed
only when both are there; otherwise it warns, with the download command.
(windows-triage won't start without them.) Runs the installer's own text."""

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
    return text[start:end]


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
    script = "\n".join(
        [
            "set -euo pipefail",
            'ok(){ echo "[OK] $*"; }; warn(){ echo "[WARN] $*"; }',
            f'INSTALL_TRIAGE=true; DB_DIR="{db_dir}"; VENV_PYTHON=/venv/bin/python',
            _summary(),
        ]
    )
    run = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    out = run.stdout
    command = (
        f"/venv/bin/python -m windows_triage.scripts.download_databases --dest {db_dir}"
    )
    if installed:
        assert out.startswith("[OK] Triage databases: installed"), out
    else:
        assert "[OK]" not in out and out.startswith("[WARN] Triage databases"), out
        assert command in out
