"""setup-sift.sh's triage database checks name the DBs the release file list fetches.

The installer checks for the triage DBs three times: whether they already exist
(so the download is skipped), the validation after every download/build/skip
path, and the closing summary. Each must name the DBs the release file list
marks as fetched by default, not a copy of two names. These run the installer's
own blocks, found by their headings, under bash with the download stubbed, never
the installer. A fixture DB is added to the file list, marked fetched by
default, through a sitecustomize on the python the blocks call; the file list
is read by importing it, so the change shows wherever it is read. The same
sitecustomize can make that import fail, as a broken venv would, or make the
file list's reader fail.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
# The setup block runs from its heading to the next one; the summary block is the
# triage check after the data maintenance heading, up to the closing blank line.
HEADINGS = (
    "# --- windows-triage database setup ---\n",
    "\n# --- OpenCTI credential wizard ---",
    "# Data Maintenance\n",
    "if $INSTALL_TRIAGE; then",
    "if $INSTALL_RAG || $INSTALL_TRIAGE; then",
)


def _blocks() -> tuple[str, str]:
    """The setup and summary blocks, each heading found after the one before it;
    a heading not found fails the test here."""
    at, start = [], 0
    for heading in HEADINGS:
        start = SCRIPT.find(heading, start)
        assert start >= 0, f"setup-sift.sh has no {heading!r} after the last heading"
        at.append(start)
    return SCRIPT[at[0] : at[1]], SCRIPT[at[3] : at[4]]


DEFAULT_DB = "fixture_default.db"
SHIM = textwrap.dedent(
    """
    import os
    import sys

    if os.environ.get("TRIAGE_TEST_LIST_UNREADABLE"):
        sys.modules["windows_triage.release_manifest"] = None

    if os.environ.get("TRIAGE_TEST_LIST_READER_FAILS"):
        from windows_triage import release_manifest as _failing

        def _fail():
            raise OSError("fixture: the release file list can't be read")

        _failing.default_databases = _fail

    _name = os.environ.get("TRIAGE_TEST_DEFAULT_DB")
    if _name:
        try:
            from windows_triage import release_manifest as _manifest
        except ImportError:
            _manifest = None
        if _manifest is not None:
            _manifest.DATABASES = {**_manifest.DATABASES, _name: True}
    """
)


def _run(
    tmp_path: Path,
    add_default_db: bool,
    unreadable: bool = False,
    reader_fails: bool = False,
) -> list[str]:
    """Run the setup block then the summary block, with known_good.db and
    context.db installed and valid; return the lines printed. With
    ``unreadable``, the release file list can't be imported; with
    ``reader_fails``, it imports but reading its default DBs raises."""
    data = tmp_path / "inst" / "packages" / "windows-triage" / "data"
    data.mkdir(parents=True)
    for name in ("known_good.db", "context.db"):
        with sqlite3.connect(data / name) as db:
            db.execute("CREATE TABLE t (x)")
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(SHIM)
    py = tmp_path / "venv-python"
    py.write_text(
        "#!/bin/bash\n"
        'if [[ "$1 $2" == "-m windows_triage.scripts.download_databases" ]]; then\n'
        '  echo "DOWNLOAD $*"; exit 1\n'
        "fi\n"
        f'PYTHONPATH="{shim}" exec "{sys.executable}" "$@"\n'
    )
    py.chmod(0o755)
    setup, summary = _blocks()
    harness = "\n".join(
        [
            "set -euo pipefail",
            "BOLD= NC=",
            'info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }',
            'warn(){ echo "[WARN] $*"; }; uv(){ :; }',
            'prompt(){ echo "3"; }; prompt_yn(){ return 1; }',
            f'VENV_PYTHON="{py}"; INSTALL_DIR="{tmp_path / "inst"}"',
            "INSTALL_TRIAGE=true; INSTALL_RAG=false; AUTO_YES=true; LOCKED=()",
            setup,
            summary,
        ]
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    if add_default_db:
        env["TRIAGE_TEST_DEFAULT_DB"] = DEFAULT_DB
    if unreadable:
        env["TRIAGE_TEST_LIST_UNREADABLE"] = "1"
    if reader_fails:
        env["TRIAGE_TEST_LIST_READER_FAILS"] = "1"
    out = subprocess.run(
        ["bash", "-c", harness],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-2000:]
    return [ln.strip() for ln in out.stdout.splitlines()]


def test_setup_needs_only_the_dbs_fetched_by_default(tmp_path):
    lines = _run(tmp_path, add_default_db=False)
    assert [ln for ln in lines if ln.startswith(("[WARN]", "DOWNLOAD"))] == [], lines
    assert "[OK] known_good.db valid" in lines and "[OK] context.db valid" in lines


def test_a_missing_default_db_is_downloaded_not_called_existing(tmp_path):
    lines = _run(tmp_path, add_default_db=True)
    assert any(ln.startswith("DOWNLOAD") for ln in lines), lines


def test_the_validation_names_a_missing_default_db(tmp_path):
    lines = _run(tmp_path, add_default_db=True)
    assert f"[WARN] {DEFAULT_DB} missing or empty" in lines, lines


def test_the_summary_says_not_installed_when_a_default_db_is_missing(tmp_path):
    lines = _run(tmp_path, add_default_db=True)
    assert lines[-1].startswith("[WARN] Triage databases: not installed"), lines


def test_an_unreadable_file_list_counts_the_dbs_as_missing(tmp_path):
    """Both default DBs are installed but the file list can't be read: the setup
    says so once, never calls the DBs existing and goes on to the download, and
    the summary never says installed."""
    lines = _run(tmp_path, add_default_db=False, unreadable=True)
    warning = "[WARN] The triage release file list could not be read from the venv"
    assert sum(ln.startswith(warning) for ln in lines) == 1, lines
    assert lines[-1].startswith("[WARN] Triage databases: not installed"), lines
    assert not any(ln.startswith("[OK] Triage databases exist") for ln in lines), lines
    assert "[INFO] Downloading pre-built databases..." in lines, lines
    assert any(ln.startswith("DOWNLOAD") for ln in lines), lines


def test_a_failing_file_list_reader_takes_the_download_path(tmp_path):
    """The file list imports but reading its default DBs raises: the installed DBs
    are not called existing, the setup downloads, and the summary says not
    installed."""
    lines = _run(tmp_path, add_default_db=False, reader_fails=True)
    warning = "[WARN] The triage release file list could not be read from the venv"
    assert sum(ln.startswith(warning) for ln in lines) == 1, lines
    assert not any(ln.startswith("[OK] Triage databases exist") for ln in lines), lines
    assert "[INFO] Downloading pre-built databases..." in lines, lines
    assert any(ln.startswith("DOWNLOAD") for ln in lines), lines
    assert lines[-1].startswith("[WARN] Triage databases: not installed"), lines
