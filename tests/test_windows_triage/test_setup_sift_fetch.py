"""setup-sift.sh's build-from-source branch replaces a source's clone only when the
new clone succeeds; when it fails, the old clone stays and the run fails naming
the source.

These run the installer's triage block, found by its heading, under bash with
"2" (build from source) as the database choice, never the installer. The HOME's
.gitconfig points each source's GitHub URL at a fixture remote, and every other
GitHub URL at a path that does not exist, so nothing reaches the network. The
python the block calls is the test's own, with the release manifest's counts set
to zero so the fixture's few rows reach every floor.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from .test_build_release_checks import SHIM
from .test_fetch import SOURCES, _advance, _dir, _files, _head, _zero_counts
from .test_update_check import _git, _remote

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "setup-sift.sh").read_text()
_start = SCRIPT.index("# --- windows-triage database setup ---\n")
SETUP = SCRIPT[_start : SCRIPT.index("\n# --- OpenCTI credential wizard ---", _start)]
NAME = "LOLBAS"


def _install(tmp: Path) -> tuple[Path, Path, dict[str, str]]:
    """An install dir holding windows-triage's scripts, and a HOME pointing each
    source's URL at a fixture remote; returns both and each remote's head."""
    home = tmp / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        f'[url "{tmp / "nowhere"}/"]\n\tinsteadOf = https://github.com/\n'
    )
    entries = {_dir(e): e for e in SOURCES.values()}
    heads = {
        name: _remote(tmp, home, entry["repo"], "main", _files(name))
        for name, entry in entries.items()
    }
    wt = tmp / "inst" / "packages" / "windows-triage"
    shutil.copytree(ROOT / "packages/windows-triage/scripts", wt / "scripts")
    (wt / "data" / "sources").mkdir(parents=True)
    return tmp / "inst", home, heads


def _clone_dir(inst: Path) -> Path:
    return inst / "packages" / "windows-triage" / "data" / "sources" / NAME


def _old_clone(tmp: Path, inst: Path) -> Path:
    """data/sources/<NAME> as a clone of its fixture remote's head now."""
    dest = _clone_dir(inst)
    _git("clone", "-q", str(tmp / "remotes" / f"{NAME}.git"), str(dest))
    return dest


def _digest(path: Path) -> dict[str, str]:
    """Each entry under ``path``: a file's sha256, "" for a dir."""
    entries = {}
    for p in sorted(path.rglob("*")):
        body = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""
        entries[str(p.relative_to(path))] = body
    return entries


def _run(tmp: Path, inst: Path, home: Path):
    shim = tmp / "pyshim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(SHIM)
    counts = tmp / "counts.json"
    counts.write_text(json.dumps(_zero_counts()))
    py = tmp / "venv-python"
    py.write_text(f'#!/bin/bash\nPYTHONPATH="{shim}" exec "{sys.executable}" "$@"\n')
    py.chmod(0o755)
    harness = "\n".join(
        [
            "set -euo pipefail",
            "BOLD= NC= RED=",
            'info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }',
            'warn(){ echo "[WARN] $*"; }; err(){ echo "[ERROR] $*"; }; uv(){ :; }',
            'prompt(){ echo "2"; }; prompt_yn(){ return 1; }',
            f'VENV_PYTHON="{py}"; INSTALL_DIR="{inst}"',
            "INSTALL_TRIAGE=true; INSTALL_RAG=false; AUTO_YES=false; LOCKED=()",
            SETUP,
        ]
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "TRIAGE_TEST_COUNTS": str(counts),
    }
    return subprocess.run(
        ["bash", "-c", harness],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _tail(run) -> str:
    return f"rc {run.returncode}: {run.stdout[-3000:]} {run.stderr[-2000:]}"


def test_an_existing_clone_is_replaced_when_the_new_clone_succeeds(tmp_path):
    inst, home, _ = _install(tmp_path)
    old = _old_clone(tmp_path, inst)
    new = _advance(tmp_path, NAME)
    run = _run(tmp_path, inst, home)
    assert _head(old) == new, _tail(run)


def test_a_failed_clone_keeps_the_old_clone_and_fails_naming_it(tmp_path):
    inst, home, _ = _install(tmp_path)
    old = _old_clone(tmp_path, inst)
    before = _digest(old)
    remotes = tmp_path / "remotes"
    (remotes / f"{NAME}.git").rename(remotes / f"{NAME}.gone")
    run = _run(tmp_path, inst, home)
    assert _digest(old) == before, f"the old clone changed: {_tail(run)}"
    assert run.returncode != 0, _tail(run)
    lines = (run.stdout + run.stderr).splitlines()
    named = [ln for ln in lines if ln.startswith("ERROR:") and f"{NAME}:" in ln]
    assert named, _tail(run)


def test_a_source_with_no_clone_is_cloned(tmp_path):
    inst, home, heads = _install(tmp_path)
    run = _run(tmp_path, inst, home)
    assert _head(_clone_dir(inst)) == heads[NAME], _tail(run)
