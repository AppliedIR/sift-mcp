"""The triage download installs the data release this code's manifest names.

The manifest holds one release's per-table counts, and a downloaded DB must match
them exactly. So the download must fetch that release by its tag, never the newest
triage-db-* release, and refuse any other tag. Each case serves a local mirror: a
sitecustomize on the python the download runs under replaces ``urlopen`` with a
reader of the mirror dir, which holds each release's assets and the release list,
newest first, as the GitHub API would. The pinned release's counts are set to its
fixture DBs' counts; a newer release's DBs hold one more row, so its counts differ.
The download runs as the installers run it: as a module, directly, and through
setup-sift.sh's and quickstart-lite.sh's own download blocks.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import zstandard
from windows_triage import release_manifest
from windows_triage.db.schemas import CONTEXT_SCHEMA, KNOWN_GOOD_SCHEMA

ROOT = Path(__file__).parent.parent
PINNED = release_manifest.RELEASE_TAG
NEWER = "triage-db-v2099.01.01-example"
TAG_FILE = "installed_release.json"
MODULE = "windows_triage.scripts.download_databases"
LIST_URL = "https://api.github.com/repos/AppliedIR/sift-mcp/releases?per_page=100"

SHIM = textwrap.dedent(
    """
    import io
    import json
    import os
    import urllib.error
    import urllib.request
    from pathlib import Path

    _mirror = os.environ.get("TRIAGE_TEST_MIRROR")
    if _mirror:
        from windows_triage import release_manifest as _manifest

        _root = Path(_mirror)
        _counts = json.loads((_root / "counts.json").read_text())
        _manifest.COUNTS = {**_manifest.COUNTS, **_counts}
        _releases = json.loads((_root / "releases.json").read_text())
        _api = "https://api.github.com/repos/AppliedIR/sift-mcp/releases"

        class _Response(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.headers = {"Content-Length": str(len(data))}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()
                return False

        def _urlopen(req, timeout=None):
            url = getattr(req, "full_url", req)
            with open(_root / "requests.log", "a") as log:
                log.write(url + "\\n")
            if url == _api + "?per_page=100":
                return _Response(json.dumps(_releases).encode())
            for rel in _releases:
                if url == f"{_api}/tags/{rel['tag_name']}":
                    return _Response(json.dumps(rel).encode())
                for asset in rel["assets"]:
                    if url == asset["url"]:
                        path = _root / rel["tag_name"] / asset["name"]
                        return _Response(path.read_bytes())
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        urllib.request.urlopen = _urlopen
    """
)


def _make_db(path: Path, schema: str, rows: list[tuple[str, dict]]) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(schema)
    for table, values in rows:
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        conn.execute(
            f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(values.values())
        )
    conn.commit()
    conn.close()


def _release(mirror: Path, tag: str, lolbins: int) -> dict:
    """A release dir of fixture DBs (``lolbins`` rows in context.db's lolbins) and
    its checksums file; return its API record."""
    where = mirror / tag
    where.mkdir(parents=True)
    kg, ctx = where / "known_good.db", where / "context.db"
    path = {
        "path_normalized": "\\windows\\system32\\example.exe",
        "directory_normalized": "\\windows\\system32",
        "filename_lower": "example.exe",
        "os_versions": "[]",
    }
    _make_db(kg, KNOWN_GOOD_SCHEMA, [("baseline_files", path)])
    rows = [("lolbins", {"filename_lower": f"example{n}.exe"}) for n in range(lolbins)]
    rows.append(("vulnerable_drivers", {"filename_lower": "example.sys"}))
    _make_db(ctx, CONTEXT_SCHEMA, rows)
    lines = []
    for db in (kg, ctx):
        zst = where / f"{db.name}.zst"
        zst.write_bytes(zstandard.ZstdCompressor().compress(db.read_bytes()))
        lines.append(f"{hashlib.sha256(zst.read_bytes()).hexdigest()}  {zst.name}\n")
    (where / "checksums.sha256").write_text("".join(lines))
    names = ("known_good.db.zst", "context.db.zst", "checksums.sha256")
    assets = [{"name": n, "url": f"https://mirror.invalid/{tag}/{n}"} for n in names]
    return {"tag_name": tag, "assets": assets}


def _mirror(tmp_path: Path, newer: bool = True) -> Path:
    """The mirror: the pinned release, and with ``newer`` a newer one listed first
    whose context.db has one more lolbins row. The counts are the pinned one's."""
    mirror = tmp_path / "mirror"
    releases = [_release(mirror, PINNED, lolbins=1)]
    if newer:
        releases.insert(0, _release(mirror, NEWER, lolbins=2))
    counts = {
        name: release_manifest.table_counts(mirror / PINNED / name)
        for name in ("known_good.db", "context.db")
    }
    (mirror / "releases.json").write_text(json.dumps(releases))
    (mirror / "counts.json").write_text(json.dumps(counts))
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(SHIM)
    return mirror


def _env(tmp_path: Path, mirror: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "PYTHONPATH": str(tmp_path / "shim"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GITHUB_TOKEN": "test-token-example",
        "TRIAGE_TEST_MIRROR": str(mirror),
    }


def _download(tmp_path: Path, mirror: Path, *args: str):
    dest = tmp_path / "dest"
    out = subprocess.run(
        [sys.executable, "-m", MODULE, "--dest", str(dest), *args],
        env=_env(tmp_path, mirror),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return out, dest


def _installed(dest: Path) -> str | None:
    try:
        return json.loads((dest / TAG_FILE).read_text())["tag_name"]
    except FileNotFoundError:
        return None


def _requests(mirror: Path) -> list[str]:
    log = mirror / "requests.log"
    return log.read_text().splitlines() if log.is_file() else []


def _venv_python(tmp_path: Path) -> Path:
    py = tmp_path / "venv-python"
    py.write_text(f'#!/bin/bash\nexec "{sys.executable}" "$@"\n')
    py.chmod(0o755)
    return py


def _bash(tmp_path: Path, mirror: Path, lines: list[str]) -> list[str]:
    out = subprocess.run(
        ["bash", "-c", "\n".join(["set -euo pipefail", *lines])],
        env=_env(tmp_path, mirror),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-3000:]
    return [ln.strip() for ln in out.stdout.splitlines()]


# --- the download module ----------------------------------------------------------


def test_a_newer_release_is_passed_over_for_the_pinned_one(tmp_path):
    mirror = _mirror(tmp_path)
    out, dest = _download(tmp_path, mirror)
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-3000:]
    assert _installed(dest) == PINNED
    assert LIST_URL not in _requests(mirror), "the download read the release list"


def test_the_pinned_release_alone_installs(tmp_path):
    mirror = _mirror(tmp_path, newer=False)
    out, dest = _download(tmp_path, mirror)
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-3000:]
    assert _installed(dest) == PINNED


def test_another_tag_is_refused_naming_the_pinned_tag(tmp_path):
    mirror = _mirror(tmp_path)
    out, dest = _download(tmp_path, mirror, "--tag", NEWER)
    said = out.stdout + out.stderr
    assert out.returncode == 1, said[-3000:]
    assert PINNED in said and "newer Valhuntir" in said, said[-3000:]
    assert _requests(mirror) == [], "a refused tag was fetched"
    assert not (dest / "context.db").exists() and _installed(dest) is None


def test_the_pinned_tag_by_name_installs(tmp_path):
    mirror = _mirror(tmp_path)
    out, dest = _download(tmp_path, mirror, "--tag", PINNED)
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-3000:]
    assert _installed(dest) == PINNED


# --- the installers' own download blocks ------------------------------------------


def test_setup_sift_installs_the_pinned_release(tmp_path):
    script = (ROOT / "setup-sift.sh").read_text()
    start = script.index("# --- windows-triage database setup ---\n")
    block = script[start : script.index("\n# --- OpenCTI credential wizard ---", start)]
    mirror = _mirror(tmp_path)
    inst = tmp_path / "inst"
    lines = _bash(
        tmp_path,
        mirror,
        [
            "BOLD= NC=",
            'info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }',
            'warn(){ echo "[WARN] $*"; }; err(){ echo "[ERR] $*"; }; uv(){ :; }',
            'prompt(){ echo "3"; }; prompt_yn(){ return 1; }',
            f'VENV_PYTHON="{_venv_python(tmp_path)}"; INSTALL_DIR="{inst}"',
            "INSTALL_TRIAGE=true; INSTALL_RAG=false; AUTO_YES=true; LOCKED=()",
            block,
        ],
    )
    assert "[OK] Databases downloaded and verified" in lines, lines
    assert _installed(inst / "packages" / "windows-triage" / "data") == PINNED


def test_quickstart_lite_installs_the_pinned_release(tmp_path):
    script = (ROOT / "quickstart-lite.sh").read_text()
    start = script.index('header "Phase 2: Triage Databases"\n')
    block = script[start : script.index("# Phase 3: RAG Index", start)]
    mirror = _mirror(tmp_path)
    data = tmp_path / "triage-db"
    lines = _bash(
        tmp_path,
        mirror,
        [
            "BOLD= NC=",
            'header(){ echo "=== $1 ==="; }; ok(){ echo "[OK] $*"; }',
            'warn(){ echo "[WARN] $*"; }',
            f'VENV_PYTHON="{_venv_python(tmp_path)}"; DB_DIR="{data}"',
            "INSTALL_TRIAGE=true",
            block,
        ],
    )
    assert [ln for ln in lines if ln.startswith("[WARN]")] == [], lines
    assert _installed(data) == PINNED
