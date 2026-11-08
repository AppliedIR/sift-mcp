"""The installed triage release tag, and the download's count check.

Each case installs from a local fixture release: ``_fetch_release``, ``_get_asset_url``
and ``_download_asset`` are patched to serve the fixture dir's files, and the retry
sleep is patched out. The fixture DBs are a few rows each, so a case that needs a
passing verify sets the manifest's counts to the fixture's counts (or, on a tree with
the row floor constants and no manifest, sets those floors to 1).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
import zstandard
from windows_triage.db.schemas import CONTEXT_SCHEMA, KNOWN_GOOD_SCHEMA
from windows_triage.scripts import download_databases as dd

TAG = "triage-db-v2099.01.01"
PRIOR_TAG = "triage-db-v2098.01.01"
TAG_FILE = "installed_release.json"
INSTALLED = ("known_good.db", "context.db")
FLOORS = ("MIN_BASELINE_FILES", "MIN_LOLBINS", "MIN_VULNERABLE_DRIVERS")
GONE = "the old tag file is gone and no tag file is left"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    query = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    names = [r[0] for r in conn.execute(query) if r[0] != "sources"]
    counts = {n: conn.execute(f"SELECT COUNT(*) FROM {n}").fetchone()[0] for n in names}
    conn.close()
    return counts


def _fixture_dbs(where: Path, marker: str = "a") -> dict[str, Path]:
    where.mkdir(parents=True, exist_ok=True)
    kg = where / "known_good.db"
    ctx = where / "context.db"
    _make_db(
        kg,
        KNOWN_GOOD_SCHEMA,
        [
            (
                "baseline_files",
                {
                    "path_normalized": f"\\windows\\system32\\{marker}.exe",
                    "directory_normalized": "\\windows\\system32",
                    "filename_lower": f"{marker}.exe",
                    "os_versions": "[]",
                },
            )
        ],
    )
    _make_db(
        ctx,
        CONTEXT_SCHEMA,
        [
            ("lolbins", {"filename_lower": f"{marker}.exe"}),
            ("vulnerable_drivers", {"filename_lower": f"{marker}.sys"}),
        ],
    )
    return {"known_good.db": kg, "context.db": ctx}


def _release_dir(where: Path, dbs: dict[str, Path], checksums: str = "all") -> Path:
    """A fixture release: the .zst assets and, per ``checksums``, a checksums.sha256
    listing all of them ("all"), all but context.db.zst ("drop-context"), all with a
    wrong context.db.zst hash ("bad-context"), or no checksums file ("none")."""
    where.mkdir(parents=True)
    lines = []
    for name, src in dbs.items():
        zst = where / f"{name}.zst"
        zst.write_bytes(zstandard.ZstdCompressor().compress(src.read_bytes()))
        digest = _sha256(zst)
        if name == "context.db" and checksums == "drop-context":
            continue
        if name == "context.db" and checksums == "bad-context":
            digest = "0" * 64
        lines.append(f"{digest}  {zst.name}\n")
    if checksums != "none":
        (where / "checksums.sha256").write_text("".join(lines))
    return where


def _serve(monkeypatch, release: Path) -> list[float]:
    """Serve ``release`` through the three download seams; return the sleeps made."""
    sleeps: list[float] = []

    def fetch_release(tag="latest"):
        files = sorted(release.iterdir())
        return {
            "tag_name": TAG,
            "assets": [{"name": p.name, "url": str(p)} for p in files],
        }

    def get_asset_url(rel, asset_name):
        path = release / asset_name
        return str(path) if path.is_file() else None

    def download_asset(url, dest):
        shutil.copyfile(url, dest)

    monkeypatch.setattr(dd, "_fetch_release", fetch_release)
    monkeypatch.setattr(dd, "_get_asset_url", get_asset_url)
    monkeypatch.setattr(dd, "_download_asset", download_asset)
    monkeypatch.setattr(dd.time, "sleep", sleeps.append)
    return sleeps


def _set_counts(
    monkeypatch, dbs: dict[str, Path], off_by_one: str | None = None
) -> None:
    """Make the release's expected counts the fixture's (``off_by_one`` names one
    "db:table" whose expected count is one more than the fixture holds). On a tree with
    a manifest, its counts table is patched; on a tree with the floor constants and no
    manifest, the floors are set to 1 when the counts are to pass."""
    try:
        from windows_triage import release_manifest
    except ImportError:
        release_manifest = None
    want = {name: _counts(path) for name, path in dbs.items()}
    if off_by_one:
        db, table = off_by_one.split(":")
        want[db][table] += 1
    if release_manifest is not None:
        counts = {**release_manifest.COUNTS, **want}
        monkeypatch.setattr(release_manifest, "COUNTS", counts)
    elif off_by_one is None:
        for name in FLOORS:
            if hasattr(dd, name):
                monkeypatch.setattr(dd, name, 1)


def _plant_prior(dest: Path, tmp: Path) -> dict[str, bytes]:
    """A prior good install: other fixture DBs copied into ``dest`` and their tag file."""
    prior = _fixture_dbs(tmp / "prior-dbs", marker="prior")
    dest.mkdir(parents=True, exist_ok=True)
    for name, src in prior.items():
        shutil.copyfile(src, dest / name)
    tag = {
        "tag_name": PRIOR_TAG,
        "installed_at": "2098-01-01T00:00:00Z",
        "databases": {name: _sha256(dest / name) for name in INSTALLED},
    }
    (dest / TAG_FILE).write_text(json.dumps(tag, indent=2) + "\n")
    return {name: (dest / name).read_bytes() for name in (*INSTALLED, TAG_FILE)}


def _reader():
    return getattr(dd, "read_installed_tag", None)


# --- the tag file after a good install ------------------------------------------------


def test_good_install_writes_one_tag_file(tmp_path, monkeypatch):
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    assert dd.download_databases(dest, "latest") is True
    tag_file = dest / TAG_FILE
    assert tag_file.is_file(), "a verified install writes the tag file"
    tag = json.loads(tag_file.read_text())
    named = {a.removesuffix(".zst") for a in dd.ASSETS if a.endswith(".db.zst")}
    assert tag["tag_name"] == TAG
    assert set(tag["databases"]) == named
    for name in named:
        assert tag["databases"][name] == _sha256(dest / name)
    assert tag["installed_at"]
    assert _reader()(dest) == TAG


def test_reader_none_after_context_db_replaced(tmp_path, monkeypatch):
    """(c) A good install, then context.db replaced by a hand copy: the reader returns none."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    assert dd.download_databases(dest, "latest") is True
    assert (dest / TAG_FILE).is_file(), "a verified install writes the tag file"
    assert _reader()(dest) == TAG
    other = _fixture_dbs(tmp_path / "other", marker="local")
    shutil.copyfile(other["context.db"], dest / "context.db")
    assert _reader()(dest) is None


# --- failures over a prior good install -----------------------------------------------


def test_checksum_mismatch_leaves_prior_install(tmp_path, monkeypatch, capsys):
    """(a1) A checksum mismatch fails before any write: the DBs and the tag file stay."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    release = _release_dir(tmp_path / "release", dbs, checksums="bad-context")
    sleeps = _serve(monkeypatch, release)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    assert dd.download_databases(dest, "latest") is False
    assert "Checksum verification failed after all attempts." in capsys.readouterr().out
    assert len(sleeps) == dd.MAX_ATTEMPTS - 1
    after = {name: (dest / name).read_bytes() for name in before}
    assert after == before


def test_db_verify_failure_removes_prior_tag(tmp_path, monkeypatch, capsys):
    """(a2) A DB verify failure after the decompress: the old tag file is gone, none is left."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs, off_by_one="context.db:lolbins")
    dest = tmp_path / "dest"
    _plant_prior(dest, tmp_path)
    assert dd.download_databases(dest, "latest") is False
    assert "Database verification failed." in capsys.readouterr().out
    assert (dest / "context.db").read_bytes() == dbs["context.db"].read_bytes()
    assert not (dest / TAG_FILE).exists(), GONE


_KILL_DRIVER = textwrap.dedent(
    """
    import shutil, signal, sys
    from pathlib import Path
    from windows_triage.scripts import download_databases as dd

    release, dest, ready = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])

    def fetch_release(tag="latest"):
        return {{"tag_name": "{tag}", "assets": [
            {{"name": p.name, "url": str(p)}} for p in sorted(release.iterdir())]}}

    def get_asset_url(rel, name):
        p = release / name
        return str(p) if p.is_file() else None

    def download_asset(url, dest_path):
        shutil.copyfile(url, dest_path)

    def held_decompress(src, db_path):
        with open(db_path, "wb") as f:
            f.write(b"partial")
            f.flush()
        ready.write_text("written")
        signal.pause()

    dd._fetch_release = fetch_release
    dd._get_asset_url = get_asset_url
    dd._download_asset = download_asset
    dd._decompress_zst = held_decompress
    dd.time.sleep = lambda s: None
    dd.download_databases(dest, "latest")
    """
)


def test_kill_mid_decompress_removes_prior_tag(tmp_path):
    """(b) A process SIGKILLed just after its first write to the install dir, inside the
    decompress: the old tag file is gone and no tag file is left."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    release = _release_dir(tmp_path / "release", dbs)
    dest = tmp_path / "dest"
    _plant_prior(dest, tmp_path)
    ready = tmp_path / "ready"
    driver = tmp_path / "driver.py"
    driver.write_text(_KILL_DRIVER.format(tag=TAG))
    proc = subprocess.Popen(
        [sys.executable, str(driver), str(release), str(dest), str(ready)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 60
        while not ready.exists():
            assert proc.poll() is None, proc.stderr.read().decode()
            assert time.monotonic() < deadline, "the driver never reached its hold"
            time.sleep(0.05)
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == -signal.SIGKILL
    assert ready.read_text() == "written"
    assert not (dest / TAG_FILE).exists(), GONE


# --- releases that are not a verified install -----------------------------------------


def test_release_without_checksums_fails_with_no_tag(tmp_path, monkeypatch, capsys):
    """(d) No checksums.sha256: the download fails as today (rc 1) and no tag file is written."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    release = _release_dir(tmp_path / "release", dbs, checksums="none")
    sleeps = _serve(monkeypatch, release)
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    monkeypatch.setattr(sys, "argv", ["download_databases", "--dest", str(dest)])
    with pytest.raises(SystemExit) as exc:
        dd.main()
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Asset not found in release: checksums.sha256" in out
    assert "All download attempts failed." in out
    assert len(sleeps) == dd.MAX_ATTEMPTS - 1
    assert not (dest / TAG_FILE).exists()


def test_checksums_missing_a_db_writes_no_tag(tmp_path, monkeypatch):
    """(e) checksums.sha256 lacks context.db's line: no tag file is written."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    release = _release_dir(tmp_path / "release", dbs, checksums="drop-context")
    _serve(monkeypatch, release)
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    dd.download_databases(dest, "latest")
    assert (dest / "known_good.db").is_file(), "the run reached the install"
    assert not (dest / TAG_FILE).exists()


# --- the count check of a downloaded DB -----------------------------------------------


def test_downloaded_db_one_row_short_fails(tmp_path, monkeypatch, capsys):
    """(D0) A downloaded DB one row short of the release's counts: the install fails."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    try:
        from windows_triage import release_manifest
    except ImportError:
        release_manifest = None
    if release_manifest is not None:
        counts = {db: dict(t) for db, t in release_manifest.COUNTS.items()}
        counts["known_good.db"]["baseline_files"] += 1
        monkeypatch.setattr(release_manifest, "COUNTS", counts)
    assert dd.download_databases(tmp_path / "dest", "latest") is False


def test_downloaded_db_at_the_counts_installs(tmp_path, monkeypatch):
    """Control for (D0): the same release at the counts installs."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    assert dd.download_databases(tmp_path / "dest", "latest") is True
