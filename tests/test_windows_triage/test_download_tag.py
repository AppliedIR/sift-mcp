"""The installed triage release tag, and the download's count check.

Each case installs from a local fixture release: ``_fetch_release``,
``_newest_release``, ``_get_asset_url`` and ``_download_asset`` are patched to serve
the fixture dir's files, and the retry sleep is patched out. The fixture DBs are a few
rows each, so a case that needs a passing verify sets the manifest's counts to the
fixture's counts (or, on a tree with the row floor constants and no manifest, sets
those floors to 1).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import textwrap
import time
from pathlib import Path

import pytest
import zstandard
from windows_triage import release_manifest
from windows_triage.db.schemas import CONTEXT_SCHEMA, KNOWN_GOOD_SCHEMA
from windows_triage.scripts import download_databases as dd

TAG = release_manifest.RELEASE_TAG  # the release whose exact counts the manifest holds
OTHER_TAG = "triage-db-v2099.01.01"
PRIOR_TAG = "triage-db-v2098.01.01"
STAGE = ".triage-db-new-*"
TAG_FILE = "installed_release.json"
INSTALLED = ("known_good.db", "context.db")
FLOORS = ("MIN_BASELINE_FILES", "MIN_LOLBINS", "MIN_VULNERABLE_DRIVERS")


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


def _serve(monkeypatch, release: Path, tag_name: str = TAG) -> list[float]:
    """Serve ``release``, tagged ``tag_name``, through the three download seams;
    return the sleeps made."""
    sleeps: list[float] = []

    def fetch_release(tag):
        files = sorted(release.iterdir())
        return {
            "tag_name": tag_name,
            "assets": [{"name": p.name, "url": str(p)} for p in files],
        }

    def get_asset_url(rel, asset_name):
        path = release / asset_name
        return str(path) if path.is_file() else None

    def download_asset(url, dest):
        shutil.copyfile(url, dest)

    monkeypatch.setattr(dd, "_fetch_release", fetch_release)
    monkeypatch.setattr(dd, "_newest_release", lambda: fetch_release(None))
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


def _files(dest: Path, names) -> dict[str, bytes]:
    return {
        name: (dest / name).read_bytes() for name in names if (dest / name).exists()
    }


def _stages(dest: Path) -> list[Path]:
    return sorted(dest.glob(STAGE))


def _add_licence_asset(release: Path, members: dict[str, bytes]) -> None:
    """Add a licence asset holding ``members`` (path to bytes) to ``release``, with
    its line in checksums.sha256."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    asset = release / release_manifest.LICENCE_ASSET
    asset.write_bytes(zstandard.ZstdCompressor().compress(buf.getvalue()))
    with open(release / "checksums.sha256", "a") as f:
        f.write(f"{_sha256(asset)}  {asset.name}\n")


def _fail_replace(monkeypatch, failing: set[int]) -> list[int]:
    """Make the os.replace calls numbered in ``failing`` (from 1) raise OSError;
    return the list of call numbers made."""
    calls: list[int] = []
    real = os.replace

    def replace(src, dst, *args, **kwargs):
        calls.append(len(calls) + 1)
        if calls[-1] in failing:
            raise OSError(f"test: os.replace call {calls[-1]} fails")
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(dd.os, "replace", replace)
    return calls


# --- the tag file after a good install ------------------------------------------------


def test_good_install_writes_one_tag_file(tmp_path, monkeypatch):
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    assert dd.download_databases(dest) is True
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
    assert dd.download_databases(dest) is True
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
    assert dd.download_databases(dest) is False
    assert "Checksum verification failed after all attempts." in capsys.readouterr().out
    assert len(sleeps) == dd.MAX_ATTEMPTS - 1
    gone = [name for name in before if not (dest / name).exists()]
    assert gone == [], "a failed install removed files of the prior install"
    after = {name: (dest / name).read_bytes() for name in before}
    assert after == before


def test_db_verify_failure_leaves_prior_install(tmp_path, monkeypatch, capsys):
    """(a2) A DB verify failure: the downloaded DBs are checked before they replace
    anything, so the prior DBs and tag file stay byte-identical."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs, off_by_one="context.db:lolbins")
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    assert dd.download_databases(dest) is False
    assert "Database verification failed." in capsys.readouterr().out
    assert _files(dest, before) == before, "a failed install changed the prior install"
    assert _stages(dest) == []


_KILL_DRIVER = textwrap.dedent(
    """
    import os, shutil, signal, sys
    from pathlib import Path
    from windows_triage.scripts import download_databases as dd

    release, dest, ready = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])

    def fetch_release(tag):
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
        # The parent kills once ready exists: write aside, then rename.
        ready.with_name(ready.name + ".tmp").write_text("written")
        os.replace(ready.with_name(ready.name + ".tmp"), ready)
        signal.pause()

    dd._fetch_release = fetch_release
    dd._newest_release = lambda: fetch_release(None)
    dd._get_asset_url = get_asset_url
    dd._download_asset = download_asset
    dd._decompress_zst = held_decompress
    dd.time.sleep = lambda s: None
    dd.download_databases(dest)
    """
)


def test_kill_mid_decompress_leaves_prior_install(tmp_path):
    """(b) A process SIGKILLed just after its first write inside the decompress: the
    prior DBs and tag file stay byte-identical."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    release = _release_dir(tmp_path / "release", dbs)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
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
    assert _files(dest, before) == before, "a killed install changed the prior install"


# --- releases that are not a verified install -----------------------------------------


def test_release_without_checksums_fails_with_no_tag(tmp_path, monkeypatch, capsys):
    """(d) No checksums.sha256: the release lacks one of this version's files, so it is
    refused before any download (rc 1) and no tag file is written."""
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
    assert "with this version's files" in out and "Nothing was downloaded" in out, out
    assert sleeps == []
    assert not (dest / TAG_FILE).exists()


def test_checksums_missing_a_db_leaves_prior_install(tmp_path, monkeypatch, capsys):
    """(e) checksums.sha256 lacks context.db's line: the install fails before it
    writes anything, so the prior DBs and tag file stay byte-identical."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    release = _release_dir(tmp_path / "release", dbs, checksums="drop-context")
    _serve(monkeypatch, release)
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    assert dd.download_databases(dest) is False
    assert "checksums.sha256 does not list: context.db.zst" in capsys.readouterr().out
    assert _files(dest, before) == before, "a failed install changed the prior install"
    assert _stages(dest) == []


def test_release_with_another_tag_is_checked_against_the_floors(tmp_path, monkeypatch):
    """A release other than RELEASE_TAG installs when each table reaches its floor:
    one row short of RELEASE_TAG's counts still installs, tagged with its own tag."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs), tag_name=OTHER_TAG)
    _set_counts(monkeypatch, dbs, off_by_one="known_good.db:baseline_files")
    dest = tmp_path / "dest"
    _plant_prior(dest, tmp_path)
    assert dd.download_databases(dest) is True
    assert _reader()(dest) == OTHER_TAG


def test_licence_failure_leaves_prior_install(tmp_path, monkeypatch, capsys):
    """A licence asset with a bad member: the install fails before it replaces
    anything, so the prior DBs, tag file and licences stay byte-identical."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    release = _release_dir(tmp_path / "release", dbs)
    _add_licence_asset(
        release, {"src/LICENSE": b"new licence", "src/deep/LICENSE": b"bad member"}
    )
    _serve(monkeypatch, release)
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    prior_licence = dest / release_manifest.LICENCE_DIR / "src" / "LICENSE"
    prior_licence.parent.mkdir(parents=True)
    prior_licence.write_bytes(b"prior licence")
    assert dd.download_databases(dest) is False
    assert "Licence install failed: unexpected member" in capsys.readouterr().out
    assert _files(dest, before) == before, "a failed install changed the prior install"
    assert prior_licence.read_bytes() == b"prior licence"
    assert _stages(dest) == []


def test_failed_swap_is_undone(tmp_path, monkeypatch, capsys):
    """A move into place fails part way: every move made is undone, so the prior
    DBs and tag file are back byte-identical, and it says so."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    calls = _fail_replace(monkeypatch, {3})
    assert dd.download_databases(dest) is False
    out = capsys.readouterr().out
    assert len(calls) >= 3, "the install did not reach a third move"
    assert f"installing into {dest} failed" in out, out
    assert "the installed databases were not changed" in out, out
    assert _files(dest, before) == before, "the failed swap was not undone"
    assert _stages(dest) == []


def test_failed_undo_keeps_the_old_files(tmp_path, monkeypatch, capsys):
    """The swap fails and its undo fails too: no tag file is left, and the files
    it replaced are kept, byte-identical, in the stage dir it names."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    before = _plant_prior(dest, tmp_path)
    _fail_replace(monkeypatch, {3, 4})
    assert dd.download_databases(dest) is False
    out = capsys.readouterr().out
    assert not (dest / TAG_FILE).exists(), "a half-undone install kept a tag file"
    stages = _stages(dest)
    assert len(stages) == 1, stages
    old = stages[0] / "old"
    assert "undoing it failed too" in out and str(old) in out, out
    kept = {name: (old / name).read_bytes() for name in (TAG_FILE, "known_good.db")}
    assert kept == {name: before[name] for name in kept}


def test_good_install_over_a_prior_install(tmp_path, monkeypatch):
    """Control: a good release over a prior install replaces its DBs and tag file,
    and leaves no stage dir."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    _plant_prior(dest, tmp_path)
    assert dd.download_databases(dest) is True
    assert _files(dest, INSTALLED) == {n: dbs[n].read_bytes() for n in INSTALLED}
    assert json.loads((dest / TAG_FILE).read_text())["tag_name"] == TAG
    assert _reader()(dest) == TAG
    assert _stages(dest) == []


def test_good_install_moves_an_old_db_journal_away(tmp_path, monkeypatch):
    """An old DB's -wal and -shm files must not meet the new DB: a good install
    moves them away with the old DB."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    _plant_prior(dest, tmp_path)
    sides = [dest / "known_good.db-wal", dest / "known_good.db-shm"]
    for side in sides:
        side.write_bytes(b"an old journal")
    assert dd.download_databases(dest) is True
    assert [s.name for s in sides if s.exists()] == []
    assert _stages(dest) == []


def test_next_run_removes_a_left_stage_and_names_a_kept_one(
    tmp_path, monkeypatch, capsys
):
    """A stage dir a killed run left (no old/ in it) is removed by the next run; one
    holding old/ (the files a failed undo kept) is named and left in place."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    dest = tmp_path / "dest"
    _plant_prior(dest, tmp_path)
    left = dest / ".triage-db-new-left"
    left.mkdir()
    (left / "known_good.db").write_bytes(b"partial")
    kept = dest / ".triage-db-new-kept"
    (kept / "old").mkdir(parents=True)
    (kept / "old" / "known_good.db").write_bytes(b"kept old db")
    assert dd.download_databases(dest) is True
    out = capsys.readouterr().out
    assert not left.exists(), "the left stage dir was not removed"
    assert (kept / "old" / "known_good.db").read_bytes() == b"kept old db"
    assert str(kept) in out, out


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
    line = "Database verification failed."
    if release_manifest is not None:
        counts = {db: dict(t) for db, t in release_manifest.COUNTS.items()}
        counts["known_good.db"]["baseline_files"] += 1
        monkeypatch.setattr(release_manifest, "COUNTS", counts)
        want = counts["known_good.db"]["baseline_files"]
        line = (
            f"known_good.db: baseline_files has {want - 1} rows, the release has {want}"
        )
    assert dd.download_databases(tmp_path / "dest") is False
    out = capsys.readouterr().out
    assert "Database verification failed." in out and line in out, out


def test_downloaded_db_at_the_counts_installs(tmp_path, monkeypatch):
    """Control for (D0): the same release at the counts installs."""
    dbs = _fixture_dbs(tmp_path / "dbs")
    _serve(monkeypatch, _release_dir(tmp_path / "release", dbs))
    _set_counts(monkeypatch, dbs)
    assert dd.download_databases(tmp_path / "dest") is True
