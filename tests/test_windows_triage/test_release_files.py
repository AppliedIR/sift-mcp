"""The triage release's file list: the three DBs, the licence asset and checksums.

A case builds a release with ``build-release.sh`` from a copy of the scripts dir, a
data dir beside it holding the three fixture DBs and one licence dir per clone, on a
fresh --output dir. The download cases then install that release through the
download seams (see test_download_tag.py), so the licence asset's format is the
build's own. ``import_all.py`` cases run it with every import skipped and read the
database list it prints.
"""

from __future__ import annotations

import collections
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from windows_triage import release_manifest
from windows_triage.db.schemas import REGISTRY_FULL_SCHEMA
from windows_triage.scripts import download_databases as dd

from .test_build_release_checks import _build, _counts, _fill, _tree
from .test_download_tag import _serve, _set_counts
from .test_fetch import DIRS, SCRIPTS, SOURCES, _load

DBS = ("known_good.db", "context.db", "known_good_registry.db")
REGISTRY_ASSET = "known_good_registry.db.zst"
EXTRA_DB = "fixture_extra.db"
EXTRA_SHIM = textwrap.dedent(
    """
    import os

    _name = os.environ.get("TRIAGE_TEST_EXTRA_DB")
    if _name:
        try:
            from windows_triage import release_manifest as _manifest
        except ImportError:
            _manifest = None
        if _manifest is not None:
            _manifest.DATABASES = {**_manifest.DATABASES, _name: False}
    """
)


def _licences(data: Path) -> dict[str, bytes]:
    """One licence dir per clone (a NOTICE in the first too); return the files."""
    files = {}
    for i, name in enumerate(DIRS):
        files[f"{name}/LICENSE"] = f"Fixture licence for {name}\n".encode()
        if i == 0:
            files[f"{name}/NOTICE"] = f"Fixture notice for {name}\n".encode()
    for rel, body in files.items():
        path = data / "licenses" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    return files


def _release(tmp: Path):
    """Build a release from three fixture DBs and the licences; return the tree, the
    build run, its output dir and the licence files."""
    root = _tree(tmp)
    _fill(root / "data" / "known_good_registry.db", REGISTRY_FULL_SCHEMA)
    licences = _licences(root / "data")
    expected = {db: _counts(root / "data" / db) for db in DBS}
    run, _ = _build(tmp, root, expected)
    return root, run, tmp / "release", licences


def _listed(out: Path) -> set[str]:
    path = out / "checksums.sha256"
    lines = path.read_text().splitlines() if path.is_file() else []
    return {line.split()[1] for line in lines if len(line.split()) == 2}


def _tail(run) -> str:
    return run.stdout[-2000:] + run.stderr[-2000:]


def _install(monkeypatch, tmp: Path, root: Path, out: Path):
    """Install the built release into a fresh dest; return (ok, dest, assets asked)."""
    _serve(monkeypatch, out)
    asked: list[str] = []
    fake = dd._download_asset

    def download_asset(url, dest):
        asked.append(Path(url).name)
        fake(url, dest)

    monkeypatch.setattr(dd, "_download_asset", download_asset)
    _set_counts(monkeypatch, {db: root / "data" / db for db in DBS[:2]})
    dest = tmp / "install"
    return dd.download_databases(dest), dest, asked


def _db_list(tmp: Path, extra: bool = False) -> list[str]:
    """Run import_all.py with every import skipped; return the DB names it lists."""
    root = _tree(tmp)
    for name in ("known_good_registry.db", EXTRA_DB):
        (root / "data" / name).write_bytes(b"\0" * 1024)
    shim = tmp / "extra-shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(EXTRA_SHIM)
    env = {**os.environ, "PYTHONPATH": str(shim)}
    if extra:
        env["TRIAGE_TEST_EXTRA_DB"] = EXTRA_DB
    skip = ["--skip-files", "--skip-registry", "--skip-context"]
    run = subprocess.run(
        [sys.executable, str(root / "scripts" / "import_all.py"), *skip],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert run.returncode == 0, _tail(run)
    lines = run.stdout.split("Database sizes:\n", 1)[-1].splitlines()
    listed = []
    for line in lines:
        if not line.startswith("  "):
            break
        listed.append(line.strip().split(":")[0])
    return listed


# --- build-release.sh packs the three DBs and the licence asset --------------


def test_the_build_packs_and_checksums_the_registry_db(tmp_path):
    _, run, out, _ = _release(tmp_path)
    assert run.returncode == 0, _tail(run)
    assert REGISTRY_ASSET in _listed(out)
    assert (out / REGISTRY_ASSET).is_file()


def test_the_build_checksums_one_licence_asset(tmp_path):
    _, run, out, _ = _release(tmp_path)
    assert run.returncode == 0, _tail(run)
    others = _listed(out) - {f"{db}.zst" for db in DBS} - {"metadata.json"}
    assert len(others) == 1, f"checksums.sha256 lists {sorted(_listed(out))}"
    assert (out / others.pop()).is_file()


# --- download_databases installs the licences, and no registry by default ----


def test_an_install_puts_each_clone_licence_in_data_licenses(tmp_path, monkeypatch):
    root, run, out, licences = _release(tmp_path)
    assert run.returncode == 0, _tail(run)
    ok, dest, _ = _install(monkeypatch, tmp_path, root, out)
    assert ok
    base = dest / "licenses"
    installed = {
        p.relative_to(base).as_posix(): p.read_bytes()
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }
    assert installed == licences


def test_a_default_install_never_asks_for_the_registry_db(tmp_path, monkeypatch):
    root, run, out, _ = _release(tmp_path)
    assert run.returncode == 0, _tail(run)
    _, _, asked = _install(monkeypatch, tmp_path, root, out)
    assert REGISTRY_ASSET not in asked, f"assets downloaded: {asked}"


# --- import_all's database list comes from the release file list -------------


def test_import_all_lists_the_registry_db(tmp_path):
    assert "known_good_registry.db" in _db_list(tmp_path)


def test_a_db_added_to_the_file_list_is_listed_by_import_all(tmp_path):
    assert EXTRA_DB in _db_list(tmp_path, extra=True)


# --- a DB a fetch builds in part is floored by FED_BY's tables ----------------


def test_fed_by_lists_each_db_a_skip_option_builds_in_part(monkeypatch):
    """A DB a --skip-* option takes some, not all, of the sources of is built in
    part. FED_BY must name exactly its sources, and their tables together must be
    the DB's tables in COUNTS, each once, so no table goes unfloored."""
    monkeypatch.syspath_prepend(str(SCRIPTS))
    import_all = _load(SCRIPTS / "import_all.py")
    feeds = collections.defaultdict(set)
    for key, entry in SOURCES.items():
        feeds[entry["db"]].add(key)
    partial = {
        db
        for skipped in import_all.FETCH_SKIPS.values()
        for db, keys in feeds.items()
        if keys & skipped and keys - skipped
    }
    assert set(release_manifest.FED_BY) == partial
    for db, fed in release_manifest.FED_BY.items():
        assert set(fed) == feeds[db], db
        tables = [t for written in fed.values() for t in written]
        assert sorted(tables) == sorted(release_manifest.COUNTS[db]), db
