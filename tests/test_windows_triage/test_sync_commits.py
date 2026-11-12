"""The importers record a source's sync commit only for an import that succeeded.

import_registry_full: a planted ``vanilla_windows_registry`` row at an older commit
keeps that commit, and the run exits non-zero, when a hive file is corrupt, when a
registry zip is bad, or when the import raises part way through (a wrapper process
patches ``flatten_registry_keys`` and calls ``main()``; rc is that process's exit).
import_registry_extractions takes one commit; import_context takes one per source,
as ``--sync-commit <clone dir name>=<commit>``, and records each on its own row only.

Each script runs from a copy of the scripts dir, with its data dir beside it.
Values are synthetic, in the upstream shapes.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest
from windows_triage.db import ContextDB, KnownGoodDB
from windows_triage.db.schemas import REGISTRY_FULL_SCHEMA

from .test_context_import_failures import GOOD
from .test_context_imports_keep_rows import HIJACKLIBS, _tree

SCRIPTS = Path(__file__).resolve().parents[2] / "packages/windows-triage/scripts"
OLD = "1" * 40  # the commit the planted row holds
NEW = "2" * 40  # the commit the run is given
REGISTRY_ROW = "vanilla_windows_registry"
OS_A = "W10_1507_Edu_20150729_10240"
OS_B = "W11_21H2_Pro_20211005_22000"
HIVE = {
    "KeyName": "ROOT",
    "KeyPath": "ROOT",
    "Values": [],
    "SubKeys": [
        {
            "KeyName": "ControlSet001",
            "KeyPath": "ROOT\\ControlSet001",
            "Values": [],
            "SubKeys": [
                {
                    "KeyName": "Services",
                    "KeyPath": "ROOT\\ControlSet001\\Services",
                    "Values": [],
                    "SubKeys": [
                        {
                            "KeyName": "fixturesvc",
                            "KeyPath": "ROOT\\ControlSet001\\Services\\fixturesvc",
                            "Values": [
                                {
                                    "ValueName": "ImagePath",
                                    "ValueType": "RegExpandSz",
                                    "ValueData": "C:\\Windows\\fixture.exe",
                                },
                                {
                                    "ValueName": "Start",
                                    "ValueType": "RegDword",
                                    "ValueData": "3",
                                },
                            ],
                            "SubKeys": [],
                        }
                    ],
                }
            ],
        }
    ],
}
WRAPPER = textwrap.dedent(
    """
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("import_registry_full", sys.argv[1])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    original = mod.flatten_registry_keys
    files = []

    def flaky(data, current_path="", results=None):
        if results is None:  # a top-level call: one per hive file
            files.append(1)
            if len(files) == 2:
                raise RuntimeError("injected part way through the import")
        return original(data, current_path, results)

    mod.flatten_registry_keys = flaky
    sys.argv = sys.argv[1:]
    mod.main()
    """
)


def _scripts(tmp: Path) -> Path:
    root = tmp / "tree"
    shutil.copytree(SCRIPTS, root / "scripts")
    (root / "data" / "sources").mkdir(parents=True)
    return root


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args], cwd=cwd, capture_output=True, text=True, timeout=120
    )


def _commit(db: Path, name: str) -> str | None:
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT last_sync_commit FROM sources WHERE name = ?", (name,)
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


# --- import_registry_full ---------------------------------------------------


def _hive_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _registry(tmp: Path, case: str) -> Path:
    """A tree whose registry DB has the planted row at OLD, and the case's sources."""
    root = _scripts(tmp)
    db = root / "data" / "known_good_registry.db"
    conn = sqlite3.connect(db)
    conn.executescript(REGISTRY_FULL_SCHEMA)
    conn.execute(
        "UPDATE sources SET last_sync_commit = ? WHERE name = ?", (OLD, REGISTRY_ROW)
    )
    conn.commit()
    conn.close()
    hives = root / "data" / "sources" / "VanillaWindowsRegistryHives"
    good = json.dumps(HIVE)
    if case == "bad-zip":  # the good source is inside a good zip; no on-disk JSON
        (hives / OS_A).mkdir(parents=True)
        with zipfile.ZipFile(hives / OS_A / "RegistryHivesJSON.zip", "w") as zf:
            zf.writestr("SYSTEM_ROOT.json", good)
        (hives / OS_B).mkdir(parents=True)
        (hives / OS_B / "RegistryHivesJSON.zip").write_bytes(b"not a zip file")
    else:
        _hive_file(hives / OS_A / "mout" / "KapeResearch" / "SYSTEM_ROOT.json", good)
        other = "{not json" if case == "corrupt-hive-file" else good
        _hive_file(hives / OS_B / "mout" / "KapeResearch" / "SYSTEM_ROOT.json", other)
    return root


def _import_registry(tmp: Path, case: str):
    root = _registry(tmp, case)
    script = root / "scripts" / "import_registry_full.py"
    args = [str(script), "--sync-commit", NEW]
    if case == "exception-mid-import":
        wrapper = tmp / "wrapper.py"
        wrapper.write_text(WRAPPER)
        args = [str(wrapper), *args]
    run = _run(args, root)
    return run, _commit(root / "data" / "known_good_registry.db", REGISTRY_ROW)


FAILED_IMPORTS = ("corrupt-hive-file", "bad-zip", "exception-mid-import")


def test_a_good_registry_import_records_the_commit(tmp_path):
    run, commit = _import_registry(tmp_path, "all-good")
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    assert commit == NEW


@pytest.mark.parametrize("case", FAILED_IMPORTS)
def test_a_failed_registry_import_exits_nonzero(tmp_path, case):
    run, _ = _import_registry(tmp_path, case)
    assert run.returncode != 0, f"{case}: rc 0"


@pytest.mark.parametrize("case", FAILED_IMPORTS)
def test_a_failed_registry_import_keeps_the_old_commit(tmp_path, case):
    _, commit = _import_registry(tmp_path, case)
    assert commit == OLD, f"{case}: the row holds {commit}"


# --- import_registry_extractions --------------------------------------------


def _extractions(tmp: Path) -> Path:
    root = _scripts(tmp)
    KnownGoodDB(root / "data" / "known_good.db").init_schema()
    hives = root / "data" / "sources" / "VanillaWindowsRegistryHives"
    hive = hives / OS_A / "mout" / "KapeResearch" / "SYSTEM_ROOT.json"
    _hive_file(hive, json.dumps(HIVE))
    return root


def test_registry_extractions_import_the_fixture(tmp_path):
    root = _extractions(tmp_path)
    run = _run([str(root / "scripts" / "import_registry_extractions.py")], root)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]


def test_registry_extractions_record_the_commit_given(tmp_path):
    root = _extractions(tmp_path)
    script = root / "scripts" / "import_registry_extractions.py"
    run = _run([str(script), "--sync-commit", NEW], root)
    commit = _commit(root / "data" / "known_good.db", REGISTRY_ROW)
    assert commit == NEW, f"rc {run.returncode}, row {commit}: {run.stderr[-500:]}"


# --- import_context ---------------------------------------------------------

CONTEXT_ROWS = {
    "LOLBAS": "lolbas",
    "LOLDrivers": "loldrivers_vulnerable",
    "HijackLibs": "hijacklibs",
}
GIVEN = {"LOLBAS": "a" * 40, "LOLDrivers": "b" * 40, "HijackLibs": "c" * 40}


def _context(tmp: Path, hijacklibs: str = "good") -> Path:
    """A tree with the three context sources cloned; ``hijacklibs`` is "good",
    "absent" (no clone dir) or "nothing" (a clone with no entries in it)."""
    root = _scripts(tmp)
    ContextDB(root / "data" / "context.db").init_schema()
    sources = root / "data" / "sources"
    for name, source in (("LOLBAS", "lolbas"), ("LOLDrivers", "loldrivers")):
        folder, file_name, text, _ = GOOD[source]
        _tree(sources / name, {f"{folder}/{file_name}": text})
    if hijacklibs == "good":
        _tree(sources / "HijackLibs" / "yml", HIJACKLIBS)
    elif hijacklibs == "nothing":
        (sources / "HijackLibs" / "yml").mkdir(parents=True)
    return root


def _import_context(root: Path, given: dict[str, str]):
    args = [str(root / "scripts" / "import_context.py")]
    for name, commit in given.items():
        args += ["--sync-commit", f"{name}={commit}"]
    run = _run(args, root)
    db = root / "data" / "context.db"
    return run, {name: _commit(db, row) for name, row in CONTEXT_ROWS.items()}


def test_import_context_records_each_source_its_own_commit(tmp_path):
    run, rows = _import_context(_context(tmp_path), GIVEN)
    assert rows == GIVEN, f"rc {run.returncode}, rows {rows}: {run.stderr[-500:]}"


def test_import_context_records_none_for_a_source_given_none(tmp_path):
    given = {k: v for k, v in GIVEN.items() if k != "HijackLibs"}
    _, rows = _import_context(_context(tmp_path), given)
    assert rows["HijackLibs"] is None, f"rows {rows}"


@pytest.mark.parametrize("hijacklibs", ["absent", "nothing"])
def test_import_context_records_no_commit_for_a_source_not_imported(
    tmp_path, hijacklibs
):
    _, rows = _import_context(_context(tmp_path, hijacklibs), GIVEN)
    assert rows["HijackLibs"] is None, f"rows {rows}"


def test_import_context_fails_for_a_source_with_no_sources_row(tmp_path):
    """A commit given for a source whose sources row is gone cannot be recorded, so
    the run fails naming the source and its row. HijackLibs is not cloned: its
    import re-creates the schema's seed rows."""
    root = _context(tmp_path, "absent")
    conn = sqlite3.connect(root / "data" / "context.db")
    conn.execute("DELETE FROM sources WHERE name = 'lolbas'")
    conn.commit()
    conn.close()
    run, _ = _import_context(root, {"LOLBAS": GIVEN["LOLBAS"]})
    assert run.returncode == 1, run.stdout[-2000:] + run.stderr[-2000:]
    assert "LOLBAS: no sources row lolbas; commit not recorded" in run.stdout


def test_each_sync_row_is_a_context_source_seeded_in_a_fresh_db(tmp_path, monkeypatch):
    """The --sync-commit names are the context sources' clone dirs, and each row
    they record on is one a fresh context.db holds."""
    from .test_fetch import _load  # test_fetch imports this module

    monkeypatch.syspath_prepend(str(SCRIPTS))
    import_context = _load(SCRIPTS / "import_context.py")
    db = tmp_path / "context.db"
    ContextDB(db).init_schema()
    conn = sqlite3.connect(db)
    try:
        seeded = {r[0] for r in conn.execute("SELECT name FROM sources")}
    finally:
        conn.close()
    assert import_context.SYNC_ROWS == CONTEXT_ROWS
    assert set(CONTEXT_ROWS.values()) <= seeded
