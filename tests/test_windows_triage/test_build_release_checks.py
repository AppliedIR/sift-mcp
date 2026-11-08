"""build-release.sh checks each DB's tables and each source's licence files before
it packs anything.

Each case runs the script from a copy of the scripts dir with a data dir beside it,
on a fresh --output dir. The fixture DBs hold two rows in every data table, far
below the release's counts, so a case sets the manifest's expected counts to the
fixture's: a sitecustomize on PYTHONPATH patches ``release_manifest.COUNTS`` in each
Python the script starts (a tree with no manifest has nothing to patch). The data
dir holds a licence file for each clone in the triage source table, as
``import_all.py --fetch`` leaves it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from windows_triage.db.schemas import CONTEXT_SCHEMA, KNOWN_GOOD_SCHEMA

SCRIPTS = Path(__file__).resolve().parents[2] / "packages/windows-triage/scripts"
ROWS = 2


def _licence_dirs() -> list[str]:
    """Each clone's licence dir: the repo name of each triage source table entry."""
    path = SCRIPTS / "update_sources.py"
    spec = importlib.util.spec_from_file_location("brc_update_sources", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return sorted({e["repo"].split("/")[1] for e in mod.SOURCES.values()})


LICENCE_DIRS = _licence_dirs()
SHIM = textwrap.dedent(
    """
    import json
    import os

    _path = os.environ.get("TRIAGE_TEST_COUNTS")
    if _path:
        try:
            from windows_triage import release_manifest as _manifest
        except ImportError:
            _manifest = None
        if _manifest is not None:
            with open(_path) as _f:
                for _db, _tables in json.load(_f).items():
                    _manifest.COUNTS = {
                        **_manifest.COUNTS,
                        _db: {**_manifest.COUNTS.get(_db, {}), **_tables},
                    }
    """
)


def _data_table(name: str) -> bool:
    return name != "sources" and not name.startswith("sqlite_")


def _fill(path: Path, schema: str, empty: tuple[str, ...] = ()) -> None:
    """Every data table gets ROWS rows (none for the tables in ``empty``)."""
    conn = sqlite3.connect(path)
    conn.executescript(schema)
    query = "SELECT name FROM sqlite_master WHERE type='table'"
    for (table,) in conn.execute(query).fetchall():
        if not _data_table(table) or table in empty:
            continue
        info = conn.execute(f"PRAGMA table_info({table})")
        cols = [(r[1], r[2].upper()) for r in info if r[1] != "id"]
        names = ", ".join(n for n, _ in cols)
        marks = ", ".join("?" for _ in cols)
        for i in range(ROWS):
            values = [i if "INT" in t else f"{table}-{n}-{i}" for n, t in cols]
            conn.execute(f"INSERT INTO {table} ({names}) VALUES ({marks})", values)
    conn.commit()
    conn.close()


def _counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    query = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    names = [r[0] for r in conn.execute(query) if _data_table(r[0])]
    counts = {n: conn.execute(f"SELECT COUNT(*) FROM {n}").fetchone()[0] for n in names}
    conn.close()
    return counts


def _tree(tmp: Path, empty: tuple[str, ...] = ()) -> Path:
    root = tmp / "tree"
    shutil.copytree(SCRIPTS, root / "scripts")
    (root / "data").mkdir()
    _fill(root / "data" / "known_good.db", KNOWN_GOOD_SCHEMA)
    _fill(root / "data" / "context.db", CONTEXT_SCHEMA, empty)
    for name in LICENCE_DIRS:
        licence = root / "data" / "licenses" / name / "LICENSE"
        licence.parent.mkdir(parents=True)
        licence.write_text(f"Fixture licence for {name}\n")
    return root


def _build(
    tmp: Path,
    root: Path,
    expected: dict[str, dict[str, int]],
    env_set: dict[str, str | None] | None = None,
):
    """Runs the script with VENV at the test's own venv; ``env_set`` sets or (with
    None) removes variables after that."""
    shim = tmp / "shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(SHIM)
    counts = tmp / "counts.json"
    counts.write_text(json.dumps(expected))
    path = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"
    env = {
        **os.environ,
        "PATH": path,
        "PYTHONPATH": str(shim),
        "TRIAGE_TEST_COUNTS": str(counts),
        "VENV": str(Path(sys.executable).parent.parent),
    }
    for key, value in (env_set or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    out = tmp / "release"
    run = subprocess.run(
        ["bash", str(root / "scripts" / "build-release.sh"), "--output", str(out)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    written = sorted(p.name for p in out.iterdir()) if out.exists() else []
    return run, written


def _fixture_counts(
    root: Path, skip: tuple[str, ...] = ()
) -> dict[str, dict[str, int]]:
    """The fixture's own counts as the expected counts, leaving the "db:table"
    entries in ``skip`` at the manifest's count."""
    expected = {}
    for db in ("known_good.db", "context.db"):
        tables = _counts(root / "data" / db)
        expected[db] = {t: n for t, n in tables.items() if f"{db}:{t}" not in skip}
    return expected


def test_every_table_at_its_count_builds_the_release(tmp_path):
    root = _tree(tmp_path)
    run, written = _build(tmp_path, root, _fixture_counts(root))
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    assert {"checksums.sha256", "known_good.db.zst", "context.db.zst"} <= set(written)


def test_a_table_under_its_floor_fails_with_nothing_written(tmp_path):
    root = _tree(tmp_path, empty=("hijackable_dlls",))
    expected = _fixture_counts(root, skip=("context.db:hijackable_dlls",))
    run, written = _build(tmp_path, root, expected)
    assert run.returncode != 0, f"rc 0 with hijackable_dlls empty, wrote {written}"
    assert written == [], f"a failed build wrote {written}"


def test_an_extra_table_fails_with_nothing_written(tmp_path):
    root = _tree(tmp_path)
    expected = _fixture_counts(root)
    conn = sqlite3.connect(root / "data" / "context.db")
    conn.execute("CREATE TABLE extra_table (value TEXT)")
    conn.execute("INSERT INTO extra_table VALUES ('x')")
    conn.commit()
    conn.close()
    run, written = _build(tmp_path, root, expected)
    assert run.returncode != 0, f"build rc 0 with an extra table, wrote {written}"
    assert written == [], f"a failed build wrote {written}"


def test_a_missing_table_fails_with_nothing_written(tmp_path):
    root = _tree(tmp_path)
    conn = sqlite3.connect(root / "data" / "context.db")
    conn.execute("DROP TABLE windows_named_pipes")
    conn.commit()
    conn.close()
    run, written = _build(tmp_path, root, _fixture_counts(root))
    assert run.returncode != 0, f"build rc 0 with a table missing, wrote {written}"
    assert written == [], f"a failed build wrote {written}"


LICENCE_CASES = ["no licenses dir", *(f"no {d} dir" for d in LICENCE_DIRS), "empty"]


@pytest.mark.parametrize("case", LICENCE_CASES)
def test_a_source_with_no_licence_fails_naming_it(tmp_path, case):
    root = _tree(tmp_path)
    licences = root / "data" / "licenses"
    if case == "no licenses dir":
        shutil.rmtree(licences)
        named = LICENCE_DIRS
    elif case == "empty":
        named = [LICENCE_DIRS[0]]
        (licences / named[0] / "LICENSE").unlink()
    else:
        named = [case.split()[1]]
        shutil.rmtree(licences / named[0])
    run, written = _build(tmp_path, root, _fixture_counts(root))
    out = run.stdout + run.stderr
    assert run.returncode != 0, f"rc 0 with no licence for {named}, wrote {written}"
    assert written == [], f"a failed build wrote {written}"
    missing = [n for n in named if f"{n}: no licence file" not in out]
    assert missing == [], f"not named: {missing}: {out[-2000:]}"


def _venv_case(tmp: Path, case: str) -> dict[str, str | None]:
    if case == "unset":
        return {"VENV": None}
    if case == "empty":
        return {"VENV": ""}
    bare = tmp / "bare-env"
    (bare / "bin").mkdir(parents=True)
    return {"VENV": str(bare)}


@pytest.mark.parametrize("case", ["unset", "empty", "no python"])
def test_the_build_fails_naming_venv_without_a_venv_python(tmp_path, case):
    root = _tree(tmp_path)
    env_set = _venv_case(tmp_path, case)
    run, written = _build(tmp_path, root, _fixture_counts(root), env_set)
    out = run.stdout + run.stderr
    named = [ln for ln in out.splitlines() if "VENV" in ln]
    assert named, f"VENV not named: {out[-2000:]}"
    assert run.returncode != 0, f"rc 0 with VENV {case}, wrote {written}"
    assert written == [], f"a failed build wrote {written}"


def test_every_python_step_runs_the_venv_python(tmp_path):
    root = _tree(tmp_path)
    venv_calls = tmp_path / "venv-python-calls"
    path_calls = tmp_path / "path-python-calls"
    venv = tmp_path / "logged-env"
    (venv / "bin").mkdir(parents=True)
    logged = venv / "bin" / "python"
    logged.write_text(
        f'#!/bin/bash\necho "$1" >> "{venv_calls}"\nexec "{sys.executable}" "$@"\n'
    )
    logged.chmod(0o755)
    path_bin = tmp_path / "path-bin"
    path_bin.mkdir()
    for name in ("python3", "python"):
        stub = path_bin / name
        stub.write_text(f'#!/bin/sh\necho "$0" >> "{path_calls}"\nexit 97\n')
        stub.chmod(0o755)
    path = f"{path_bin}{os.pathsep}{os.environ.get('PATH', '')}"
    env_set = {"VENV": str(venv), "PATH": path}
    run, written = _build(tmp_path, root, _fixture_counts(root), env_set)
    calls = path_calls.read_text() if path_calls.exists() else ""
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    assert calls == "", f"a step ran the python on PATH: {calls}"
    assert venv_calls.exists(), "no step ran $VENV/bin/python"
