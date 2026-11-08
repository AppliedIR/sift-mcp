"""build-release.sh checks each DB's tables before it packs anything.

Each case runs the script from a copy of the scripts dir with a data dir beside it,
on a fresh --output dir. The fixture DBs hold two rows in every data table, far
below the release's counts, so a case sets the manifest's expected counts to the
fixture's: a sitecustomize on PYTHONPATH patches ``release_manifest.COUNTS`` in each
Python the script starts (a tree with no manifest has nothing to patch).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

from windows_triage.db.schemas import CONTEXT_SCHEMA, KNOWN_GOOD_SCHEMA

SCRIPTS = Path(__file__).resolve().parents[2] / "packages/windows-triage/scripts"
ROWS = 2
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
    return root


def _build(tmp: Path, root: Path, expected: dict[str, dict[str, int]]):
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
    }
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
