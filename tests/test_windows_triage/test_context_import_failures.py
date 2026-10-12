"""An upstream file the importers can't read never freezes a source.

- HijackLibs reads an empty or null ExpectedLocations or VulnerableExecutables
  as none and skips an item that isn't a mapping; a file it still can't read
  is skipped by name and counted, and every other file is imported.
- An update whose import had errors, or found nothing, isn't recorded as
  synced (the next update tries again) and reports failure.
- LOLBAS skips a null item in Commands or Full_Path, not the binary.
- dlls_imported counts distinct DLLs.

The importers run as update_sources and import_context call them; the update
leg runs update_sources' own update_context_source with its clone served
from a scratch tree. Values are synthetic, in the upstream YAML shapes.
"""

from __future__ import annotations

import importlib.util
import shutil
import sqlite3
from pathlib import Path

import pytest
from windows_triage.importers import import_hijacklibs, import_lolbas

from .test_context_imports_keep_rows import HIJACKLIBS, _dbs, _tree

SCRIPTS = Path(__file__).resolve().parents[2] / "packages/windows-triage/scripts"
NEW = ("Name: new.dll\nVendor: N\nVulnerableExecutables:\n"
       "- Path: '%PROGRAMFILES%\\N\\n.exe'\n  Type: Sideloading\n")  # fmt: skip
EXE = "- Path: '%PROGRAMFILES%\\X\\x.exe'\n  Type: Sideloading\n"
TOLERATED = {  # read as none: the file's other parts still count
    "empty ExpectedLocations": f"Name: el.dll\nVendor: X\nExpectedLocations:\nVulnerableExecutables:\n{EXE}",
    "empty VulnerableExecutables": "Name: ve.dll\nVendor: X\nVulnerableExecutables:\n",
    "null item in VulnerableExecutables": f"Name: ni.dll\nVendor: X\nVulnerableExecutables:\n- \n{EXE}",
}  # fmt: skip
UNREADABLE = "Name: bad.dll\nVulnerableExecutables: [unclosed\n"  # a YAML error


def _update_sources():
    spec = importlib.util.spec_from_file_location(
        "update_sources_under_test", SCRIPTS / "update_sources.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rows(ctx, dll):
    conn = sqlite3.connect(ctx)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM hijackable_dlls WHERE dll_name_lower = ?", (dll,)
        ).fetchone()[0]
    finally:
        conn.close()


def _upstream(root, extra):
    return _tree(root / "HijackLibs" / "yml", {**HIJACKLIBS, **extra}).parent


@pytest.mark.parametrize("name", TOLERATED)
def test_an_empty_or_null_list_reads_as_none(tmp_path, name):
    ctx = _dbs(tmp_path)
    stats = import_hijacklibs(
        ctx, _upstream(tmp_path, {"x/odd.yml": TOLERATED[name], "n/new.yml": NEW})
    )
    assert stats["errors"] == 0 and _rows(ctx, "new.dll") == 1
    expected = {"empty VulnerableExecutables": 0}.get(
        name, 1
    )  # no executables: no rows
    assert _rows(ctx, TOLERATED[name].split("\n")[0].split(": ")[1]) == expected


def test_a_file_that_cant_be_read_is_skipped_by_name_and_the_rest_imported(
    tmp_path, caplog
):
    ctx = _dbs(tmp_path)
    stats = import_hijacklibs(
        ctx, _upstream(tmp_path, {"x/bad.yml": UNREADABLE, "n/new.yml": NEW})
    )
    assert (
        stats["errors"] == 1
        and _rows(ctx, "new.dll") == 1
        and _rows(ctx, "sqlite.dll") == 2
    )
    assert "HijackLibs: 1 file(s) skipped, unreadable: x/bad.yml" in caplog.text


def _update(tmp_path, upstream, commit="c0ffee1"):
    ctx = _dbs(tmp_path)
    us = _update_sources()
    us.shallow_clone = lambda url, dest, depth=1: bool(shutil.copytree(upstream, dest))
    us.SOURCES["hijacklibs"]["db"] = ctx.name
    ok = us.update_context_source(
        "hijacklibs", tmp_path, {"latest_commit": commit}, False, False
    )
    return ok, us.get_last_sync(ctx, "hijacklibs")


@pytest.mark.parametrize(
    "shape", ["a file it can't read", "no yml folder", "no entries"]
)
def test_an_update_with_errors_or_nothing_isnt_recorded_as_synced(tmp_path, shape):
    if shape == "a file it can't read":
        upstream = _upstream(tmp_path, {"x/bad.yml": UNREADABLE})
    elif shape == "no yml folder":
        upstream = tmp_path / "HijackLibs"
        upstream.mkdir()
    else:
        upstream = _tree(
            tmp_path / "HijackLibs" / "yml", {"x/none.yml": "Name: n.dll\n"}
        ).parent
    assert _update(tmp_path, upstream) == (False, None)


def test_a_clean_update_is_recorded_as_synced(tmp_path):
    assert _update(tmp_path, _upstream(tmp_path, {})) == (True, "c0ffee1")


def test_dlls_imported_counts_distinct_dlls(tmp_path):
    ctx = _dbs(tmp_path)
    stats = import_hijacklibs(
        ctx, _tree(tmp_path / "HijackLibs" / "yml", HIJACKLIBS).parent
    )
    assert stats["dlls_imported"] == 3  # sqlite.dll from two vendors' files is one DLL


@pytest.mark.parametrize(
    "body",
    [
        "Commands:\n- \n- Command: a.exe x\n  Category: Execute\nFull_Path:\n- Path: C:\\a.exe\n",
        "Commands:\n- Command: a.exe x\n  Category: Execute\nFull_Path:\n- \n- Path: C:\\a.exe\n",
    ],
    ids=["null command", "null path"],
)
def test_a_null_item_in_a_lolbas_list_is_skipped_not_the_binary(tmp_path, body):
    ctx = _dbs(tmp_path)
    lol = tmp_path / "LOLBAS" / "yml" / "OSBinaries"
    lol.mkdir(parents=True)
    (lol / "a.yml").write_text(f"Name: a.exe\nDescription: d\n{body}", encoding="utf-8")
    stats = import_lolbas(ctx, tmp_path / "LOLBAS")
    conn = sqlite3.connect(ctx)
    assert conn.execute("SELECT name FROM lolbins").fetchall() == [("a.exe",)]
    assert stats["errors"] == 0


@pytest.mark.parametrize("hijacklibs", ["unreadable file", "clean"])
def test_import_context_exits_non_zero_and_says_why_on_errors(
    tmp_path, capsys, hijacklibs
):
    """import_context reads <its package>/data: run with its __file__ in a
    scratch package, whose data/ holds the databases and sources."""
    spec = importlib.util.spec_from_file_location(
        "import_context_under_test", SCRIPTS / "import_context.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    data = tmp_path / "pkg" / "data"
    data.mkdir(parents=True)
    _dbs(data)
    files = {
        **HIJACKLIBS,
        **({"x/bad.yml": UNREADABLE} if hijacklibs != "clean" else {}),
    }
    _tree(data / "sources" / "HijackLibs" / "yml", files)
    mod.__file__ = str(tmp_path / "pkg" / "scripts" / "import_context.py")
    if hijacklibs == "clean":
        mod.main()
        return
    with pytest.raises(SystemExit) as e:
        mod.main()
    assert e.value.code not in (0, None)
    assert (
        "HijackLibs: 1 file(s) skipped, unreadable: x/bad.yml"
        in capsys.readouterr().out
    )
