"""HijackLibs keeps one row per install path and type, and its table is
rebuilt in one transaction only when the files parse; a LOLBAS list key that
is present but empty reads as no items.

The importers run as update_sources and import_context call them, on a fresh
context.db and on one keyed the 0.6.4 way; answers come from the server's
own check_hijackable_dll and check_lolbin. Values are synthetic, in the
upstream YAML shapes.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from types import SimpleNamespace

import pytest
from windows_triage.config import Config
from windows_triage.db import ContextDB, KnownGoodDB
from windows_triage.db.schemas import CONTEXT_SCHEMA
from windows_triage.importers import hijacklibs, import_hijacklibs, import_lolbas
from windows_triage.server import WindowsTriageServer

NEW_KEY = "UNIQUE(dll_name_lower, vulnerable_exe_path, hijack_type)"
OLD_KEY = "UNIQUE(dll_name_lower, vulnerable_exe)"
ONEDRIVE_PF = "\\program files\\microsoft onedrive\\onedrive.exe"
ONEDRIVE_USER = "\\users\\<user>\\appdata\\local\\microsoft\\onedrive\\onedrive.exe"


def _exe(path, kind="Sideloading"):
    return f"- Path: '{path}'\n  Type: {kind}\n"


HIJACKLIBS = {
    "microsoft/built-in/sspicli.yml": "Name: sspicli.dll\nVendor: Microsoft\n"
    "VulnerableExecutables:\n"
    + _exe("%LOCALAPPDATA%\\Microsoft\\OneDrive\\OneDrive.exe")
    + _exe("%PROGRAMFILES%\\Microsoft OneDrive\\OneDrive.exe"),
    "3rd_party/a/sqlite.yml": "Name: sqlite.dll\nVendor: A\nVulnerableExecutables:\n"
    + _exe("%PROGRAMFILES%\\A\\a.exe"),
    "3rd_party/b/sqlite.yml": "Name: sqlite.dll\nVendor: B\nVulnerableExecutables:\n"
    + _exe("%PROGRAMFILES%\\B\\b.exe"),
    "fixture/dup.yml": "Name: dup.dll\nVendor: F\nVulnerableExecutables:\n"
    + _exe("%PROGRAMFILES%\\F\\dup.exe") * 2  # the same row twice
    + _exe("%PROGRAMFILES%\\F\\dup.exe", "Phantom"),
}


def _tree(root, files):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def _dbs(tmp_path, old=False):
    ctx = tmp_path / "context.db"
    if old:  # a context.db made by 0.6.4: the old key, and the one row its import kept
        conn = sqlite3.connect(ctx)
        conn.executescript(CONTEXT_SCHEMA.replace(NEW_KEY, OLD_KEY))
        conn.execute(
            "INSERT INTO hijackable_dlls (dll_name_lower, hijack_type, vulnerable_exe,"
            " vulnerable_exe_path, expected_paths, vendor) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "sspicli.dll",
                "Sideloading",
                "onedrive.exe",
                ONEDRIVE_PF,
                "[]",
                "Microsoft",
            ),
        )
        conn.commit()
        conn.close()
    else:
        ContextDB(ctx).init_schema()
    KnownGoodDB(tmp_path / "known_good.db").init_schema()
    return ctx


def _table(ctx):
    conn = sqlite3.connect(ctx)
    ddl = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name='hijackable_dlls'"
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT dll_name_lower, hijack_type, vulnerable_exe_path FROM hijackable_dlls"
    ).fetchall()
    conn.close()
    return ("NEW" if NEW_KEY in ddl else "OLD" if OLD_KEY in ddl else ddl), sorted(rows)


def _ask(tmp_path, tool, arg):
    server = WindowsTriageServer(
        config=Config(
            known_good_db=tmp_path / "known_good.db",
            context_db=tmp_path / "context.db",
            skip_db_validation=True,
            cache_size=0,
        )
    )
    return asyncio.run(getattr(server, f"_{tool}")(arg))


def _scenarios(answer):
    by_type = answer.get("scenarios_by_type") or {}
    return sorted(
        (t, e["vulnerable_exe_path"]) for t, rows in by_type.items() for e in rows
    )


@pytest.mark.parametrize("old", [False, True], ids=["fresh", "made-by-0.6.4"])
def test_every_install_path_and_type_is_a_row(tmp_path, caplog, old):
    ctx = _dbs(tmp_path, old)
    caplog.set_level(logging.INFO)
    stats = import_hijacklibs(
        ctx, _tree(tmp_path / "HijackLibs/yml", HIJACKLIBS).parent
    )
    key, rows = _table(ctx)
    assert (key, len(rows)) == ("NEW", 6)
    assert stats == {  # was dlls_imported 4: the files, where sqlite.dll is one DLL
        "dlls_imported": 3, "entries_imported": 6, "duplicates": 1, "errors": 0, "skipped": 0,
        "skipped_files": [],
    }  # fmt: skip
    assert (
        "Imported 3 hijackable DLLs (6 vulnerable exe entries; 1 duplicate entries not stored)"
        in (caplog.messages)
    )
    sspicli = _scenarios(_ask(tmp_path, "check_hijackable_dll", "sspicli.dll"))
    assert sspicli == [("Sideloading", ONEDRIVE_PF), ("Sideloading", ONEDRIVE_USER)]
    dup = _scenarios(_ask(tmp_path, "check_hijackable_dll", "dup.dll"))
    assert [t for t, _ in dup] == ["Phantom", "Sideloading"]
    sqlite = _scenarios(_ask(tmp_path, "check_hijackable_dll", "sqlite.dll"))
    assert [p for _, p in sqlite] == [
        "\\program files\\a\\a.exe",
        "\\program files\\b\\b.exe",
    ]


def test_nothing_parsed_leaves_the_table_and_says_so(tmp_path, caplog):
    ctx = _dbs(tmp_path, old=True)
    before = _table(ctx)
    yml = _tree(tmp_path / "HijackLibs/yml", {"x/sspicli.yml": "Name: sspicli.dll\n"})
    caplog.set_level(logging.INFO)
    import_hijacklibs(ctx, yml.parent)
    assert _table(ctx) == before
    assert (
        f"HijackLibs: 0 entries parsed from {yml}; hijackable_dlls left unchanged"
        in caplog.messages
    )
    assert [r.levelname for r in caplog.records if "0 entries parsed" in r.message] == [
        "ERROR"
    ]


def test_a_file_that_fails_to_parse_is_skipped_and_named(tmp_path, caplog):
    """Was all or nothing (the table left unchanged), which let one bad
    upstream file block every later update: now the file is skipped by name
    and counted, and the rest replace the table."""
    ctx = _dbs(tmp_path, old=True)
    files = {
        "microsoft/built-in/sspicli.yml": HIJACKLIBS["microsoft/built-in/sspicli.yml"],
        "bad/a.yml": "Name: [unclosed\n",
        "bad/b.yml": "Name: 5\nVulnerableExecutables: []\n",  # parses, then raises
    }
    caplog.set_level(logging.INFO)
    stats = import_hijacklibs(ctx, _tree(tmp_path / "HijackLibs/yml", files).parent)
    key, rows = _table(ctx)
    assert (key, len(rows)) == ("NEW", 2)  # sspicli's two install paths
    assert (stats["errors"], stats["skipped_files"]) == (2, ["bad/a.yml", "bad/b.yml"])
    error = [r for r in caplog.records if r.levelname == "ERROR"]
    assert [r.message for r in error] == [
        "HijackLibs: 2 file(s) skipped, unreadable: bad/a.yml, bad/b.yml"
    ]


def test_an_interrupted_import_keeps_the_old_table(tmp_path, monkeypatch):
    ctx = _dbs(tmp_path, old=True)
    before = _table(ctx)
    real, calls = hijacklibs.json.dumps, []

    def dumps(obj, *a, **k):  # one call per row inserted: Ctrl-C at the 3rd
        calls.append(obj)
        if len(calls) == 3:
            raise KeyboardInterrupt
        return real(obj, *a, **k)

    monkeypatch.setattr(hijacklibs, "json", SimpleNamespace(dumps=dumps))
    with pytest.raises(KeyboardInterrupt):
        import_hijacklibs(ctx, _tree(tmp_path / "HijackLibs/yml", HIJACKLIBS).parent)
    assert _table(ctx) == before


LOLBAS = {
    "OSBinaries/Certutil.yml": "Name: Certutil.exe\nCommands:\n"
    "  - Command: certutil.exe -urlcache -f http://x/y z\n    Category: Download\n"
    "    MitreID: T1105\nFull_Path:\n  - Path: C:\\Windows\\System32\\certutil.exe\n"
    "Detection:\n  - IOC: Certutil.exe creating new files on disk\n",
    "OtherMSBinaries/Copilot_proxy.yml": "Name: Copilot_proxy.exe\nCommands:\n"
    "  - Command: copilot_proxy.exe x\n    Category: Execute\n    MitreID: T1218\n"
    "Full_Path:\n  - Path: C:\\Program Files\\Copilot\\copilot_proxy.exe\n"
    "Detection:\nResources:\n  - Link: https://example.invalid/r\n",
    "OtherMSBinaries/Allnull.yml": "Name: Allnull.exe\nCommands:\nFull_Path:\nDetection:\n"
    "Aliases:\nResources:\n",
    "HonorableMentions/Mention.yml": "Name: Mention.exe\nCommands:\n"
    "  - Command: mention.exe\n    Category: Execute\n",
}


def test_a_lolbas_list_key_present_but_empty_reads_as_no_items(tmp_path, caplog):
    ctx = _dbs(tmp_path)
    caplog.set_level(logging.INFO)
    stats = import_lolbas(ctx, _tree(tmp_path / "LOLBAS/yml", LOLBAS).parent)
    assert (stats["lolbins_imported"], stats["errors"]) == (3, 0)
    assert not [m for m in caplog.messages if "Error processing" in m]

    def answer(name):
        a = _ask(tmp_path, "check_lolbin", name)
        lists = [list(a.get(k) or ()) for k in ("functions", "mitre_techniques")]
        return [a.get("is_lolbin"), *lists, a.get("detection")]

    assert answer("copilot_proxy.exe") == [True, ["Execute"], ["T1218"], None]
    assert answer("allnull.exe") == [True, [], [], None]
    assert answer("certutil.exe") == [
        True, ["Download"], ["T1105"], "IOC: Certutil.exe creating new files on disk"
    ]  # fmt: skip
    assert _ask(tmp_path, "check_lolbin", "mention.exe").get("is_lolbin") is False
