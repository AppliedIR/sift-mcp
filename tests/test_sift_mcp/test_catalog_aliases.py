"""A catalog tool is found by any name it goes by.

The AI names a tool as it reads it: "plaso", "Volatility 3", "volatility".
get_tool_help and check_tools look the name up in the catalog, which knew
only each tool's name and binary, so those names failed. A catalog entry can
carry aliases, and every lookup (help, checks, suggestions, runs) uses them.
No alias can be another tool's name, binary or alias. Every tool the
knowledge base names in an artifact's related_tools is found, or is listed
below as a tool the SIFT catalog doesn't carry.
"""

from __future__ import annotations

import os
import shutil

import pytest
from forensic_knowledge import loader
from sift_mcp.catalog import get_tool_def, load_catalog
from sift_mcp.tools import discovery

# Tools the knowledge base names that have no SIFT catalog entry, by why
NO_CATALOG_TOOL = {
    # Windows-only tools (run through wintools, or on a Windows host)
    "autoruns", "autorunsc", "bitsadmin", "bmc-tools", "BrowsingHistoryView",
    "Get-WMIObject", "Hindsight", "KAPE", "KStrike", "NTFS Log Tracker",
    "sigcheck", "streams.exe", "vssadmin", "WxTCmd",
    # macOS system tools and macOS-only parsers
    "APOLLO", "ccl-segb", "chainbreaker", "codesign", "csrutil", "diskutil",
    "DumpBTM", "FSEventsParser", "ioreg", "kextstat", "kmutil", "KnockKnock",
    "launchctl", "log", "mac_apt", "mdfind", "mdls", "mdutil", "mount_apfs",
    "plutil", "security", "sfltool", "spctl", "stapler", "systemextensionsctl",
    "tccutil", "tmutil", "unifiedlog_iterator", "xattr", "xprotect",
    # Linux and Unix system commands the catalog doesn't carry
    "at", "crontab", "journalctl", "last", "lastb", "lsof", "ssh-keygen", "w",
    "who",
    # Other analysis tools and scripts the catalog doesn't carry
    "DB Browser for SQLite", "INDXParse.py", "istat", "osslsigncode", "sqlite3",
    "wmi_persistence.py",
}  # fmt: skip


def _related_tools() -> set[str]:
    root = loader._find_data_dir() / "artifacts"
    return {
        name
        for path in root.glob("*/*.yaml")
        for name in (loader.get_artifact(path.stem) or {}).get("related_tools", [])
    }


def test_no_alias_is_another_tools_name_binary_or_alias():
    owners: dict[str, set[str]] = {}
    for td in load_catalog().values():
        for name in {td.name, td.binary, *td.aliases}:
            owners.setdefault(name.lower(), set()).add(td.name)
    clashes = {
        alias: sorted(owners[alias.lower()])
        for td in load_catalog().values()
        for alias in td.aliases
        if len(owners[alias.lower()]) > 1
    }
    assert clashes == {}


def test_no_alias_is_another_program():
    """An alias that's also a program's name would describe that program as
    the tool: p7zip is 7-Zip's gzip-style wrapper, which compresses the files
    it's given and deletes them, so it isn't 7z's alias. No alias may be a
    program on this host's PATH other than the tool's own binary (a SIFT box
    has them; CI may not, so p7zip is also checked by name)."""

    def program(name):
        found = shutil.which(name)
        return os.path.realpath(found) if found else None

    others = {
        alias: path
        for td in load_catalog().values()
        for alias in td.aliases
        if (path := program(alias)) and path != program(td.binary)
    }
    assert others == {}
    assert get_tool_def("p7zip") is None


def test_every_related_tool_is_found_or_listed_as_not_in_the_catalog():
    names = _related_tools()
    unfound = {n for n in names if get_tool_def(n) is None}
    assert sorted(unfound - NO_CATALOG_TOOL) == []  # found, or listed
    assert sorted(NO_CATALOG_TOOL - unfound) == []  # listed, but used and unfound


@pytest.mark.parametrize(
    "typed, tool",
    [
        ("plaso", "log2timeline"),
        ("Plaso", "log2timeline"),
        ("Plaso (log2timeline)", "log2timeline"),
        ("Volatility 3", "vol3"),
        ("Volatility3", "vol3"),
        ("volatility", "vol3"),
        ("7-Zip", "7z"),
        ("Bulk Extractor", "bulk_extractor"),
        ("bulk-extractor", "bulk_extractor"),
    ],
)
def test_help_and_checks_take_the_names_a_tool_goes_by(monkeypatch, typed, tool):
    assert discovery.get_tool_help(typed)["name"] == tool
    monkeypatch.setattr(discovery, "find_binary", lambda binary: f"/usr/bin/{binary}")
    assert discovery.check_tools([typed])[typed]["available"] is True


@pytest.mark.parametrize(
    "artifact, tool, entry",
    [
        ("syslog", "log2timeline", "Plaso (log2timeline)"),
        ("auth_log", "Plaso (log2timeline)", "Plaso (log2timeline)"),
        ("proc_filesystem", "Volatility3", "Volatility 3"),
    ],
)
def test_suggest_tools_describes_a_tool_from_its_entry(
    monkeypatch, artifact, tool, entry
):
    monkeypatch.setattr(discovery, "find_binary", lambda binary: f"/usr/bin/{binary}")
    (row,) = [
        s for s in discovery.suggest_tools(artifact)["suggestions"] if s["tool"] == tool
    ]
    assert row["description"] == loader.get_tool(entry)["description"] != ""
    assert row["available"] is True
