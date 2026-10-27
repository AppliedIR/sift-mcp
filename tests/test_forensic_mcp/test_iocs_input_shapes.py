"""record_finding takes `iocs` as a list of IOCs, or a flat mapping of key → IOC
or list of IOCs (its keys dropped). An IOC is a string, a number, or an object
with a string or number `value` and an optional string `type`. Any other shape,
anywhere in the value, is refused before anything is written, naming the first
place it occurs. It was stored as a repr ("{'gadget.js': ...}") or dropped
without a word.

A domain-shaped value whose extension is a file's and no top-level domain
(x.bin) is a file name; one that is also a TLD (.zip) stays a domain, and a
command line ending in such an extension keeps its type.

The real forensic-mcp server runs in-process on scratch cases."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from forensic_mcp.server import create_server

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    _record,
    case,
    home,
)

SHA = "722968f89a70fa5da845180d16855df3220e5f6a7362ee5bd5f26a3f175b171e"
LABELLED = {  # labels as keys, hashes as their values, beside lists of values
    "sha256": {"gadget.js": SHA, "embedded DLL rofivjve.dll": "8f8d" + "0" * 60},
    "paths": ["C:\\Users\\slevine\\Downloads\\gadget.js"],
    "strings": ["GadgetToJScript.bin", "rofivjve.dll", "explorer"],
}
PAST_THE_CUT = [f"172.16.6.{n}" for n in range(1, 102)] + [
    "x" * 10000,
    "C:\\Windows\\Temp\\perfmon\\abc\U0001f525STUN.exe",
    "invoice\u202eexe.pdf",
    {"ip": "172.16.6.200"},  # index 104, past the 100 stored
]
MIXED = {
    "IPv4": ["172.16.6.12:3389", "172[.]16[.]6[.]13"],
    "URL": ["hxxp://stun-update[.]com/a"],
    "Account": [{"value": "SHIELDBASE\\tdungan", "type": "user-account"}],
}

REFUSED = [  # (id, iocs, the path named, what it holds)
    ("a mapping under a key after a list", {"strings": ["s1.example.net"], "sha256": {"a": "a" * 64}}, "iocs.sha256", 'mapping with no "value"'),
    ("labels as keys of hashes", LABELLED, "iocs.sha256", 'mapping with no "value"'),
    ("a list in the list", ["l0.example.net", ["l1.example.net"]], "iocs[1]", "list"),
    ("past the 100 cut", PAST_THE_CUT, "iocs[104]", 'mapping with no "value"'),
    ("a bare string", "172.16.6.14", "iocs", "string"),
    ("a JSON string of a list", '["js.example.net", "js2.example.net"]', "iocs", "string"),
    ("a number type", [{"value": "it.example.net", "type": 5}, "it2.example.net"], "iocs[0].type", "number"),
    ("a null type", [{"value": "nt.example.net", "type": None}], "iocs[0].type", "null"),
    ("a list type", [{"value": "lt.example.net", "type": ["domain-name"]}], "iocs[0].type", "list"),
    ("a type without a value", [{"type": "domain-name"}, "tv.example.net"], "iocs[0]", 'mapping with no "value"'),
    ("a list value", [{"value": ["nl1.example.net"], "type": "domain-name"}], "iocs[0].value", "list"),
    ("a bool value", [{"value": True}], "iocs[0].value", "bool"),
    ("a null item", [None, "no.example.net"], "iocs[0]", "null"),
    ("a bool item", [True, "bo.example.net"], "iocs[0]", "bool"),
    ("a bad item in a keyed list", {"Account": [{"value": None}]}, "iocs.Account[0].value", "null"),
    ("a bool under a key", {"seen": False}, "iocs.seen", "bool"),
    ("a key that is no word", {"a `b`": [[]]}, 'iocs["a \\u0060b\\u0060"][0]', "list"),
    ("a number in place of the list", 5, "iocs", "number"),
]  # fmt: skip

ACCEPTED = [  # (id, iocs, the records stored: value -> type)
    ("hashes listed under one key", {"sha256": [SHA, "8f8d" + "0" * 60]},
     {SHA: "file:hash:sha256", "8f8d" + "0" * 60: "file:hash:sha256"}),
    ("lists under several keys", MIXED,
     {"172.16.6.12": "ipv4-addr", "172.16.6.13": "ipv4-addr",
      "http://stun-update.com/a": "url", "SHIELDBASE\\tdungan": "user-account"}),
    ("a typed IOC under a key", {"domain": {"value": "fo.example.net", "type": "domain-name"}},
     {"fo.example.net": "domain-name"}),
    ("a number value with its type", [{"value": 12345, "type": "port"}], {"12345": "port"}),
    ("null", None, {}),
    ("an empty list", [], {}),
    ("an empty mapping", {}, {}),
    ("a list of strings", ["a1.example.net", "a2.example.net"],
     {"a1.example.net": "domain-name", "a2.example.net": "domain-name"}),
    ("a list with a typed IOC", [{"value": "rsydow-a", "type": "user-account", "note": "kept"}, "ao.example.net"],
     {"rsydow-a": "user-account", "ao.example.net": "domain-name"}),
    ("a key to an IOC", {"k": "fm.example.net"}, {"fm.example.net": "domain-name"}),
    ("a key to null beside a key to a list", {"strings": None, "domains": ["fn.example.net"]},
     {"fn.example.net": "domain-name"}),
    ("a number item", [4444, "bn.example.net"], {"4444": "unknown", "bn.example.net": "domain-name"}),
]  # fmt: skip


def _counts(case: Path) -> tuple:
    files = ("findings.json", "timeline.json", "iocs.json")
    return tuple(
        len(json.loads((case / n).read_text())) if (case / n).is_file() else 0
        for n in files
    )


@pytest.mark.parametrize(("iocs", "path", "kind"), [r[1:] for r in REFUSED],
                         ids=[r[0] for r in REFUSED])  # fmt: skip
def test_an_iocs_shape_outside_the_contract_is_refused_and_nothing_written(
    case,  # noqa: F811
    iocs,
    path,
    kind,
):
    _record({**FINDING, "iocs": ["10.0.0.1"]})  # a case with records already
    before = _counts(case)
    result = _record({**FINDING, "iocs": iocs})
    assert result["status"] == "VALIDATION_FAILED", result
    assert "finding_id" not in result
    error = result["errors"][0]
    assert error.startswith(f"iocs refused: `{path}` holds a {kind}, "), error
    for element in ("nothing was recorded", "Send a list of IOCs", "keys are dropped",
                    "Put labels in the finding text", "Example: iocs=["):  # fmt: skip
        assert element in error
    assert _counts(case) == before


def test_validate_finding_refuses_the_same_iocs_with_the_same_error(case):  # noqa: F811
    finding = {**FINDING, "iocs": LABELLED}
    refused = _record(finding)["errors"]
    server = create_server(reference_mode="tools")
    result = asyncio.run(
        server.call_tool("validate_finding", {"finding_json": finding})
    )
    result = result[0] if isinstance(result, tuple) else result
    data = json.loads(result[0].text)
    assert data["valid"] is False and data["errors"] == refused


@pytest.mark.parametrize(("iocs", "stored"), [r[1:] for r in ACCEPTED],
                         ids=[r[0] for r in ACCEPTED])  # fmt: skip
def test_an_accepted_iocs_shape_stores_one_record_per_ioc(case, iocs, stored):  # noqa: F811
    result = _record({**FINDING, "iocs": iocs})
    assert result["status"] == "STAGED", result
    path = case / "iocs.json"
    records = json.loads(path.read_text()) if path.is_file() else []
    assert {r["value"]: r["type"] for r in records} == stored


# --- a file name whose extension is no top-level domain ----------------------

FILE_EXTS = ["bak", "bin", "cfg", "cpl", "dat", "db", "dmp", "doc", "docx", "drv", "evtx",
             "gz", "hta", "img", "inf", "ini", "iso", "jar", "jse", "json", "lnk", "log",
             "ocx", "pdf", "rar", "tar", "tmp", "txt", "vbe", "wsf", "xls", "xlsx", "xml"]  # fmt: skip
FILE_NAMES = ["GadgetToJScript.bin", "GadgetToJScript.BIN", "GadgetToJScript[.]bin",
              "payload.tar.gz", "a.b.bin"] + [f"x.{e}" for e in FILE_EXTS]  # fmt: skip
KEPT = {  # each keeps its type: a path, a TLD extension, an executable
    "C:\\Temp\\x.bin": "file:path", "/tmp/x.bin": "file:path",
    "evil.zip": "domain-name", "example.com": "domain-name", "x.sh": "domain-name",
    "x.ps1": "file:name",
}  # fmt: skip


@pytest.mark.parametrize("shape", ["list", "mapping"])
@pytest.mark.parametrize("value", FILE_NAMES)
def test_a_file_extension_that_is_no_tld_makes_a_file_name(case, value, shape):  # noqa: F811
    iocs = [value] if shape == "list" else {"strings": [value]}
    result = _record({**FINDING, "iocs": iocs})
    assert result["status"] == "STAGED", result
    (record,) = json.loads((case / "iocs.json").read_text())
    assert (record["type"], record["category"]) == ("file:name", "host")


@pytest.mark.parametrize(("value", "kept"), KEPT.items())
def test_a_path_a_tld_extension_and_an_executable_keep_their_types(case, value, kept):  # noqa: F811
    result = _record({**FINDING, "iocs": [value]})
    assert result["status"] == "STAGED", result
    (record,) = json.loads((case / "iocs.json").read_text())
    assert record["type"] == kept


# --- the extension rule moves only a domain-shaped value ---------------------

COMMAND_LINES = {  # each keeps the type it had before the extension rule
    "tool.exe output.txt": ("process:command-line", "system"),
    "tool.exe\toutput.json": ("process:command-line", "system"),
    "rundll32.exe x.dll,Run": ("process:command-line", "system"),
    "tool.exe -o dump.dmp": ("process:command-line", "system"),
    "certutil.exe -decode a.b64 b.bin": ("process:command-line", "system"),
    "7z.exe a out.rar": ("process:command-line", "system"),
    "tool.exe x.zip": ("process:command-line", "system"),
    "tool.exe out.log": ("process:command-line", "system"),
    "notepad.exe a.ini": ("process:command-line", "system"),
    "tool.exe /o out.txt": ("process:command-line", "system"),
    "TOOL.EXE OUT.TXT": ("process:command-line", "system"),
    "x.exe y.exe": ("file:name", "host"),
    "powershell.exe -f a.ps1": ("file:name", "host"),
}  # fmt: skip


@pytest.mark.parametrize(("value", "kept"), COMMAND_LINES.items())
def test_a_command_line_ending_in_a_file_extension_keeps_its_type(case, value, kept):  # noqa: F811
    result = _record({**FINDING, "iocs": [value]})
    assert result["status"] == "STAGED", result
    (record,) = json.loads((case / "iocs.json").read_text())
    assert (record["value"], record["type"], record["category"]) == (value, *kept)
