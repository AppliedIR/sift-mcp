"""save_report defangs the report and its block's lines in one pass, as one
text, and splits it back: each part comes out as defanging it alone writes
it, a block line holding newlines stays one line, and the patterns compiled
don't grow with the number of lines."""

from __future__ import annotations

import json
import re

import pytest
import yaml
from vhir_cli.defang import defang_iocs
from vhir_signing import sign_approved

IOCS = [{"type": "domain-name", "value": "evil.com"}, "10.1.2.3",
        "http://bad.example.com/x"]  # fmt: skip
FINDING = {"id": "F-tester-001", "title": "C2 at evil.com", "observation": "o",
           "interpretation": "i", "confidence": "HIGH", "status": "APPROVED",
           "iocs": IOCS}  # fmt: skip
# occurrences at each end of a part, where a newline joins it to the next
CONTENT = "# Report\n\nBeacon to evil.com from 10.1.2.3, see /evil.com\nthen /"
LINES = [
    "evil.com at the start, at the end evil.com",
    "/evil.com is a path here, http://bad.example.com/x is not",
    "a line holding a newline: evil.com\n/evil.com\n\\evil.com and 10.1.2.3",
    "\n",
    "",
    "evil.com.",
    "notevil.com evil.com.au evil.com",
]


@pytest.fixture
def rs(tmp_path, monkeypatch):
    case = tmp_path / "INC-ONE-1"
    case.mkdir()
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-ONE-1", "name": "one"}))
    (case / "findings.json").write_text(json.dumps([FINDING]))
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text("[]")
    sign_approved(case)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return rs


def _save(rs, monkeypatch, lines, content=CONTENT):
    monkeypatch.setattr(rs, "verification_block", lambda view: list(lines))
    monkeypatch.setattr(rs, "provenance_block", lambda view: ["Saved by evil.com"])
    tool = {t.name: t for t in rs.create_server()._tool_manager.list_tools()}
    got = tool["save_report"].fn(filename="r.md", content=content, profile="full")
    assert got["status"] == "saved", got
    return got, (rs._resolve_case_dir() / "reports" / "r.md").read_text()


def test_each_part_is_written_as_defanging_it_alone_writes_it(rs, monkeypatch):
    got, saved = _save(rs, monkeypatch, LINES)
    case = rs._resolve_case_dir()
    iocs = rs._report_iocs(case, rs.approved_view(case))
    want = [defang_iocs(p, iocs) for p in [*LINES, "", "Saved by evil.com"]]
    assert got["verification_block"] == want
    assert saved.startswith(defang_iocs(CONTENT, iocs).rstrip("\n") + "\n\n```\n")
    assert "\n".join(want) in saved
    assert "/evil.com is a path here, hxxp://bad[.]example[.]com/x" in saved
    # a newline inside a line bounds an occurrence as a line's start does
    assert "evil[.]com\n/evil.com\n\\evil.com and 10[.]1[.]2[.]3" in saved


@pytest.fixture
def compiles(monkeypatch):
    compiler = getattr(re, "_compiler", None) or re.sre_compile
    count, real = [0], compiler.compile

    def counted(*args, **kwargs):
        count[0] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(compiler, "compile", counted)
    return count


def test_the_patterns_compiled_dont_grow_with_the_blocks_lines(
    tmp_path, monkeypatch, compiles
):
    # more IOCs than re's cache holds, each in the report: compiling one per
    # line would compile every one of them again on each line
    names = [f"host{n}.evil.com" for n in range(600)]
    case = tmp_path / "INC-ONE-2"
    case.mkdir()
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-ONE-2", "name": "two"}))
    finding = {**FINDING, "iocs": [{"type": "domain-name", "value": v} for v in names]}
    (case / "findings.json").write_text(json.dumps([finding]))
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text("[]")
    sign_approved(case)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    counts = []
    for lines in (LINES[:1], LINES * 30):
        re.purge()
        compiles[0] = 0
        _save(rs, monkeypatch, lines, content=" ".join(names))
        counts.append(compiles[0])
    assert counts[0] == counts[1] < 2 * len(names)
