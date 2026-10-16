"""forensic-mcp's reads page as they say, and mark the timeline as they do
findings.

- Paging: `limit=0` is every item from `offset` on, with `has_more: false`;
  a negative offset is refused by both tools, whatever the limit (at db9ddef
  `limit=0` ignored `offset`, said `has_more: true` with everything returned,
  and a negative offset sliced from the end).
- `get_timeline` and case-mcp's `export_bundle` mark each APPROVED event
  with `approval_verification`, from one check, and name every one that
  doesn't verify in one warning, findings first.

The real servers run in-process on scratch cases; approvals are signed with
one key per case (a new key per commit would read KEY_CHANGED).
"""

from __future__ import annotations

import asyncio
import json

import case_mcp.server as cms
import forensic_mcp.case.manager as fmm
import pytest
from forensic_mcp.server import create_server
from mcp.types import CallToolRequest, CallToolRequestParams
from vhir_signing import sign_approved

OFFSET = "offset must be 0 or more"
NOT_RECORDED = "The examiner must review these again; don't build on them as approved."


def _finding(n: int, status: str = "DRAFT") -> dict:
    return {"id": f"F-rig-00{n}", "title": f"title {n}", "observation": "seen in 4688",
            "interpretation": "lateral movement", "confidence": "HIGH", "status": status}  # fmt: skip


def _event(n: int, status: str = "DRAFT") -> dict:
    return {"id": f"T-rig-00{n}", "timestamp": f"2026-10-0{n}T10:00:00+00:00",
            "description": f"event {n}", "status": status}  # fmt: skip


def _make_case(root, name, findings, events, monkeypatch):
    d = root / "cases" / name
    d.mkdir(parents=True)
    (d / "CASE.yaml").write_text(f"case_id: {name}\n")
    (d / "findings.json").write_text(json.dumps(findings))
    (d / "timeline.json").write_text(json.dumps(events))
    pointer = root / f"active_case-{name}"
    pointer.write_text(str(d))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setattr(fmm, "_ACTIVE_CASE_FILE", pointer)
    monkeypatch.setattr(cms, "_ACTIVE_CASE_FILE", pointer)
    return d


def _tool(name):
    return create_server()._tool_manager._tools[name].fn


def _ids(items):
    return [i["id"] for i in items]


# --- P: paging ----------------------------------------------------------------


@pytest.fixture
def drafts(tmp_path, monkeypatch):
    """T1–T3 and F1–F3, all DRAFT."""
    return _make_case(tmp_path, "INC-P", [_finding(n) for n in (1, 2, 3)],
                      [_event(n) for n in (1, 2, 3)], monkeypatch)  # fmt: skip


@pytest.mark.parametrize(
    "kw, ids, more",
    [
        ({"limit": 0}, ["T-rig-001", "T-rig-002", "T-rig-003"], False),  # P1
        ({"limit": 0, "offset": 1}, ["T-rig-002", "T-rig-003"], False),  # P2
        ({}, ["T-rig-001", "T-rig-002", "T-rig-003"], False),  # PC1
        ({"limit": 2}, ["T-rig-001", "T-rig-002"], True),  # PC2
        ({"limit": 2, "offset": 2}, ["T-rig-003"], False),  # PC3
    ],
    ids=["P1", "P2", "PC1", "PC2", "PC3"],
)
def test_get_timeline_pages_from_offset(drafts, kw, ids, more):
    out = _tool("get_timeline")(**kw)
    assert (_ids(out["events"]), out["has_more"], out["total"]) == (ids, more, 3)


@pytest.mark.parametrize(
    "kw, ids",
    [
        ({"limit": 0, "offset": 1}, ["F-rig-002", "F-rig-003"]),  # P3
        ({"limit": 2, "offset": 1}, ["F-rig-002", "F-rig-003"]),  # PC4
        ({}, ["F-rig-001", "F-rig-002", "F-rig-003"]),  # PC5
        ({"limit": 1, "offset": 5}, []),  # PC6
    ],
    ids=["P3", "PC4", "PC5", "PC6"],
)
def test_get_findings_pages_from_offset(drafts, kw, ids):
    out = _tool("get_findings")(**kw)
    assert (_ids(out["findings"]), out["total"]) == (ids, 3)


@pytest.mark.parametrize(
    "tool, key, kw",
    [
        ("get_timeline", "events", {"offset": -1}),  # P5
        ("get_findings", "findings", {"offset": -1, "limit": 2}),  # P6
        ("get_timeline", "events", {"offset": -2, "limit": 0}),  # P7
        ("get_findings", "findings", {"offset": -2, "limit": 0}),  # P8
    ],
    ids=["P5", "P6", "P7", "P8"],
)
def test_a_negative_offset_is_refused_whatever_the_limit(drafts, tool, key, kw):
    out = _tool(tool)(**kw)  # an error, not a row, and no count
    assert (out[key], out["error"]) == ([], OFFSET) and "total" not in out, out


def _wire(tool: str, **args):
    """A tools/call request as the MCP route sends it: (isError, text)."""
    handler = create_server()._mcp_server.request_handlers[CallToolRequest]
    request = CallToolRequest(method="tools/call",
                              params=CallToolRequestParams(name=tool, arguments=args))  # fmt: skip
    result = asyncio.run(handler(request)).root
    return result.isError, result.content[0].text


@pytest.mark.parametrize("tool", ["get_findings", "get_timeline"])
def test_a_negative_offset_is_refused_by_the_schema(drafts, tool):
    tools = {t.name: t for t in asyncio.run(create_server().list_tools())}
    assert tools[tool].inputSchema["properties"]["offset"]["minimum"] == 0
    is_error, text = _wire(tool, offset=-1)
    assert is_error and "greater than or equal to 0" in text, text
    assert '"total"' not in text
    is_error, text = _wire(tool, offset=1)  # twin: the real count
    assert not is_error and json.loads(text)["total"] == 3, text


# --- A, E: the timeline's approvals are verified --------------------------------


@pytest.fixture
def approved(tmp_path, monkeypatch):
    """T1, T2, F1, F2 approved and signed with one key; then T2's description
    and F2's interpretation altered by hand, and T4 set APPROVED by hand with
    no signed line. T3 stays DRAFT."""
    d = _make_case(tmp_path, "INC-A", [_finding(1, "APPROVED"), _finding(2, "APPROVED")],
                   [_event(1, "APPROVED"), _event(2, "APPROVED"), _event(3)], monkeypatch)  # fmt: skip
    sign_approved(d)
    fs = json.loads((d / "findings.json").read_text())
    fs[1]["interpretation"] = "ALTERED BY HAND after approval"
    ts = json.loads((d / "timeline.json").read_text())
    ts[1]["description"] = "ALTERED BY HAND after approval"
    ts.append(dict(_event(4, "APPROVED"), approved_by="tester",
                   approved_at="2026-10-08T00:00:00+00:00"))  # fmt: skip
    for name, items in (("findings.json", fs), ("timeline.json", ts)):
        (d / name).chmod(0o644)
        (d / name).write_text(json.dumps(items))
    return d


def _marks(items):
    return {i["id"]: i.get("approval_verification") for i in items}


A1_MARKS = {"T-rig-001": "VALID", "T-rig-002": "ALTERED_AFTER_APPROVAL",
            "T-rig-003": None, "T-rig-004": "APPROVED_NO_LINE"}  # fmt: skip


def test_get_timeline_marks_each_approved_event_and_warns_once(approved):
    out = _tool("get_timeline")()
    assert _marks(out["events"]) == A1_MARKS  # A1
    assert out["warning"] == (
        "Not approved as recorded: T-rig-002 ALTERED_AFTER_APPROVAL, "
        f"T-rig-004 APPROVED_NO_LINE. {NOT_RECORDED}"
    )


def test_a_page_of_verified_events_has_no_warning(approved):
    out = _tool("get_timeline")(limit=1)  # A3
    assert _marks(out["events"]) == {"T-rig-001": "VALID"} and "warning" not in out


def test_get_findings_still_marks_findings(approved):
    out = _tool("get_findings")()  # AC1
    assert _marks(out["findings"]) == {
        "F-rig-001": "VALID",
        "F-rig-002": "ALTERED_AFTER_APPROVAL",
    }
    assert out["warning"] == (
        f"Not approved as recorded: F-rig-002 ALTERED_AFTER_APPROVAL. {NOT_RECORDED}"
    )


def test_export_marks_findings_and_events_with_one_warning(
    approved, tmp_path, monkeypatch
):
    before = {
        n: (approved / n).read_bytes() for n in ("findings.json", "timeline.json")
    }
    _tool("get_timeline")()
    out = cms.create_server()._tool_manager._tools["export_bundle"].fn()
    assert _marks(out["findings"]) == {
        "F-rig-001": "VALID",
        "F-rig-002": "ALTERED_AFTER_APPROVAL",
    }
    assert _marks(out["timeline"]) == A1_MARKS  # E1
    assert out["warning"] == (
        "Not approved as recorded: F-rig-002 ALTERED_AFTER_APPROVAL, "
        "T-rig-002 ALTERED_AFTER_APPROVAL, T-rig-004 APPROVED_NO_LINE. " + NOT_RECORDED
    )
    assert {n: (approved / n).read_bytes() for n in before} == before  # A4

    # E1, the import half: a fresh case takes all six as drafts, unmarked
    bundle = {k: out[k] for k in ("case_id", "examiner", "exported_at", "findings",
                                  "timeline") if k in out}  # fmt: skip
    other = _make_case(tmp_path, "INC-B", [], [], monkeypatch)
    path = other / "bundle.json"
    path.write_text(json.dumps(bundle))
    got = (
        cms.create_server()
        ._tool_manager._tools["import_bundle"]
        .fn(bundle_path=str(path))
    )
    assert got["status"] == "merged", got
    stored = [*json.loads((other / "findings.json").read_text()),
              *json.loads((other / "timeline.json").read_text())]  # fmt: skip
    assert len(stored) == 6 and {i["status"] for i in stored} == {"DRAFT"}
    assert not any("approval_verification" in i for i in stored)


def test_the_tool_list_says_how_get_timeline_marks_approvals():
    tools = {t.name: t for t in asyncio.run(create_server().list_tools())}  # D2
    assert (
        "Each APPROVED event carries approval_verification: VALID, or why its approval "
        "doesn't verify (e.g. ALTERED_AFTER_APPROVAL): then treat it as not approved; "
        "`warning` names each such event."
    ) in " ".join(tools["get_timeline"].description.split())
