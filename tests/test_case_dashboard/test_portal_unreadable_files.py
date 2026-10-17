"""The Portal says when it couldn't read a case file or an audit log.

A findings.json, timeline.json or iocs.json that is a FIFO or can't be read is
refused by name on its routes, never an empty case. An audit log that can't be
read is named in the audit view (it may hold a cited entry), and noted where
its entries are counted (withdrawn, no_terminal). A case with every file
readable answers as before.
"""

from __future__ import annotations

import errno
import json
import os

import pytest

from .conftest import NOW0, Portal, finding

_NON_ROOT = pytest.mark.skipif(os.geteuid() == 0, reason="mode 000 doesn't stop root")


def _entry(aid, tool="run_command", **extra):
    e = {"audit_id": aid, "ts": NOW0, "tool": tool, "examiner": "steve"}
    e.update(extra)
    return e


def _jsonl(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))


@pytest.fixture
def portal(tmp_path, monkeypatch, box):
    """Two findings citing entries in sift-mcp and forensic-mcp; a withdrawal
    in sift-mcp; one approve refused for want of a terminal in cli-approve."""
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    (d / "timeline.json").write_text("[]\n")
    (d / "evidence.json").write_text('{"files": []}\n')
    (d / "todos.json").write_text("[]\n")
    findings = [
        finding("F-steve-001", audit_ids=["sift-steve-001", "forensic-steve-001"]),
        finding(
            "F-steve-002",
            audit_ids=["sift-steve-002", "sift-steve-003", "forensic-steve-002"],
        ),
    ]
    (d / "findings.json").write_text(json.dumps(findings, indent=2) + "\n")
    withdrawn = {"status": "WITHDRAWN", "title": "w1", "observation": "o",
                 "contradiction": "c"}  # fmt: skip
    _jsonl(
        d / "audit" / "sift-mcp.jsonl",
        [
            _entry("sift-steve-001"),
            _entry("sift-steve-002"),
            _entry("sift-steve-003"),
            _entry(
                "forensic-steve-009", tool="record_finding", result_summary=withdrawn
            ),
        ],
    )
    _jsonl(
        d / "audit" / "forensic-mcp.jsonl",
        [_entry("forensic-steve-001"), _entry("forensic-steve-002")],
    )
    _jsonl(
        d / "audit" / "cli-approve.jsonl",
        [
            _entry(
                "cli-1",
                tool="approve",
                mcp="cli-approve",
                params={"ids": ["F-steve-001"]},
                result_summary={"status": "NO_TERMINAL"},
            )
        ],
    )
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    yield Portal(d)
    for p in [d / "findings.json", *(d / "audit").iterdir()]:
        if not (p.is_fifo() or p.is_symlink()):
            p.chmod(0o644)


def _fifo(path):
    path.unlink(missing_ok=True)
    os.mkfifo(path)


@pytest.mark.parametrize("route", ["/api/findings", "/api/findings/F-steve-001"])
@pytest.mark.parametrize("shape", ["fifo", pytest.param("mode-000", marks=_NON_ROOT)])
def test_an_unreadable_findings_file_is_refused_by_name(portal, shape, route):
    path = portal.dir / "findings.json"
    _fifo(path) if shape == "fifo" else path.chmod(0)
    r = portal.get(route)
    assert r.status_code == 409, (r.status_code, r.text)
    assert r.json()["error"].startswith("findings.json couldn't be read (")


@pytest.mark.parametrize(
    "name, route", [("timeline.json", "/api/timeline"), ("iocs.json", "/api/iocs")]
)
def test_an_unreadable_timeline_or_iocs_file_is_refused_by_name(portal, name, route):
    _fifo(portal.dir / name)
    r = portal.get(route)
    assert r.status_code == 409, (r.status_code, r.text)
    assert r.json()["error"].startswith(f"{name} couldn't be read (")


@_NON_ROOT
def test_an_unreadable_log_holding_a_cited_entry_refuses_the_audit_view(portal):
    (portal.dir / "audit" / "sift-mcp.jsonl").chmod(0)
    for fid in ("F-steve-001", "F-steve-002"):
        r = portal.get(f"/api/audit/{fid}")
        assert r.status_code == 409, (fid, r.text)
        assert r.json()["error"].startswith(
            "Couldn't read audit/sift-mcp.jsonl (Permission denied): "
        )


@_NON_ROOT
def test_an_unreadable_log_refuses_the_audit_view_even_with_no_cited_entry(portal):
    (portal.dir / "audit" / "cli-approve.jsonl").chmod(0)
    r = portal.get("/api/audit/F-steve-001")
    assert r.status_code == 409, r.text
    assert r.json()["error"].startswith(
        "Couldn't read audit/cli-approve.jsonl (Permission denied): "
    )


@_NON_ROOT
def test_an_unreadable_log_is_noted_where_its_entries_are_counted(portal):
    (portal.dir / "audit" / "sift-mcp.jsonl").chmod(0)
    body = portal.get("/api/summary").json()
    withdrawn, no_terminal = body["withdrawn"], body["no_terminal"]
    assert withdrawn["unread_logs"] == ["audit/sift-mcp.jsonl (Permission denied)"]
    assert withdrawn["note"].startswith(
        "Couldn't read audit/sift-mcp.jsonl (Permission denied): "
    )
    assert no_terminal["unavailable"] is True
    assert no_terminal["total"] == 1  # the one in cli-approve, still counted
    assert "audit/sift-mcp.jsonl" in no_terminal["error"]


@_NON_ROOT
def test_an_unreadable_log_keeps_the_note_on_lines_that_arent_utf8(portal):
    with (portal.dir / "audit" / "sift-mcp.jsonl").open("ab") as f:
        f.write(b'{"tool": "record_finding", "x": "\xff"}\n')
    (portal.dir / "audit" / "forensic-mcp.jsonl").chmod(0)
    note = portal.get("/api/summary").json()["withdrawn"]["note"]
    assert note.startswith(
        "Couldn't read audit/forensic-mcp.jsonl (Permission denied): "
    )
    assert note.endswith(
        "Audit lines skipped because they aren't UTF-8: 1. "
        "A withdrawal recorded on them isn't listed."
    )


def test_a_log_link_to_nothing_is_skipped_as_before(portal):
    (portal.dir / "audit" / "gone.jsonl").symlink_to(portal.dir / "no-such.jsonl")
    r = portal.get("/api/audit/F-steve-001")
    assert r.status_code == 200, r.text
    assert sorted(e["audit_id"] for e in r.json()) == [
        "forensic-steve-001",
        "sift-steve-001",
    ]
    withdrawn = portal.get("/api/summary").json()["withdrawn"]
    assert set(withdrawn) == {"total", "items"} and withdrawn["total"] == 1


def test_a_findings_file_that_isnt_json_is_refused_by_name(portal):
    (portal.dir / "findings.json").write_text("{not json\n")
    r = portal.get("/api/findings")
    assert r.status_code == 409, (r.status_code, r.text)
    assert r.json()["error"].startswith("findings.json couldn't be read (")


def _eio_on(monkeypatch, module, attr, name):
    """`module.attr(path, ...)` raises EIO for the file called `name`."""
    real = getattr(module, attr)

    def read(path, *a, **k):
        if os.path.basename(path) == name:
            raise OSError(errno.EIO, os.strerror(errno.EIO), str(path))
        return real(path, *a, **k)

    monkeypatch.setattr(module, attr, read)


def test_a_findings_file_that_fails_to_read_is_refused_by_name(portal, monkeypatch):
    from vhir_cli import case_io

    _eio_on(monkeypatch, case_io, "read_case_document", "findings.json")
    r = portal.get("/api/findings")
    assert r.status_code == 409, (r.status_code, r.text)
    assert r.json()["error"].startswith("findings.json couldn't be read (")


def test_a_log_that_fails_to_read_refuses_the_audit_view(portal, monkeypatch):
    from sift_common import file_identity

    _eio_on(monkeypatch, file_identity, "capped_lines", "sift-mcp.jsonl")
    r = portal.get("/api/audit/F-steve-001")
    assert r.status_code == 409, (r.status_code, r.text)
    assert r.json()["error"].startswith(
        "Couldn't read audit/sift-mcp.jsonl (Input/output error): "
    )


def test_a_readable_case_answers_as_before(portal):
    assert [f["id"] for f in portal.get("/api/findings").json()] == [
        "F-steve-001",
        "F-steve-002",
    ]
    assert portal.get("/api/findings/F-steve-001").json()["id"] == "F-steve-001"
    for fid, ids in (
        ("F-steve-001", ["forensic-steve-001", "sift-steve-001"]),
        ("F-steve-002", ["forensic-steve-002", "sift-steve-002", "sift-steve-003"]),
    ):
        r = portal.get(f"/api/audit/{fid}")
        assert r.status_code == 200
        assert sorted(e["audit_id"] for e in r.json()) == ids
    summary = portal.get("/api/summary").json()
    assert set(summary["withdrawn"]) == {"total", "items"}
    assert summary["withdrawn"]["total"] == 1
    assert summary["no_terminal"] == {
        "total": 1,
        "latest": NOW0,
        "ids": ["F-steve-001"],
    }
    case = portal.get("/api/case").json()["verification"]
    assert case["exit_code"] == 0 and case["case_failures"] == []
    for route in ("/api/evidence", "/api/timeline", "/api/iocs", "/api/todos"):
        r = portal.get(route)
        assert (r.status_code, r.json()) == (200, []), route
