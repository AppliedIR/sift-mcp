"""The portal's audit scans skip the file-identity log, as record_finding's do.

One hash job's results are one line of audit/file-identity.jsonl, and a big
job's line runs to hundreds of MB. The summary's withdrawals scan and a
finding's audit view parsed every line of every audit log, so opening either
page on such a case held several times that in memory. Neither reads that log
now. It never holds a record_finding entry, so the withdrawals are unchanged.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import case_dashboard.routes as D
import pytest

FI = "fileidentity-steve-20261007-006"  # a hash job's results
RUN = "sift-steve-20261007-001"  # a tool run


def _withdrawal(audit_id, ts, title):
    return {
        "tool": "record_finding",
        "audit_id": audit_id,
        "ts": ts,
        "examiner": "steve",
        "result_summary": {"status": "WITHDRAWN", "title": title},
    }


def _write(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    _write(
        d / "audit" / "forensic-mcp.jsonl",
        [_withdrawal("forensic-steve-20261007-002", "2026-10-07T08:00:00Z", "w")],
    )
    _write(d / "audit" / "sift-mcp.jsonl", [{"audit_id": RUN, "tool": "run_command"}])
    _write(
        d / "audit" / "file-identity.jsonl",
        [
            {
                "audit_id": FI,
                "tool": "hash_complete",
                "job_id": "hash-1",
                "files": [{"path": "evidence/a.evtx", "sha256": "0" * 64}],
            }
        ],
    )
    return d


@pytest.fixture
def opened(monkeypatch):
    """The names of the audit logs the routes parse."""
    names: list[str] = []
    read = D._read_jsonl

    def spy(path):
        names.append(path.name)
        return read(path)

    monkeypatch.setattr(D, "_read_jsonl", spy)
    return names


def _summary():
    return json.loads(asyncio.run(D.get_summary(None)).body)["withdrawn"]


def _audit(case, audit_ids):
    (case / "findings.json").write_text(
        json.dumps([{"id": "F-steve-001", "status": "DRAFT", "audit_ids": audit_ids}])
    )
    request = SimpleNamespace(path_params={"finding_id": "F-steve-001"})
    body = json.loads(asyncio.run(D.get_audit_for_finding(request)).body)
    return [(e["audit_id"], e["_backend"]) for e in body]


def test_the_summary_doesnt_parse_the_file_identity_log(case, opened):
    withdrawn = _summary()
    assert "file-identity.jsonl" not in opened
    assert "forensic-mcp.jsonl" in opened
    assert withdrawn["total"] == 1 and withdrawn["items"][0]["title"] == "w"


def test_a_findings_audit_view_doesnt_parse_the_file_identity_log(case, opened):
    assert _audit(case, [RUN, FI]) == [(RUN, "sift-mcp")]
    assert "file-identity.jsonl" not in opened
    assert "sift-mcp.jsonl" in opened


def test_anchor_the_summary_is_the_same_with_or_without_the_log(case):
    with_log = _summary()
    (case / "audit" / "file-identity.jsonl").unlink()
    assert _summary() == with_log


def test_anchor_an_audit_view_citing_tool_runs_is_unchanged(case):
    with_log = _audit(case, [RUN])
    (case / "audit" / "file-identity.jsonl").unlink()
    assert _audit(case, [RUN]) == with_log == [(RUN, "sift-mcp")]
