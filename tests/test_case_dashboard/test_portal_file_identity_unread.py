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
import shutil
import subprocess
from types import SimpleNamespace

import case_dashboard.routes as D
import pytest

from .test_portal_provenance_display import DRIVER, PAGE

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


def _audit_body(case, audit_ids):
    (case / "findings.json").write_text(
        json.dumps([{"id": "F-steve-001", "status": "DRAFT", "audit_ids": audit_ids}])
    )
    request = SimpleNamespace(path_params={"finding_id": "F-steve-001"})
    return json.loads(asyncio.run(D.get_audit_for_finding(request)).body)


def _audit(case, audit_ids):
    return [(e["audit_id"], e["_backend"]) for e in _audit_body(case, audit_ids)]


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


# --- at approval, a cited file-identity id is named as not checked ---------------------

# the page's own script under node (the provenance display rows' stand-in
# document), rendering one finding's evidence panel from the route's reply
PANEL = (
    DRIVER.split("vm.runInContext(")[0]
    + r"""
vm.runInContext(src + `
;(async function(){
  var f = __F[0]; auditCache[f.id] = __A;
  await loadEvidencePanel(f);
  globalThis.__OUT = document.getElementById('evidenceItems').innerHTML;
})().catch(function(e){ globalThis.__ERR = String(e && e.stack || e); });`, ctx);
setTimeout(() => {
  if (ctx.__ERR) { process.stderr.write(ctx.__ERR); process.exit(3); }
  process.stdout.write(JSON.stringify(ctx.__OUT));
}, 200);
"""
)


def test_at_approval_a_cited_file_identity_id_reads_not_checked_real_or_not(case):
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    made_up = "fileidentity-steve-20261007-099"
    ids = [RUN, FI, made_up]
    finding = {"id": "F-steve-001", "status": "DRAFT", "audit_ids": ids}
    r = subprocess.run(
        [node, "-e", PANEL],
        capture_output=True,
        text=True,
        timeout=120,
        input=json.dumps(
            {"page": str(PAGE), "findings": [finding], "audit": _audit_body(case, ids)}
        ),
    )
    assert r.returncode == 0, r.stderr[-2000:]
    run, real, fake = json.loads(r.stdout).split('<div class="evidence-item"')[1:]
    assert "(sift-mcp)" in run and "run_command" in run
    assert "not checked" not in run.lower()
    for item in (real, fake):
        assert "not checked (the file-identity log isn't read here)" in item
        assert "Not checked: the file-identity log isn't read here." in item
        assert "(unknown)" not in item
    assert real.replace(FI, "ID") == fake.replace(made_up, "ID")
