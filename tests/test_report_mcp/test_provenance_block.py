"""A saved report ends with the server's PROVENANCE block, after VERIFICATION
and inside the same fence: each approved, verified finding's grade, roots
and links. The client's own text can't stand in for it."""

from __future__ import annotations

import json

import pytest
import yaml
from vhir_signing import sign_approved

H7Z, HM2 = "a" * 64, "b" * 64
ROOT = {
    "path": "/cases/c1/evidence/samples.7z",
    "sha256": H7Z,
    "label": "AI-registered",
}


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-P-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-P-1", "name": "p"}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


def _f(fid, status="APPROVED", **extra):
    return {"id": fid, "title": f"title {fid}", "observation": "o", "interpretation": "i",
            "confidence": "HIGH", "status": status, **extra}  # fmt: skip


def _chained(fid, path=ROOT["path"], status="APPROVED"):
    return _f(fid, status, provenance_schema=2, provenance_grade="FULL", artifacts=[{
        "source": "s", "content": "c", "audit_id": "x-1", "provenance_grade": "FULL",
        "provenance_reason": "", "provenance_root": {**ROOT, "path": path},
        "provenance_chain": [{"method": "registered-path", "audit_id": "sift-1-001",
                              "entry_sha256": "e" * 64,
                              "from": {"path": path, "sha256": H7Z},
                              "to": {"path": "/x/mem2.raw", "sha256": HM2}}]}])  # fmt: skip


def _save(content):
    from report_mcp.server import create_server

    s = create_server()
    tool = {t.name: t for t in s._tool_manager.list_tools()}["save_report"]
    return tool.fn(filename="r.md", content=content, profile="full")


def _write(case, findings):
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text("[]")


def test_the_server_s_provenance_follows_its_verification_block(case):
    _write(case, [_chained("F-tester-001"), _chained("F-tester-002", status="DRAFT")])
    sign_approved(case)
    fake = "PROVENANCE\n[F-tester-002] title F-tester-002\n  Provenance: FULL\n"
    _save("# Report\n" + fake)
    saved = (case / "reports" / "r.md").read_text()
    fence = saved.rindex("\n```\nVERIFICATION")
    tail = saved[fence:]
    v, p = tail.index("VERIFICATION"), tail.index("\nPROVENANCE\n")
    assert v < p and tail.rstrip().endswith("```")
    assert "[F-tester-001] title F-tester-001" in tail
    assert f"root: {ROOT['path']} sha256={H7Z[:16]} (AI-registered)" in tail
    assert "[registered-path] sift-1-001" in tail
    assert "F-tester-002" not in tail  # a draft is not in the server's block


def test_a_backtick_run_in_a_path_lengthens_the_fence(case):
    _write(case, [_chained("F-tester-001", path="/e/````x.7z")])
    sign_approved(case)
    _save("# Report")
    saved = (case / "reports" / "r.md").read_text()
    assert "\n`````\nVERIFICATION" in saved and saved.endswith("\n`````\n")


def test_the_instructions_say_provenance_is_appended_to_reports():
    from sift_common.instructions import REPORT_MCP

    assert "Provenance" not in REPORT_MCP.split("stay out of")[0]
    assert "saved reports end with each approved finding's provenance" in REPORT_MCP
    assert "they do not appear in reports" not in REPORT_MCP
