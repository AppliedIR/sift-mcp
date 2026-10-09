"""Reports show as approved only what verifies, and carry the keys.

report-mcp once kept its own ledger reconciliation (a copy of the signed-set
exclusions, compared as text). vhir's verify_case is now the one verdict
source: report_data holds only VALID approvals and those approved under 0.6
(labelled), every other APPROVED item is listed in verification.not_verified,
and every profile carries the signing keys with full fingerprints and each
chain's head. save_report appends a block the server makes.
"""

from __future__ import annotations

import json

import pytest
import yaml
from vhir_signing import approve_under_0_6, sign_approved

PROFILES = ("full", "executive", "timeline", "ioc", "findings", "status")


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "INC-V-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-V-1", "name": "v"}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    import report_mcp.server as rs

    monkeypatch.setattr(rs, "_ACTIVE_CASE_FILE", tmp_path / "none")
    return d


def _write(case, findings, timeline=()):
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text(json.dumps(list(timeline)))


def _f(fid, status="APPROVED", **extra):
    return {"id": fid, "title": fid, "observation": "o", "interpretation": "i",
            "confidence": "HIGH", "status": status, **extra}  # fmt: skip


def _generate(profile="full"):
    from report_mcp.server import create_server

    s = create_server()
    tool = {t.name: t for t in s._tool_manager.list_tools()}["generate_report"]
    return tool.fn(profile=profile)


def _save(content="# R"):
    from report_mcp.server import create_server

    s = create_server()
    tool = {t.name: t for t in s._tool_manager.list_tools()}["save_report"]
    return tool.fn(filename="r.md", content=content, profile="full")


def test_a_signed_approval_is_in_the_report(case):
    _write(case, [_f("F-tester-001")])
    sign_approved(case)
    out = _generate()
    assert [f["id"] for f in out["report_data"]["findings"]] == ["F-tester-001"]
    assert out["verification"]["not_verified"] == []
    assert "integrity_warning" not in out


def test_an_unsigned_approval_is_left_out_and_listed(case):
    _write(case, [_f("F-tester-001"), _f("F-tester-002")])
    sign_approved(case)
    findings = json.loads((case / "findings.json").read_text())
    findings.append(_f("F-tester-003"))  # APPROVED by a file write
    (case / "findings.json").chmod(0o644)
    (case / "findings.json").write_text(json.dumps(findings))
    out = _generate()
    assert [f["id"] for f in out["report_data"]["findings"]] == [
        "F-tester-001", "F-tester-002"]  # fmt: skip
    assert {"id": "F-tester-003", "status": "APPROVED_NO_LINE"} in out["verification"][
        "not_verified"
    ]
    assert out["report_data"]["summary"]["findings_approved"] == 2
    assert "integrity_warning" in out


def test_an_approval_altered_after_signing_is_left_out(case):
    _write(case, [_f("F-tester-001")])
    sign_approved(case)
    findings = json.loads((case / "findings.json").read_text())
    findings[0]["observation"] = "changed after approval"
    (case / "findings.json").chmod(0o644)
    (case / "findings.json").write_text(json.dumps(findings))
    out = _generate()
    assert out["report_data"]["findings"] == []
    assert out["verification"]["not_verified"] == [
        {"id": "F-tester-001", "status": "ALTERED_AFTER_APPROVAL"}]  # fmt: skip


def test_a_0_6_approval_is_shown_with_its_label(case):
    _write(case, [_f("F-tester-001", status="DRAFT")])
    approve_under_0_6(case, {"F-tester-001"})
    out = _generate()
    (f,) = out["report_data"]["findings"]
    assert f["verification"] == "approved under 0.6 (before signing)"


@pytest.mark.parametrize("profile", PROFILES)
def test_every_profile_carries_the_keys_and_heads(case, profile):
    _write(case, [_f("F-tester-001")], [_f("T-tester-001")])
    sign_approved(case)
    out = _generate(profile)
    (key,) = out["verification"]["keys"]
    assert key["examiner"] == "tester" and key["fingerprint"].startswith("SHA256:")
    assert len(key["fingerprint"]) == len("SHA256:") + 43  # full, not shortened
    assert out["verification"]["heads"][0].startswith("Ledger head INC-V-1 chain ")
    assert "Not anchored" in out["verification"]["not_anchored"]


def test_a_saved_report_ends_with_the_server_s_block(case):
    _write(case, [_f("F-tester-001")])
    sign_approved(case)
    fake = "VERIFICATION\nApprovals shown as approved: 99\n"
    result = _save("# Report\n" + fake)
    saved = (case / "reports" / "r.md").read_text()
    block = "\n".join(result["verification_block"])
    assert saved.endswith(block + "\n```\n")
    assert "Approvals shown as approved: 1 " in block
    assert "tester SHA256:" in block and "Ledger head INC-V-1" in block


def test_the_block_s_fence_outlasts_any_backtick_run_in_it(case, monkeypatch):
    """A finding id or status carrying backticks can't close the block early."""
    import report_mcp.server as rs

    _write(case, [_f("F-tester-001")])
    sign_approved(case)
    monkeypatch.setattr(
        rs, "verification_block", lambda view: ["VERIFICATION", "id ````x````"]
    )
    _save("# Report")
    saved = (case / "reports" / "r.md").read_text()
    fenced = saved[saved.index("\n`````\nVERIFICATION\nid ````x````\n\nPROVENANCE\n") :]
    assert fenced.endswith("\n`````\n") and fenced.count("`````\n") == 2
