"""The portal's approvals run the same checks as the CLI's: a finding whose
evidence changed since registration isn't planned until the examiner types
why they approve it anyway, and that reason is signed with the checks. The
page checks the plan it is handed in view 2, and its override reasons
against the ones typed."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess

import pytest
from case_dashboard import signing
from vhir_cli.case_io import VIEW_EXCLUDES, compute_content_hash
from vhir_cli.commands.evidence import register_evidence_data
from vhir_cli.ledger_verify import verify_case

from .conftest import enrol, finding, reviewed
from .test_portal_sign_block import block, run

REASON = "Re-copied from the original media; checked by hand"


def sha(b: bytes | str) -> str:
    return hashlib.sha256(b.encode() if isinstance(b, str) else b).hexdigest()


@pytest.fixture
def case(portal):
    """F-steve-001 cites vol run on a registered memory image, with its chain."""
    enrol("steve")
    d = portal.dir
    (d / "evidence").mkdir()
    (d / "audit").mkdir()
    mem = d / "evidence" / "mem.raw"
    mem.write_bytes(b"memory image " * 100)
    msha = register_evidence_data(d, str(mem), "steve", registered_via="mcp")["sha256"]
    out = d / "extractions" / "pslist.txt"
    out.parent.mkdir()
    out.write_text("PID 4242 evil.exe\n")
    line = json.dumps({"audit_id": "sift-steve-001", "tool": "run_command",
                       "params": {"command": f"vol -f {mem} windows.pslist"}})  # fmt: skip
    (d / "audit" / "sift-mcp.jsonl").write_text(line + "\n")
    f = finding("F-steve-001", provenance="MCP", provenance_schema=2,
                provenance_grade="FULL", source_evidence=str(mem), artifacts=[{
                    "source": "pslist", "content": "PID 4242 evil.exe",
                    "audit_id": "sift-steve-001", "provenance_grade": "FULL",
                    "provenance_root": {"path": str(mem), "sha256": msha,
                                        "label": "AI-registered"},
                    "provenance_chain": [{
                        "method": "registered-path", "audit_id": "sift-steve-001",
                        "entry_sha256": sha(line), "from": {"path": str(mem), "sha256": msha},
                        "to": {"path": str(out), "sha256": sha(out.read_bytes())}}],
                }])  # fmt: skip
    f["content_hash"] = compute_content_hash(f)
    portal.write("findings.json", [f, finding("F-steve-002")])
    portal.write("timeline.json", [])
    portal.write("iocs.json", [])
    return portal


def public_key() -> str:
    from vhir_cli import keys

    return keys.active(keys.load("steve"))["public_key"]


def change_root(case) -> None:
    with open(case.dir / "evidence" / "mem.raw", "ab") as f:
        f.write(b"tampered")


def plan(case, entries, reasons=None):
    body = {"entries": entries, "include_others": []}
    if reasons is not None:
        body["approval_override_reasons"] = reasons
    return case.post("/api/commit/plan", body)


def given(case, reason=REASON, fid="F-steve-001") -> dict:
    """A reason as the dialog sends it: for the failed checks the plan showed."""
    r = plan(case, [reviewed(case, fid)])
    assert r.status_code == 409, r.text
    (item,) = [i for i in r.json()["items"] if i["id"] == fid]
    return {fid: {"reason": reason, "failed_sha256": item["failed_sha256"]}}


def bodies(r) -> list[dict]:
    return [json.loads(b["body"]) for b in r.json()["bodies"]]


# --- The plan ------------------------------------------------------------------


def test_a_clean_approval_is_planned_with_its_checks_in_a_v4_body(case):
    r = plan(case, [reviewed(case, "F-steve-001")])
    assert r.status_code == 200, r.text
    (b,) = bodies(r)
    assert (b["v"], b["view"], b["checks"]["result"]) == (4, 2, "ok")
    assert {i["check"] for i in b["checks"]["items"]} == {"ENTRY", "ROOT"}
    assert "approval_override_reason" not in b


def test_a_failed_check_without_a_reason_is_refused_with_the_checks(case):
    change_root(case)
    r = plan(case, [reviewed(case, "F-steve-001")])
    assert r.status_code == 409 and r.json()["code"] == "CHECKS_FAILED"
    (item,) = r.json()["items"]
    assert item["id"] == "F-steve-001" and item["checks"]["result"] == "failed"
    assert [i["code"] for i in item["checks"]["items"] if i["status"] == "failed"] == [
        "ROOT_CHANGED"
    ]
    assert signing._challenges == {}


def test_make_plan_refuses_a_failed_check_without_a_reason(case):
    change_root(case)
    lists, _ = signing._read_lists(case.dir)
    p = signing.make_plan(case.dir, "C-1", [reviewed(case, "F-steve-001")], lists,
                          "steve", public_key(), "2026-10-09T01:00:00+00:00", None)  # fmt: skip
    assert [r["reason"] for r in p.refused] == ["CHECKS_FAILED"] and p.bodies == []


def test_make_plan_signs_the_reason_with_the_failed_checks(case):
    change_root(case)
    lists, _ = signing._read_lists(case.dir)
    p = signing.make_plan(case.dir, "C-1", [reviewed(case, "F-steve-001")], lists,
                          "steve", public_key(), "2026-10-09T01:00:00+00:00", None,
                          approval_override_reasons=given(case))  # fmt: skip
    (b,) = p.bodies
    assert (b["v"], b["approval_override_reason"], b["checks"]["result"]) == (
        4, REASON, "failed",
    )  # fmt: skip


def test_a_typed_reason_is_signed_and_verifies(case):
    change_root(case)
    entries = [reviewed(case, "F-steve-001")]
    reasons = given(case)
    r = plan(case, entries, reasons)
    assert r.status_code == 200, r.text
    ch = signing._challenges[r.json()["challenge_id"]]
    assert ch["approval_override_reasons"] == reasons
    p = r.json()
    k = case.login(p)
    c = case.commit(p, case.sign(p, k.json()))
    assert c.status_code == 200, c.text
    (line,) = case.chain()
    assert line["approval_override_reason"] == REASON
    assert line["checks"]["result"] == "failed"
    result = verify_case(case.dir)
    assert result.exit_code == 0, result.failures
    assert case.item("F-steve-001")["status"] == "APPROVED"


def test_a_reason_for_an_item_whose_checks_pass_isn_t_signed(case):
    reasons = {"F-steve-001": {"reason": REASON, "failed_sha256": "0" * 64}}
    r = plan(case, [reviewed(case, "F-steve-001")], reasons)
    assert r.status_code == 200, r.text
    (b,) = bodies(r)
    assert b["checks"]["result"] == "ok" and "approval_override_reason" not in b


def test_evidence_changed_between_plan_and_commit_refuses_the_commit(case):
    entries = [reviewed(case, "F-steve-001")]
    r = plan(case, entries)
    assert r.status_code == 200
    p = r.json()
    k = case.login(p)
    sigs = case.sign(p, k.json())
    change_root(case)
    c = case.commit(p, sigs)
    assert c.status_code == 409 and c.json()["code"] == "CHECKS_FAILED"
    assert case.chain() == [] and case.item("F-steve-001")["status"] == "DRAFT"


def test_a_reason_planned_then_a_check_passing_at_commit_refuses_it(case):
    change_root(case)
    r = plan(case, [reviewed(case, "F-steve-001")], given(case))
    p = r.json()
    k = case.login(p)
    sigs = case.sign(p, k.json())
    register_evidence_data(case.dir, str(case.dir / "evidence" / "mem.raw"), "steve",
                           force_reregister=True)  # fmt: skip
    c = case.commit(p, sigs)
    assert c.status_code == 409 and case.chain() == []


@pytest.mark.parametrize("reasons,says", [
    (["F-steve-001"], "must be a map"),
    ({"F-steve-009": {"reason": REASON, "failed_sha256": "0" * 64}}, "isn't an entry"),
    ({"F-steve-001": REASON}, "names no failed checks"),
    ({"F-steve-001": {"reason": REASON}}, "names no failed checks"),
    ({"F-steve-001": {"reason": "   ", "failed_sha256": "0" * 64}}, "is empty"),
    ({"F-steve-001": {"reason": 5, "failed_sha256": "0" * 64}}, "is empty"),
    ({"F-steve-001": {"reason": "x" * 2001, "failed_sha256": "0" * 64}}, "longer than 2000"),
])  # fmt: skip
def test_a_bad_reasons_map_is_a_400(case, reasons, says):
    r = plan(case, [reviewed(case, "F-steve-001")], reasons)
    assert r.status_code == 400 and says in r.json()["error"]


def test_a_reason_of_2000_characters_is_taken(case):
    change_root(case)
    r = plan(case, [reviewed(case, "F-steve-001")], given(case, "x" * 2000))
    assert r.status_code == 200, r.text


def test_the_reason_is_never_an_entry_field(case):
    change_root(case)
    e = dict(reviewed(case, "F-steve-001"), approval_override_reason=REASON)
    r = plan(case, [e])
    assert r.status_code == 400
    assert "approval_override_reason" not in signing.ENTRY_KEYS


# --- The page ------------------------------------------------------------------


def frozen(case) -> dict:
    return {"items": [], "findings": case.get("/api/findings").json(),
            "timelineEvents": case.get("/api/timeline").json(),
            "iocs": case.get("/api/iocs").json(), "case_id": "C-1", "examiner": "steve"}  # fmt: skip


def check(case, p, entries, reasons=None):
    driver = (
        "var API_BASE = ''; function apiHeaders() { return {}; }\n"
        + block()
        + "\nconst I = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
        "VHIR_SIGN._test.checkPlan(I.frozen, I.plan, I.selected, I.reasons)"
        ".then(p => process.stdout.write(JSON.stringify(p)));"
    )
    import shutil
    import subprocess

    node = shutil.which("node") or pytest.skip("node isn't installed")
    r = subprocess.run([node, "-e", driver], capture_output=True, text=True, timeout=120,
                       input=json.dumps({"frozen": frozen(case), "plan": p,
                                         "selected": entries, "reasons": reasons}))  # fmt: skip
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_page_s_view_2_set_is_vhir_s():
    out = run("constants")
    assert "view1" in out
    m = re.search(r"var VIEW2_EXCLUDES = \[(.*?)\];", block(), re.S)
    assert set(re.findall(r"'([^']+)'", m.group(1))) == set(VIEW_EXCLUDES[2])


def test_the_page_accepts_a_v4_plan_of_a_finding_with_its_chain(case):
    entries = [reviewed(case, "F-steve-001")]
    r = plan(case, entries)
    assert check(case, r.json(), entries) == []


def test_the_page_accepts_an_edited_entry_in_view_2(case):
    f = case.item("F-steve-001")
    e = reviewed(case, "F-steve-001", modifications={
        "interpretation": {"original": f["interpretation"], "modified": "changed"}})  # fmt: skip
    r = plan(case, [e])
    assert r.status_code == 200, r.text
    snap = json.loads(bodies(r)[0]["content_snapshot"])
    assert snap["examiner_modifications"]["interpretation"]["modified"] == "changed"
    assert check(case, r.json(), [e]) == []


def test_the_page_accepts_the_reason_it_typed_and_refuses_another(case):
    change_root(case)
    entries = [reviewed(case, "F-steve-001")]
    reasons = given(case)
    r = plan(case, entries, reasons)
    assert check(case, r.json(), entries, reasons) == []
    other = {"F-steve-001": dict(reasons["F-steve-001"], reason="something else")}
    problems = check(case, r.json(), entries, other)
    assert problems == ["F-steve-001: its override reason is not the one typed"]
    elsewhere = {"F-steve-001": dict(reasons["F-steve-001"], failed_sha256="0" * 64)}
    problems = check(case, r.json(), entries, elsewhere)
    assert problems == [
        "F-steve-001: its override reason was typed for other failed checks"
    ]


def test_the_page_refuses_a_view_it_doesn_t_know(case):
    entries = [reviewed(case, "F-steve-001")]
    p = plan(case, entries).json()
    b = json.loads(p["bodies"][0]["body"])
    b["view"] = 9
    p["bodies"][0]["body"] = json.dumps(b)
    problems = check(case, p, entries)
    assert any("signs view 9" in x for x in problems), problems


def test_the_page_refuses_a_provenance_field_it_wasn_t_shown(case):
    entries = [reviewed(case, "F-steve-001")]
    p = plan(case, entries).json()
    b = json.loads(p["bodies"][0]["body"])
    snap = json.loads(b["content_snapshot"])
    snap["source_evidence"] = "/elsewhere/other.raw"
    b["content_snapshot"] = json.dumps(snap, sort_keys=True)
    b["content_sha256"] = sha(b["content_snapshot"])
    p["bodies"][0]["body"] = json.dumps(b)
    assert check(case, p, entries) == ["F-steve-001: source_evidence differ"]


# --- The dialog ----------------------------------------------------------------


def test_the_dialog_shows_the_root_grade_and_failed_checks(case):
    import shutil
    import subprocess

    change_root(case)
    item = case.item("F-steve-001")
    item["provenance_grade"] = "DECLARED"
    item["artifacts"][0].update(provenance_grade="DECLARED",
                                provenance_reason="named by the AI, not in the command")  # fmt: skip
    r = plan(case, [reviewed(case, "F-steve-001")])
    checks = r.json()["items"][0]["checks"]
    node = shutil.which("node") or pytest.skip("node isn't installed")
    script = ("var API_BASE = ''; function apiHeaders() { return {}; }\n" + block()
              + "\nconst I = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "process.stdout.write(JSON.stringify(VHIR_SIGN._test.provenanceLines(I.item, I.checks)));")  # fmt: skip
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60,
                         input=json.dumps({"item": item, "checks": checks}))  # fmt: skip
    lines = [text for _, text in json.loads(out.stdout)]
    mem = str(case.dir / "evidence" / "mem.raw")
    assert any(
        t.startswith(f"root: {mem} ") and t.endswith("(AI-registered)") for t in lines
    )
    assert "provenance: DECLARED" in lines
    assert "  DECLARED: named by the AI, not in the command" in lines
    assert any(t.startswith("check failed: ROOT_CHANGED") for t in lines)


def test_the_dialog_plans_again_with_the_reasons_not_as_a_retry():
    text = block()
    fn = re.search(r"function renderFailed\(items\) \{(.*?)\n  \}\n", text, re.S).group(
        1
    )
    assert "data-reason" in fn and "planAndShow(null)" in fn and "retry" not in fn
    assert (
        "if (!retryOf && Object.keys(s.reasons).length) body.approval_override_reasons"
        in text
    )


# --- A reason is bound to the failures it was typed for -----------------------


def _edit_audit_line(case):
    p = case.dir / "audit" / "sift-mcp.jsonl"
    p.write_text(p.read_text().replace("windows.pslist", "windows.psscan"))


def test_a_reason_for_other_failures_is_refused_and_the_new_ones_shown(case):
    change_root(case)
    reasons = given(case)  # typed for ROOT_CHANGED alone
    _edit_audit_line(case)  # now ENTRY_CHANGED too
    r = plan(case, [reviewed(case, "F-steve-001")], reasons)
    assert r.status_code == 409 and r.json()["code"] == "CHECKS_FAILED"
    (item,) = r.json()["items"]
    codes = [i["code"] for i in item["checks"]["items"] if i["status"] == "failed"]
    assert codes == ["ENTRY_CHANGED", "ROOT_CHANGED"]
    assert item["failed_sha256"] != reasons["F-steve-001"]["failed_sha256"]


def test_the_page_hashes_failed_checks_as_the_server_does(case):
    from vhir_cli import approval_checks

    change_root(case)
    _edit_audit_line(case)
    r = plan(case, [reviewed(case, "F-steve-001")])
    (item,) = r.json()["items"]
    node = shutil.which("node") or pytest.skip("node isn't installed")
    script = ("var API_BASE = ''; function apiHeaders() { return {}; }\n" + block()
              + "\nconst I = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "VHIR_SIGN._test.failedSha256(I.checks).then(h => process.stdout.write(h));")  # fmt: skip
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60,
                         input=json.dumps({"checks": item["checks"]}))  # fmt: skip
    assert (
        out.stdout
        == item["failed_sha256"]
        == approval_checks.failed_sha256(item["checks"])
    )


def test_what_was_shown_includes_the_failed_checks_and_the_reason(case):
    change_root(case)
    entries = [reviewed(case, "F-steve-001")]
    p = plan(case, entries, given(case)).json()
    node = shutil.which("node") or pytest.skip("node isn't installed")
    script = ("var API_BASE = ''; function apiHeaders() { return {}; }\n" + block()
              + "\nconst I = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "process.stdout.write(JSON.stringify(VHIR_SIGN._test.shownOf(I.plan)));")  # fmt: skip
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60,
                         input=json.dumps({"plan": p}))  # fmt: skip
    (shown,) = json.loads(out.stdout)
    assert "ROOT_CHANGED" in shown and REASON in shown


def test_a_retry_sends_no_reason_and_shows_its_failures_again():
    text = block()
    plan_fn = re.search(
        r"async function planAndShow\(retryOf\) \{(.*?)\n  \}\n", text, re.S
    ).group(1)
    assert "if (!retryOf && Object.keys(s.reasons).length)" in plan_fn
    assert "r.data.code === 'CHECKS_FAILED') {" in plan_fn  # a retry's too
    assert "checkPlan(s.frozen, r.data, selected, retryOf ? {} : s.reasons)" in plan_fn


def test_the_dialog_keeps_earlier_reasons_and_shows_them():
    fn = re.search(
        r"function renderFailed\(items\) \{(.*?)\n  \}\n", block(), re.S
    ).group(1)
    assert "s.reasons = Object.assign({}, s.reasons, typed)" in fn
    assert "Your earlier reason, for other failed checks: " in fn
    assert (
        "earlier.reason" in fn
        and "</textarea>" in fn
        and "escapeHtml(s.reasons" not in fn
    )


# --- Every root; a large root hashed in the background --------------------------


def test_every_root_is_checked_and_shown(case):
    other = case.dir / "evidence" / "second.raw"
    other.write_bytes(b"a second input " * 40)
    osha = register_evidence_data(case.dir, str(other), "steve")["sha256"]
    fs = case.read("findings.json")
    a = fs[0]["artifacts"][0]
    a["provenance_roots"] = [a["provenance_root"],
                             {"path": str(other), "sha256": osha, "label": "examiner-registered"}]  # fmt: skip
    fs[0]["content_hash"] = compute_content_hash(fs[0])
    case.write("findings.json", fs)
    with open(other, "ab") as f:
        f.write(b"changed")
    r = plan(case, [reviewed(case, "F-steve-001")])
    (item,) = r.json()["items"]
    failed = [
        (i["code"], i["subject"])
        for i in item["checks"]["items"]
        if i["status"] == "failed"
    ]
    assert failed == [("ROOT_CHANGED", str(other))]
    node = shutil.which("node") or pytest.skip("node isn't installed")
    script = ("var API_BASE = ''; function apiHeaders() { return {}; }\n" + block()
              + "\nconst I = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "process.stdout.write(JSON.stringify(VHIR_SIGN._test.provenanceLines(I.item, I.checks)));")  # fmt: skip
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60,
                         input=json.dumps({"item": fs[0], "checks": item["checks"]}))  # fmt: skip
    lines = [t for _, t in json.loads(out.stdout)]
    assert any(t.startswith(f"root: {other} ") for t in lines)
    assert any(
        t.startswith(f"root: {case.dir / 'evidence' / 'mem.raw'} ") for t in lines
    )


def test_a_large_root_without_stat_fields_is_hashed_in_the_background(
    case, monkeypatch
):
    import threading

    from vhir_cli import approval_checks

    reg = json.loads((case.dir / "evidence.json").read_text())
    for e in reg["files"]:
        for k in approval_checks._STAT_KEYS:
            e.pop(k, None)
    (case.dir / "evidence.json").write_text(json.dumps(reg))
    monkeypatch.setattr(approval_checks, "INLINE_LIMIT", 10)
    r = plan(case, [reviewed(case, "F-steve-001")])
    assert r.status_code == 409, r.text
    (item,) = r.json()["items"]
    failed = [
        (i["code"], i["detail"])
        for i in item["checks"]["items"]
        if i["status"] == "failed"
    ]
    assert failed == [("ROOT_UNVERIFIED", "not yet verified (hashing)")]
    for t in threading.enumerate():
        if t.name == "approval-root-hash":
            t.join(timeout=30)
    r = plan(case, [reviewed(case, "F-steve-001")])
    assert r.status_code == 200, r.text
    assert bodies(r)[0]["checks"]["result"] == "ok"
