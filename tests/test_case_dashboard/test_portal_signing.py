"""The portal's signed commit: plan with the token, sign in, sign in the
browser, commit under the case lock. Nothing is written on any refusal."""

from __future__ import annotations

import json
import threading
import time

import pytest
from case_dashboard import signing
from vhir_cli import credentials, keys, ledger
from vhir_cli.ledger_verify import verify_case

from .conftest import PASSWORD, enrol, entry, event, finding, reviewed


@pytest.fixture
def case(portal):
    enrol("steve")
    portal.write("findings.json", [finding("F-steve-001"), finding("F-steve-002")])
    portal.write("timeline.json", [])
    return portal


def _snapshot(portal) -> dict:
    """Every file the commit could write, as bytes."""
    out = {p.name: p.read_bytes() for p in portal.dir.iterdir() if p.is_file()}
    path = ledger.chain_path("C-1")
    out["<chain>"] = path.read_bytes() if path.exists() else None
    return out


def test_a_portal_approval_is_signed_applied_and_verifies(case):
    case.stage(dict(reviewed(case, "F-steve-001"), staged_by="steve"))
    r = case.sign_all([reviewed(case, "F-steve-001")])
    assert r.status_code == 200, r.text
    out = r.json()
    lines = case.chain()
    assert [ln["item_id"] for ln in lines] == ["F-steve-001"]
    line = lines[0]
    assert line["mode"] == "portal" and line["examiner"] == "steve"
    assert ledger.signature_valid(line)
    f = case.item("F-steve-001")
    assert f["status"] == "APPROVED"
    assert (f["approved_by"], f["approved_at"]) == ("steve", line["at"])
    assert out["head"]["seq"] == 1 and out["fingerprint"].startswith("SHA256:")
    assert case.read("pending-reviews.json")["items"] == []
    result = verify_case(case.dir)
    assert result.exit_code == 0
    assert result.verdict("F-steve-001").status == "VALID"


def test_the_signed_body_is_the_one_handed_to_the_browser(case):
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    k = case.login(plan).json()
    case.commit(plan, case.sign(plan, k))
    (line,) = case.chain()
    assert ledger.canonical(ledger.body_of(line)).decode() == plan["bodies"][0]["body"]


def test_without_gateway_api_keys_nobody_signs(case):
    before = _snapshot(case)
    r = case.plan([reviewed(case, "F-steve-001")], examiner="anonymous")
    assert r.status_code == 403 and r.json()["code"] == "NO_API_KEYS"
    assert "vhir approve --review" in r.json()["error"]
    for path in ("/api/commit/key", "/api/commit"):
        r = case.post(path, {"challenge_id": "x"}, examiner="anonymous")
        assert r.json()["code"] == "NO_API_KEYS"
    assert _snapshot(case) == before


def test_no_key_names_the_enrol_command(case):
    r = case.plan([reviewed(case, "F-steve-001")], examiner="lab2")
    assert r.status_code == 409 and r.json()["code"] == "NO_SIGNING_KEY"
    assert "vhir enrol --name lab2" in r.json()["error"]


def test_a_0_6_password_names_the_upgrade(case, box):
    (box / "passwords" / "lab2.json").write_text(
        json.dumps({"hash": "ab", "salt": "cd"})
    )
    r = case.plan([reviewed(case, "F-steve-001")], examiner="lab2")
    assert r.json()["code"] == "NO_SIGNING_KEY"
    assert "vhir enrol --name lab2 --upgrade" in r.json()["error"]
    state = case.get("/api/case", examiner="lab2").json()["signing"]
    assert state["signing_available"] is False and state["schema"] == "0.6"


def test_the_plan_needs_no_password_and_serves_no_key(case):
    r = case.plan([reviewed(case, "F-steve-001")])
    assert r.status_code == 200
    plan = r.json()
    assert "wrapped_private" not in plan and "salt_ledger" not in plan
    assert plan["expires_in"] == 120 and len(plan["bodies"]) == 1


def test_a_wrong_password_counts_and_serves_no_key(case):
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    r = case.login(plan, password="wrong passphrase here")
    assert r.status_code == 401 and r.json()["code"] == "BAD_PASSWORD"
    assert "wrapped_private" not in r.json()
    assert "2 attempt(s) remaining" in r.json()["error"]
    case.login(plan, password="wrong passphrase here")
    case.login(plan, password="wrong passphrase here")
    r = case.login(plan)
    assert r.status_code == 429 and r.json()["code"] == "LOCKED_OUT"


def test_a_commit_without_signing_in_is_refused(case):
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    before = _snapshot(case)  # after the plan: it may give the case its identity
    r = case.commit(plan, {"F-steve-001": "AAAA"})
    assert r.status_code == 401 and r.json()["code"] == "CHALLENGE_INVALID"
    assert _snapshot(case) == before


def test_a_signature_by_another_key_writes_nothing(case):
    enrol("mallory", "another long passphrase")
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    before = _snapshot(case)  # after the plan: it may give the case its identity
    case.login(plan)
    other = keys.load("mallory")
    k = {"wrapped_private": keys.active(other)["wrapped_private"],
         "public_key": keys.active(other)["public_key"], "salt_ledger": other["salt_ledger"]}  # fmt: skip
    sigs = case.sign(plan, k, examiner="mallory", password="another long passphrase")
    r = case.commit(plan, sigs)
    assert r.status_code == 401 and r.json()["code"] == "BAD_SIGNATURE"
    assert _snapshot(case) == before


def test_a_missing_signature_writes_nothing(case):
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    before = _snapshot(case)  # after the plan: it may give the case its identity
    case.login(plan)
    r = case.commit(plan, {})
    assert r.status_code == 401 and r.json()["code"] == "BAD_SIGNATURE"
    assert _snapshot(case) == before


def test_a_challenge_is_single_use(case):
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    k = case.login(plan).json()
    sigs = case.sign(plan, k)
    assert case.commit(plan, sigs).status_code == 200
    r = case.commit(plan, sigs)
    assert r.status_code == 401 and r.json()["code"] == "CHALLENGE_INVALID"
    assert len(case.chain()) == 1


def test_an_expired_challenge_is_refused(case, monkeypatch):
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    signing._challenges[plan["challenge_id"]]["expires"] = time.time() - 1
    r = case.login(plan)
    assert r.status_code == 401 and r.json()["code"] == "CHALLENGE_EXPIRED"


def test_a_fifth_open_challenge_drops_the_first(case):
    ids = [
        case.plan([reviewed(case, "F-steve-001")]).json()["challenge_id"]
        for _ in range(5)
    ]
    assert ids[0] not in signing._challenges
    assert all(i in signing._challenges for i in ids[1:])


def test_another_examiners_challenge_is_refused(case):
    enrol("lab2")
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    r = case.login(plan, examiner="lab2")
    assert r.status_code == 401 and r.json()["code"] == "CHALLENGE_INVALID"


def _other_commit(case):
    """Another examiner signs F-steve-002 meanwhile, moving the head."""
    enrol("lab2")
    r = case.sign_all([reviewed(case, "F-steve-002")], examiner="lab2")
    assert r.status_code == 200, r.text


def test_a_moved_head_is_refused_then_one_retry_signs(case):
    e = [reviewed(case, "F-steve-001")]
    plan = case.plan(e).json()
    k = case.login(plan).json()
    sigs = case.sign(plan, k)
    _other_commit(case)
    before = _snapshot(case)
    r = case.commit(plan, sigs)
    assert r.status_code == 409 and r.json()["code"] == "LEDGER_MOVED"
    assert _snapshot(case) == before
    again = case.plan(e, retry_of=plan["challenge_id"]).json()
    case.login(again)
    r = case.commit(again, case.sign(again, k))
    assert r.status_code == 200, r.text
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-002", "F-steve-001"]
    assert verify_case(case.dir).exit_code == 0  # two examiners, one key each


def test_only_one_retry(case):
    e = [reviewed(case, "F-steve-001")]
    plan = case.plan(e).json()
    k = case.login(plan).json()
    sigs = case.sign(plan, k)
    _other_commit(case)
    case.commit(plan, sigs)
    again = case.plan(e, retry_of=plan["challenge_id"]).json()
    r = case.plan(e, retry_of=plan["challenge_id"])
    assert r.status_code == 409 and r.json()["code"] == "RETRY_REFUSED"
    r = case.plan(e, retry_of=again["challenge_id"])
    assert r.json()["code"] == "RETRY_REFUSED"


def test_an_item_changed_after_the_plan_is_refused_whole(case):
    e = [reviewed(case, "F-steve-001"), reviewed(case, "F-steve-002")]
    plan = case.plan(e).json()
    k = case.login(plan).json()
    sigs = case.sign(plan, k)
    findings = case.read("findings.json")
    findings[1]["observation"] = "changed meanwhile"
    case.write("findings.json", findings)
    before = _snapshot(case)
    r = case.commit(plan, sigs)
    assert r.status_code == 409 and r.json()["code"] == "PLAN_CHANGED"
    assert "F-steve-002" in r.json()["error"]
    assert _snapshot(case) == before


def test_a_body_that_would_change_is_refused_as_changed_not_as_unsigned(case):
    """An own click carries no review hash, so only the commit's own re-plan,
    compared with what was signed, sees the item changed."""
    plan = case.plan([entry("F-steve-001")]).json()
    k = case.login(plan).json()
    sigs = case.sign(plan, k)
    findings = case.read("findings.json")
    findings[0]["observation"] = "changed after the plan"
    case.write("findings.json", findings)
    before = _snapshot(case)
    r = case.commit(plan, sigs)
    assert r.status_code == 409 and r.json()["code"] == "PLAN_CHANGED"
    assert _snapshot(case) == before


def test_a_stale_entry_is_refused_at_the_plan(case):
    stale = entry("F-steve-001", content_hash_at_review="0" * 64)
    r = case.plan([stale])
    assert r.status_code == 409 and r.json()["code"] == "PLAN_CHANGED"
    assert r.json()["items"] == [
        {"id": "F-steve-001", "reason": "changed after it was reviewed"}
    ]


def test_a_busy_lock_is_503_with_nothing_written(case, monkeypatch):
    monkeypatch.setattr(signing, "LOCK_SECONDS", 0.3)
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    k = case.login(plan).json()
    sigs = case.sign(plan, k)
    before = _snapshot(case)
    held, release = threading.Event(), threading.Event()

    def hold():
        with ledger.case_lock("C-1"):
            held.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    held.wait(5)
    try:
        r = case.commit(plan, sigs)
    finally:
        release.set()
        t.join()
    assert r.status_code == 503 and r.json()["code"] == "LEDGER_BUSY"
    assert _snapshot(case) == before
    again = case.plan([reviewed(case, "F-steve-001")], retry_of=plan["challenge_id"])
    assert again.status_code == 200


def test_the_gateway_answers_while_a_commit_waits(case, monkeypatch):
    monkeypatch.setattr(signing, "LOCK_SECONDS", 2)
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    k = case.login(plan).json()
    sigs = case.sign(plan, k)
    held, release = threading.Event(), threading.Event()

    def hold():
        with ledger.case_lock("C-1"):
            held.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    held.wait(5)
    result = {}
    c = threading.Thread(target=lambda: result.update(r=case.commit(plan, sigs)))
    c.start()
    time.sleep(0.2)
    assert case.get("/api/summary").status_code == 200  # not blocked by the wait
    release.set()
    t.join()
    c.join()
    assert result["r"].status_code == 200


def test_a_reject_is_signed(case):
    r = case.sign_all(
        [reviewed(case, "F-steve-001", "reject", rejection_reason="benign")]
    )
    assert r.status_code == 200, r.text
    f = case.item("F-steve-001")
    assert f["status"] == "REJECTED" and f["rejection_reason"] == "benign"
    assert case.chain()[0]["decision"] == "reject"


def test_an_edit_and_approve_signs_the_edited_text(case):
    e = reviewed(case, "F-steve-001", modifications={
        "title": {"original": "title F-steve-001", "modified": "better title"}})  # fmt: skip
    r = case.sign_all([e])
    assert r.status_code == 200, r.text
    snap = json.loads(case.chain()[0]["content_snapshot"])
    assert snap["title"] == "better title"
    assert case.item("F-steve-001")["title"] == "better title"
    assert verify_case(case.dir).exit_code == 0


def test_a_modification_whose_original_changed_is_refused(case):
    e = reviewed(case, "F-steve-001", modifications={
        "title": {"original": "not the title", "modified": "x"}})  # fmt: skip
    r = case.plan([e])
    assert r.json()["code"] == "PLAN_CHANGED"
    assert "field 'title' changed since review" in r.json()["error"]


def test_an_ioc_edit_is_limited_to_tags_and_description(case):
    case.write("iocs.json", [{"id": "IOC-001", "value": "1.2.3.4", "type": "ipv4",
                              "status": "DRAFT", "tags": []}])  # fmt: skip
    e = reviewed(case, "IOC-001", modifications={"value": {"original": "1.2.3.4", "modified": "5.6.7.8"}})  # fmt: skip
    r = case.plan([e])
    assert (
        r.json()["code"] == "PLAN_CHANGED"
        and "can't be edited: value" in r.json()["error"]
    )
    ok = reviewed(
        case, "IOC-001", modifications={"tags": {"original": [], "modified": ["c2"]}}
    )
    r = case.sign_all([ok])
    assert r.status_code == 200, r.text
    ioc = case.item("IOC-001")
    assert ioc["tags"] == ["c2"] and ioc["manually_reviewed"] is True


def test_an_approval_cascades_to_its_auto_created_event(portal):
    enrol("steve")
    portal.write(
        "findings.json", [finding("F-steve-001", timeline_event_id="T-steve-001")]
    )
    portal.write("timeline.json", [event("T-steve-001", "F-steve-001")])
    plan = portal.plan([reviewed(portal, "F-steve-001")]).json()
    assert [(b["item_id"], b["coupled_from"]) for b in plan["bodies"]] == [
        ("F-steve-001", None), ("T-steve-001", "F-steve-001")]  # fmt: skip
    k = portal.login(plan).json()
    r = portal.commit(plan, portal.sign(plan, k))
    assert r.json()["cascades"] == [
        {"id": "T-steve-001", "decision": "approve", "coupled_from": "F-steve-001"}]  # fmt: skip
    assert portal.item("T-steve-001")["status"] == "APPROVED"
    assert verify_case(portal.dir).exit_code == 0


def test_one_id_selected_twice_is_refused(case):
    e = reviewed(case, "F-steve-001")
    r = case.plan([e, dict(e, action="reject")])
    assert r.status_code == 409 and r.json()["code"] == "DUPLICATE_ITEM"


def test_another_examiners_entry_needs_the_include_tick(case):
    enrol("lab2")
    theirs = dict(reviewed(case, "F-steve-002"), staged_by="lab2")
    mine = dict(reviewed(case, "F-steve-001"), staged_by="steve")
    case.stage(mine, theirs)
    r = case.plan([mine, theirs])
    assert r.status_code == 409 and r.json()["code"] == "NOT_INCLUDED"
    r = case.sign_all([mine, theirs], include=["F-steve-002"])
    assert r.status_code == 200, r.text
    lines = case.chain()
    assert {ln["item_id"]: ln["examiner"] for ln in lines} == {
        "F-steve-001": "steve", "F-steve-002": "steve"}  # fmt: skip
    assert case.read("pending-reviews.json")["items"] == []


def test_a_commit_leaves_entries_it_did_not_sign(case):
    theirs = dict(reviewed(case, "F-steve-002"), staged_by="lab2")
    mine = dict(reviewed(case, "F-steve-001"), staged_by="steve")
    todo = {"id": "F-steve-002", "type": "finding", "action": "todo",
            "todo_description": "check it", "staged_by": "steve"}  # fmt: skip
    case.stage(mine, theirs, todo)
    before = json.dumps(theirs, sort_keys=True)
    r = case.sign_all([mine, todo])
    assert r.status_code == 200, r.text
    left = case.read("pending-reviews.json")["items"]
    assert [
        json.dumps(e, sort_keys=True) for e in left if e.get("staged_by") == "lab2"
    ] == [before]
    assert any(e["action"] == "todo" for e in left)
    assert r.json()["todo_note"] == (
        "1 TODO entries are still staged; `vhir approve --review` creates them.")  # fmt: skip
    assert not (case.dir / "pending-reviews.processing").exists()


def test_an_own_entry_not_yet_saved_is_signed(case):
    case.stage()
    r = case.sign_all([reviewed(case, "F-steve-001")])
    assert r.status_code == 200, r.text


def test_a_save_failure_says_the_decisions_were_signed(case, monkeypatch):
    from vhir_cli import decide

    mine = dict(reviewed(case, "F-steve-001"), staged_by="steve")
    case.stage(mine)
    monkeypatch.setattr(decide, "_save_twice", lambda *a: OSError("disk full"))
    r = case.sign_all([mine])
    assert r.status_code == 500 and r.json()["code"] == "SAVE_FAILED"
    assert (
        "Signed decisions were recorded; case data was not saved (disk full)"
        in r.json()["error"]
    )
    assert len(case.chain()) == 1
    assert case.read("pending-reviews.json")["items"] == [mine]  # still staged


def test_a_torn_ledger_is_named(case, monkeypatch):
    def torn(*a, **k):
        raise ledger.LedgerTorn("a write to the chain failed and couldn't be cut back.")

    monkeypatch.setattr(ledger, "commit", torn)
    r = case.sign_all([reviewed(case, "F-steve-001")])
    assert r.status_code == 500 and r.json()["code"] == "LEDGER_TORN"
    assert "vhir review --verify" in r.json()["error"]


@pytest.mark.parametrize("folder", ["keys", "ledger"])
def test_an_unfinished_update_is_named_before_anything_is_planned(case, folder):
    """A box updated once by 0.6's update code can lack the signing folders
    (or have them root's): the plan is refused by name, and the page says so."""
    target = keys.KEYS_DIR if folder == "keys" else ledger.LEDGER_DIR
    before = _snapshot(case)
    target.chmod(0o500)
    try:
        r = case.plan([reviewed(case, "F-steve-001")])
        state = case.get("/api/case").json()["signing"]
    finally:
        target.chmod(0o700)
    named = credentials.not_writable_text(target)  # this folder, and whose it is
    assert r.status_code == 409 and r.json()["code"] == "UPDATE_UNFINISHED"
    assert r.json()["error"] == named
    assert (state["signing_available"], state["reason"]) == (False, "UPDATE_UNFINISHED")
    assert state["message"] == named
    assert _snapshot(case) == before


def test_a_copy_of_the_case_can_t_sign_in_the_portal(case):
    """The chain's first line binds the folder that began it; a folder with
    the same case id and another identity (a copy) is refused by name."""
    yaml = case.dir / "CASE.yaml"
    original = yaml.read_text()
    yaml.write_text(original + "case_uuid: 11111111-2222-4333-8444-555555555555\n")
    case.stage(dict(reviewed(case, "F-steve-001"), staged_by="steve"))
    assert case.sign_all([reviewed(case, "F-steve-001")]).status_code == 200
    (first,) = case.chain()
    assert first["case_uuid"] == "11111111-2222-4333-8444-555555555555"
    yaml.write_text(original + "case_uuid: 99999999-8888-4777-8666-555555555555\n")
    before = _snapshot(case)
    r = case.plan([reviewed(case, "F-steve-002")])
    assert r.status_code == 409 and r.json()["code"] == "CASE_COPY"
    assert r.json()["error"] == ledger.copy_text("C-1")
    state = case.get("/api/case").json()["signing"]
    assert (state["signing_available"], state["reason"]) == (False, "CASE_COPY")
    assert _snapshot(case) == before


@pytest.mark.parametrize("how", ["not UTF-8", "unreadable"])
def test_an_unreadable_chain_is_a_named_signing_state_not_a_500(case, how):
    case.stage(dict(reviewed(case, "F-steve-001"), staged_by="steve"))
    assert case.sign_all([reviewed(case, "F-steve-001")]).status_code == 200
    path = ledger.chain_path("C-1")
    if how == "not UTF-8":
        path.write_bytes(path.read_bytes() + b"\xff\xfe\n")
    else:
        path.chmod(0o000)
    try:
        page = case.get("/api/case")
        r = case.plan([reviewed(case, "F-steve-002")])
    finally:
        path.chmod(0o600)
    assert page.status_code == 200
    state = page.json()["signing"]
    assert (state["signing_available"], state["reason"]) == (False, "CHAIN_UNREADABLE")
    assert state["message"] == ledger.CHAIN_UNREADABLE
    assert r.status_code == 409 and r.json()["code"] == "CHAIN_UNREADABLE"


def test_the_first_folder_to_sign_is_recorded_and_a_copy_recorded_meanwhile_is_refused(
    case, tmp_path, monkeypatch
):
    """The portal records the case's folder under the case lock just before
    its commit, as the CLI does. A plan made before another folder holding
    the identity was recorded is refused at the commit, with nothing signed."""
    import json as _json

    from vhir_cli.case_identity import _paths_file, record_case_path

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    uuid = "11111111-2222-4333-8444-555555555555"
    yaml = case.dir / "CASE.yaml"
    yaml.write_text(yaml.read_text() + f"case_uuid: {uuid}\n")
    case.stage(dict(reviewed(case, "F-steve-001"), staged_by="steve"))
    assert case.sign_all([reviewed(case, "F-steve-001")]).status_code == 200
    assert _json.loads(_paths_file().read_text()) == {uuid: str(case.dir.resolve())}
    # a hand copy, recorded in place of the original (it was activated while
    # the original was away), then the original's plan and commit
    _paths_file().unlink()
    copy = tmp_path / "C-1-cp"
    copy.mkdir()
    (copy / "CASE.yaml").write_text(yaml.read_text())
    plan = case.plan([reviewed(case, "F-steve-002")]).json()  # no record: passes
    record_case_path(copy)
    k = case.login(plan).json()
    before = _snapshot(case)
    r = case.commit(plan, case.sign(plan, k))
    assert r.status_code == 409 and r.json()["code"] == "CASE_COPY", r.text
    assert f"If {case.dir.resolve()} is the original" in r.json()["error"]
    assert _snapshot(case) == before


def test_an_upgraded_case_gets_its_identity_at_its_first_portal_signing(
    case, tmp_path, monkeypatch
):
    """A case 0.6.4 left with no case_uuid: the plan gives it one, so the
    commit's first line binds this folder."""
    import yaml as _yaml

    pytest.importorskip("sift_common.host_identity")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert "case_uuid" not in (
        _yaml.safe_load((case.dir / "CASE.yaml").read_text()) or {}
    )
    case.stage(dict(reviewed(case, "F-steve-001"), staged_by="steve"))
    assert case.sign_all([reviewed(case, "F-steve-001")]).status_code == 200
    uuid = _yaml.safe_load((case.dir / "CASE.yaml").read_text())["case_uuid"]
    assert case.chain()[0]["case_uuid"] == uuid


def test_a_lost_identity_refuses_the_plan_by_name(case, tmp_path, monkeypatch):
    from vhir_cli.case_identity import ensure_identity

    pytest.importorskip("sift_common.host_identity")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    ensure_identity(case.dir)
    lines = (case.dir / "CASE.yaml").read_text().splitlines()
    (case.dir / "CASE.yaml").write_text(
        "\n".join(x for x in lines if not x.startswith("case_uuid")) + "\n"
    )
    before = _snapshot(case)
    r = case.plan([reviewed(case, "F-steve-001")])
    assert r.status_code == 409 and r.json()["code"] == "CASE_IDENTITY", r.text
    assert "case_uuid" in r.json()["error"]
    assert _snapshot(case) == before


def test_a_commit_whose_signatures_fail_records_no_folder(case, tmp_path, monkeypatch):
    from vhir_cli.case_identity import _paths_file

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    case.login(plan)
    r = case.commit(plan, {"F-steve-001": "AAAA"})
    assert r.status_code == 401 and r.json()["code"] == "BAD_SIGNATURE"
    assert not _paths_file().exists()


def test_a_folder_record_that_can_t_be_written_is_named(case, tmp_path, monkeypatch):
    import vhir_cli.case_identity as ci

    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    def full(case_dir):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ci, "record_case_path", full)
    case.stage(dict(reviewed(case, "F-steve-001"), staged_by="steve"))
    r = case.sign_all([reviewed(case, "F-steve-001")])
    assert r.status_code == 500 and r.json()["code"] == "CASE_RECORD_UNWRITABLE", r.text
    assert "record of case folders couldn't be written" in r.json()["error"]
    assert case.chain() == []  # nothing signed
    assert [e["id"] for e in case.read("pending-reviews.json")["items"]] == [
        "F-steve-001"
    ]
    assert case.item("F-steve-001")["status"] == "DRAFT"


def test_the_case_page_shows_the_signing_state(case):
    state = case.get("/api/case").json()["signing"]
    assert state["signing_available"] is True and state["schema"] == 3
    assert state["fingerprint"] == keys.key_fingerprint(keys.active(keys.load("steve")))
    assert (
        case.get("/api/case", examiner="anonymous").json()["signing"]["reason"]
        == "NO_API_KEYS"
    )


def test_badges_come_from_verify(case):
    assert case.get("/api/findings").json()[0]["verification"] == "draft"
    case.sign_all([reviewed(case, "F-steve-001")])
    served = {f["id"]: f for f in case.get("/api/findings").json()}
    assert served["F-steve-001"]["verification"] == "valid (not anchored)"
    note = case.get("/api/case").json()["verification"]["badge_notes"]["F-steve-001"]
    assert note.startswith("Valid (not anchored): compare the fingerprint")
    assert keys.key_fingerprint(keys.active(keys.load("steve"))) in note
    # an item served gains only keys its signed view leaves out
    from vhir_cli.case_io import VIEW_EXCLUDES

    assert (
        set(served["F-steve-001"]) - set(case.item("F-steve-001")) <= VIEW_EXCLUDES[1]
    )
    findings = case.read("findings.json")
    findings[0]["observation"] = "edited on disk"
    case.write("findings.json", findings)
    served = {f["id"]: f for f in case.get("/api/findings").json()}
    assert served["F-steve-001"]["verification"] == "ALTERED_AFTER_APPROVAL"


def test_a_0_6_approval_is_labelled(case, box):
    from vhir_cli.case_io import hmac_text

    findings = case.read("findings.json")
    findings[0].update(
        status="APPROVED", approved_by="steve", approved_at="2026-01-01T00:00:00+00:00"
    )
    case.write("findings.json", findings)
    line = {"finding_id": "F-steve-001", "content_snapshot": hmac_text(findings[0]),
            "approved_by": "steve", "approved_at": "2026-01-01T00:00:00+00:00",
            "hmac": "00", "hmac_version": 2, "case_id": "C-1", "type": "finding"}  # fmt: skip
    (box / "verification" / "C-1.jsonl").write_text(json.dumps(line) + "\n")
    served = {f["id"]: f for f in case.get("/api/findings").json()}
    assert (
        served["F-steve-001"]["verification"] == "approved under 0.6 (before signing)"
    )


def test_served_items_carry_the_recomputed_content_hash(case):
    from vhir_cli.case_io import compute_content_hash

    findings = case.read("findings.json")
    findings[0]["content_hash"] = "stale"
    case.write("findings.json", findings)
    served = case.get("/api/findings").json()[0]
    assert served["content_hash"] == compute_content_hash(findings[0])


def test_the_password_is_never_needed_before_display(case):
    """The plan carries every body to display; only /key takes the login."""
    plan = case.plan([reviewed(case, "F-steve-001")]).json()
    body = json.loads(plan["bodies"][0]["body"])
    assert body["examiner"] == "steve" and body["case_id"] == "C-1"
    assert body["at"] == plan["now"] and "sig" not in body
    assert PASSWORD not in json.dumps(plan)


def test_each_badge_names_the_key_of_its_own_line(case, monkeypatch):
    """Two approvals by one examiner under two keys (a rotation), judged with
    both keys pinned so the case verifies: each badge names its own line's
    key, not the examiner's newest."""
    from vhir_cli import ledger_verify

    first = case.sign_all([reviewed(case, "F-steve-001")])
    assert first.status_code == 200, first.text
    old = first.json()["fingerprint"]
    data = keys.load("steve")
    fresh = keys.new_credential("steve", PASSWORD)
    for k in data["keys"]:
        k["status"] = "retired"
    fresh["keys"] = data["keys"] + fresh["keys"]
    keys.save("steve", fresh)
    second = case.sign_all([reviewed(case, "F-steve-002")])
    assert second.status_code == 200, second.text
    new = second.json()["fingerprint"]
    real = ledger_verify.verify_case
    pins = [ledger_verify.parse_pin(f"steve={fp}") for fp in (old, new)]
    monkeypatch.setattr(
        ledger_verify, "verify_case", lambda d, **kw: real(d, expect_keys=pins)
    )
    notes = case.get("/api/case").json()["verification"]["badge_notes"]
    assert (
        f"Key: steve {old}." in notes["F-steve-001"] and new not in notes["F-steve-001"]
    )
    assert (
        f"Key: steve {new}." in notes["F-steve-002"] and old not in notes["F-steve-002"]
    )
