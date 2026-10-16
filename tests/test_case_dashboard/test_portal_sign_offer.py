"""The Sign dialog offers the passphrase box and the Sign button only for a
plan with decisions in it. A failed approval check shows the check and Plan
again instead, and a dialog with nothing of the examiner's to sign offers
neither. Names are synthetic."""

from __future__ import annotations

import re

from .conftest import reviewed
from .test_portal_approval_checks import REASON, case, change_root  # noqa: F401
from .test_portal_page import V2, live  # noqa: F401


def _stage(case, *staged_by):
    case.stage(
        *(dict(reviewed(case, "F-steve-001"), staged_by=who) for who in staged_by)
    )


def test_a_failed_check_offers_no_passphrase_box_and_no_sign_button(case, live):
    change_root(case)
    _stage(case, "steve")
    out = live([{"do": "open"}, {"do": "snap", "as": "s"}])
    s = out["s"]
    assert s["boxShown"] is False and s["signShown"] is False, s
    assert "check failed: ROOT_CHANGED" in s["list"]
    assert ">Plan again with these reasons</button>" in s["list"]
    assert s["error"].startswith("CHECKS_FAILED")
    assert out["posts"].count("/api/commit") == 0


def test_a_passing_plan_offers_the_box_and_signs_its_decisions(case, live):
    # twin: the same case, its evidence unchanged
    _stage(case, "steve")
    out = live([{"do": "open"}, {"do": "snap", "as": "s"}, {"do": "sign"},
                {"do": "snap", "as": "after"}])  # fmt: skip
    s = out["s"]
    assert s["boxShown"] is True and s["signShown"] is True, s
    assert s["signButton"] == "Sign 1 decision" and s["signDisabled"] is False
    assert "check failed" not in s["list"]
    assert [ln["item_id"] for ln in case.chain()] == ["F-steve-001"]


def test_a_reason_and_plan_again_offer_the_box_for_the_approval(case, live):
    change_root(case)
    _stage(case, "steve")
    out = live([{"do": "open"}, {"do": "snap", "as": "failed"},
                {"do": "replan", "reason": REASON}, {"do": "snap", "as": "planned"},
                {"do": "sign"}])  # fmt: skip
    assert out["failed"]["boxShown"] is False and out["failed"]["signShown"] is False
    p = out["planned"]
    assert p["boxShown"] is True and p["signShown"] is True, p
    assert p["signButton"] == "Sign 1 decision" and p["error"] == ""
    assert "approved with override: " + REASON in p["list"]
    (line,) = case.chain()
    assert line["item_id"] == "F-steve-001"


def test_nothing_of_the_examiners_to_sign_offers_no_sign_button(case, live):
    # only another examiner's entry is staged: zero decisions, no failed check
    _stage(case, "lab2")
    out = live([{"do": "open"}, {"do": "snap", "as": "s"}])
    s = out["s"]
    assert s["boxShown"] is False and s["signShown"] is False, s
    assert s["error"] == "Nothing of yours is staged to sign."
    assert "check failed" not in s["list"]
    assert out["posts"].count("/api/commit/plan") == 0


def test_the_box_and_the_button_start_hidden_in_the_page():
    page = V2.read_text()
    row = re.search(r'<div id="commitPasswordRow"[^>]*>', page).group(0)
    button = re.search(r'<button[^>]*id="commitSubmitBtn"[^>]*>', page, re.S).group(0)
    assert 'style="display:none"' in row and 'style="display:none"' in button
