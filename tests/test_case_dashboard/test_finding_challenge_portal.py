"""The portal applies an examiner's edit to a finding's alternatives, and lists
the candidates withdrawn after challenge. The hashes cover both new keys, and
reports keep the alternatives but not the challenge.

The portal's signed commit and get_summary run on a scratch case.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from pathlib import Path

import case_dashboard.routes as D
import forensic_mcp.case.manager as fm
import pytest
from report_mcp.profiles import STRIPPED_FINDING_FIELDS
from vhir_cli.case_io import HASH_EXCLUDE_KEYS, compute_content_hash
from vhir_cli.ledger_verify import verify_case

from .conftest import enrol, reviewed
from .conftest import finding as conftest_finding

NOW0 = "2026-10-07T07:00:00+00:00"
ALTERNATIVES = [{"explanation": "An admin's test", "status": "open"}]


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    finding = {
        "id": "F-steve-001",
        "type": "finding",
        "title": "t",
        "observation": "o",
        "interpretation": "i",
        "confidence": "MEDIUM",
        "status": "DRAFT",
        "examiner": "steve",
        "created_by": "steve",
        "staged": NOW0,
        "modified_at": NOW0,
        "audit_ids": ["x-1"],
        "alternatives": ALTERNATIVES,
    }
    finding["content_hash"] = compute_content_hash(finding)
    (d / "findings.json").write_text(json.dumps([finding]))
    (d / "timeline.json").write_text("[]")
    return d


@pytest.mark.parametrize("action", ["approve", "edit"])
def test_an_examiners_edit_of_the_alternatives_is_signed_and_applied(portal, action):
    """The portal's signed commit applies the edited alternatives."""
    enrol("steve")
    original = dict(conftest_finding("F-steve-001"), alternatives=ALTERNATIVES)
    portal.write("findings.json", [original])
    portal.write("timeline.json", [])
    edited = ALTERNATIVES + [
        {"explanation": "Scheduled backup", "status": "ruled_out", "evidence": "x"}
    ]
    entry = dict(
        reviewed(portal, "F-steve-001", action,
                 modifications={"alternatives": {"original": ALTERNATIVES,
                                                 "modified": edited}}),
        staged_by="steve",
    )  # fmt: skip
    portal.stage(entry)
    r = portal.sign_all([entry])
    assert r.status_code == 200, r.text
    finding = portal.item("F-steve-001")
    assert finding["alternatives"] == edited
    assert finding["examiner_modifications"]["alternatives"]["modified"] == edited
    (line,) = portal.chain()
    assert line["item_id"] == "F-steve-001"
    assert verify_case(portal.dir).exit_code == 0


NEW_FIELDS = {
    "challenged": {
        "outcome": "contested", "contradiction": "Fits the admin's jump host.",
        "checks": [{"name": "re-read", "result": "not run", "audit_ids": [],
                    "reason": "unverified audit id: x-1"}],
        "skeptic_audit_ids": [], "skeptic": {"client": "codex", "model": "m",
                                             "self_reported": True}},
    "prior_challenge": [{"kind": "withdrawn", "ref": "forensic-steve-20261013-001",
                         "contradiction": "installer path", "new_since": []}],
    "produced_by": {"client": "claude-code", "model": "m", "self_reported": True},
}  # fmt: skip


def test_a_finding_with_the_challenge_fields_is_served_as_stored_signed_and_verified(
    portal,
):
    """The fields record_finding now writes are part of the signed content:
    the portal serves them as stored (its checkPlan compares the payload), and
    an approval through the portal signs them and verifies."""
    enrol("steve")
    original = dict(conftest_finding("F-steve-001"), **NEW_FIELDS)
    portal.write("findings.json", [original])
    portal.write("timeline.json", [])
    served = portal.item("F-steve-001")
    assert {k: served[k] for k in NEW_FIELDS} == NEW_FIELDS
    entry = dict(reviewed(portal, "F-steve-001", "approve"), staged_by="steve")
    portal.stage(entry)
    r = portal.sign_all([entry])
    assert r.status_code == 200, r.text
    (line,) = portal.chain()
    assert line["item_id"] == "F-steve-001"
    assert verify_case(portal.dir).exit_code == 0
    assert all(f in json.loads(line["content_snapshot"]) for f in NEW_FIELDS)


def _withdrawal(audit_id, ts, title="t"):
    return {
        "ts": ts,
        "tool": "record_finding",
        "audit_id": audit_id,
        "examiner": "steve",
        "params": {"finding": {"title": title}},
        "result_summary": {
            "status": "WITHDRAWN",
            "title": title,
            "observation": "o",
            "contradiction": "no such file",
            "skeptic_audit_ids": ["sift-steve-20261007-002"],
        },
    }


def _summary():
    return json.loads(asyncio.run(D.get_summary(None)).body)


def test_the_summary_lists_each_withdrawal_once(case):
    lines = [
        _withdrawal("forensic-steve-20261007-001", "2026-10-07T08:00:00Z", "first"),
        _withdrawal("forensic-steve-20261007-001", "2026-10-07T08:00:00Z", "first"),
        _withdrawal("forensic-steve-20261007-001", "2026-10-07T09:00:00Z", "second"),
        {"tool": "record_finding", "audit_id": "f-3", "result_summary": "WITHDRAWN"},
        {"tool": "record_finding", "result_summary": {"status": "STAGED"}},
        {"tool": "log_reasoning", "result_summary": {"status": "WITHDRAWN"}},
    ]
    text = "\n".join(json.dumps(e) for e in lines) + "\n{corrupt\n"
    (case / "audit" / "forensic-mcp.jsonl").write_text(text)
    withdrawn = _summary()["withdrawn"]
    assert withdrawn["total"] == 2
    assert [w["title"] for w in withdrawn["items"]] == ["first", "second"]
    assert withdrawn["items"][0]["contradiction"] == "no such file"
    assert withdrawn["items"][0]["skeptic_audit_ids"] == ["sift-steve-20261007-002"]


def test_a_line_that_isnt_utf8_is_skipped_counted_and_noted(case):
    good = json.dumps(
        _withdrawal("forensic-steve-20261007-001", "2026-10-07T08:00:00Z", "first")
    )
    raw = (
        b'{"tool": "record_finding", "title": "\xff"}\n'
        + good.encode()
        + b"\n\xfe\xff\n"
    )
    (case / "audit" / "forensic-mcp.jsonl").write_bytes(raw)
    withdrawn = _summary()["withdrawn"]
    assert withdrawn["total"] == 1 and withdrawn["items"][0]["title"] == "first"
    assert withdrawn["unreadable_lines"] == 2
    assert withdrawn["note"] == (
        "Audit lines skipped because they aren't UTF-8: 2. "
        "A withdrawal recorded on them isn't listed."
    )


def test_anchor_a_case_without_withdrawals_counts_none(case):
    assert _summary()["withdrawn"] == {"total": 0, "items": []}


@pytest.mark.parametrize("key", ["alternatives", "challenged"])
@pytest.mark.parametrize(
    "exclude",
    [fm._HASH_EXCLUDE_KEYS, HASH_EXCLUDE_KEYS],
    ids=["forensic-mcp", "vhir (the portal and report-mcp use it)"],
)
def test_every_hash_covers_the_new_keys(key, exclude):
    assert key not in exclude


def test_reports_keep_the_alternatives_but_not_the_challenge():
    assert "challenged" in STRIPPED_FINDING_FIELDS
    assert "alternatives" not in STRIPPED_FINDING_FIELDS


def test_the_portal_shows_alternatives_the_challenge_and_withdrawals():
    from pathlib import Path

    page = (Path(D.__file__).parent / "static" / "v2" / "index.html").read_text()
    for marker in (
        "renderAlternatives(eff.alternatives)",
        "renderChallengeLine(f.challenged, f)",
        "renderWithdrawnList(summary.withdrawn)",
        "'Not challenged (imported)' : 'Not challenged'",
        "startEdit(\\'alternatives\\')",
    ):
        assert marker in page, marker


PORTAL = (Path(D.__file__).parent / "static" / "v2" / "index.html").read_text()


def _js_function(name: str) -> str:
    start = PORTAL.index(f"function {name}(")
    return PORTAL[start : PORTAL.index("\n}\n", start) + 3]


@pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")
def test_the_challenge_line_shows_both_reasons_escaped():
    marker = {
        "outcome": "withdrawn",
        "skeptic_audit_ids": [],
        "contradiction": "the re-run shows <img src=x onerror=alert(1)>",
        "refused": "Withdrawal refused: it needs the skeptic's tool output.",
    }
    script = (
        # textContent in, innerHTML out, as a browser escapes it
        "const document = {createElement: () => ({set textContent(s) {"
        "this.innerHTML = String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')"
        ".replace(/>/g, '&gt;').replace(/\"/g, '&quot;');}})};\n"
        + _js_function("safeStr")  # escapeHtml converts through it
        + _js_function("escapeHtml")
        + "".join(_js_function(n) for n in CHALLENGE_FNS)
        + f"process.stdout.write(renderChallengeLine({json.dumps(marker)}));"
    )
    out = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout
    assert "Contradiction (client-reported): the re-run shows &lt;img" in out
    assert "Server: Withdrawal refused: it needs the skeptic&#39;s tool output." in out
    assert not re.search(r"<img", out)


# --- what the challenge line shows (A3) ------------------------------------------

CHALLENGE_FNS = [
    "challengeText",
    "challengeIsClean",
    "renderChallengeDetail",
    "renderChallengeLine",
]
_DOM = (
    "const document = {createElement: () => ({set textContent(s) {"
    "this.innerHTML = String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')"
    ".replace(/>/g, '&gt;').replace(/\"/g, '&quot;');}})};\n"
)
RUN = "sift-tester-20261013-001"
CHECK = {"name": "prefetch re-parsed", "result": "consistent", "audit_ids": [RUN],
         "ran": {RUN: "PECmd -f EVIL.EXE-1.pf"}}  # fmt: skip
UPHELD = {"outcome": "stands", "checks": [CHECK], "skeptic_audit_ids": [RUN]}


def _line(marker, finding=None) -> str:
    script = (
        _DOM
        + _js_function("safeStr")  # escapeHtml converts through it
        + _js_function("escapeHtml")
        + "".join(_js_function(n) for n in CHALLENGE_FNS)
        + f"process.stdout.write(renderChallengeLine({json.dumps(marker)}, "
        + f"{json.dumps(finding or {})}));"
    )
    return subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout


needs_node = pytest.mark.skipif(
    not shutil.which("node"), reason="node is not installed"
)


@needs_node
def test_a_clean_upheld_challenge_is_one_line_and_no_detail():
    out = _line(UPHELD)
    assert out == (
        '<div class="challenge-line">Challenged (client-reported): upheld \u2014 '
        f"skeptic: {RUN}</div>"
    )


@needs_node
@pytest.mark.parametrize(
    "marker, finding, shown",
    [
        ({**UPHELD, "contradiction": "Run count is 3, not 1."}, {},
         "Contradiction (client-reported): Run count is 3, not 1."),
        ({**UPHELD, "checks": [{**CHECK, "result": "contradicts"}]}, {},
         "prefetch re-parsed: contradicts"),
        ({**UPHELD, "checks": [CHECK, {"name": "event logs", "result": "not run",
                                       "audit_ids": [], "reason": "no evtx"}]}, {},
         "event logs: not run \u2014 no evtx"),
        ({"outcome": "contested", "checks": [], "skeptic_audit_ids": [],
          "contradiction": "Fits the admin's jump host."}, {},
         "Fits the admin&#39;s jump host."),
        (UPHELD, {"prior_challenge": [{"kind": "withdrawn", "ref": "a-1",
                                       "contradiction": "installer path",
                                       "new_since": [{"audit_id": "x-2", "ran": "date"}]}]},
         "Previously withdrawn (a-1): installer path \u2014 new since: date (x-2)"),
    ],
    ids=["upheld with a contradiction", "a check that contradicts", "a skipped check",
         "contested", "an earlier challenge"],
)  # fmt: skip
def test_a_challenge_that_needs_a_look_opens_to_its_checks(marker, finding, shown):
    out = _line(marker, finding)
    assert '<details class="challenge-detail">' in out and shown in out, out
    assert f"{RUN} (ran: PECmd -f EVIL.EXE-1.pf)" in out or not marker.get("checks"), (
        out
    )


@needs_node
@pytest.mark.parametrize(
    "marker, finding, first",
    [
        ({"outcome": "not_challenged", "reason": "no subagent", "checks": []}, {},
         '<div class="challenge-line not-challenged">Not challenged: no subagent</div>'),
        (None, {}, '<div class="challenge-line not-challenged">Not challenged</div>'),
        (None, {"imported_from": {"case_id": "c"}},
         '<div class="challenge-line not-challenged">Not challenged (imported)</div>'),
    ],
    ids=["not challenged, with its reason", "an old finding", "an imported finding"],
)  # fmt: skip
def test_a_finding_without_a_skeptic_says_so(marker, finding, first):
    assert _line(marker, finding).startswith(first)


@needs_node
def test_each_check_shows_what_its_ids_ran():
    """An author's own `date` run offered as the skeptic's is visible."""
    marker = {"outcome": "stands", "skeptic_audit_ids": [RUN], "checks": [
        {"name": "re-run", "result": "not run", "audit_ids": [RUN], "reason": "x",
         "ran": {RUN: "date"}}]}  # fmt: skip
    assert f"re-run: not run \u2014 x \u2014 {RUN} (ran: date)" in _line(marker)


@needs_node
@pytest.mark.parametrize(
    "bad", [{"a": 1}, {"toString": None}, ["x"]], ids=["object", "no toString", "list"]
)
def test_a_check_id_of_any_shape_renders(bad):
    """A marker is case data: an id that isn't text is shown as JSON, never a throw."""
    marker = {"outcome": "stands", "skeptic_audit_ids": [], "checks": [
        {"name": "re-run", "result": "not run", "audit_ids": [bad, RUN], "reason": "x",
         "ran": {RUN: "date"}}]}  # fmt: skip
    out = _line(marker)
    assert f"{RUN} (ran: date)" in out and "re-run: not run" in out, out
