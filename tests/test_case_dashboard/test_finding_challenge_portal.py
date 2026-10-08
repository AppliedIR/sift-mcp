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


def test_the_legacy_dashboard_says_what_it_does_not_show():
    from pathlib import Path

    legacy = Path(D.__file__).parent / "static" / "index.html"
    assert "does not show finding alternatives, challenge status or withdrawn" in (
        legacy.read_text()
    )


def test_the_portal_shows_alternatives_the_challenge_and_withdrawals():
    from pathlib import Path

    page = (Path(D.__file__).parent / "static" / "v2" / "index.html").read_text()
    for marker in (
        "renderAlternatives(eff.alternatives)",
        "renderChallengeLine(f.challenged)",
        "renderWithdrawnList(summary.withdrawn)",
        ">Not challenged<",
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
        + _js_function("escapeHtml")
        + _js_function("renderChallengeLine")
        + f"process.stdout.write(renderChallengeLine({json.dumps(marker)}));"
    )
    out = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout
    assert "Contradiction (client-reported): the re-run shows &lt;img" in out
    assert "Server: Withdrawal refused: it needs the skeptic&#39;s tool output." in out
    assert not re.search(r"<img", out)
