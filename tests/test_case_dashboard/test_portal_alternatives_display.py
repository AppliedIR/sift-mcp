"""A finding's Alternatives section on the portal card. With none recorded it
says so in words, never a bare "None" and never an empty section. A recorded
alternative of any shape is shown as text: a string as it is, anything else
as JSON, escaped, and never "[object Object]" or a broken card.

The page's own script runs under node (test_portal_ioc_display's driver);
each row renders a finding's card through renderFinding and reads back the
Alternatives section."""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from .conftest import finding
from .test_portal_ioc_display import DRIVER, PAGE

NONE_LINE = "No alternatives recorded."
LONG = "x" * (65 * 1024)
CONTROLS = "a\tb\rc\x1bd\x00e\x85f"
HOSTILE = {"toString": None}

# id -> the finding's alternatives (absent for the "missing" row)
SHAPES = {
    "F-steve-001": None,
    "F-steve-002": [],
    "F-steve-003": "",
    "F-steve-005": [{"explanation": "An admin's test", "status": "open"}],
    "F-steve-006": [
        {
            "explanation": "Patch job",
            "status": "ruled_out",
            "evidence": "no patch run that day",
            "audit_ids": ["a-1", "a-2"],
        }
    ],
    "F-steve-007": "A scheduled backup",
    "F-steve-008": 5,
    "F-steve-009": {"explanation": "Kept outside a list", "status": "open"},
    "F-steve-010": ["plain text alternative", 7, ["nested"]],
    "F-steve-011": [
        {
            "explanation": {"k": "v"},
            "status": {"s": 1},
            "evidence": ["e1", "e2"],
            "audit_ids": [{"id": "a-3"}],
        }
    ],
    "F-steve-012": [
        {
            "explanation": HOSTILE,
            "status": HOSTILE,
            "evidence": HOSTILE,
            "audit_ids": [HOSTILE],
        }
    ],
    "F-steve-013": [{"explanation": CONTROLS, "status": "open"}],
    "F-steve-014": [{"explanation": LONG, "status": "open"}],
    "F-steve-015": [{"explanation": "Ünïcødé 管理者 test", "status": "maybe"}],
    "F-steve-016": [{"explanation": "<img src=x onerror=alert(1)>", "status": "<b>"}],
    "F-steve-017": [
        {"explanation": "first", "status": "open"},
        {"explanation": "second", "status": "ruled_out"},
    ],
    "F-steve-018": [{"explanation": "Was empty before the edit", "status": "open"}],
    "F-steve-019": [{"explanation": "Removed by the edit", "status": "open"}],
    "F-steve-020": [{"evidence": "seen once"}],
}


def _finding(fid):
    if fid == "F-steve-004":
        return finding(fid)  # no alternatives key at all
    return finding(fid, alternatives=SHAPES[fid])


# The hostile shape renders on its own, so a throw there fails only its row
HOSTILE_ID = "F-steve-012"
FINDINGS = [_finding(fid) for fid in ["F-steve-004", *SHAPES] if fid != HOSTILE_ID]
DELTA = {
    "version": 1,
    "case_id": "C-1",
    "items": [
        {"id": "F-steve-018", "action": "edit", "staged_by": "steve",
         "modifications": {"alternatives": {
             "original": None, "modified": SHAPES["F-steve-018"]}}},
        {"id": "F-steve-019", "action": "edit", "staged_by": "steve",
         "modifications": {"alternatives": {
             "original": SHAPES["F-steve-019"], "modified": []}}},
    ],
}  # fmt: skip


def _render(findings: list) -> dict:
    """Each finding's Alternatives section, rendered by renderFinding."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    r = subprocess.run(
        [node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
        input=json.dumps({"page": str(PAGE), "findings": findings,
                          "caseMeta": {"signing": {"examiner": "steve"}},
                          "delta": DELTA}),
    )  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    out = {}
    for fid, card in json.loads(r.stdout).items():
        start = card.index('Alternatives <span class="edit-pencil"')
        out[fid] = card[start : card.index('<div class="context-section"', start)]
    return out


@pytest.fixture(scope="module")
def sections() -> dict:
    return _render(FINDINGS)


def _text(section: str) -> str:
    """The section's visible text after the label: tags dropped."""
    return re.sub(r"<[^>]*>", "", section.split("</div>", 1)[1])


@pytest.mark.parametrize(
    "fid", ["F-steve-001", "F-steve-002", "F-steve-003", "F-steve-004"]
)
def test_no_alternatives_says_so_in_words_never_none(sections, fid):
    # null, [], "" and a finding without the key
    assert _text(sections[fid]) == NONE_LINE
    assert "None" not in sections[fid]


def test_a_recorded_alternative_is_shown_with_its_status(sections):
    assert _text(sections["F-steve-005"]) == "[open]An admin&#39;s test"
    assert NONE_LINE not in sections["F-steve-005"]


def test_a_ruled_out_alternative_shows_its_evidence_and_audit_ids(sections):
    assert _text(sections["F-steve-006"]) == (
        "[ruled out]Patch jobno patch run that dayaudit: a-1, a-2"
    )


@pytest.mark.parametrize("fid, shown", [
    ("F-steve-007", "A scheduled backup"),
    ("F-steve-008", "5"),
    ("F-steve-009", "[open]Kept outside a list"),
])  # fmt: skip
def test_a_value_stored_outside_a_list_is_shown_not_hidden(sections, fid, shown):
    assert _text(sections[fid]) == shown


def test_items_that_are_not_records_are_shown_as_text(sections):
    assert (
        _text(sections["F-steve-010"]) == "plain text alternative7[&quot;nested&quot;]"
    )


def test_field_values_that_are_not_text_are_shown_as_json(sections):
    assert _text(sections["F-steve-011"]) == (
        "[{&quot;s&quot;:1}]{&quot;k&quot;:&quot;v&quot;}"
        "[&quot;e1&quot;,&quot;e2&quot;]audit: {&quot;id&quot;:&quot;a-3&quot;}"
    )
    assert "[object Object]" not in sections["F-steve-011"]


def test_a_hostile_object_is_shown_never_a_broken_card():
    hostile = "{&quot;toString&quot;:null}"
    section = _render([_finding(HOSTILE_ID)])[HOSTILE_ID]
    assert _text(section) == f"[{hostile}]{hostile}{hostile}audit: {hostile}"


def test_control_characters_are_kept_as_text(sections):
    assert _text(sections["F-steve-013"]) == "[open]" + CONTROLS


def test_a_very_long_alternative_is_shown_whole(sections):
    assert _text(sections["F-steve-014"]) == "[open]" + LONG


def test_non_ascii_text_and_an_unusual_status_are_shown(sections):
    assert _text(sections["F-steve-015"]) == "[maybe]Ünïcødé 管理者 test"


def test_markup_is_escaped(sections):
    s = sections["F-steve-016"]
    assert "<img" not in s and "<b>" not in s
    assert _text(s) == "[&lt;b&gt;]&lt;img src=x onerror=alert(1)&gt;"


def test_two_alternatives_are_both_shown(sections):
    assert _text(sections["F-steve-017"]) == "[open]first[ruled out]second"


def test_a_record_without_status_or_explanation_reads_open(sections):
    assert _text(sections["F-steve-020"]) == "[open]seen once"


def _sides(section: str) -> tuple[str, str]:
    """An edited section's original and new sides, as visible text."""
    head, tail = section.split('<div class="modified-new">', 1)
    return _text(head), re.sub(r"<[^>]*>", "", tail)


def test_an_edit_from_none_shows_both_sides_in_words(sections):
    assert _sides(sections["F-steve-018"]) == (
        NONE_LINE,
        "[open]Was empty before the edit",
    )
    assert "None" not in sections["F-steve-018"]


def test_an_edit_to_none_shows_both_sides_in_words(sections):
    assert _sides(sections["F-steve-019"]) == ("[open]Removed by the edit", NONE_LINE)
    assert "None" not in sections["F-steve-019"]


def test_no_card_prints_none_or_object_object(sections):
    for fid, s in sections.items():
        assert ">None<" not in s, fid
        assert "[object Object]" not in s, fid
