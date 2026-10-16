"""The portal's chain panel shows each step once within each group's chain: a
fan-in step that stores one link per input it read renders once, whatever its
key order. A step two groups share stays in both, and records render as stored.
An artifact stored cut shows its stored text and the cut marker on the card.

Renders through the page's own script under node, as
test_portal_provenance_display does."""

from __future__ import annotations

import gzip
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import finding
from .test_portal_provenance_display import DRIVER, PAGE

FIXTURE = Path(__file__).parents[1] / "fixtures" / "fan_in_chain.json.gz"
STEP = "border-left:2px solid var(--border)"
H = "a" * 64


def link(aid, frm, to, method="recorded-id"):
    return {"method": method, "audit_id": aid, "entry_sha256": "e" * 64,
            "from": {"path": frm, "sha256": H}, "to": {"path": to, "sha256": H}}  # fmt: skip


def record(aid, doc_id):
    return {"audit_id": aid, "document": {"_id": doc_id, "event.code": "4624"}}


def reordered(step: dict) -> dict:
    """The same step with its keys, and its ends' keys, in reverse order."""
    out = {}
    for k in reversed(list(step)):
        v = step[k]
        out[k] = {kk: v[kk] for kk in reversed(list(v))} if isinstance(v, dict) else v
    return out


def reordered_list(step: dict) -> dict:
    """The same step with the objects in its lists in reverse key order."""
    return {k: [{kk: o[kk] for kk in reversed(list(o))} for o in v] if isinstance(v, list) else v
            for k, v in step.items()}  # fmt: skip


def art(chain, label):
    return {"source": "s", "extraction": label, "content": "4624", "audit_id": "x-1",
            "provenance_grade": "FULL", "provenance_reason": "", "provenance_root": None,
            "provenance_chain": chain, "provenance_break": None}  # fmt: skip


A = link("sift-steve-101", "/e/disk.E01", "/x/1/Security.evtx", "registered-path")
B = link("sift-steve-102", "/x/1/Security.evtx", "/x/2/a.csv")
C = link("sift-steve-103", "/x/1/Security.evtx", "/x/3/b.csv")
LISTED = {**A, "inputs": [{"path": "/x/1/Security.evtx", "sha256": H}]}
MARK = "\n[cut: 5000 of 9000 chars stored]"
# stored text as record_finding keeps it: its first 5000 chars, then the marker
CUT = {end: "<td>" + "A" * 4995 + end + MARK for end in ("A", "\t", "\r", "\x1b")}
R1, R2 = record("opensearch-steve-201", "d1"), record("opensearch-steve-202", "d2")


def _fan_in() -> dict:
    return json.loads(gzip.decompress(FIXTURE.read_bytes()))[0]


def _findings() -> list:
    fan = _fan_in()
    return [
        finding("F-steve-020", artifacts=fan["artifacts"]),
        # two groups: each record's chain is the steps stored just before it
        finding("F-steve-021", artifacts=[art([A, B, R1, A, C, R2], "two groups")]),
        finding("F-steve-022", artifacts=[art([A, A, B, A, B, R1], "repeats")]),
        finding(
            "F-steve-023",
            artifacts=[art([A, reordered(A), B, reordered(B)], "key order")],
        ),
        # a step whose list holds an object, stored again in another key order
        finding(
            "F-steve-025", artifacts=[art([LISTED, reordered_list(LISTED)], "list")]
        ),
        # the same audit id and ends, a different method: two steps
        finding(
            "F-steve-024",
            artifacts=[art([A, {**A, "method": "hash+place"}], "differs")],
        ),
        *(
            finding(
                f"F-steve-{30 + i}",
                artifacts=[{**art([A], "cut"), "content": CUT[end]}],
            )
            for i, end in enumerate(CUT)
        ),
    ]


@pytest.fixture(scope="module")
def shown() -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("node isn't installed")
    audit = [{"audit_id": "x-1", "tool": "run_command", "_backend": "sift-mcp",
              "params": {"command": "cat a.csv"}}]  # fmt: skip
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
                       input=json.dumps({"page": str(PAGE), "findings": _findings(),
                                         "audit": audit}))  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout)


def chain_panel(shown, fid) -> str:
    return shown[fid]["panel"].split("Additional Tool Invocations")[0]


def ids(panel: str) -> list:
    """Each rendered step's audit id, in order."""
    return [p.split("]")[0] for p in panel.split('font-size:10px">[')[1:]]


def test_the_fan_in_chain_renders_each_step_once(shown):
    chain = _fan_in()["artifacts"][0]["provenance_chain"]
    distinct = {json.dumps(s, sort_keys=True) for s in chain}
    assert (len(chain), len(distinct)) == (1082, 364)
    assert chain_panel(shown, "F-steve-020").count(STEP) == 364


def test_a_step_two_groups_share_stays_in_both(shown):
    p = chain_panel(shown, "F-steve-021")
    assert ids(p) == ["sift-steve-101", "sift-steve-102", "opensearch-steve-201",
                      "sift-steve-101", "sift-steve-103", "opensearch-steve-202"]  # fmt: skip


def test_repeats_within_a_group_show_once_first_kept(shown):
    p = chain_panel(shown, "F-steve-022")
    assert ids(p) == ["sift-steve-101", "sift-steve-102", "opensearch-steve-201"]


def test_a_step_stored_in_another_key_order_shows_once(shown):
    p = chain_panel(shown, "F-steve-023")
    assert ids(p) == ["sift-steve-101", "sift-steve-102"]


def test_a_step_with_a_list_stored_in_another_key_order_shows_once(shown):
    p = chain_panel(shown, "F-steve-025")
    assert ids(p) == ["sift-steve-101"]


def test_steps_that_differ_in_one_field_both_show(shown):
    p = chain_panel(shown, "F-steve-024")
    assert ids(p) == ["sift-steve-101", "sift-steve-101"]
    assert "[registered-path]" in p and "[hash+place]" in p


def test_a_cut_quote_shows_its_text_and_marker_on_the_card(shown):
    for i, end in enumerate(CUT):
        card = shown[f"F-steve-{30 + i}"]["card"]
        assert "&lt;td&gt;" + "A" * 4995 + end + MARK in card, repr(end)
