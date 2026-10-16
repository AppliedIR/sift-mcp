"""What record_finding stores for an artifact: its chain without exact repeats,
and its content cut at 5000 chars with a marker when longer, the whole quote
checked either way, and a warning in the reply.

Uses test_finding_chains' own case, entries and helpers.
"""

import collections
import gzip
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from forensic_mcp.case import manager
from sift_common import provenance as pv
from test_case_dashboard.test_portal_chain_steps_once import chain_panel
from test_case_dashboard.test_portal_provenance_display import DRIVER, PAGE

from .test_finding_chains import (  # noqa: F401
    _doc,
    _extract,
    _ingested_samples,
    _search,
    _seven_zip,
    c,
    g,
    sha,
)

CAP = 5000


def _key(link) -> str:
    return json.dumps(link, sort_keys=True)


def _fan_in(c):
    """One run reading two files that one recorded extraction made from one
    registered 7z: both inputs trace through the same steps."""
    z = _seven_zip(c)
    s1, s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run(
        "sift-tester-20261009-002",
        ["cat", s1, s2],
        [s1, s2],
        "sample one\nsample two\n",
    )
    return "sift-tester-20261009-002"


def test_a_fan_in_chain_stores_each_step_once(c):
    aid = _fan_in(c)
    res, st = c.find([{"content": "sample one\nsample two", "audit_id": aid}])
    chain = st["artifacts"][0]["provenance_chain"]
    n = collections.Counter(_key(x) for x in chain)
    assert g(res, st)[0] == "FULL", g(res, st)
    assert chain and max(n.values()) == 1, n


def test_the_stored_chain_is_the_traces_links_in_order_first_kept(c):
    aid = _fan_in(c)
    t = pv.trace_artifact(pv.load_case(c.d), aid, "sample one\nsample two")
    keys = [_key(x) for x in t.links]
    assert len(keys) > len(set(keys))  # the trace itself repeats steps
    res, st = c.find([{"content": "sample one\nsample two", "audit_id": aid}])
    a = st["artifacts"][0]
    assert [_key(x) for x in a["provenance_chain"]] == list(dict.fromkeys(keys))
    # the grade is the trace's, with or without the repeats
    assert (a["provenance_grade"], res["provenance_grade"]) == (t.grade, t.grade)


def test_a_chain_with_no_repeats_is_stored_as_traced(c):
    z = _seven_zip(c)
    s1, _s2 = _extract(c, "sift-tester-20261009-001", z)
    c.run("sift-tester-20261009-002", ["cat", s1], [s1], "sample one\n")
    t = pv.trace_artifact(pv.load_case(c.d), "sift-tester-20261009-002", "sample one")
    res, st = c.find(
        [{"content": "sample one", "audit_id": "sift-tester-20261009-002"}]
    )
    assert g(res, st)[0] == "FULL", g(res, st)
    assert st["artifacts"][0]["provenance_chain"] == json.loads(json.dumps(t.links))


def test_a_stored_fan_in_chain_keeps_each_link_once_first_kept():
    fixture = Path(__file__).parents[1] / "fixtures" / "fan_in_chain.json.gz"
    chain = json.loads(gzip.decompress(fixture.read_bytes()))[0]["artifacts"][0][
        "provenance_chain"
    ]
    kept = manager._distinct_links(chain)
    assert (len(chain), len(kept)) == (1082, 364)
    assert [_key(x) for x in kept] == list(dict.fromkeys(_key(x) for x in chain))
    assert kept[0] is chain[0]


# --- one search's records from two ingests that share a step ------------------

X = "opensearch-ingest-7-20261009-010"
I1, I2 = "opensearch-ingest-7-20261009-011", "opensearch-ingest-7-20261009-012"


def _two_ingests_of_one_sample(c):
    """Two recorded ingests of sample two, both reached through one extraction:
    each record's chain is that step, then its own ingest."""
    s2 = _extract(c, X, _seven_zip(c), log="opensearch-ingest-7", tool="extract_archive")[1]  # fmt: skip
    for aid, tool in ((I1, "ingest_vol3_pslist"), (I2, "ingest_vol3_netscan")):
        c.op(
            "opensearch-ingest-7",
            aid,
            tool=tool,
            params={"run_id": "run-m", "image": s2},
            input_files=[s2],
            input_sha256s=[sha(s2)],
            input_detection_method="parsed",
        )


def _recorded(c, ingests):
    """For a quote in records d1, d2, ... from `ingests` in turn: the chain
    record_finding stores, and its steps in the order the Portal renders them."""
    _two_ingests_of_one_sample(c)
    docs = [
        _doc(f"d{i}", ing, **{"process.name": "evil.exe"})
        for i, ing in enumerate(ingests, 1)
    ]
    aid = _search(c, docs)
    res, st = c.find([{"content": "evil.exe", "audit_id": aid}])
    assert g(res, st)[0] == "FULL", g(res, st)
    node = shutil.which("node") or pytest.skip("node isn't installed")
    audit = [{"audit_id": aid, "tool": "idx_search"}]
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=120,
                       input=json.dumps({"page": str(PAGE), "findings": [st], "audit": audit}))  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    panel = chain_panel(json.loads(r.stdout), st["id"])
    shown = []
    for step in panel.split(STEP)[1:]:
        doc = re.search(r"record (d\d+) in ", step)
        aid = re.search(r'data-audit-id="([^"]*)"', step)
        shown.append(doc[1] if doc else NAMES.get(aid[1] if aid else "", "?"))
    return _short(st["artifacts"][0]["provenance_chain"]), shown


STEP = "border-left:2px solid var(--border)"
# the registered 7z (no audit id), the extraction's two links, the two ingests
NAMES = {"": "Z", X: "X", I1: "I1", I2: "I2"}
Z_X = ["Z", "X", "X"]


def _short(chain) -> list:
    return [
        x["document"]["_id"] if isinstance(x.get("document"), dict)
        else NAMES.get(x.get("audit_id"), "?")
        for x in chain
    ]  # fmt: skip


def test_records_from_two_ingests_each_keep_the_steps_they_share(c):
    stored, shown = _recorded(c, [I1, I2])
    assert stored == [*Z_X, "I1", "d1", *Z_X, "I2", "d2"]
    # each record renders under its own ingest, the shared steps in both
    assert shown == stored


def test_interleaved_records_each_render_under_their_own_ingest(c):
    stored, shown = _recorded(c, [I1, I2, I1])
    assert shown == [*Z_X, "I1", "d1", "d3", *Z_X, "I2", "d2"]
    assert stored == [*Z_X, "I1", "d1", *Z_X, "I2", "d2", *Z_X, "I1", "d3"]


def test_two_records_from_one_ingest_render_its_chain_once(c):
    _stored, shown = _recorded(c, [I1, I1])
    assert shown == [*Z_X, "I1", "d1", "d2"]


LINK_SHAPES = [
    {"document": d, **({} if t is None else {"to": t})}
    for d in ({"_id": "d1"}, {}, [], None, "d1", 0, 1)
    for t in (None, {}, {"path": ""}, {"path": "/x"}, {"path": []}, {"path": {}},
              {"path": 0}, {"path": float("nan")}, "/x", [], 1)
] + [{}, {"to": {"path": "/x"}}, "x", 1, []]  # fmt: skip


def test_a_record_link_is_the_one_the_portal_groups_records_by():
    """manager's record test answers as the page's isRecord for each shape (each
    shape is JSON text, NaN read as JS reads it)."""
    js = re.search(r"function isRecord\(step\) \{.*?\n    \}", PAGE.read_text(), re.S)
    node = shutil.which("node") or pytest.skip("node isn't installed")
    script = (
        js[0]
        + """
const shapes = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(shapes.map(s => !!isRecord(eval('(' + s + ')')))));"""
    )
    r = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60,
                       input=json.dumps([json.dumps(x) for x in LINK_SHAPES]))  # fmt: skip
    assert r.returncode == 0, r.stderr[-2000:]
    mine = [manager._is_record_link(x) for x in LINK_SHAPES]
    assert mine == json.loads(r.stdout) and sum(mine) == 24, mine


# --- content over 5000 chars ---------------------------------------------------


def _long_doc():
    fields = {
        f"winlog.event_data.Field{i:03d}": f"value-{i:03d}-" + "A" * 40
        for i in range(120)
    }
    return _doc(
        "d1", "opensearch-ingest-7-20261009-011", **{"event.code": "4624", **fields}
    )


def _quote(doc, limit=None):
    """The record's lines as an indented JSON reply shows them, up to `limit`
    chars on whole lines."""
    lines = [
        ln.strip().rstrip(",") for ln in json.dumps(doc, indent=1).splitlines()[1:-1]
    ]
    out = []
    for ln in lines:
        if limit is not None and len("\n".join(out + [ln])) > limit:
            break
        out.append(ln)
    return "\n".join(out)


def _searched(c):
    _ingested_samples(c)
    d = _long_doc()
    return d, _search(c, [d])


def test_a_quote_under_5000_is_stored_whole_with_no_warning(c):
    d, aid = _searched(c)
    q = _quote(d, 4900)
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert g(res, st)[0] == "FULL", g(res, st)
    assert st["artifacts"][0]["content"] == q
    assert "cut" not in res.get("warning", "")


def test_a_quote_of_exactly_5000_is_not_cut(c):
    d, aid = _searched(c)
    q = _quote(d)[:CAP].rstrip()
    q = q + "x" * (CAP - len(q))  # the last line is cut, so it doesn't verify
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert len(q) == CAP
    assert st["artifacts"][0]["content"] == q
    assert "cut" not in res.get("warning", "")


def test_a_genuine_quote_over_5000_grades_as_the_whole_quote(c):
    d, aid = _searched(c)
    q = _quote(d)
    assert len(q) > CAP
    # the base cut it mid-line, and the cut line isn't in the record
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert g(res, st)[0] == "FULL", g(res, st)
    t = pv.trace_artifact(pv.load_case(c.d), aid, q)
    assert t.grade == "FULL"


def test_a_cut_quote_is_stored_with_a_marker_and_the_reply_warns(c):
    d, aid = _searched(c)
    q = _quote(d)
    res, st = c.find([{"content": q, "audit_id": aid}])
    stored = st["artifacts"][0]["content"]
    marker = f"\n[cut: {CAP} of {len(q)} chars stored]"
    assert stored == q[:CAP] + marker
    assert res["warning"].split(" | ")[0] == (
        f"Artifact 1's content is {len(q)} chars: its first {CAP} are stored, "
        "marked as cut. The whole quote was checked against its source."
    )


def test_the_warning_names_each_cut_artifact_by_its_place(c):
    d, aid = _searched(c)
    q = _quote(d)
    short = _quote(d, 200)
    res, st = c.find(
        [
            {"content": short, "audit_id": aid},
            {"content": q, "audit_id": aid},
            {"content": q + "\n" + "\t", "audit_id": aid},
        ]
    )
    arts = st["artifacts"]
    assert arts[0]["content"] == short
    assert [
        a["content"].endswith(f"[cut: {CAP} of {len(q)} chars stored]")
        for a in arts[1:]
    ] == [True, True]
    w = res["warning"]
    assert "Artifact 1's" not in w
    assert w.count(f"Artifact 2's content is {len(q)} chars") == 1
    assert w.count(f"Artifact 3's content is {len(q)} chars") == 1  # stripped first


def test_a_cut_quote_that_doesnt_verify_is_still_cited_unverified(c):
    d, aid = _searched(c)
    q = _quote(d) + "\n" + '"winlog.event_data.Planted": "not in the record"'
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert g(res, st)[0] == "CITED-UNVERIFIED", g(res, st)
    # the line that fails is past the stored part, and the marker says so
    assert "Planted" not in st["artifacts"][0]["content"]
    assert st["artifacts"][0]["content"].endswith(
        f"[cut: {CAP} of {len(q)} chars stored]"
    )


def test_the_marker_follows_stored_text_ending_in_a_control_char(c):
    _d, aid = _searched(c)
    for end in ("\t", "\r", "\x1b", "\x00", "\x85"):
        q = "A" * (CAP - 1) + end + "B" * 10
        res, st = c.find([{"content": q, "audit_id": aid}])
        stored = st["artifacts"][0]["content"]
        assert (
            stored == "A" * (CAP - 1) + end + f"\n[cut: {CAP} of {len(q)} chars stored]"
        ), repr(end)


# --- the longest quote checked -------------------------------------------------

QUOTE_CAP = 64 << 10


def test_a_quote_at_the_check_limit_is_checked_and_stored_cut(c):
    _d, aid = _searched(c)
    q = ("A" * 63 + "\n") * (QUOTE_CAP // 64 - 1) + "A" * 64
    res, st = c.find([{"content": q, "audit_id": aid}])
    assert len(q) == QUOTE_CAP
    assert res["status"] == "STAGED", res
    assert st["artifacts"][0]["content"].endswith(
        f"[cut: {CAP} of {QUOTE_CAP} chars stored]"
    )
    assert res["warning"].startswith(f"Artifact 1's content is {QUOTE_CAP} chars:")


def test_a_quote_over_the_check_limit_is_refused_by_its_place(c):
    d, aid = _searched(c)
    q = "A" * (QUOTE_CAP + 1)
    res, st = c.find(
        [{"content": _quote(d, 200), "audit_id": aid}, {"content": q, "audit_id": aid}]
    )
    assert st is None
    assert res == {
        "status": "REJECTED",
        "error": (
            f"Artifact 2's content is {QUOTE_CAP + 1} chars. A quote is checked against "
            f"its source up to {QUOTE_CAP} chars. Quote the lines that show what the "
            "finding says, not the whole output."
        ),
    }
    assert (c.d / "findings.json").read_text() == "[]"


def test_whitespace_around_a_quote_doesnt_count_toward_the_limit(c):
    _d, aid = _searched(c)
    q = "\n" * 10 + "A" * QUOTE_CAP + " \t\n" * 10
    res, _st = c.find([{"content": q, "audit_id": aid}])
    assert res["status"] == "STAGED", res
