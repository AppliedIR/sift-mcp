"""What record_finding stores for an artifact: its chain without exact repeats,
and its content cut at 5000 chars with a marker when longer, the whole quote
checked either way, and a warning in the reply.

Uses test_finding_chains' own case, entries and helpers.
"""

import collections
import gzip
import json
from pathlib import Path

from forensic_mcp.case import manager
from sift_common import provenance as pv

from .test_finding_chains import (  # noqa: F401
    _doc,
    _extract,
    _ingested_samples,
    _search,
    _seven_zip,
    c,
    g,
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
