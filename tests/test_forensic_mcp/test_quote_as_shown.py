"""A query's quote is checked against the reply as the AI was shown it, and a
log_external_action step with no output against its own output_summary.

An MCP reply is shown as indent=2 JSON (pydantic_core.to_json, as FastMCP
renders a tool's dict). A line copied from it, such as `"user.name": "bob",`,
is a whole line of that rendering, not a substring of any value. It counts as
one, under four guards that keep a quote from grading FULL on records that
don't hold it: a brace names no record; records holding every quoted line are
preferred; a quote with a pair line no one record holds whole is unverified;
an opener line (`"user": {`) counts only with the line it opens.

The findings go through CaseManager.record_finding; the log_external_action
steps through case-mcp's own tool. Values are synthetic.
"""

import json

import pydantic_core
import pytest

from .test_finding_chains import (  # noqa: F401 - c is a fixture
    _doc,
    _ingest,
    _ingested_samples,
    _search,
    _triaged,
    c,
    g,
    sha,
)

ING_A = "opensearch-ingest-7-20261009-101"  # a registered file's ingest
ING_B = "opensearch-ingest-7-20261009-102"  # an unregistered file's ingest
IDX = "case-x-evtx-0"
FULL, DECL = ("FULL", None), ("DECLARED", None)
UNV = ("CITED-UNVERIFIED", "cited-unverified")
BROKEN = ("BROKEN", "no-recorded-origin")


def _shown(body) -> str:
    """The reply as the AI is shown it."""
    return pydantic_core.to_json(body, indent=2).decode()


def _rec(i, ingest, **fields):
    return {**_doc(i, ingest, **fields), "_index": IDX}


@pytest.fixture
def q(c):
    """One query entry per reply, each with its saved reply: `two` (d1 from a
    registered file, d2 not), `nested` (d3), `count`, `scored` (d1 + d4),
    `dashes` (d1 + d2b), `ips` (d5), `pair_in_value` (d6), `winlog` (d7) and
    `target` (d8 + d9); `.text[name]` is the reply as shown."""
    ev = c.file("evidence/Security.evtx", "registered evtx bytes")
    c.register(ev)
    _ingest(c, ING_A, ev)
    _ingest(c, ING_B, c.file("work/other.evtx", "unregistered evtx bytes"))
    a = {"vhir.content_hash": "c"}
    d1 = _rec("d1", ING_A, **{"@timestamp": "2026-01-01T00:00:00Z", "event.code": "4624",
              "user.name": "bob", "process.executable": "C:\\Windows\\Temp\\a.exe",
              "message": 'Logon "interactive" for bob', "event.category": ["authentication"],
              "logon.id": 7}, **a)  # fmt: skip
    d2 = _rec("d2", ING_B, **{"@timestamp": "2026-01-01T00:00:01Z", "event.code": "4625",
              "user.name": "alice"}, **a)  # fmt: skip
    d3 = {"_index": IDX, "_id": "d3", "@timestamp": "2026-01-01T00:00:02Z",
          "event": {"code": "4688"}, "user": {"name": "carol"},
          "vhir.ingest_audit_id": ING_A}  # fmt: skip
    d1x = _rec("d1", ING_A, **{"event.code": "4624", "user.name": "bob", "parent": None,
               "score": 1.0}, **a)  # fmt: skip
    d4 = _rec("d4", ING_A, **{"event.code": "4625", "user.name": "alice"}, **a)
    d2b = _rec("d2b", ING_B, **{"event.code": "4625", "user.name": "mallory",
               "message": "-----"}, **a)  # fmt: skip
    d5 = {"_index": IDX, "_id": "d5", "source": {"ip": "10.0.0.5"},
          "destination": {"ip": "8.8.8.8"}, "tags": ["user"], "groups": ["admin"],
          "vhir.ingest_audit_id": ING_A}  # fmt: skip
    d6 = _rec("d6", ING_A, message='x", "process.name": "svchost.exe', **a)
    d7 = {"_index": IDX, "_id": "d7", "event.code": "4624",
          "winlog.event_data": {"SubjectUserName": "admin", "TargetUserName": "bob"},
          "vhir.ingest_audit_id": ING_A}  # fmt: skip
    d8 = _rec("d8", ING_A, **{"event.code": "4624", "user.name": "bob",
              "target.user": "alice"}, **a)  # fmt: skip
    d9 = _rec("d9", ING_B, **{"event.code": "4625", "user.name": "alice"}, **a)
    out = type("Q", (), {"aid": {}, "text": {}})()
    n = iter(range(10, 99))

    def search(name, docs):
        aid = f"opensearch-tester-20261009-{next(n):03d}"
        body = {"results": docs, "total": len(docs), "audit_id": aid}
        out.aid[name] = _search(c, docs, aid=aid, text=json.dumps(body))
        out.text[name] = _shown(body)

    for name, docs in (("two", [d1, d2]), ("nested", [d3]), ("scored", [d1x, d4]), ("dashes", [d1x, d2b]),
                       ("ips", [d5]), ("pair_in_value", [d6]), ("winlog", [d7]), ("target", [d8, d9])):  # fmt: skip
        search(name, docs)
    for name, count in (("count", 1234), ("count999", 999)):
        aid = f"opensearch-tester-20261009-{next(n):03d}"
        body = {"count": count, "query": "*", "audit_id": aid}
        resp = c.file(f"extractions/{aid}/response.json", json.dumps(body))
        c.op("opensearch-mcp", aid, tool="idx_count",
             params={"query": "*", "result_ingests": [ING_A]}, result_summary=f"{count}",
             response={"path": resp, "sha256": sha(resp)})  # fmt: skip
        out.aid[name], out.text[name] = aid, _shown(body)
    out.c = c
    return out


def _grade(q, name, content):
    """(grade, break kind, the record ids followed)."""
    res, st = q.c.find([{"content": content, "audit_id": q.aid[name]}])
    grade = g(res, st)[:2]
    if st is None:
        return grade
    chain = st["artifacts"][0].get("provenance_chain") or []
    ids = sorted(
        {lk["document"]["_id"] for lk in chain if isinstance(lk.get("document"), dict)}
    )
    return (*grade, ids)


def _line(q, name, start):
    return next(x for x in q.text[name].splitlines() if x.strip().startswith(start))


# --- a reply's lines as shown: criteria --------------------------------------------


def test_lines_copied_from_the_reply_as_shown(q):
    d1_block = (
        q.text["two"].split('"results": [\n', 1)[1].split("\n    },", 1)[0] + "\n    },"
    )
    rows = {
        "a pair line, with its comma": ("two", _line(q, "two", '"user.name": "bob"'), FULL + (["d1"],)),
        "a pair line": ("two", '"user.name": "bob"', FULL + (["d1"],)),
        "two pair lines of one record": ("two", _line(q, "two", '"event.code": "4624"') + "\n"
               + _line(q, "two", '"user.name": "bob"'), FULL + (["d1"],)),
        "a whole record as shown": ("two", d1_block, FULL + (["d1"],)),
        "a number pair": ("two", '"logon.id": 7', FULL + (["d1"],)),
        "a pair of a record with no origin": ("two", '"user.name": "alice"', BROKEN + (["d2"],)),
        "a nested opener and its line": ("nested", '"user": {\n"name": "carol"', FULL + (["d3"],)),
        "the total of one record": ("nested", '"total": 1,', FULL + (["d3"],)),
        "the total over a record with no origin": ("two", '"total": 2', BROKEN + (["d1", "d2"],)),
        "a whole count reply": ("count", q.text["count"], FULL + ([],)),
        "a count pair": ("count", '"count": 1234', FULL + ([],)),
        "a line every record shows, and the next": ("two", f'"_index": "{IDX}",\n"@timestamp": "2026-01-01T00:00:00Z"', FULL + (["d1"],)),
        "a pair line with escapes, as shown": ("two", _line(q, "two", '"process.executable"'), FULL + (["d1"],)),
        "null as shown": ("scored", '"parent": null', FULL + (["d1"],)),
        "a float as shown": ("scored", '"score": 1.0', FULL + (["d1"],)),
        "a pair one record holds under that key": ("target", '"user.name": "alice"', BROKEN + (["d9"],)),
    }  # fmt: skip
    got = {k: _grade(q, name, content) for k, (name, content, _want) in rows.items()}
    assert got == {k: want for k, (_n, _c, want) in rows.items()}


# --- near-misses: never upgraded --------------------------------------------------


@pytest.mark.parametrize(
    "name,content",
    [
        ("two", '"user.name": "carol"'),  # another query's value
        ("two", '"user.name": "bo"'),  # value cut
        ("two", '"user.name": "bobby"'),  # value longer
        ("count", '"count": 999'),  # another query's count
        ("two", '"total": 1'),  # another query's total
        ("two", '"user.name": bob'),  # unquoted string
        ("two", '"event.code": 4624'),  # number for a string
        ("two", "user.name: bob"),  # unquoted key
        ("two", '"USER.NAME": "BOB"'),  # case-folded
        ("two", "Logon interactive for bob"),  # quotes stripped
        ("two", "C:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\a.exe"),  # escaped twice
        ("two", '"user.name": "bob",,'),  # two commas
        ("two", '"bob",'),  # a value as a line
        ("two", '"logon.id": "7"'),  # string for a number
        ("two", '"user.name": "bob"\n====='),  # a separator not shown
        ("two", '"user.name": "bob"\n{{'),  # a brace line not shown
        (
            "scored",
            '"user.name": "bob",\n"event.code": "4625",',
        ),  # pairs of two records
        ("ips", '"destination": {\n"ip": "10.0.0.5"'),  # an opener and another's line
        (
            "winlog",
            '"winlog.event_data": {\n"SubjectUserName": "bob"',
        ),  # the opener of another field's line
        ("ips", '"tags": [\n"admin"'),  # a list opener and another list's item
        (
            "pair_in_value",
            '"message": "x", "process.name": "svchost.exe"',
        ),  # pairs out of one value
        ("target", '"user.name": "alice"\n"event.code": "4624"'),  # two records' pairs
    ],
)
def test_a_near_miss_stays_unverified(q, name, content):
    assert _grade(q, name, content)[:2] == UNV


def test_the_reason_says_the_lines_dont_appear_together(q):
    why = "lines don't appear together in one returned record"
    for name, content in (
        ("scored", '"user.name": "bob",\n"event.code": "4625",'),
        ("ips", '"destination": {\n"ip": "10.0.0.5"'),
        (
            "two",
            f'"_index": "{IDX}",\n"user.name": "bob"',
        ),  # one record's, not together
    ):
        res, st = q.c.find([{"content": content, "audit_id": q.aid[name]}])
        assert why in st["artifacts"][0]["provenance_reason"], (
            content,
            st["artifacts"][0],
        )


# --- controls: as before ----------------------------------------------------------


def test_bare_values_grade_as_before(q):
    rows = {
        "count": ("two", "bob", FULL + (["d1"],)),
        "count999": ("two", "4624\nbob", FULL + (["d1"],)),
        "a value of a record with no origin": ("two", "alice", BROKEN + (["d2"],)),
        "a value as returned": ("two", 'Logon "interactive" for bob', FULL + (["d1"],)),
        "a count value": ("count", "1234", FULL + ([],)),
        "a value not returned": ("two", "mimikatz", UNV + ([],)),
        "a nested value": ("nested", "carol", FULL + (["d3"],)),
        "values of two records": ("two", "bob\n4625", BROKEN + (["d1", "d2"],)),
        "values of two records, both traced": (
            "scored",
            "bob\n4625",
            FULL + (["d1", "d4"],),
        ),
        "a value and a separator line": (
            "dashes",
            "bob\n-----",
            BROKEN + (["d1", "d2b"],),
        ),
    }
    got = {k: _grade(q, name, content) for k, (name, content, _want) in rows.items()}
    assert got == {k: want for k, (_n, _c, want) in rows.items()}


def test_a_value_every_record_shares_follows_the_record_holding_the_rest(q):
    """The one change to bare values: with a line only d1 holds, a line every
    record shares no longer follows d2 too."""
    assert _grade(q, "two", f"{IDX}\nbob") == FULL + (["d1"],)


# --- log_external_action with no output: its own output_summary -------------------


@pytest.fixture
def lea(c):
    from case_mcp.server import create_server

    tool = create_server()._tool_manager._tools["log_external_action"].fn
    ev = c.file("evidence/mem.raw", "MZ....hxxp://evil.example/beacon.php....")
    c.register(ev)
    summary = (
        "hxxp://evil.example/beacon.php\nhxxp://evil.example/gate.php\n2 URLs found"
    )
    ids = {
        "a1": tool(command=f"strings -el {ev} | grep -i hxxp", output_summary=summary,
                   purpose="find beacon URL", input_files=[ev]),
        "a2": tool(command="remnux analyze_file sample.exe (capa)",
                   output_summary="capa: communicate using HTTP (T1071.001)",
                   purpose="REMnux analysis", input_files=[ev]),
        "a3": tool(command="strings sample.exe", output_summary="hxxp://other.example/x",
                   purpose="p"),
        "a5": tool(command="yara rules.yar mem.raw", output_summary="rule Cobalt_Beacon matched",
                   purpose="yara sweep", input_files=[ev]),
    }  # fmt: skip
    saved = c.file("extractions/bash/beacon.txt", "hxxp://evil.example/beacon.php\n")
    ids["a4"] = tool(command=f"strings -el {ev} > {saved}",
                     output_summary="hxxp://evil.example/beacon.php and 41 more lines",
                     purpose="p", input_files=[ev], output_files=[saved])  # fmt: skip
    ids = {k: v["audit_id"] for k, v in ids.items()}
    assert all(ids.values()), ids
    run = "sift-tester-20261009-201"  # a run whose params also carry an output_summary
    out = c.file(f"extractions/{run}.txt", "hxxp://evil.example/beacon.php\n")
    c.op("sift-mcp", run, tool="run_command",
         params={"command": ["strings", "-el", ev], "purpose": "p",
                 "output_summary": "hxxp://forged.example/"},
         result_summary={"exit_code": 0, "output_file": out, "output_sha256": sha(out)},
         input_files=[ev], input_sha256s=[sha(ev)], input_detection_method="parsed")  # fmt: skip
    ids["run"] = run
    return ids, summary


def _lea_grade(c, aid, content):
    res, st = c.find([{"content": content, "audit_id": aid}])
    a = st["artifacts"][0] if st else {}
    return (*g(res, st)[:2], a.get("provenance_reason", ""))


def test_a_lea_step_with_no_output_is_checked_against_its_summary(c, lea):
    ids, summary = lea
    a1 = ids["a1"]
    for content in ("hxxp://evil.example/beacon.php", summary, "evil.example/gate"):
        grade, kind, reason = _lea_grade(c, a1, content)
        assert (grade, kind) == DECL and reason == (
            f"declared by the AI: {a1} (log_external_action)"
        ), (content, grade, reason)
    assert _lea_grade(c, ids["a2"], "communicate using HTTP (T1071.001)")[:2] == DECL
    assert _lea_grade(c, ids["a3"], "hxxp://other.example/x")[:2] == (
        "BROKEN",
        "no-inputs",
    )


@pytest.mark.parametrize(
    "who,content",
    [
        ("a1", "hxxp://evil.example/c2.php"),  # not in the summary
        ("a1", "find beacon URL"),  # the purpose
        ("a1", "grep -i hxxp"),  # the command
        ("a1", "rule Cobalt_Beacon matched"),  # another step's summary
        ("a4", "and 41 more lines"),  # a saved output exists
        ("run", "hxxp://forged.example/"),  # output_summary on a run entry
        (
            "a1",
            "hxxp://evil.example/beacon.php\nhxxp://evil.example/c2.php",
        ),  # one in, one not
    ],
)
def test_a_line_not_in_the_summary_stays_unverified(c, lea, who, content):
    assert _lea_grade(c, lea[0][who], content)[:2] == UNV


def test_the_reason_names_the_line_missing_from_both(c, lea):
    reason = _lea_grade(
        c, lea[0]["a1"], "hxxp://evil.example/beacon.php\nhxxp://evil.example/c2.php"
    )[2]
    assert reason.startswith("'hxxp://evil.example/c2.php' isn't in"), reason


def test_steps_with_an_output_grade_as_before(c, lea):
    assert _lea_grade(c, lea[0]["a4"], "hxxp://evil.example/beacon.php")[:2] == DECL
    assert _lea_grade(c, lea[0]["run"], "hxxp://evil.example/beacon.php")[:2] == FULL


# --- a reply's own line never stands in for the checks on the rest ----------------


def test_a_summary_line_doesnt_skip_an_enrichment_check(c):
    """The record's triage data names a step that isn't recorded: BROKEN,
    with or without the reply's own `"total": 1` quoted beside it."""
    _ingested_samples(c)
    docs, groups = _triaged("opensearch-tester-20261009-151")  # never logged
    aid = "opensearch-tester-20261009-150"
    body = {"results": docs, "total": len(docs), "audit_id": aid}
    _search(c, docs, aid=aid, groups=groups, text=json.dumps(body))
    for quote in ("SUSPICIOUS", '"total": 1,\nSUSPICIOUS'):
        res, st = c.find([{"content": quote, "audit_id": aid}])
        assert g(res, st)[:2] == ("BROKEN", "reference-not-recorded"), (
            quote,
            g(res, st),
        )


def test_a_total_over_records_not_returned_is_never_full(q):
    """The reply counts 1000 records and returned one: its total speaks for
    999 records nothing traces, so the quote is at best AMBIGUOUS."""
    c = q.c
    aid = "opensearch-tester-20261009-160"
    docs = [_rec("d1", ING_A, **{"user.name": "bob", "vhir.content_hash": "c"})]
    _search(
        c,
        docs,
        aid=aid,
        text=json.dumps({"results": docs, "total": 1000, "audit_id": aid}),
    )
    res, st = c.find([{"content": '"total": 1000', "audit_id": aid}])
    a = st["artifacts"][0]
    assert a["provenance_grade"] == "AMBIGUOUS", a
    assert "counted 1000 records and returned 1:" in a["provenance_reason"], a


def test_every_line_under_an_opener_is_read_in_that_object(q):
    """`"port": 1` is source's, not destination's: spliced under
    destination's opener it is no line the reply showed."""
    c = q.c
    aid = "opensearch-tester-20261009-170"
    d = {"_index": IDX, "_id": "d5p", "source": {"ip": "10.0.0.5", "port": 1},
         "destination": {"ip": "8.8.8.8", "port": 53}, "vhir.ingest_audit_id": ING_A}  # fmt: skip
    _search(
        c, [d], aid=aid, text=json.dumps({"results": [d], "total": 1, "audit_id": aid})
    )
    ok = '"destination": {\n"ip": "8.8.8.8",\n"port": 53'
    spliced = '"destination": {\n"ip": "8.8.8.8",\n"port": 1'
    assert _grade_aid(c, aid, ok)[:2] == FULL
    assert _grade_aid(c, aid, spliced)[:2] == UNV


def test_an_opener_with_no_line_after_it_is_refused(q):
    """`"user": {` last in the quote opens nothing that was quoted: carol's
    line before it doesn't make it hers."""
    assert _grade(q, "nested", '"name": "carol",\n"user": {')[:2] == UNV


def test_a_value_ending_in_a_brace_is_no_opener(q):
    """A bare value that ends in `{` quoted before another line grades as
    before: only a `"field": {` line opens an object."""
    c = q.c
    aid = "opensearch-tester-20261009-180"
    d = _rec("d1", ING_A, **{"process.executable": "powershell -c {", "user.name": "bob",
             "vhir.content_hash": "c"})  # fmt: skip
    _search(
        c, [d], aid=aid, text=json.dumps({"results": [d], "total": 1, "audit_id": aid})
    )
    assert _grade_aid(c, aid, "powershell -c {\nbob") == FULL + (["d1"],)


def _grade_aid(c, aid, content):
    res, st = c.find([{"content": content, "audit_id": aid}])
    chain = (st["artifacts"][0].get("provenance_chain") or []) if st else []
    ids = sorted(
        {lk["document"]["_id"] for lk in chain if isinstance(lk.get("document"), dict)}
    )
    return (*g(res, st)[:2], ids)


def test_an_escaped_quote_in_a_key_splices_nothing(q):
    """A key holding a quote is shown escaped; a sibling's line after it is
    still no line the reply showed there."""
    c = q.c
    aid = "opensearch-tester-20261009-190"
    d = {"_index": IDX, "_id": "d5e", 'dst"x': {"ip": "8.8.8.8", "port": 53},
         "src": {"port": 1}, "vhir.ingest_audit_id": ING_A}  # fmt: skip
    _search(
        c, [d], aid=aid, text=json.dumps({"results": [d], "total": 1, "audit_id": aid})
    )
    assert _grade_aid(c, aid, '"dst\\"x": {\n"ip": "8.8.8.8",\n"port": 53')[:2] == FULL
    assert _grade_aid(c, aid, '"dst\\"x": {\n"ip": "8.8.8.8",\n"port": 1')[:2] == UNV


def test_lines_shown_together_follow_the_record_that_shows_them(q):
    """carol's `"user": {` block is d3's; d10 (no recorded origin) shows both
    lines too, but not together, and isn't followed."""
    c = q.c
    aid = "opensearch-tester-20261009-191"
    d3 = {
        "_index": IDX,
        "_id": "d3",
        "user": {"name": "carol"},
        "vhir.ingest_audit_id": ING_A,
    }
    d10 = {"_index": IDX, "_id": "d10", "user": {"id": 1}, "name": "carol",
           "vhir.ingest_audit_id": ING_B}  # fmt: skip
    body = {"results": [d3, d10], "total": 2, "audit_id": aid}
    _search(c, [d3, d10], aid=aid, text=json.dumps(body))
    assert _grade_aid(c, aid, '"user": {\n"name": "carol"') == FULL + (["d3"],)


def test_a_long_quote_is_checked_quickly(q):
    """One object of 300 fields quoted as shown, from its opener to its close,
    in a reply of 30 such records."""
    import time

    from sift_common import provenance as pv

    c = q.c
    aid = "opensearch-tester-20261009-192"
    docs = [{"_index": IDX, "_id": f"big{i}", "vhir.ingest_audit_id": ING_A,
             "data": {f"field_{n:03d}": f"value {i}.{n}" for n in range(300)}}
            for i in range(30)]  # fmt: skip
    _search(
        c,
        docs,
        aid=aid,
        text=json.dumps({"results": docs, "total": 30, "audit_id": aid}),
    )
    lines = _shown(docs[7]).splitlines()
    quote = "\n".join(lines[lines.index('  "data": {') : -1])
    assert len(quote) >= 5000, len(quote)
    case = pv.load_case(c.d)
    start = time.perf_counter()
    t = pv.trace_artifact(case, aid, quote)
    assert time.perf_counter() - start < 0.1 and t.grade == "FULL", t


def test_an_opener_needs_its_quoted_child(q):
    """carol's `"name"` line, then `"user": {` (bob's object): the opener is
    a line the record shows, but on its own it claims a structure it doesn't
    quote."""
    c = q.c
    aid = "opensearch-tester-20261009-193"
    o1 = {"_index": IDX, "_id": "o1", "name": "carol", "user": {"name": "bob"},
          "vhir.ingest_audit_id": ING_A}  # fmt: skip
    _search(
        c,
        [o1],
        aid=aid,
        text=json.dumps({"results": [o1], "total": 1, "audit_id": aid}),
    )
    assert _grade_aid(c, aid, '"user": {')[:2] == UNV
    assert _grade_aid(c, aid, '"name": "carol",\n"user": {')[:2] == UNV
    assert _grade_aid(c, aid, '"user": {\n"name": "bob"') == FULL + (["o1"],)
