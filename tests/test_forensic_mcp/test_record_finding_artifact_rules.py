"""record_finding stores each artifact as it was sent, or refuses the whole call
and leaves every case document as it was. Each call goes as an MCP client
sends it: through the gateway's per-backend route to forensic-mcp running as
a stdio backend. (The launcher only points the case lock at a folder of the
test's own, as conftest does in-process.)

- At most 10 artifacts, sent as the artifacts parameter or as a list in
  finding["artifacts"], never both.
- Each needs source, extraction and content (raw_data stands in for content),
  quotable text and an audit_id in the trail. Content and extraction are kept
  whole up to 65,536 chars. A refusal names the artifact, counted from 1.
- A finding that would take findings.json past the 16 MiB the readers open is
  refused.
- The reply grades each artifact that isn't FULL, and its message names the
  one that set the finding's grade.
- A check whose result is kept stores the caller's reason, up to 2,000 chars.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

import mcp.types as types
import pytest
from sift_common import file_identity
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server
from sift_gateway.server import Gateway

LIMIT = 65536
RUN_ID = "sift-rig-20261027-001"  # cat of a registered file
DECLARED_ID = "sift-rig-20261027-002"  # the same cat, declared by the AI
SKEPTIC_ID = "sift-rig-20261027-003"  # the skeptic's own grep
NO_INPUTS_ID = "sift-rig-20261027-004"  # a cat that recorded no inputs
REF_ID = "sift-gateway-rig-20261027-001"  # a baseline lookup
LINES = [f"rd09 line {i:02d}: event {i} on RD09" for i in range(1, 13)]
LAUNCH = (
    "import runpy, sys\n"
    "from pathlib import Path\n"
    "from forensic_mcp.case import manager\n"
    "manager.LEDGER_DIR = Path(sys.argv.pop(1))\n"
    "runpy.run_module('forensic_mcp', run_name='__main__', alter_sys=True)\n"
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="stdio rig is POSIX")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
async def rig(tmp_path):
    """The case, and record(finding fields, artifacts, carrier) -> reply."""
    home, ledger, d = tmp_path / "home", tmp_path / "ledger", tmp_path / "rig-case"
    (home / ".vhir").mkdir(parents=True)
    ledger.mkdir()
    for sub in ("audit", "evidence", "extractions"):
        (d / sub).mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: rig-case\nstatus: open\nexaminer: rig\n")
    (d / "findings.json").write_text("[]")
    (d / "timeline.json").write_text("[]")
    x = d / "evidence" / "rd09.txt"
    x.write_text("".join(f"{line}\n" for line in LINES))
    real, xs = os.path.realpath(x), _sha(x.read_bytes())
    out = d / "extractions" / "rd09.out"
    out.write_bytes(x.read_bytes())

    def run(aid, command, **extra):
        return {"audit_id": aid, "ts": "2026-10-27T00:00:00+00:00", "tool": "run_command",
                "mcp": "sift-mcp", "params": {"command": [*command, real]},
                "input_files": [real], "input_sha256s": [xs],
                "result_summary": {"output_file": str(out),
                                   "output_sha256": _sha(out.read_bytes())}, **extra}  # fmt: skip

    entries = [run(RUN_ID, ["cat"]), run(DECLARED_ID, ["cat"], declared=True),
               run(SKEPTIC_ID, ["grep", "RD09"])]  # fmt: skip
    entries.append(
        {**entries[0], "audit_id": NO_INPUTS_ID, "params": {"command": ["cat"]}}
    )
    del entries[-1]["input_files"], entries[-1]["input_sha256s"]
    (d / "audit" / "sift-mcp.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in entries)
    )
    ref = {"audit_id": REF_ID, "ts": "2026-10-27T00:00:01+00:00", "tool": "check_file",
           "mcp": "sift-gateway", "reference": {"source": "windows-triage-mcp",
                                                "source_version": "1.0"}}  # fmt: skip
    (d / "audit" / "sift-gateway.jsonl").write_text(json.dumps(ref) + "\n")
    (d / "evidence.json").write_text(
        json.dumps(
            {"files": [{"path": real, "sha256": xs, "registered_by": "examiner"}]}
        )
    )
    (home / ".vhir" / "active_case").write_text(f"{d}\n")

    env = {"HOME": str(home), "PATH": os.environ.get("PATH", ""),
           "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}  # fmt: skip
    backend = StdioMCPBackend("forensic-mcp", {
        "type": "stdio", "command": sys.executable,
        "args": ["-c", LAUNCH, str(ledger), "--deferred-tools"], "env": env})  # fmt: skip
    await backend.start()
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {"forensic-mcp": backend}
    gw._tool_map = {"record_finding": "forensic-mcp"}
    handler = create_backend_mcp_server(gw, "forensic-mcp").request_handlers[
        types.CallToolRequest
    ]

    async def record(title, arts=None, carrier="parameter", **fields):
        finding = {
            "title": title, "observation": "RD09 records list events 1 to 12.",
            "interpretation": "a rig record", "confidence": "LOW",
            "confidence_justification": "rig data", "type": "finding",
            "event_timestamp": "2026-01-01T00:00:00Z", "audit_ids": [],
            "challenged": {"outcome": "not_challenged", "reason": "no skeptic in this test"},
            **fields,
        }  # fmt: skip
        args = {"finding": finding}
        if carrier == "finding":
            finding["artifacts"] = arts
        elif arts is not None:
            args["artifacts"] = arts
        request = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="record_finding", arguments=args),
        )
        result = (await asyncio.wait_for(handler(request), 60)).root
        return json.loads(result.content[0].text)

    record.backend = backend
    try:
        yield d, record
    finally:
        await backend.stop()


def art(line=LINES[0], audit_id=RUN_ID, **extra) -> dict:
    return {"source": "evidence/rd09.txt", "extraction": "cat evidence/rd09.txt",
            "content": line, "content_type": "log_entry", "audit_id": audit_id, **extra}  # fmt: skip


def _documents(d: Path) -> dict:
    """Every case document but the audit trail, as bytes."""
    return {p.name: p.read_bytes() for p in d.iterdir() if p.is_file()}


def _stored(d: Path, title: str) -> list[dict]:
    return [
        f for f in json.loads((d / "findings.json").read_text()) if f["title"] == title
    ]


async def _refused(rig, title, sent, *, carrier="parameter", **fields) -> str:
    d, record = rig
    before = _documents(d)
    res = await record(title, sent, carrier, **fields)
    assert res["status"] == "REJECTED", res
    assert _documents(d) == before  # no case document changed
    return res["error"]


@pytest.mark.parametrize("carrier", ["parameter", "finding"])
async def test_more_than_ten_artifacts_refuse_the_call_before_any_is_read(rig, carrier):
    d, record = rig
    first = {k: v for k, v in art().items() if k != "extraction"}  # never read
    error = await _refused(rig, "eleven", [first] + [art()] * 10, carrier=carrier)
    assert error.startswith("11 artifacts were sent; a finding takes at most 10."), (
        error
    )
    res = await record("ten", [art(x) for x in LINES[:10]], carrier)
    assert res["status"] == "STAGED" and "warning" not in res, res
    (f,) = _stored(d, "ten")
    assert [a["content"] for a in f["artifacts"]] == LINES[:10]


@pytest.mark.parametrize("n", [1, 3, 5])
@pytest.mark.parametrize("carrier", ["parameter", "finding"])
async def test_a_refusal_names_the_artifact_wherever_it_is_sent(rig, carrier, n):
    arts = [art(x) for x in LINES[:5]]
    del arts[n - 1]["extraction"]
    error = await _refused(rig, f"no extraction at {n}", arts, carrier=carrier)
    assert error == (
        f"Artifact {n}: extraction is missing, empty or not a string. Send the "
        "command or query that produced the content. The finding wasn't recorded."
    )


@pytest.mark.parametrize(
    ("change", "says"),
    [
        ({"source": ""}, "Artifact 2: source is missing, empty or not a string. Send the "
                         "evidence file or tool the content came from."),
        ({"source": 123}, "Artifact 2: source is missing, empty or not a string."),
        ({"extraction": None}, "Artifact 2: extraction is missing, empty or not a string."),
        ({"content": {}}, "Artifact 2: content is missing, empty or not a string. Send "
                          "the output lines the cited operation produced, as returned."),
        ({"content": " \n "}, "Artifact 2: content is missing, empty or not a string."),
        ({"content": "... -- ..."}, "Artifact 2: content has no quotable text. Send the "
                                    "output lines the cited operation produced"),
        ({"audit_id": ""}, "Artifact 2: audit_id is missing. Send the audit_id from the "
                           "tool response, or record a Bash command with "
                           "log_external_action first"),
        ({"audit_id": "sift-rig-20261027-099"}, "Artifact 2: audit_id "
         "'sift-rig-20261027-099' isn't in the audit trail. Send the audit_id from the "
         "tool response."),
    ],
)  # fmt: skip
async def test_an_incomplete_artifact_refuses_the_call_naming_its_field(
    rig, change, says
):
    arts = [art(LINES[0]), art(LINES[1], **change), art(LINES[2])]
    error = await _refused(rig, "incomplete", arts)
    assert error.startswith(says) and error.endswith("The finding wasn't recorded."), (
        error
    )


async def test_a_non_object_artifact_refuses_the_call_and_raw_data_stands_in_for_content(
    rig,
):
    d, record = rig
    sent = [art(), "a string", art()]  # the parameter's schema refuses it first
    error = await _refused(rig, "non-object", sent, carrier="finding")
    assert error.startswith("Artifact 2: not an object. Send {source, extraction, "), (
        error
    )
    raw = {k: v for k, v in art(LINES[3]).items() if k != "content"}
    res = await record("raw_data", [{**raw, "raw_data": LINES[3]}])
    assert res["status"] == "STAGED", res
    assert _stored(d, "raw_data")[0]["artifacts"][0]["content"] == LINES[3]


@pytest.mark.parametrize("sent", ["both", {"source": "x"}, "[]"])
async def test_artifacts_come_as_one_list_by_one_carrier(rig, sent):
    d, record = rig
    before = _documents(d)
    finding = [art(LINES[1])] if sent == "both" else sent
    res = await record("one carrier", [art()] if sent == "both" else None,
                       artifacts=finding, audit_ids=[RUN_ID])  # fmt: skip
    assert res["status"] == "REJECTED" and _documents(d) == before, res
    assert res["error"].startswith("artifacts were sent "), res
    assert "Send one list, as the artifacts parameter." in res["error"], res


WITHDRAWN = {"outcome": "withdrawn", "contradiction": LINES[0],
             "checks": [{"name": "re-ran grep", "result": "contradicts",
                         "audit_ids": [SKEPTIC_ID], "reason": "the re-run disagrees"}]}  # fmt: skip


@pytest.mark.parametrize(
    ("arts", "carrier", "inline"),
    [([art()] * 11, "parameter", None), ([art()] * 11, "finding", None),
     ([art()], "parameter", [art()]), ("x", "finding", None)],
    ids=["eleven as the parameter", "eleven in the finding", "both carriers", "not a list"],
)  # fmt: skip
async def test_a_withdrawal_is_refused_by_the_same_artifact_rules(
    rig, arts, carrier, inline
):
    d, record = rig
    fields = {"challenged": WITHDRAWN} | ({"artifacts": inline} if inline else {})
    error = await _refused(rig, "withdrawn", arts, carrier=carrier, **fields)
    assert error.startswith(("11 artifacts were sent", "artifacts were sent ")), error
    trail = "".join(p.read_text() for p in (d / "audit").iterdir())
    assert "WITHDRAWN" not in trail
    res = await record("withdrawn", [art()], challenged=WITHDRAWN)
    assert res["status"] == "WITHDRAWN" and res["audit_ids"] == [RUN_ID], res


@pytest.mark.parametrize("carrier", ["parameter", "finding"])
async def test_content_and_extraction_up_to_the_limit_are_stored_whole(rig, carrier):
    d, record = rig
    content = ("x" * 63 + "\n") * (LIMIT // 64)
    content = content[:-1] + "é"  # non-ASCII counts as one char
    extraction = "cat evidence/rd09.txt " + "#" * (LIMIT - 22)
    assert len(content) == len(extraction) == LIMIT
    sent = art(" \n\t" + content + "\n\n", extraction=extraction)
    res = await record("at the limit", [sent], carrier)
    assert res["status"] == "STAGED" and "warning" not in res, res
    (stored,) = _stored(d, "at the limit")[0]["artifacts"]
    assert stored["content"] == content and stored["extraction"] == extraction


@pytest.mark.parametrize("field", ["content", "extraction"])
async def test_content_or_extraction_past_the_limit_refuses_the_call(rig, field):
    error = await _refused(
        rig, "past the limit", [art(), art(**{field: "y" * (LIMIT + 1)})]
    )
    assert error.startswith(
        f"Artifact 2: {field} is 65,537 chars, over the 65,536 limit. Send at most 65,536 "
        "chars: "
    ), error


def test_findings_json_has_the_size_limit_vhir_reads_it_with():
    from vhir_cli import case_io

    assert file_identity.DOC_CAP == case_io.DOC_CAP


async def test_a_finding_that_would_take_findings_json_past_16_mib_is_refused(rig):
    d, record = rig
    assert (await record("first", [art()]))["status"] == "STAGED"
    path = d / "findings.json"
    data = json.loads(path.read_text())
    data.append(dict(data[0], id="F-rig-900", title="padding", observation=""))
    size = len(json.dumps(data, indent=2, default=str))
    data[-1]["observation"] = "p" * (file_identity.DOC_CAP - 4096 - size)
    os.chmod(path, 0o644)  # the server writes it read-only
    path.write_text(json.dumps(data, indent=2, default=str))
    os.chmod(path, 0o444)
    error = await _refused(rig, "one more", [art("y" * 5000)], iocs=["10.1.2.3"])
    assert "past the 16 MiB the Portal and vhir read" in error, error
    assert path.stat().st_size <= file_identity.DOC_CAP
    res = await record("a short one", [art()])
    assert res["status"] == "STAGED", res  # what still fits is recorded


async def test_the_reply_names_the_artifact_that_set_the_findings_grade(rig):
    d, record = rig
    unverified = art("rd09 line 99: not in the output")
    ref = art('"path": "rigtool.exe"', REF_ID)  # graded BROKEN, not counted
    # (title, artifacts, finding's grade, the artifact named, what its reason says)
    for title, arts, grade, named, says in (
        ("full first", [art(), unverified], "CITED-UNVERIFIED", 2, ""),
        ("reference first", [ref, unverified], "CITED-UNVERIFIED", 2, ""),
        ("declared first", [art(audit_id=DECLARED_ID), unverified], "CITED-UNVERIFIED", 2, ""),
        ("reference first, the rest full", [ref, art()], "FULL", 2, ""),
        ("reference first, the rest broken", [ref, art(audit_id=NO_INPUTS_ID)], "BROKEN", 2,
         "recorded no inputs"),
        ("every artifact reference data", [ref, art('"path": "other.exe"', REF_ID)], "BROKEN",
         1, "reference data"),
    ):  # fmt: skip
        res = await record(title, arts)
        (stored,) = _stored(d, title)
        grades = [{"artifact": n, "grade": a["provenance_grade"],
                   "reason": a["provenance_reason"]}
                  for n, a in enumerate(stored["artifacts"], 1)]  # fmt: skip
        # the reply says what findings.json holds
        assert res["provenance_grade"] == stored["provenance_grade"] == grade, res
        assert res["artifact_grades"] == [g for g in grades if g["grade"] != "FULL"], (
            res
        )
        reason = grades[named - 1]["reason"]
        assert says in reason, grades
        assert res["message"] == f"Finding staged as {grade}: Artifact {named}" + (
            f": {reason}" if reason else "."
        ), res
    res = await record("all full", [art(), art(LINES[1])])
    assert "artifact_grades" not in res and "message" not in res, res
    res = await record("no artifacts", audit_ids=[RUN_ID])
    assert res["message"] == "Finding staged as DECLARED.", res


def _challenge(result, reason) -> dict:
    ids = [] if result == "not run" else [SKEPTIC_ID]
    return {"outcome": "stands", "skeptic": {"client": "rig", "model": "rig"},
            "checks": [{"name": f"re-ran it ({result})", "result": result,
                        "audit_ids": ids, "reason": reason}]}  # fmt: skip


@pytest.mark.parametrize(
    "result", ["consistent", "nothing found", "contradicts", "not run"]
)
async def test_a_checks_reason_is_stored_up_to_2000_chars_and_refused_past_it(
    rig, result
):
    d, record = rig
    res = await record(result, [art()], challenged=_challenge(result, "r" * 2000))
    assert res["status"] == "STAGED", res
    (check,) = _stored(d, result)[0]["challenged"]["checks"]
    assert (check["result"], check["reason"]) == (result, "r" * 2000)
    for reason, got in (("r" * 2001, "2,001 chars"), (123, "not a string")):
        error = await _refused(
            rig, "refused", [art()], challenged=_challenge(result, reason)
        )
        assert error.startswith(
            f"Check 're-ran it ({result})': its reason is {got}."
        ), error


async def test_a_replaced_check_result_keeps_the_servers_reason(rig):
    d, record = rig
    check = _challenge("consistent", "it matched")["checks"][0]
    check["audit_ids"] = []
    res = await record(
        "replaced", [art()], challenged={"outcome": "stands", "checks": [check]}
    )
    assert res["status"] == "STAGED", res
    (stored,) = _stored(d, "replaced")[0]["challenged"]["checks"]
    assert stored["result"] == "not run" and stored["reason"] != "it matched"


async def test_the_tool_descriptions_state_the_artifact_rules(rig):
    _d, record = rig
    tools = {t.name: t.description for t in await record.backend.list_tools()}
    said = " ".join(tools["record_finding"].split())
    for rule in ("at most 10. Send them here or as finding[\"artifacts\"], not both.",
                 "stored whole, up to 65,536 chars each.",
                 "refuses the whole call, naming the artifact and the field",
                 "A check's reason is up to 2,000 chars of text"):  # fmt: skip
        assert rule in said, rule
    assert "record_timeline_event(event={" in tools["record_timeline_event"]
