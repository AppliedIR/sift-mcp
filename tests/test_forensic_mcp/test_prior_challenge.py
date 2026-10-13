"""A new draft that cites what an earlier contested or withdrawn draft ran
carries that challenge, and names what it ran since.

A re-run makes a new audit id, so a match on ids alone was evaded by one
re-run or one unrelated new id. The match is on what was RUN: a command,
whitespace-normalised, or a tool and its parameters, shell commands included.
The flag never blocks and never clears: a draft with new evidence is still
flagged, with the new entries named, and the examiner judges.

The real forensic-mcp server runs in-process on a scratch case, as in
test_finding_challenge.py.
"""

from __future__ import annotations

import json

import pytest

from .test_finding_challenge import FINDING, _record, _stored, case, home  # noqa: F401

BEFORE, AFTER = "2000-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00"
MFT, PREFETCH, EVTX, RUN_KEY, HAYABUSA = (
    f"sift-tester-20261013-0{n:02d}" for n in (21, 22, 23, 24, 25)
)
SKEPTIC_MFT, SKEPTIC_AMCACHE, SKEPTIC_EVTX, DATE, MFT_AGAIN, PREFETCH_AGAIN = (
    f"sift-tester-20261013-0{n:02d}" for n in (31, 32, 33, 34, 35, 36)
)
RUNS = [
    (MFT, "MFTECmd -f C/$MFT --csv /out/mft", BEFORE),
    (PREFETCH, "PECmd -d C/Windows/Prefetch --csv /out/pf", BEFORE),
    (HAYABUSA, "hayabusa csv-timeline -d evtx -o /out/hb.csv", BEFORE),
    (EVTX, "EvtxECmd -f Security.evtx", BEFORE),
    (
        SKEPTIC_MFT,
        "MFTECmd -f C/$MFT  --csv /out/mft2",
        BEFORE,
    ),  # the skeptic's cited re-run
    (
        SKEPTIC_AMCACHE,
        "AmcacheParser -f Amcache.hve",
        BEFORE,
    ),  # the skeptic ran it, didn't cite it
    (SKEPTIC_EVTX, "EvtxECmd -f Security.evtx --inc 4625", BEFORE),
    (DATE, "date", AFTER),  # unrelated, after the challenge
    (MFT_AGAIN, "MFTECmd  -f C/$MFT --csv /out/mft", AFTER),  # the same command, re-run
    (PREFETCH_AGAIN, "PECmd -d C/Windows/Prefetch --csv /out/pf", AFTER),
    (RUN_KEY, "RECmd --bn Run.reb -d hives", AFTER),
]
WITHDRAWN_BECAUSE = "MFT re-run shows evil.exe under the vendor installer path."
CONTESTED_BECAUSE = "The logon fits the admin's jump host."


@pytest.fixture
def challenged_case(case):  # noqa: F811
    with open(case / "audit" / "sift-mcp.jsonl", "a") as f:
        for aid, cmd, ts in RUNS:
            f.write(json.dumps({"audit_id": aid, "tool": "run_command", "ts": ts,
                                "params": {"command": cmd}, "source": "mcp_server"}) + "\n")  # fmt: skip
    withdrawn = {"outcome": "withdrawn", "skeptic_audit_ids": [SKEPTIC_MFT],
                 "contradiction": WITHDRAWN_BECAUSE}  # fmt: skip
    assert _record({**FINDING, "audit_ids": [MFT, PREFETCH], "challenged": withdrawn})[
        "status"
    ] == ("WITHDRAWN")
    contested = {"outcome": "contested", "skeptic_audit_ids": [SKEPTIC_EVTX],
                 "contradiction": CONTESTED_BECAUSE}  # fmt: skip
    _stored(
        case,
        _record({**FINDING, "audit_ids": [HAYABUSA, EVTX], "challenged": contested}),
    )
    return case


def _draft(case, ids, **params):  # noqa: F811
    return _stored(case, _record({**FINDING, "audit_ids": ids}, **params))


SHAPES = {
    "reworded and reordered": ([PREFETCH, MFT], {}, "withdrawn", []),
    "plus an unrelated new run": ([MFT, PREFETCH, DATE], {}, "withdrawn", [DATE]),
    "plus the skeptic's cited re-run": ([MFT, PREFETCH, SKEPTIC_MFT], {}, "withdrawn", []),
    "plus the skeptic's uncited run": ([MFT, PREFETCH, SKEPTIC_AMCACHE], {}, "withdrawn", []),
    "the same command re-run": ([MFT_AGAIN, PREFETCH], {}, "withdrawn", []),
    "both commands re-run": ([MFT_AGAIN, PREFETCH_AGAIN], {}, "withdrawn", []),
    "a shell-only re-draft": ([], {"supporting_commands": [
        {"command": "MFTECmd -f C/$MFT --csv /out/mft", "purpose": "creation time",
         "output_excerpt": "evil.exe created 10:00"}]}, "withdrawn", []),
    "another finding sharing a contested run": ([HAYABUSA], {}, "contested", []),
    "another finding sharing it, with new evidence": ([HAYABUSA, RUN_KEY], {}, "contested", [RUN_KEY]),
}  # fmt: skip


@pytest.mark.parametrize("shape", list(SHAPES))
def test_a_draft_that_ran_what_a_challenged_one_ran_carries_its_challenge(
    challenged_case, shape
):
    ids, params, kind, new = SHAPES[shape]
    stored = _draft(challenged_case, ids, **params)
    prior = stored["prior_challenge"]
    assert [p["kind"] for p in prior] == [kind], prior
    because = WITHDRAWN_BECAUSE if kind == "withdrawn" else CONTESTED_BECAUSE
    assert prior[0]["contradiction"] == because
    assert [n["audit_id"] for n in prior[0]["new_since"]] == new, prior


def test_the_new_entries_are_named_by_what_they_ran(challenged_case):
    prior = _draft(challenged_case, [MFT, PREFETCH, DATE])["prior_challenge"]
    assert prior[0]["new_since"] == [{"audit_id": DATE, "ran": "date"}]


def test_a_draft_that_ran_nothing_a_challenged_one_ran_carries_no_flag(challenged_case):
    assert "prior_challenge" not in _draft(challenged_case, [RUN_KEY])


def test_the_flag_never_blocks_and_is_said_when_staged(challenged_case):
    result = _record({**FINDING, "audit_ids": [MFT, PREFETCH]})
    assert result["status"] == "STAGED"
    assert (
        "previously withdrawn" in result["warning"]
        and WITHDRAWN_BECAUSE in result["warning"]
    )


SHAPES_OF_EARLIER_IDS = {
    "a contested draft whose ids are lists": (
        "findings", {"audit_ids": [["x"]], "challenged": {
            "outcome": "contested", "contradiction": "c", "checks": []}}),
    "a contested draft whose skeptic ids are lists": (
        "findings", {"audit_ids": [MFT], "challenged": {
            "outcome": "contested", "contradiction": "c", "skeptic_audit_ids": [["y"]]}}),
    "a withdrawal whose ids are objects": (
        "audit", {"status": "WITHDRAWN", "audit_ids": [{"a": 1}]}),
}  # fmt: skip


@pytest.mark.parametrize("shape", list(SHAPES_OF_EARLIER_IDS))
def test_an_earlier_record_with_ids_of_any_shape_never_stops_a_recording(case, shape):  # noqa: F811
    """Earlier records are case data the VM can write: an id that isn't text
    is skipped, and the new draft is staged (the only refusal stays a missing
    challenge)."""
    where, record = SHAPES_OF_EARLIER_IDS[shape]
    with open(case / "audit" / "sift-mcp.jsonl", "a") as f:
        f.write(json.dumps({"audit_id": MFT, "tool": "run_command", "ts": BEFORE,
                            "params": {"command": "MFTECmd -f C/$MFT"}}) + "\n")  # fmt: skip
    if where == "findings":
        planted = {
            "id": "F-tester-090",
            "status": "DRAFT",
            "title": "t",
            "staged": BEFORE,
            **record,
        }
        (case / "findings.json").write_text(json.dumps([planted]))
    else:
        with open(case / "audit" / "forensic-mcp.jsonl", "a") as f:
            f.write(json.dumps({"audit_id": "forensic-tester-x-001", "tool": "record_finding",
                                "ts": BEFORE, "result_summary": record}) + "\n")  # fmt: skip
    assert _record({**FINDING, "audit_ids": [MFT]})["status"] == "STAGED"
