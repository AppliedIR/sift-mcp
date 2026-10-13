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
E1, E2, E3, E4, BIG = (f"sift-tester-20261013-0{n:02d}" for n in (21, 22, 23, 24, 25))
S1, S2, S3, U1, R1, R2 = (
    f"sift-tester-20261013-0{n:02d}" for n in (31, 32, 33, 34, 35, 36)
)
RUNS = [
    (E1, "MFTECmd -f C/$MFT --csv /out/mft", BEFORE),
    (E2, "PECmd -d C/Windows/Prefetch --csv /out/pf", BEFORE),
    (BIG, "hayabusa csv-timeline -d evtx -o /out/hb.csv", BEFORE),
    (E3, "EvtxECmd -f Security.evtx", BEFORE),
    (S1, "MFTECmd -f C/$MFT  --csv /out/mft2", BEFORE),  # the skeptic's cited re-run
    (S2, "AmcacheParser -f Amcache.hve", BEFORE),  # the skeptic ran it, didn't cite it
    (S3, "EvtxECmd -f Security.evtx --inc 4625", BEFORE),
    (U1, "date", AFTER),  # unrelated, after the challenge
    (R1, "MFTECmd  -f C/$MFT --csv /out/mft", AFTER),  # the same command, re-run
    (R2, "PECmd -d C/Windows/Prefetch --csv /out/pf", AFTER),
    (E4, "RECmd --bn Run.reb -d hives", AFTER),
]
WITHDRAWN_BECAUSE = "MFT re-run shows evil.exe under the vendor installer path."
CONTESTED_BECAUSE = "The logon fits the admin's jump host."


@pytest.fixture
def challenged_case(case):  # noqa: F811
    with open(case / "audit" / "sift-mcp.jsonl", "a") as f:
        for aid, cmd, ts in RUNS:
            f.write(json.dumps({"audit_id": aid, "tool": "run_command", "ts": ts,
                                "params": {"command": cmd}, "source": "mcp_server"}) + "\n")  # fmt: skip
    withdrawn = {"outcome": "withdrawn", "skeptic_audit_ids": [S1],
                 "contradiction": WITHDRAWN_BECAUSE}  # fmt: skip
    assert _record({**FINDING, "audit_ids": [E1, E2], "challenged": withdrawn})[
        "status"
    ] == ("WITHDRAWN")
    contested = {"outcome": "contested", "skeptic_audit_ids": [S3],
                 "contradiction": CONTESTED_BECAUSE}  # fmt: skip
    _stored(case, _record({**FINDING, "audit_ids": [BIG, E3], "challenged": contested}))
    return case


def _draft(case, ids, **params):  # noqa: F811
    return _stored(case, _record({**FINDING, "audit_ids": ids}, **params))


SHAPES = {
    "reworded and reordered": ([E2, E1], {}, "withdrawn", []),
    "plus an unrelated new run": ([E1, E2, U1], {}, "withdrawn", [U1]),
    "plus the skeptic's cited re-run": ([E1, E2, S1], {}, "withdrawn", []),
    "plus the skeptic's uncited run": ([E1, E2, S2], {}, "withdrawn", []),
    "the same command re-run": ([R1, E2], {}, "withdrawn", []),
    "both commands re-run": ([R1, R2], {}, "withdrawn", []),
    "a shell-only re-draft": ([], {"supporting_commands": [
        {"command": "MFTECmd -f C/$MFT --csv /out/mft", "purpose": "creation time",
         "output_excerpt": "evil.exe created 10:00"}]}, "withdrawn", []),
    "another finding sharing a contested run": ([BIG], {}, "contested", []),
    "another finding sharing it, with new evidence": ([BIG, E4], {}, "contested", [E4]),
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
    prior = _draft(challenged_case, [E1, E2, U1])["prior_challenge"]
    assert prior[0]["new_since"] == [{"audit_id": U1, "ran": "date"}]


def test_a_draft_that_ran_nothing_a_challenged_one_ran_carries_no_flag(challenged_case):
    assert "prior_challenge" not in _draft(challenged_case, [E4])


def test_the_flag_never_blocks_and_is_said_when_staged(challenged_case):
    result = _record({**FINDING, "audit_ids": [E1, E2]})
    assert result["status"] == "STAGED"
    assert (
        "previously withdrawn" in result["warning"]
        and WITHDRAWN_BECAUSE in result["warning"]
    )
