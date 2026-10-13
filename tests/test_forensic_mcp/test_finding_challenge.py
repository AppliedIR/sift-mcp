"""A finding carries its alternatives and its challenge, and a withdrawn
candidate is logged, not staged.

record_finding dropped an `alternatives` list and a `challenged` marker
without a word, and staged a withdrawn candidate as a DRAFT the examiner then
had to process. Now anything that removes doubt (a ruled-out alternative, a
challenge, a withdrawal) must cite tool output from the case's audit trail,
other than the model's own account of a command, or it falls back to the
doubtful form; anything that adds doubt is kept.

The real forensic-mcp server runs in-process on scratch cases under a scratch
HOME.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import forensic_mcp.case.manager as fmanager
import pytest
from forensic_mcp.server import create_server

OWN = "ev-tester-20261007-001"  # the finding's own evidence
SKEPTIC = "sift-tester-20261007-002"  # a re-run by the skeptic
SKEPTIC_2 = "sift-tester-20261007-003"
SHELL = "shell-tester-20261007-001"  # the model's account of a shell command
VOLUNTARY = "case-tester-20261007-004"  # log_external_action
HOOK = "hook-tester-20261007-005"  # the client hook's record
ELSEWHERE = "sift-tester-20261007-099"  # not in this case's trail

FINDING = {
    "title": "Mimikatz run on wkstn05",
    "observation": "Prefetch shows MIMIKATZ.EXE run at 14:32",
    "interpretation": "Credential dumping",
    "confidence": "MEDIUM",
    "confidence_justification": "One artifact",
    "type": "finding",
    "audit_ids": [OWN],
    "event_timestamp": "2026-10-01T14:32:00Z",
    "iocs": ["10.0.0.99"],
    "challenged": {"outcome": "not_challenged", "reason": "no skeptic in this test"},
}


def _case(root: Path, name: str) -> Path:
    case = root / "cases" / name
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {name}\nname: {name}\nstatus: open\n")
    (case / "evidence.json").write_text('{"files": []}')
    tool = [
        {"audit_id": a, "tool": "run_command", "source": "mcp_server"}
        for a in (OWN, SKEPTIC, SKEPTIC_2)
    ]
    with open(case / "audit" / "sift-mcp.jsonl", "w") as f:
        f.writelines(json.dumps(e) + "\n" for e in tool)
    self_reported = [
        {
            "audit_id": SHELL,
            "tool": "supporting_command",
            "source": "shell_self_report",
        },
        {
            "audit_id": VOLUNTARY,
            "tool": "log_external_action",
            "source": "orchestrator_voluntary",
        },
    ]
    with open(case / "audit" / "case-mcp.jsonl", "w") as f:
        f.writelines(json.dumps(e) + "\n" for e in self_reported)
    (case / "audit" / "claude-code.jsonl").write_text(
        json.dumps({"audit_id": HOOK, "tool": "Bash"}) + "\n"
    )
    return case


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(fmanager, "_ACTIVE_CASE_FILE", home / ".vhir" / "active_case")
    return home


@pytest.fixture
def case(tmp_path, home):
    case = _case(tmp_path, "case-a")
    (home / ".vhir" / "active_case").write_text(str(case))
    return case


def _record(finding: dict, **params) -> dict:
    r = asyncio.run(
        create_server().call_tool("record_finding", {"finding": finding, **params})
    )
    r = r[0] if isinstance(r, tuple) else r
    return json.loads(r[0].text)


def _stored(case: Path, result: dict) -> dict:
    assert result["status"] == "STAGED", result
    findings = json.loads((case / "findings.json").read_text())
    return next(f for f in findings if f["id"] == result["finding_id"])


def _entries(case: Path) -> list[dict]:
    f = case / "audit" / "forensic-mcp.jsonl"
    if not f.is_file():
        return []
    return [json.loads(line) for line in f.read_text().splitlines() if line.strip()]


# --- alternatives ----------------------------------------------------------


def test_alternatives_are_stored_and_in_the_content_hash(case):
    alternatives = [
        {"explanation": "An admin's sanctioned test", "status": "open"},
        {
            "explanation": "A renamed backup tool",
            "status": "ruled_out",
            "evidence": "sigcheck: unsigned, 'mimikatz' in the version info",
            "audit_ids": [SKEPTIC],
        },
    ]
    result = _record({**FINDING, "alternatives": alternatives})
    stored = _stored(case, result)
    assert stored["alternatives"] == alternatives
    assert stored["content_hash"] == fmanager._compute_content_hash(stored)
    without = {k: v for k, v in stored.items() if k != "alternatives"}
    assert fmanager._compute_content_hash(without) != stored["content_hash"]
    assert stored["audit_ids"] == [OWN]  # never merged into the evidence


@pytest.mark.parametrize(
    "ids, evidence",
    [
        ([ELSEWHERE], "re-run shows no task"),
        ([SKEPTIC], ""),
        ([SHELL], "re-run shows no task"),
        ([VOLUNTARY], "re-run shows no task"),
        ([HOOK], "re-run shows no task"),
    ],
    ids=["not in trail", "no evidence", "shell", "voluntary", "hook"],
)
def test_ruling_out_needs_tool_output_and_its_evidence(case, ids, evidence):
    alternative = {
        "explanation": "A scheduled backup",
        "status": "ruled_out",
        "evidence": evidence,
        "audit_ids": ids,
    }
    result = _record({**FINDING, "alternatives": [alternative]})
    (stored,) = _stored(case, result)["alternatives"]
    assert stored["status"] == "open"
    assert "alternative 1 stored as open" in result["warning"]


def test_text_and_entries_without_an_explanation_are_kept_open(case):
    raw = ["Could be an admin", {"status": "ruled_out", "evidence": "x"}, 7]
    result = _record({**FINDING, "alternatives": raw})
    assert _stored(case, result)["alternatives"] == [
        {"explanation": "Could be an admin", "status": "open"},
        {"explanation": "", "status": "open", "evidence": "x"},
    ]
    assert "alternative 3 dropped" in result["warning"]


def test_alternatives_as_a_json_string_are_read(case):
    raw = json.dumps([{"explanation": "Admin test", "status": "open"}])
    result = _record({**FINDING, "alternatives": raw})
    assert _stored(case, result)["alternatives"] == [
        {"explanation": "Admin test", "status": "open"}
    ]


def test_alternatives_are_bounded(case):
    raw = [{"explanation": f"alt {n}" + "x" * 3000} for n in range(12)]
    result = _record({**FINDING, "alternatives": raw})
    stored = _stored(case, result)["alternatives"]
    assert len(stored) == 10
    assert all(len(a["explanation"]) == 2000 for a in stored)
    assert "2 alternative(s) over the limit of 10 dropped" in result["warning"]


def test_alternatives_that_are_not_a_list_are_dropped_with_a_warning(case):
    result = _record({**FINDING, "alternatives": {"explanation": "x"}})
    assert "alternatives" not in _stored(case, result)
    assert "alternatives dropped" in result["warning"]


@pytest.mark.parametrize(
    "extra", [{}, {"alternatives": []}, {"alternatives": None}], ids=str
)
def test_anchor_a_finding_without_alternatives_stores_no_key_but_its_challenge(
    case, extra
):
    stored = _stored(case, _record({**FINDING, **extra}))
    assert "alternatives" not in stored
    assert stored["challenged"] == NOT_RUN_BY_TEST


# --- the challenge marker -------------------------------------------------

NOT_RUN_BY_TEST = {"outcome": "not_challenged", "reason": "no skeptic in this test",
                   "checks": [], "skeptic_audit_ids": []}  # fmt: skip


@pytest.mark.parametrize("outcome", ["stands", "revised"])
def test_a_legacy_challenge_citing_the_skeptics_tool_output_is_one_check(case, outcome):
    """The 0.6.4 shape {outcome, skeptic_audit_ids}, as an un-updated skeptic sends it."""
    challenged = {"outcome": outcome, "skeptic_audit_ids": [SKEPTIC]}
    stored = _stored(case, _record({**FINDING, "challenged": challenged}))
    check = {"name": "skeptic re-run", "result": "consistent", "audit_ids": [SKEPTIC],
             "ran": {SKEPTIC: "run_command {}"}}  # fmt: skip
    assert stored["challenged"] == {
        "outcome": outcome, "checks": [check], "skeptic_audit_ids": [SKEPTIC]}  # fmt: skip
    assert SKEPTIC not in stored["audit_ids"]


@pytest.mark.parametrize(
    "ids, unverified, kept",
    [([ELSEWHERE], ELSEWHERE, []), ([OWN], OWN, []),
     ([SHELL, VOLUNTARY, HOOK], f"{SHELL}, {VOLUNTARY}, {HOOK}", []),
     ([SKEPTIC, ELSEWHERE], ELSEWHERE, [SKEPTIC])],
    ids=["not in trail", "own evidence", "self-reported", "one of two"],
)  # fmt: skip
def test_a_check_without_the_skeptics_tool_output_is_stored_as_not_run(
    case, ids, unverified, kept
):
    """Stored, never dropped: the examiner sees the check that didn't run."""
    result = _record(
        {**FINDING, "challenged": {"outcome": "stands", "skeptic_audit_ids": ids}}
    )
    marker = _stored(case, result)["challenged"]
    assert marker["outcome"] == "stands"
    assert marker["checks"] == [{"name": "skeptic re-run", "result": "not run",
                                 "audit_ids": kept,
                                 **({"ran": {SKEPTIC: "run_command {}"}} if kept else {}),
                                 "reason": f"unverified audit id: {unverified}"}]  # fmt: skip
    assert marker["skeptic_audit_ids"] == kept
    assert (
        f"skeptic re-run: not run (unverified audit id: {unverified})"
        in result["warning"]
    )
    assert "dropped" not in result["warning"]


def test_a_challenge_with_checks_is_stored_as_given_where_its_ids_verify(case):
    challenged = {
        "outcome": "stands",
        "skeptic": {"client": "claude-code", "model": "a-model"},
        "checks": [
            {
                "name": "prefetch re-parsed",
                "result": "consistent",
                "audit_ids": [SKEPTIC],
            },
            {"name": "amcache", "result": "nothing found", "audit_ids": [SKEPTIC_2]},
            {
                "name": "event logs",
                "result": "not run",
                "reason": "no evtx in the case",
            },
            {"name": "a guess", "result": "probably fine", "audit_ids": [SKEPTIC]},
            "not an object",
        ],
    }
    stored = _stored(case, _record({**FINDING, "challenged": challenged}))["challenged"]
    assert stored["skeptic"] == {"client": "claude-code", "model": "a-model",
                                 "self_reported": True}  # fmt: skip
    assert [(c["name"], c["result"], c.get("reason")) for c in stored["checks"]] == [
        ("prefetch re-parsed", "consistent", None),
        ("amcache", "nothing found", None),
        ("event logs", "not run", "no evtx in the case"),
        ("a guess", "not run", 'malformed check: result "probably fine"'),
        ("check 5", "not run", "malformed check: not an object"),
    ]
    assert stored["skeptic_audit_ids"] == [SKEPTIC, SKEPTIC_2]


def test_each_check_names_what_its_ids_ran(case):
    """An author's own `date` run offered as the skeptic's shows as `date`."""
    date = "sift-tester-20261007-777"
    with open(case / "audit" / "sift-mcp.jsonl", "a") as f:
        f.write(json.dumps({"audit_id": date, "tool": "run_command",
                            "params": {"command": "date"}}) + "\n")  # fmt: skip
    check = {"name": "re-run", "result": "consistent", "audit_ids": [date]}
    stored = _stored(case, _record({**FINDING, "challenged": {"outcome": "stands",
                                                              "checks": [check]}}))  # fmt: skip
    assert stored["challenged"]["checks"][0]["ran"] == {date: "date"}


def test_not_challenged_is_stored_with_its_reason_and_no_warning(case):
    reason = "no subagent in this client"
    result = _record(
        {**FINDING, "challenged": {"outcome": "not_challenged", "reason": reason}}
    )
    assert _stored(case, result)["challenged"] == {
        **NOT_RUN_BY_TEST, "reason": reason}  # fmt: skip
    assert "warning" not in result or "challenged" not in result["warning"]


@pytest.mark.parametrize(
    "challenged, reason",
    [("revised", "malformed challenge: expected an object, not a string"),
     ({"outcome": "maybe", "skeptic_audit_ids": [SKEPTIC]}, 'malformed challenge: outcome "maybe"'),
     ({"outcome": ["revised"]}, 'malformed challenge: outcome ["revised"]'),
     ({"outcome": "stands"}, "malformed challenge: no checks"),
     ({"outcome": "stands", "checks": []}, "malformed challenge: no checks"),
     ({"outcome": "not_challenged"}, "malformed challenge: no reason given"),
     ({"outcome": "contested", "skeptic_audit_ids": [SKEPTIC]},
      "malformed challenge: contested without a contradiction")],
    ids=["text", "unknown outcome", "outcome a list", "no checks", "empty checks",
         "not_challenged without a reason", "contested without a contradiction"],
)  # fmt: skip
def test_a_malformed_challenge_is_stored_as_not_challenged_with_what_is_wrong(
    case, challenged, reason
):
    result = _record(
        {**FINDING, "challenged": challenged}
    )  # staged, never an exception
    assert _stored(case, result)["challenged"] == {**NOT_RUN_BY_TEST, "reason": reason}
    assert f"challenged: {reason}; stored as not challenged." in result["warning"]


@pytest.mark.parametrize("missing", [{}, {"challenged": None}], ids=["absent", "null"])
def test_a_finding_without_a_challenge_is_rejected_with_the_payload_to_send(
    case, missing
):
    finding = {k: v for k, v in FINDING.items() if k != "challenged"} | missing
    result = _record(finding)
    assert result["status"] == "REJECTED", result
    assert result["error"] == (
        "challenged is required: challenge the finding with the finding-skeptic "
        "skill first (an isolated subagent), and pass its result. If no skeptic can "
        'run, send challenged={"outcome": "not_challenged", "reason": "<why no skeptic '
        'ran>"} with the reason; the examiner sees it at approval.'
    )
    assert not (case / "findings.json").exists()


@pytest.mark.parametrize("cited", [[OWN], []], ids=["its own output", "no id"])
def test_a_contested_challenge_is_kept_like_a_withdrawal(case, cited):
    """An interpretive dispute: the skeptic cites only the finding's own output.
    Kept, with its contradiction; its check shows as not run."""
    challenged = {"outcome": "contested", "contradiction": "The run count says 3, not 1",
                  "checks": [{"name": "re-read", "result": "contradicts", "audit_ids": cited}]}  # fmt: skip
    result = _record({**FINDING, "challenged": challenged})
    marker = _stored(case, result)["challenged"]
    assert marker["outcome"] == "contested"
    assert marker["contradiction"] == "The run count says 3, not 1"
    assert marker["checks"][0]["result"] == "not run"


def test_who_produced_the_finding_is_stored_as_self_reported(case):
    finding = {
        **FINDING,
        "produced_by": {"client": "codex", "model": "m-1", "x": "dropped"},
    }
    stored = _stored(case, _record(finding))
    assert stored["produced_by"] == {
        "client": "codex",
        "model": "m-1",
        "self_reported": True,
    }
    assert "produced_by" not in _stored(case, _record(dict(FINDING)))


# --- withdrawal ------------------------------------------------------------

WITHDRAWN = {
    "outcome": "withdrawn",
    "skeptic_audit_ids": [SKEPTIC, SKEPTIC_2],
    "contradiction": "PECmd re-run: no MIMIKATZ.EXE prefetch file exists",
}


@pytest.mark.parametrize("cold", [False, True], ids=["warm", "cold"])
def test_a_complete_withdrawal_stages_nothing_and_is_logged(case, cold):
    if cold:
        files = {}
    else:
        _record(dict(FINDING))  # one staged finding, its timeline event and IOC
        files = {
            n: (case / n).read_bytes()
            for n in ("findings.json", "timeline.json", "iocs.json")
        }
    result = _record({**FINDING, "challenged": WITHDRAWN})
    assert result["status"] == "WITHDRAWN"
    assert result["contradiction"] == WITHDRAWN["contradiction"]
    assert result["skeptic_audit_ids"] == [SKEPTIC, SKEPTIC_2]
    assert "finding_id" not in result
    for name in ("findings.json", "timeline.json", "iocs.json"):
        if cold:
            assert not (case / name).exists(), name
        else:
            assert (case / name).read_bytes() == files[name], name
    logged = _entries(case)[-1]
    assert logged["tool"] == "record_finding"
    assert logged["result_summary"]["status"] == "WITHDRAWN"
    assert logged["result_summary"]["skeptic_audit_ids"] == [SKEPTIC, SKEPTIC_2]
    assert logged["result_summary"]["contradiction"] == WITHDRAWN["contradiction"]
    assert logged["result_summary"]["title"] == FINDING["title"]
    assert logged["params"]["finding"]["observation"] == FINDING["observation"]


def test_a_withdrawal_needs_only_a_title_and_observation(case):
    candidate = {"title": "t", "observation": "o", "challenged": WITHDRAWN}
    assert _record(candidate)["status"] == "WITHDRAWN"


@pytest.mark.parametrize(
    "challenged, ids",
    [
        ({**WITHDRAWN, "skeptic_audit_ids": [ELSEWHERE]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [OWN]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [SHELL]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [VOLUNTARY]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [HOOK]}, []),
    ],
    ids=[
        "not in trail",
        "own evidence",
        "shell",
        "voluntary",
        "hook",
    ],
)
def test_a_withdrawal_without_tool_output_is_staged_with_its_marker(
    case, challenged, ids
):
    result = _record({**FINDING, "challenged": challenged})
    marker = _stored(case, result)["challenged"]
    assert marker["outcome"] == "withdrawn"
    assert marker["skeptic_audit_ids"] == ids
    assert "Withdrawal refused" in result["warning"]


@pytest.mark.parametrize("contradiction", ["", "  "], ids=["none", "blank"])
def test_a_withdrawal_without_a_contradiction_is_stored_as_not_challenged(
    case, contradiction
):
    result = _record(
        {**FINDING, "challenged": {**WITHDRAWN, "contradiction": contradiction}}
    )
    assert _stored(case, result)["challenged"] == {
        **NOT_RUN_BY_TEST, "reason": "malformed challenge: withdrawn without a contradiction"}  # fmt: skip


def test_a_withdrawal_that_cant_be_logged_is_staged_for_the_examiner(case):
    (case / "audit" / "forensic-mcp.jsonl").mkdir()  # every audit write fails
    result = _record({**FINDING, "challenged": WITHDRAWN})
    marker = _stored(case, result)["challenged"]
    assert marker["outcome"] == "withdrawn"
    assert marker["contradiction"] == WITHDRAWN["contradiction"]
    assert (
        "Withdrawal could not be logged; staged for the examiner" in (result["warning"])
    )
    assert "Audit write failed" in result["warning"]


@pytest.mark.parametrize(
    "challenged, reason",
    [
        (
            {**WITHDRAWN, "skeptic_audit_ids": [ELSEWHERE]},
            f"unverified audit id: {ELSEWHERE}",
        )
    ],
    ids=["not in trail"],
)
def test_a_refused_withdrawal_keeps_the_server_s_reason(case, challenged, reason):
    marker = _stored(case, _record({**FINDING, "challenged": challenged}))
    assert reason in marker["challenged"]["refused"]
    assert "Withdrawal refused" in marker["challenged"]["refused"]


def test_the_server_s_reason_reads_as_product_text(case):
    """Ids joined, no list repr, and no "challenged:" label under the
    portal's challenge line, which already says challenged."""
    other = "sift-tester-20261007-098"
    challenged = {**WITHDRAWN, "skeptic_audit_ids": [OWN, ELSEWHERE, other]}
    result = _record({**FINDING, "challenged": challenged})
    refused = _stored(case, result)["challenged"]["refused"]
    assert refused == (
        f"Skeptic re-run: not run (unverified audit id: {ELSEWHERE}, {other}, {OWN}). "
        "Withdrawal refused: it needs the skeptic's tool output and the output that "
        "contradicts the observation. Staged for the examiner."
    )
    assert (
        f"skeptic re-run: not run (unverified audit id: {ELSEWHERE}, {other}, {OWN})"
        in (result["warning"])
    )


def test_a_withdrawal_that_cant_be_logged_keeps_that_reason(case):
    (case / "audit" / "forensic-mcp.jsonl").mkdir()  # every audit write fails
    marker = _stored(case, _record({**FINDING, "challenged": WITHDRAWN}))
    assert "could not be logged" in marker["challenged"]["refused"]
    assert "Withdrawal refused" not in marker["challenged"]["refused"]


def test_a_withdrawal_is_logged_in_the_active_case_whatever_vhir_case_dir_says(
    tmp_path, home, monkeypatch
):
    a, b = _case(tmp_path, "case-a"), _case(tmp_path, "case-b")
    (home / ".vhir" / "active_case").write_text(str(b))
    monkeypatch.setenv("VHIR_CASE_DIR", str(a))
    assert _record({**FINDING, "challenged": WITHDRAWN})["status"] == "WITHDRAWN"
    assert [e["result_summary"]["status"] for e in _entries(b)] == ["WITHDRAWN"]
    assert _entries(a) == []


# --- only the evidence backends' own output counts -------------------------

REFUSED = {
    "a log_reasoning entry": ("case-mcp.jsonl", "log_reasoning", "mcp_server"),
    "a verified external action": (
        "case-mcp.jsonl",
        "log_external_action",
        "orchestrator_verified",
    ),
    "a record_finding entry": ("forensic-mcp.jsonl", "record_finding", "mcp_server"),
    "a forensic-mcp entry": ("forensic-mcp.jsonl", "add_todo", "mcp_server"),
    "a knowledge search": ("forensic-rag-mcp.jsonl", "search_knowledge", "mcp_server"),
    "the gateway's record": ("sift-gateway.jsonl", "run_command", "gateway_proxy"),
}
ACCEPTED = [
    "sift-mcp.jsonl",
    "opensearch-mcp.jsonl",
    "opensearch-ingest-4242.jsonl",
    "windows-triage-mcp.jsonl",
    "opencti-mcp.jsonl",
    "threatintel-mcp.jsonl",
    "wintools-mcp.jsonl",
]
CITED = "cited-tester-20261007-777"


def _cite_from(case: Path, file: str, tool: str = "run_command", source="x") -> None:
    with open(case / "audit" / file, "a") as f:
        f.write(json.dumps({"audit_id": CITED, "tool": tool, "source": source}) + "\n")


@pytest.mark.parametrize("label", list(REFUSED))
def test_an_id_from_outside_the_evidence_backends_removes_no_doubt(case, label):
    _cite_from(case, *REFUSED[label])
    withdrawal = _record(
        {**FINDING, "challenged": {**WITHDRAWN, "skeptic_audit_ids": [CITED]}}
    )
    assert _stored(case, withdrawal)["challenged"]["skeptic_audit_ids"] == []
    ruled = _record(
        {
            **FINDING,
            "alternatives": [
                {
                    "explanation": "a backup",
                    "status": "ruled_out",
                    "evidence": "no task",
                    "audit_ids": [CITED],
                }
            ],
        }
    )
    assert _stored(case, ruled)["alternatives"][0]["status"] == "open"


@pytest.mark.parametrize("file", ACCEPTED)
def test_an_id_from_an_evidence_backend_counts(case, file):
    _cite_from(case, file)
    result = _record(
        {**FINDING, "challenged": {**WITHDRAWN, "skeptic_audit_ids": [CITED]}}
    )
    assert result["status"] == "WITHDRAWN", result


def test_a_line_that_isn_t_utf8_doesn_t_block_recording(case):
    """One damaged line in the trail used to fail every record_finding that
    read it; now it's skipped with a warning and the rest of the trail counts."""
    with open(case / "audit" / "sift-mcp.jsonl", "ab") as f:
        f.write(b'{"audit_id": "x", "tool": "\xff\xfe"}\n')
    alternative = {
        "explanation": "A renamed backup tool",
        "status": "ruled_out",
        "evidence": "sigcheck: unsigned",
        "audit_ids": [SKEPTIC],
    }
    result = _record(
        {
            **FINDING,
            "alternatives": [alternative],
            "challenged": {"outcome": "stands", "skeptic_audit_ids": [SKEPTIC]},
        }
    )
    stored = _stored(case, result)
    assert stored["challenged"]["skeptic_audit_ids"] == [SKEPTIC]
    assert stored["alternatives"][0]["status"] == "ruled_out"
    assert stored["provenance"] == "MCP"


def test_a_withdrawal_lists_each_of_its_own_audit_ids_once_in_order(case):
    """The finding's own ids [C, A] plus an artifact citing A: A is listed
    once, after C, in the reply and in the audit entry (C, A isn't sorted)."""
    c, a = HOOK, OWN  # two of the finding's own ids, out of sorted order
    finding = {**FINDING, "audit_ids": [c, a], "challenged": WITHDRAWN}
    result = _record(
        finding, artifacts=[{"audit_id": a, "source": "x", "content": "y"}]
    )
    assert result["status"] == "WITHDRAWN"
    assert result["audit_ids"] == [c, a]
    assert _entries(case)[-1]["result_summary"]["audit_ids"] == [c, a]


def test_the_tool_list_says_what_challenged_takes():
    tools = {t.name: t for t in asyncio.run(create_server().list_tools())}
    assert (
        'challenged (dict, optional): after the skeptic\'s challenge, {"outcome": '
        '"stands", "revised" or "withdrawn", "skeptic_audit_ids": [the skeptic\'s own '
        'audit ids]}; withdrawn also takes "contradiction".'
    ) in " ".join(tools["record_finding"].description.split())
