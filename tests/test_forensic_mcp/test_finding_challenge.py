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
def test_anchor_a_finding_without_them_stores_neither_key(case, extra):
    stored = _stored(case, _record({**FINDING, **extra}))
    assert "alternatives" not in stored and "challenged" not in stored


# --- the challenge marker -------------------------------------------------


@pytest.mark.parametrize("outcome", ["stands", "revised"])
def test_a_challenge_citing_the_skeptics_tool_output_is_stored(case, outcome):
    challenged = {"outcome": outcome, "skeptic_audit_ids": [SKEPTIC, ELSEWHERE]}
    result = _record({**FINDING, "challenged": challenged})
    stored = _stored(case, result)
    assert stored["challenged"] == {"outcome": outcome, "skeptic_audit_ids": [SKEPTIC]}
    assert SKEPTIC not in stored["audit_ids"]
    assert "removed" in result["warning"]


@pytest.mark.parametrize(
    "challenged",
    [
        {"outcome": "stands", "skeptic_audit_ids": [ELSEWHERE]},
        {"outcome": "stands", "skeptic_audit_ids": [OWN]},
        {"outcome": "stands", "skeptic_audit_ids": [SHELL, VOLUNTARY, HOOK]},
        {"outcome": "agreed", "skeptic_audit_ids": [SKEPTIC]},
        "stands",
    ],
    ids=["not in trail", "own evidence", "self-reported", "unknown outcome", "text"],
)
def test_a_challenge_without_the_skeptics_tool_output_is_not_stored(case, challenged):
    result = _record({**FINDING, "challenged": challenged})
    assert "challenged" not in _stored(case, result)
    assert "will show as not challenged" in result["warning"]


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
        ({**WITHDRAWN, "contradiction": ""}, [SKEPTIC, SKEPTIC_2]),
        ({**WITHDRAWN, "contradiction": "  "}, [SKEPTIC, SKEPTIC_2]),
        ({**WITHDRAWN, "skeptic_audit_ids": [ELSEWHERE]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [OWN]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [SHELL]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [VOLUNTARY]}, []),
        ({**WITHDRAWN, "skeptic_audit_ids": [HOOK]}, []),
    ],
    ids=[
        "no contradiction",
        "blank contradiction",
        "not in trail",
        "own evidence",
        "shell",
        "voluntary",
        "hook",
    ],
)
def test_an_incomplete_withdrawal_is_staged_with_its_marker(case, challenged, ids):
    result = _record({**FINDING, "challenged": challenged})
    marker = _stored(case, result)["challenged"]
    assert marker["outcome"] == "withdrawn"
    assert marker["skeptic_audit_ids"] == ids
    assert "Withdrawal refused" in result["warning"]


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
        ({**WITHDRAWN, "contradiction": ""}, "Withdrawal refused"),
        (
            {**WITHDRAWN, "skeptic_audit_ids": [ELSEWHERE]},
            "not tool output in this case's audit trail",
        ),
    ],
    ids=["no contradiction", "not in trail"],
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
        "The finding's own audit ids don't count as the skeptic's re-run. "
        f"Skeptic audit id(s) {ELSEWHERE}, {other} removed, not tool output in this "
        "case's audit trail. Withdrawal refused: it needs the skeptic's tool output and "
        "the output that contradicts the observation. Staged for the examiner."
    )
    assert f"skeptic audit id(s) {ELSEWHERE}, {other} removed" in result["warning"]


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
