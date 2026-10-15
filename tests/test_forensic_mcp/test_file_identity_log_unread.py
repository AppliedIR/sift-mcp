"""record_finding's audit scans skip the file-identity log, and say so.

One hash job's results are one line of audit/file-identity.jsonl, and a big
job's line runs to hundreds of MB: every scan that parsed each line of every
audit log held several times that in memory. The scans now leave that log
out. A file-identity id a finding cites is checked only where its artifacts
load the case's provenance; elsewhere it's named as not checked, never
reported as not found, and on its own it isn't an evidence trail.

The real forensic-mcp server runs in-process on scratch cases under a scratch
HOME.
"""

from __future__ import annotations

import json
from pathlib import Path

import forensic_mcp.case.manager as fmanager
import pytest

from .test_finding_challenge import (  # noqa: F401 (case and home are fixtures)
    FINDING,
    OWN,
    WITHDRAWN,
    _entries,
    _record,
    case,
    home,
)

FI = "fileidentity-tester-20261007-006"  # a hash job's results
NOT_CHECKED = f"Audit ids not checked (the file-identity log isn't read here): {FI}"


@pytest.fixture
def fi_case(case):  # noqa: F811
    (case / "audit" / "file-identity.jsonl").write_text(
        json.dumps({"audit_id": FI, "tool": "hash_complete", "job_id": "hash-1",
                    "files": [{"path": "evidence/a.evtx", "sha256": "0" * 64}]})
        + "\n"
    )  # fmt: skip
    return case


@pytest.fixture
def opened(monkeypatch):
    """The audit files the scanners open, by name."""
    names: list[str] = []
    real = fmanager._audit_text

    def spy(path: Path):
        names.append(Path(path).name)
        return real(path)

    monkeypatch.setattr(fmanager, "_audit_text", spy)
    return names


# --- the log isn't read ------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [{}, {"supporting_commands": [{"command": "grep 4624 a.csv", "purpose": "logons"}]}],
    ids=["audit ids", "supporting commands"],
)  # fmt: skip
def test_a_finding_doesnt_open_the_file_identity_log(fi_case, opened, extra):
    result = _record(FINDING, **extra)
    assert result["status"] == "STAGED", result
    assert "sift-mcp.jsonl" in opened
    assert "file-identity.jsonl" not in opened


def test_a_withdrawal_doesnt_open_the_file_identity_log(fi_case, opened):
    result = _record({**FINDING, "challenged": WITHDRAWN})
    assert result["status"] == "WITHDRAWN", result
    assert opened and "file-identity.jsonl" not in opened


# --- a cited file-identity id is named as not checked ----------------------------------


def test_a_file_identity_id_alone_is_not_an_evidence_trail(fi_case):
    result = _record({**FINDING, "audit_ids": [FI]})
    assert result["status"] == "REJECTED", result
    assert NOT_CHECKED in result["error"]
    assert (
        not (fi_case / "findings.json").is_file()
        or FI not in (fi_case / "findings.json").read_text()
    )


def test_a_file_identity_id_beside_tool_output_is_staged_with_a_warning(fi_case):
    result = _record({**FINDING, "audit_ids": [OWN, FI]})
    assert result["status"] == "STAGED", result
    assert NOT_CHECKED in result["warning"]


def test_a_withdrawal_names_a_file_identity_id_as_not_checked(fi_case):
    result = _record({**FINDING, "audit_ids": [OWN, FI], "challenged": WITHDRAWN})
    assert result["status"] == "WITHDRAWN", result
    assert result["audit_ids"] == [OWN]
    assert (
        "Audit ids not checked (the file-identity log isn't read here), so not "
        f"listed: {FI}"
    ) in result["message"]
    assert "not in this case's audit trail" not in result["message"]
    assert _entries(fi_case)[-1]["result_summary"]["audit_ids"] == [OWN]


def test_the_classifier_marks_a_file_identity_id_unchecked_unless_loaded(fi_case):
    m = fmanager.CaseManager()
    alone = m._classify_provenance([FI], fi_case)
    assert alone["unchecked"] == [FI] and alone["none"] == []
    assert alone["summary"] == "NONE"
    mixed = m._classify_provenance([OWN, FI], fi_case)
    assert mixed["mcp"] == [OWN] and mixed["unchecked"] == [FI]
    assert mixed["summary"] == "MIXED"
    loaded = m._classify_provenance([FI], fi_case, {FI: {}})
    assert loaded["mcp"] == [FI] and loaded["summary"] == "MCP"


def test_an_unknown_id_is_still_not_found(fi_case):
    other = "sift-tester-20261007-099"
    result = _record({**FINDING, "audit_ids": [OWN, other]})
    assert result["status"] == "STAGED", result
    assert "not checked" not in str(result.get("warning"))


# --- guard: where artifacts load the case, the id is checked -------------------------


def test_artifacts_loading_the_case_check_a_file_identity_id(fi_case):
    artifact = {"source": "evidence/a.evtx", "extraction": "EvtxECmd -f a.evtx",
                "content": "4624", "content_type": "log_entry", "audit_id": OWN}  # fmt: skip
    result = _record({**FINDING, "audit_ids": [OWN, FI]}, artifacts=[artifact])
    assert result["status"] == "STAGED", result
    assert "not checked" not in str(result.get("warning"))
