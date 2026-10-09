"""log_external_action: what the AI says it ran outside the MCP tools is
recorded as declared, never upgraded to verified, with the files it names."""

import json
from datetime import datetime, timezone

import pytest
import yaml
from case_mcp.server import create_server


@pytest.fixture
def case(tmp_path, monkeypatch):
    for var in (
        "VHIR_CASE_DIR",
        "VHIR_CASES_DIR",
        "VHIR_ACTIVE_CASE",
        "VHIR_AUDIT_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    cd = tmp_path / "CASE-1"
    for sub in ("evidence", "extractions", "audit"):
        (cd / sub).mkdir(parents=True)
    meta = {"case_id": "CASE-1", "name": "t", "status": "open", "examiner": "tester",
            "created": datetime.now(timezone.utc).isoformat()}  # fmt: skip
    (cd / "CASE.yaml").write_text(yaml.dump(meta))
    (cd / "evidence.json").write_text('{"files": []}')
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("VHIR_CASE_DIR", str(cd))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    import case_mcp.server as cs

    monkeypatch.setattr(cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
    return cd


def _log(**kw):
    tools = {n: t.fn for n, t in create_server()._tool_manager._tools.items()}
    args = {
        "command": "7z x a.7z",
        "output_summary": "2 files",
        "purpose": "extract",
        **kw,
    }
    return tools["log_external_action"](**args)


def _entries(case):
    lines = (case / "audit" / "case-mcp.jsonl").read_text().splitlines()
    return [
        e
        for e in map(json.loads, filter(None, lines))
        if e["tool"] == "log_external_action"
    ]


def test_an_external_action_is_declared(case):
    result = _log()
    (e,) = _entries(case)
    assert e["declared"] is True and result["declared"] is True


def test_a_hook_entry_never_upgrades_it_to_verified(case):
    hook = {"audit_id": "hook-tester-20261009-001", "source": "claude-code-hook"}
    (case / "audit" / "claude-code.jsonl").write_text(json.dumps(hook) + "\n")
    result = _log(hook_audit_id=hook["audit_id"])
    (e,) = _entries(case)
    assert e["declared"] is True and e["source"] == "orchestrator_voluntary"
    assert e["params"]["hook_audit_id"] == hook["audit_id"]  # a cross-reference only
    assert result["source"] == "orchestrator_voluntary"
    assert "verified" not in json.dumps(result)
