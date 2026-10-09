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


def _sha(p):
    import hashlib

    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_its_files_are_recorded_with_their_place_and_hash(case):
    import os

    z = case / "evidence" / "mem.7z"
    z.write_bytes(b"ARCHIVE")
    registry = {"files": [{"path": str(z.resolve()), "sha256": "a" * 64}]}
    (case / "evidence.json").write_text(json.dumps(registry))
    out = case / "extractions" / "b1"
    out.mkdir()
    s1 = out / "sample1.raw"
    s1.write_bytes(b"S1")
    s2 = out / "sample2.raw"
    s2.write_bytes(b"S2")
    _log(input_files=[str(z), str(s1)], output_files=[str(s2)])
    (e,) = _entries(case)
    # the registered archive links by its path to the registry's hash, unread
    assert e["input_registered"] == [{"path": str(z.resolve()), "sha256": "a" * 64}]
    zin, s1in = e["inputs"]
    assert zin["realpath"] == str(z.resolve()) and "sha256" not in zin
    assert zin["st_dev"] == os.stat(z).st_dev
    assert s1in["sha256"] == _sha(s1) and s1in["st_dev"] == os.stat(s1).st_dev
    (o,) = e["outputs"]
    assert o["realpath"] == str(s2.resolve()) and o["sha256"] == _sha(s2)
    assert o["st_dev"] == os.stat(s2).st_dev and o["size"] == 2
    assert e["input_files"] == [str(z.resolve()), str(s1.resolve())]
    assert e["input_sha256s"] == ["a" * 64, _sha(s1)]


def test_a_large_file_is_hashed_in_the_background(case, monkeypatch):
    from sift_common import file_identity as fi

    big = case / "extractions" / "big.raw"
    big.write_bytes(b"BIG")
    pending = fi.Pending(str(big), "hash-0123456789abcdef")
    monkeypatch.setattr(fi, "hash_for_call", lambda *a, **k: pending)
    _log(input_files=[str(big)], output_files=[str(big)])
    (e,) = _entries(case)
    assert e["inputs"][0]["sha256"] == "pending:hash-0123456789abcdef"
    assert e["outputs"][0]["sha256"] == "pending:hash-0123456789abcdef"


def test_a_file_that_isnt_there_is_kept_as_named(case):
    _log(input_files=["/nonexistent/a.raw"])
    (e,) = _entries(case)
    (i,) = e["inputs"]
    assert i["path"] == "/nonexistent/a.raw" and "st_dev" not in i and "sha256" not in i


def test_the_remnux_guidance_asks_for_each_step_to_be_logged(tmp_path, monkeypatch):
    from case_mcp.server import _build_platform_capabilities

    (tmp_path / ".claude.json").write_text(
        json.dumps({"mcpServers": {"remnux-mcp": {}}})
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    guidance = _build_platform_capabilities()["investigation_guidance"]
    (line,) = [x for x in guidance.splitlines() if "REMnux" in x]
    assert "log_external_action" in line
    doc = create_server()._tool_manager._tools["log_external_action"].fn.__doc__
    assert "REMnux" in doc
