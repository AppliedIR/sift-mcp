"""Unit tests for case-mcp server: _resolve_case_dir, tool handlers, security."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from case_mcp.server import _resolve_case_dir, create_server


def _parse(result):
    """Parse tool result — handles both dict returns and legacy JSON strings."""
    if isinstance(result, (dict, list)):
        return result
    return json.loads(result)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure no env leakage between tests."""
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    monkeypatch.delenv("VHIR_CASES_DIR", raising=False)
    monkeypatch.delenv("VHIR_ACTIVE_CASE", raising=False)
    monkeypatch.delenv("VHIR_EXAMINER", raising=False)
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal case directory and wire env vars."""
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc)
    case_id = f"TEST-{ts.strftime('%Y%m%d%H%M%S')}"
    cd = tmp_path / case_id
    cd.mkdir()
    for sub in ("evidence", "extractions", "reports", "audit"):
        (cd / sub).mkdir()
    meta = {
        "case_id": case_id,
        "name": "Unit Test Case",
        "status": "open",
        "examiner": "tester",
        "created": ts.isoformat(),
    }
    (cd / "CASE.yaml").write_text(yaml.dump(meta, default_flow_style=False))
    (cd / "findings.json").write_text("[]")
    (cd / "timeline.json").write_text("[]")
    (cd / "todos.json").write_text("[]")
    (cd / "evidence.json").write_text('{"files": []}')
    (cd / "actions.jsonl").write_text("")

    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("VHIR_CASE_DIR", str(cd))
    monkeypatch.setenv("VHIR_ACTIVE_CASE", case_id)
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(cd / "audit"))
    # Prevent _resolve_case_dir from reading the real ~/.vhir/active_case
    import case_mcp.server as _cs

    monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
    return {"case_id": case_id, "path": cd, "parent": tmp_path}


@pytest.fixture
def server(case_dir):
    """Create a case-mcp server and return its tool callables."""
    srv = create_server()
    tools = {}
    for name, tool_obj in srv._tool_manager._tools.items():
        tools[name] = tool_obj.fn
    return tools


# ---------------------------------------------------------------------------
# _resolve_case_dir
# ---------------------------------------------------------------------------


class TestResolveCaseDir:
    def test_explicit_case_id(self, tmp_path, monkeypatch):
        import case_mcp.server as _cs

        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
        case_id = "INC-2026-test"
        (tmp_path / case_id).mkdir()
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
        result = _resolve_case_dir(case_id)
        assert result == tmp_path / case_id

    def test_explicit_case_id_not_found(self, tmp_path, monkeypatch):
        import case_mcp.server as _cs

        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Case not found"):
            _resolve_case_dir("nonexistent")

    def test_env_var_fallback(self, tmp_path, monkeypatch):
        """VHIR_CASE_DIR is used when active_case file doesn't exist."""
        import case_mcp.server as _cs

        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
        monkeypatch.setenv("VHIR_CASE_DIR", str(tmp_path))
        assert _resolve_case_dir() == tmp_path

    def test_env_var_missing_dir(self, tmp_path, monkeypatch):
        import case_mcp.server as _cs

        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
        monkeypatch.setenv("VHIR_CASE_DIR", "/nonexistent/path/xyz")
        with pytest.raises(ValueError, match="does not exist"):
            _resolve_case_dir()

    def test_active_case_file_absolute(self, tmp_path, monkeypatch):
        import case_mcp.server as _cs

        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        case_dir = tmp_path / "my-case"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: my-case\nstatus: open\n")
        active_file = tmp_path / "active_case"
        active_file.write_text(str(case_dir))
        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", active_file)
        result = _resolve_case_dir()
        assert result == case_dir

    def test_active_case_file_relative(self, tmp_path, monkeypatch):
        import case_mcp.server as _cs

        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        case_id = "INC-2026-rel"
        (tmp_path / case_id).mkdir()
        (tmp_path / case_id / "CASE.yaml").write_text(
            "case_id: " + case_id + "\nstatus: open\n"
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
        active_file = tmp_path / "active_case"
        active_file.write_text(case_id)
        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", active_file)
        result = _resolve_case_dir()
        assert result == tmp_path / case_id

    def test_no_active_case(self, tmp_path, monkeypatch):
        import case_mcp.server as _cs

        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        with pytest.raises(ValueError, match="No active case"):
            _resolve_case_dir()

    def test_active_file_traversal_rejected(self, tmp_path, monkeypatch):
        import case_mcp.server as _cs

        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        active_file = tmp_path / "active_case"
        active_file.write_text("../etc/passwd")
        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", active_file)
        with pytest.raises(ValueError, match="Invalid case ID"):
            _resolve_case_dir()

    # --- Security: path traversal ---

    def test_traversal_dotdot_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Invalid case ID"):
            _resolve_case_dir("../etc/passwd")

    def test_traversal_slash_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Invalid case ID"):
            _resolve_case_dir("foo/bar")

    def test_traversal_backslash_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Invalid case ID"):
            _resolve_case_dir("foo\\bar")


# ---------------------------------------------------------------------------
# Tool handlers — lifecycle
# ---------------------------------------------------------------------------


class TestCaseInit:
    def test_creates_case(self, case_dir, monkeypatch):
        monkeypatch.setenv("VHIR_EXAMINER", "tester")
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_init"](name="Incident Alpha"))
        assert "case_id" in result
        assert "case_dir" in result
        assert result["case_id"].startswith("INC-")

    def test_returns_error_on_failure(self, case_dir, monkeypatch):
        monkeypatch.setenv("VHIR_EXAMINER", "tester")
        with patch("case_mcp.server._case_init_data", side_effect=ValueError("bad")):
            srv = create_server()
            tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
            result = _parse(tools["case_init"](name="fail"))
        assert "error" in result
        assert "bad" in result["error"]

    def test_a_new_case_encourages_a_host_list(self, case_dir, monkeypatch):
        from sift_common.host_gate import HOST_LIST_HINT

        monkeypatch.setenv("VHIR_EXAMINER", "tester")
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_init"](name="Incident Alpha"))
        assert result["host_list_hint"] == HOST_LIST_HINT


class TestCaseActivate:
    def test_activates_case(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_activate"](case_id=case_dir["case_id"]))
        assert "error" not in result
        assert "case_dir" in result

    def test_nonexistent_case(self, case_dir, monkeypatch):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_activate"](case_id="NONEXISTENT-999"))
        assert "error" in result


class TestCaseList:
    def test_lists_cases(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_list"]())
        assert isinstance(result, dict), f"Expected dict, got {type(result)}"
        assert "error" not in result


class TestCaseStatus:
    def test_active_case_status(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_status"]())
        assert "error" not in result

    def test_explicit_case_id(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_status"](case_id=case_dir["case_id"]))
        assert "error" not in result

    def test_no_case_returns_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        import case_mcp.server as _cs

        monkeypatch.setattr(_cs, "_ACTIVE_CASE_FILE", tmp_path / "no_active_case")
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_status"]())
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool handlers — evidence
# ---------------------------------------------------------------------------


class TestEvidenceRegister:
    def test_registers_file(self, case_dir):
        evidence_file = case_dir["path"] / "evidence" / "disk.e01"
        evidence_file.write_text("fake evidence content")
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(
            tools["evidence_register"](
                path=str(evidence_file), description="Test disk image"
            )
        )
        assert "error" not in result

    def test_registering_evidence_encourages_a_host_list_until_one_is_loaded(
        self, case_dir
    ):
        from sift_common import host_proposal
        from sift_common.host_gate import HOST_LIST_HINT

        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        first = case_dir["path"] / "evidence" / "a.e01"
        first.write_text("fake evidence content")
        result = _parse(tools["evidence_register"](path=str(first)))
        assert result["host_list_hint"] == HOST_LIST_HINT
        host_proposal.upload_host_list(case_dir["path"], "WKS01\n", "tester")
        second = case_dir["path"] / "evidence" / "b.e01"
        second.write_text("more fake evidence")
        result = _parse(tools["evidence_register"](path=str(second)))
        assert "error" not in result and "host_list_hint" not in result

    def test_a_file_registered_here_is_marked_as_the_ais(self, case_dir):
        evidence_file = case_dir["path"] / "evidence" / "c.csv"
        evidence_file.write_text("Computer\nWKS01\n")
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        _parse(tools["evidence_register"](path=str(evidence_file)))
        files = json.loads((case_dir["path"] / "evidence.json").read_text())["files"]
        assert [f.get("registered_via") for f in files] == ["mcp"]

    def test_missing_file_returns_error(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["evidence_register"](path="/nonexistent/file.e01"))
        assert "error" in result


class TestEvidenceList:
    def test_empty_list(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["evidence_list"]())
        assert "error" not in result


class TestEvidenceVerify:
    def test_empty_verify(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["evidence_verify"]())
        assert "error" not in result


# ---------------------------------------------------------------------------
# Tool handlers — export / import
# ---------------------------------------------------------------------------


class TestExportBundle:
    def test_export_empty_case(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["export_bundle"]())
        assert "error" not in result

    def test_export_with_since(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["export_bundle"](since="2026-01-01T00:00:00"))
        assert "error" not in result


class TestImportBundle:
    def test_missing_bundle_file(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path="/tmp/nonexistent.json"))
        assert "error" in result
        assert "not found" in result["error"]

    def test_bundle_outside_allowed_dirs(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path="/etc/passwd"))
        assert "error" in result
        assert "must be within" in result["error"]

    def test_invalid_json_bundle(self, case_dir, tmp_path):
        bad_bundle = tmp_path / "bad.json"
        bad_bundle.write_text("not valid json {{{")
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path=str(bad_bundle)))
        assert "error" in result

    def test_valid_bundle_import(self, case_dir, tmp_path):
        bundle = {
            "findings": [],
            "timeline": [],
            "examiner": "other-user",
            "exported_at": "2026-01-01T00:00:00",
        }
        bundle_file = tmp_path / "bundle.json"
        bundle_file.write_text(json.dumps(bundle))
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path=str(bundle_file)))
        assert "error" not in result

    def _bundle(self, tmp_path):
        bundle = {
            "findings": [{"id": "F-other-001", "title": "t", "status": "DRAFT",
                          "modified_at": "2026-01-01T00:00:00+00:00"}],
            "timeline": [],
            "ledger": {"keys": [{"examiner": "other", "fingerprint": "SHA256:x",
                                "chain_id": "0" * 16, "first_seq": 1, "last_seq": 1,
                                "label": "not registered here"}],
                       "heads": [{"chain_id": "0" * 16, "seq": 1, "hash": "a" * 64}],
                       "chains": {"0" * 16: "{}\n"}},
        }  # fmt: skip
        path = tmp_path / "bundle.json"
        path.write_text(json.dumps(bundle))
        return path

    def test_an_import_adds_no_chain_and_returns_the_bundle_s_anchors(
        self, case_dir, tmp_path
    ):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path=str(self._bundle(tmp_path))))
        assert result["ledger"]["keys"][0]["fingerprint"] == "SHA256:x"
        assert not (case_dir["path"] / "ledger").exists()

    def test_an_imported_finding_needs_no_challenge_and_gets_none(
        self, case_dir, tmp_path
    ):
        """The challenge record_finding requires is never asked of an import:
        the finding is stored as the bundle has it, nothing written into it
        (the portal shows it "Not challenged (imported)")."""
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path=str(self._bundle(tmp_path))))
        assert "error" not in result, result
        stored = json.loads((case_dir["path"] / "findings.json").read_text())
        imported = [f for f in stored if f.get("id") == "F-other-001"]
        assert imported and "challenged" not in imported[0], stored

    def test_an_import_waits_for_the_case_lock(self, case_dir, tmp_path):
        import threading
        import time

        from vhir_cli import ledger
        from vhir_cli.case_io import case_id_of

        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        path = self._bundle(tmp_path)
        held, release = threading.Event(), threading.Event()

        def commit():
            with ledger.case_lock(case_id_of(case_dir["path"])):
                held.set()
                release.wait(5)

        t = threading.Thread(target=commit)
        t.start()
        held.wait(5)
        threading.Timer(0.3, release.set).start()
        start = time.monotonic()
        result = _parse(tools["import_bundle"](bundle_path=str(path)))
        t.join()
        assert "error" not in result and time.monotonic() - start >= 0.25

    def test_a_missing_lock_folder_merges_nothing(
        self, case_dir, tmp_path, monkeypatch
    ):
        from vhir_cli import ledger

        monkeypatch.setattr(ledger, "LEDGER_DIR", tmp_path / "not-made")
        before = (case_dir["path"] / "findings.json").read_bytes()
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path=str(self._bundle(tmp_path))))
        assert (
            "vhir update" in result["error"] and "Nothing was merged" in result["error"]
        )
        assert (case_dir["path"] / "findings.json").read_bytes() == before

    @staticmethod
    def _audited(case_dir) -> list:
        lines = [json.loads(ln) for f in (case_dir["path"] / "audit").glob("*.jsonl")
                 for ln in f.read_text().splitlines() if ln.strip()]  # fmt: skip
        return [e for e in lines if e.get("tool") == "import_bundle"]

    # beyond every json decoder: 3.10 stops near 1000 levels, 3.12 and 3.13 near 10,000
    @pytest.mark.parametrize("levels", [20_000, 100_000])
    def test_a_bundle_too_deep_to_decode_is_refused_by_name_and_audited(
        self, case_dir, tmp_path, levels
    ):
        from vhir_cli.case_io import bundle_too_deep

        finding = {"id": "F-other-001", "title": "t", "status": "DRAFT",
                   "modified_at": "2026-01-01T00:00:00+00:00"}  # fmt: skip
        text = json.dumps(finding)[:-1] + ', "x": ' + "[" * levels + "]" * levels + "}"
        path = tmp_path / "deep.json"
        path.write_text('{"case_id": "INC-C", "findings": [' + text + "]}")
        before = {n: (case_dir["path"] / n).read_bytes()
                  for n in ("findings.json", "timeline.json")}  # fmt: skip
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path=str(path)))
        assert result == bundle_too_deep()
        (entry,) = self._audited(case_dir)
        assert entry["params"] == {"bundle_path": str(path)}
        assert bundle_too_deep()["message"] in json.dumps(entry)
        after = {n: (case_dir["path"] / n).read_bytes() for n in before}
        assert after == before

    def test_a_bundle_100_levels_deep_still_merges_and_is_audited(
        self, case_dir, tmp_path
    ):
        inner: list = []
        for _ in range(98):  # the item is level 1, its field's lists 2..100
            inner = [inner]
        finding = {"id": "F-other-001", "title": "t", "status": "DRAFT",
                   "modified_at": "2026-01-01T00:00:00+00:00", "x": inner}  # fmt: skip
        path = tmp_path / "deep.json"
        path.write_text(json.dumps({"case_id": "INC-C", "findings": [finding]}))
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path=str(path)))
        assert result["status"] == "merged" and result["findings"]["added"] == 1
        assert len(self._audited(case_dir)) == 1


# ---------------------------------------------------------------------------
# Tool handlers — audit
# ---------------------------------------------------------------------------


class TestAuditSummary:
    def test_returns_summary(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["audit_summary"]())
        assert "error" not in result


# ---------------------------------------------------------------------------
# Tool handlers — action logging
# ---------------------------------------------------------------------------


class TestRecordAction:
    def test_records_action(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["record_action"](description="Ran volatility pslist"))
        assert result["status"] == "recorded"
        assert "timestamp" in result
        # Verify JSONL was written
        content = (case_dir["path"] / "actions.jsonl").read_text()
        assert "Ran volatility pslist" in content

    def test_records_with_tool_and_command(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(
            tools["record_action"](
                description="Analyzed registry",
                tool="RECmd.exe",
                command="RECmd.exe -f NTUSER.DAT --csv out",
            )
        )
        assert result["status"] == "recorded"
        content = (case_dir["path"] / "actions.jsonl").read_text()
        entry = json.loads(content.strip().split("\n")[-1])
        assert entry["tool"] == "RECmd.exe"
        assert entry["command"] == "RECmd.exe -f NTUSER.DAT --csv out"

    def test_omits_empty_tool_and_command(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        tools["record_action"](description="Simple note")
        content = (case_dir["path"] / "actions.jsonl").read_text()
        entry = json.loads(content.strip().split("\n")[-1])
        assert "tool" not in entry
        assert "command" not in entry


class TestLogReasoning:
    def test_logs_reasoning(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(
            tools["log_reasoning"](text="Hypothesis: lateral movement via PsExec")
        )
        assert result["status"] == "logged"

    def test_audit_entry_written(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        tools["log_reasoning"](text="Test reasoning")
        # Check audit JSONL
        audit_file = case_dir["path"] / "audit" / "case-mcp.jsonl"
        assert audit_file.exists()
        entries = [
            json.loads(l)
            for l in audit_file.read_text().strip().split("\n")
            if l.strip()
        ]
        reasoning_entries = [e for e in entries if e["tool"] == "log_reasoning"]
        assert len(reasoning_entries) >= 1
        assert reasoning_entries[0]["source"] == "orchestrator"


class TestLogExternalAction:
    def test_logs_external_action(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(
            tools["log_external_action"](
                command="grep -r 'password' /evidence/",
                output_summary="Found 3 matches in config files",
                purpose="Search for hardcoded credentials",
            )
        )
        assert result["status"] == "logged"
        assert result["audit_id"].startswith("case-")
        assert result["declared"] is True

    def test_audit_entry_source(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        tools["log_external_action"](
            command="ls", output_summary="files", purpose="listing"
        )
        audit_file = case_dir["path"] / "audit" / "case-mcp.jsonl"
        entries = [
            json.loads(l)
            for l in audit_file.read_text().strip().split("\n")
            if l.strip()
        ]
        ext_entries = [e for e in entries if e["tool"] == "log_external_action"]
        assert ext_entries[0]["source"] == "orchestrator_voluntary"


# ---------------------------------------------------------------------------
# Security: path traversal via tool parameters
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_case_activate_traversal(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_activate"](case_id="../../etc/passwd"))
        assert "error" in result

    def test_case_status_traversal(self, case_dir):
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_status"](case_id="../../../etc/shadow"))
        assert "error" in result

    def test_evidence_register_outside_case(self, case_dir):
        """evidence_register with a path outside the case should fail."""
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(
            tools["evidence_register"](path="/etc/passwd", description="system file")
        )
        assert "error" in result

    def test_import_bundle_traversal(self, case_dir, tmp_path):
        """import_bundle with traversal path should fail or return error."""
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["import_bundle"](bundle_path="../../etc/passwd"))
        assert "error" in result


# ---------------------------------------------------------------------------
# Server creation
# ---------------------------------------------------------------------------


class TestCreateServer:
    def test_server_has_16_tools(self, case_dir):
        srv = create_server()
        tool_names = list(srv._tool_manager._tools.keys())
        assert len(tool_names) == 16

    def test_expected_tool_names(self, case_dir):
        srv = create_server()
        tool_names = set(srv._tool_manager._tools.keys())
        expected = {
            "case_init",
            "case_activate",
            "case_list",
            "case_status",
            "evidence_register",
            "evidence_list",
            "evidence_verify",
            "export_bundle",
            "import_bundle",
            "audit_summary",
            "record_action",
            "log_reasoning",
            "log_external_action",
            "backup_case",
            "open_case_dashboard",
            "prepare_host_list",
        }
        assert tool_names == expected

    def test_server_has_audit_writer(self, case_dir):
        srv = create_server()
        assert hasattr(srv, "_audit")
        assert srv._audit.mcp_name == "case-mcp"


class TestOpenCaseDashboard:
    """Tests for the open_case_dashboard tool."""

    def _call_tool(self, case_dir):
        srv = create_server()
        tool_fn = srv._tool_manager._tools["open_case_dashboard"].fn
        return _parse(tool_fn())

    def test_missing_gateway_yaml(self, case_dir, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "nohome")
        srv = create_server()
        tool_fn = srv._tool_manager._tools["open_case_dashboard"].fn
        result = _parse(tool_fn())
        assert "error" in result
        assert "gateway.yaml" in result["error"]

    def test_builds_url_no_auth(self, case_dir, tmp_path, monkeypatch):
        """No api_keys → URL without token fragment."""
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        config = {"gateway": {"host": "127.0.0.1", "port": 4508}}
        (home / ".vhir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open") as mock_open:
            result = self._call_tool(case_dir)

        assert result["url"] == "http://127.0.0.1:4508/portal/"
        assert result["status"] == "opened"
        mock_open.assert_called_once_with("http://127.0.0.1:4508/portal/")

    def test_builds_url_with_token(self, case_dir, tmp_path, monkeypatch):
        """api_keys present → URL includes #token= fragment."""
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        config = {
            "gateway": {"host": "10.0.0.5", "port": 9000},
            "api_keys": {"vhir_gw_testtoken": {"examiner": "alice", "role": "lead"}},
        }
        (home / ".vhir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        # Token stripped from MCP response (LLM should not see bearer token)
        assert result["url"] == "http://10.0.0.5:9000/portal/"

    def test_picks_correct_examiner_token(self, case_dir, tmp_path, monkeypatch):
        """Multi-examiner: picks the token matching current examiner."""
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        config = {
            "gateway": {"host": "127.0.0.1", "port": 4508},
            "api_keys": {
                "vhir_gw_alice": {"examiner": "alice", "role": "lead"},
                "vhir_gw_bob": {"examiner": "bob", "role": "examiner"},
            },
        }
        (home / ".vhir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.setenv("VHIR_EXAMINER", "bob")

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        # Token stripped from MCP response (LLM should not see bearer token)
        assert "#token=" not in result["url"]
        assert "portal/" in result["url"]

    def test_falls_back_to_first_key(self, case_dir, tmp_path, monkeypatch):
        """Examiner not in api_keys → falls back to first key."""
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        config = {
            "gateway": {"host": "127.0.0.1", "port": 4508},
            "api_keys": {"vhir_gw_only": {"examiner": "alice", "role": "lead"}},
        }
        (home / ".vhir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.setenv("VHIR_EXAMINER", "unknown_user")

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        # Token stripped from MCP response (LLM should not see bearer token)
        assert "#token=" not in result["url"]
        assert "portal/" in result["url"]

    def test_tls_uses_https(self, case_dir, tmp_path, monkeypatch):
        """TLS configured → scheme is https."""
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        config = {
            "gateway": {
                "host": "sift.local",
                "port": 4508,
                "tls": {"certfile": "/etc/ssl/cert.pem", "keyfile": "/etc/ssl/key.pem"},
            },
        }
        (home / ".vhir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        assert result["url"].startswith("https://")

    def test_zero_host_becomes_localhost(self, case_dir, tmp_path, monkeypatch):
        """0.0.0.0 → 127.0.0.1 for browser access."""
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        config = {"gateway": {"host": "0.0.0.0", "port": 4508}}
        (home / ".vhir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        assert "127.0.0.1" in result["url"]
        assert "0.0.0.0" not in result["url"]

    def test_browser_failure_returns_url(self, case_dir, tmp_path, monkeypatch):
        """webbrowser.open fails → status=browser_failed, URL still returned."""
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        config = {"gateway": {"host": "127.0.0.1", "port": 4508}}
        (home / ".vhir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open", side_effect=OSError("no display")):
            result = self._call_tool(case_dir)

        assert result["status"] == "browser_failed"
        assert result["url"] == "http://127.0.0.1:4508/portal/"


class TestWintoolsSharingBeforeTheGroupApplies:
    """A gateway started before its user joined the sift group can't chgrp.

    Activation still repoints the share and tells wintools, and says the
    group step didn't apply.
    """

    @pytest.fixture
    def sharing(self, case_dir, monkeypatch):
        import grp
        import os
        import types

        import case_mcp.server as _cs

        monkeypatch.setenv("HOME", str(case_dir["parent"]))
        calls = []
        monkeypatch.setattr(_cs, "_wintools_configured", lambda: True)
        monkeypatch.setattr(
            _cs, "_repoint_samba_share", lambda p: calls.append(("repoint", p))
        )
        monkeypatch.setattr(
            _cs,
            "notify_wintools_case_activated",
            lambda c: calls.append(("notify", c)) or True,
        )
        monkeypatch.setattr(
            grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=4242)
        )

        def chown(path, uid, gid):
            raise PermissionError(1, "Operation not permitted", path)

        monkeypatch.setattr(os, "chown", chown)
        srv = create_server()
        return {n: t.fn for n, t in srv._tool_manager._tools.items()}, calls

    def test_activate_repoints_and_notifies_with_a_warning(self, sharing, case_dir):
        tools, calls = sharing
        result = _parse(tools["case_activate"](case_id=case_dir["case_id"]))
        assert result["wintools_shared"] is True
        assert calls == [("repoint", case_dir["path"]), ("notify", case_dir["case_id"])]
        assert any("Group permissions not applied" in w for w in result["warnings"])

    def test_init_repoints_and_notifies_with_a_warning(self, sharing):
        tools, calls = sharing
        result = _parse(
            tools["case_init"](name="Shared before the group", share_wintools=True)
        )
        assert result["wintools_shared"] is True
        assert [c[0] for c in calls] == ["repoint", "notify"]
        assert any("Group permissions not applied" in w for w in result["warnings"])
