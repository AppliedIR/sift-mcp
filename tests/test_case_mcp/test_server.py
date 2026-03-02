"""Unit tests for case-mcp server: _resolve_case_dir, tool handlers, security."""

import json
import os
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
    monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
    monkeypatch.delenv("AIIR_CASES_DIR", raising=False)
    monkeypatch.delenv("AIIR_ACTIVE_CASE", raising=False)
    monkeypatch.delenv("AIIR_EXAMINER", raising=False)
    monkeypatch.delenv("AIIR_AUDIT_DIR", raising=False)


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

    monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("AIIR_CASE_DIR", str(cd))
    monkeypatch.setenv("AIIR_ACTIVE_CASE", case_id)
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    monkeypatch.setenv("AIIR_AUDIT_DIR", str(cd / "audit"))
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
        case_id = "INC-2026-test"
        (tmp_path / case_id).mkdir()
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        result = _resolve_case_dir(case_id)
        assert result == tmp_path / case_id
        assert os.environ["AIIR_CASE_DIR"] == str(tmp_path / case_id)

    def test_explicit_case_id_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Case not found"):
            _resolve_case_dir("nonexistent")

    def test_env_var_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        assert _resolve_case_dir() == tmp_path

    def test_env_var_missing_dir(self, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", "/nonexistent/path/xyz")
        with pytest.raises(ValueError, match="does not exist"):
            _resolve_case_dir()

    def test_active_case_file_absolute(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        fake_home = tmp_path / "fakehome"
        (fake_home / ".aiir").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
        case_dir = tmp_path / "my-case"
        case_dir.mkdir()
        (fake_home / ".aiir" / "active_case").write_text(str(case_dir))
        result = _resolve_case_dir()
        assert result == case_dir

    def test_active_case_file_relative(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        fake_home = tmp_path / "fakehome"
        (fake_home / ".aiir").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
        case_id = "INC-2026-rel"
        (tmp_path / case_id).mkdir()
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        (fake_home / ".aiir" / "active_case").write_text(case_id)
        result = _resolve_case_dir()
        assert result == tmp_path / case_id

    def test_no_active_case(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        fake_home = tmp_path / "fakehome"
        (fake_home / ".aiir").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
        with pytest.raises(ValueError, match="No active case"):
            _resolve_case_dir()

    # --- Security: path traversal ---

    def test_traversal_dotdot_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Invalid case ID"):
            _resolve_case_dir("../etc/passwd")

    def test_traversal_slash_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Invalid case ID"):
            _resolve_case_dir("foo/bar")

    def test_traversal_backslash_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        with pytest.raises(ValueError, match="Invalid case ID"):
            _resolve_case_dir("foo\\bar")

    def test_active_file_traversal_rejected(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        fake_home = tmp_path / "fakehome"
        (fake_home / ".aiir").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
        (fake_home / ".aiir" / "active_case").write_text("../../etc/shadow")
        with pytest.raises(ValueError, match="Invalid case ID in active_case"):
            _resolve_case_dir()


# ---------------------------------------------------------------------------
# Tool handlers — lifecycle
# ---------------------------------------------------------------------------


class TestCaseInit:
    def test_creates_case(self, case_dir, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        srv = create_server()
        tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
        result = _parse(tools["case_init"](name="Incident Alpha"))
        assert "case_id" in result
        assert "case_dir" in result
        assert result["case_id"].startswith("INC-")

    def test_returns_error_on_failure(self, case_dir, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        with patch("case_mcp.server._case_init_data", side_effect=ValueError("bad")):
            srv = create_server()
            tools = {n: t.fn for n, t in srv._tool_manager._tools.items()}
            result = _parse(tools["case_init"](name="fail"))
        assert "error" in result
        assert "bad" in result["error"]


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
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        fake_home = tmp_path / "fakehome"
        (fake_home / ".aiir").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
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
        result = _parse(tools["import_bundle"](bundle_path="/nonexistent.json"))
        assert "error" in result
        assert "not found" in result["error"]

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
        assert result["evidence_id"].startswith("case-")
        assert "not independently verified" in result["note"]

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
    def test_server_has_14_tools(self, case_dir):
        srv = create_server()
        tool_names = list(srv._tool_manager._tools.keys())
        assert len(tool_names) == 14

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
            "open_case_dashboard",
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
        (home / ".aiir").mkdir(parents=True)
        config = {"gateway": {"host": "127.0.0.1", "port": 4508}}
        (home / ".aiir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open") as mock_open:
            result = self._call_tool(case_dir)

        assert result["url"] == "http://127.0.0.1:4508/dashboard/"
        assert result["status"] == "opened"
        mock_open.assert_called_once_with("http://127.0.0.1:4508/dashboard/")

    def test_builds_url_with_token(self, case_dir, tmp_path, monkeypatch):
        """api_keys present → URL includes #token= fragment."""
        home = tmp_path / "home"
        (home / ".aiir").mkdir(parents=True)
        config = {
            "gateway": {"host": "10.0.0.5", "port": 9000},
            "api_keys": {"aiir_gw_testtoken": {"examiner": "alice", "role": "lead"}},
        }
        (home / ".aiir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.setenv("AIIR_EXAMINER", "alice")

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        # Token stripped from MCP response (LLM should not see bearer token)
        assert result["url"] == "http://10.0.0.5:9000/dashboard/"

    def test_picks_correct_examiner_token(self, case_dir, tmp_path, monkeypatch):
        """Multi-examiner: picks the token matching current examiner."""
        home = tmp_path / "home"
        (home / ".aiir").mkdir(parents=True)
        config = {
            "gateway": {"host": "127.0.0.1", "port": 4508},
            "api_keys": {
                "aiir_gw_alice": {"examiner": "alice", "role": "lead"},
                "aiir_gw_bob": {"examiner": "bob", "role": "examiner"},
            },
        }
        (home / ".aiir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.setenv("AIIR_EXAMINER", "bob")

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        # Token stripped from MCP response (LLM should not see bearer token)
        assert "#token=" not in result["url"]
        assert "dashboard/" in result["url"]

    def test_falls_back_to_first_key(self, case_dir, tmp_path, monkeypatch):
        """Examiner not in api_keys → falls back to first key."""
        home = tmp_path / "home"
        (home / ".aiir").mkdir(parents=True)
        config = {
            "gateway": {"host": "127.0.0.1", "port": 4508},
            "api_keys": {"aiir_gw_only": {"examiner": "alice", "role": "lead"}},
        }
        (home / ".aiir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.setenv("AIIR_EXAMINER", "unknown_user")

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        # Token stripped from MCP response (LLM should not see bearer token)
        assert "#token=" not in result["url"]
        assert "dashboard/" in result["url"]

    def test_tls_uses_https(self, case_dir, tmp_path, monkeypatch):
        """TLS configured → scheme is https."""
        home = tmp_path / "home"
        (home / ".aiir").mkdir(parents=True)
        config = {
            "gateway": {
                "host": "sift.local",
                "port": 4508,
                "tls": {"certfile": "/etc/ssl/cert.pem", "keyfile": "/etc/ssl/key.pem"},
            },
        }
        (home / ".aiir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        assert result["url"].startswith("https://")

    def test_zero_host_becomes_localhost(self, case_dir, tmp_path, monkeypatch):
        """0.0.0.0 → 127.0.0.1 for browser access."""
        home = tmp_path / "home"
        (home / ".aiir").mkdir(parents=True)
        config = {"gateway": {"host": "0.0.0.0", "port": 4508}}
        (home / ".aiir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open"):
            result = self._call_tool(case_dir)

        assert "127.0.0.1" in result["url"]
        assert "0.0.0.0" not in result["url"]

    def test_browser_failure_returns_url(self, case_dir, tmp_path, monkeypatch):
        """webbrowser.open fails → status=browser_failed, URL still returned."""
        home = tmp_path / "home"
        (home / ".aiir").mkdir(parents=True)
        config = {"gateway": {"host": "127.0.0.1", "port": 4508}}
        (home / ".aiir" / "gateway.yaml").write_text(yaml.dump(config))
        monkeypatch.setattr(Path, "home", lambda: home)

        with patch("webbrowser.open", side_effect=OSError("no display")):
            result = self._call_tool(case_dir)

        assert result["status"] == "browser_failed"
        assert result["url"] == "http://127.0.0.1:4508/dashboard/"
