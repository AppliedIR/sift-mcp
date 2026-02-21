"""Tests for MCP server tool registration and basic calls."""

import asyncio
import json

import pytest

from forensic_mcp.server import create_server


@pytest.fixture
def server():
    return create_server()


class TestServerSetup:
    def test_server_name(self, server):
        assert server.name == "forensic-mcp"

    @pytest.mark.asyncio
    async def test_tool_count(self, server):
        tools = await server.list_tools()
        assert len(tools) >= 40

    @pytest.mark.asyncio
    async def test_expected_tools_present(self, server):
        tools = await server.list_tools()
        names = {t.name for t in tools}
        expected = {
            "init_case", "close_case", "get_case_status", "list_cases",
            "set_active_case", "record_action", "record_finding",
            "record_timeline_event", "get_findings", "get_timeline",
            "get_actions", "register_evidence", "verify_evidence_integrity",
            "list_evidence", "get_evidence_access_log",
            "get_audit_log", "get_audit_summary", "get_rules",
            "validate_finding", "get_playbook", "list_playbooks",
            "get_collection_checklist", "get_tool_guidance",
            "get_false_positive_context", "get_corroboration_suggestions",
            "log_reasoning", "log_external_action",
            "get_investigation_framework",
            "get_checkpoint_requirements", "get_evidence_standards",
            "get_confidence_definitions", "get_anti_patterns",
            "get_evidence_template",
            "add_todo", "list_todos", "update_todo", "complete_todo",
            "export_contributions", "import_contributions",
            "ingest_remote_audit", "get_team_status",
        }
        assert expected.issubset(names), f"Missing: {expected - names}"


class TestDisciplineTools:
    @pytest.mark.asyncio
    async def test_get_rules(self, server):
        result = await server.call_tool("get_rules", {})
        # FastMCP returns list of TextContent
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_validate_finding_empty(self, server):
        result = await server.call_tool("validate_finding", {"finding_json": {}})
        text = result[0].text
        data = json.loads(text)
        assert data["valid"] is False
        assert len(data["errors"]) >= 5

    @pytest.mark.asyncio
    async def test_validate_finding_valid(self, server):
        finding = {
            "title": "Test",
            "evidence_ids": ["ev-001"],
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
        }
        result = await server.call_tool("validate_finding", {"finding_json": finding})
        text = result[0].text
        data = json.loads(text)
        assert data["valid"] is True

    @pytest.mark.asyncio
    async def test_list_playbooks(self, server):
        result = await server.call_tool("list_playbooks", {})
        # call_tool returns (content_list, metadata) tuple; content has 14 playbook items
        content = result[0] if isinstance(result, tuple) else result
        assert len(content) == 14

    @pytest.mark.asyncio
    async def test_get_playbook(self, server):
        result = await server.call_tool("get_playbook", {"name": "unusual_logon"})
        text = result[0].text
        data = json.loads(text)
        assert data["name"] == "Unusual Logon Investigation"

    @pytest.mark.asyncio
    async def test_get_tool_guidance(self, server):
        result = await server.call_tool("get_tool_guidance", {"tool_name": "check_file"})
        text = result[0].text
        data = json.loads(text)
        assert "score_interpretation" in data

    @pytest.mark.asyncio
    async def test_get_corroboration_suggestions(self, server):
        result = await server.call_tool("get_corroboration_suggestions", {"finding_type": "persistence"})
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_get_checkpoint_requirements_attribution(self, server):
        result = await server.call_tool("get_checkpoint_requirements", {"action_type": "attribution"})
        text = result[0].text
        data = json.loads(text)
        assert data["min_evidence_ids"] == 3
        assert data["human_approval"] is True

    @pytest.mark.asyncio
    async def test_get_evidence_standards(self, server):
        result = await server.call_tool("get_evidence_standards", {})
        text = result[0].text
        data = json.loads(text)
        assert len(data) == 5
        for key in ("CONFIRMED", "INDICATED", "INFERRED", "UNKNOWN", "CONTRADICTED"):
            assert key in data

    @pytest.mark.asyncio
    async def test_get_confidence_definitions(self, server):
        result = await server.call_tool("get_confidence_definitions", {})
        text = result[0].text
        data = json.loads(text)
        assert len(data) == 4
        for key in ("HIGH", "MEDIUM", "LOW", "SPECULATIVE"):
            assert key in data

    @pytest.mark.asyncio
    async def test_get_anti_patterns(self, server):
        result = await server.call_tool("get_anti_patterns", {})
        # call_tool returns (content_list, metadata) — content has 6 TextContent items
        content = result[0] if isinstance(result, tuple) else result
        assert len(content) == 6
        data = json.loads(content[0].text)
        assert "name" in data

    @pytest.mark.asyncio
    async def test_get_evidence_template(self, server):
        result = await server.call_tool("get_evidence_template", {})
        text = result[0].text
        data = json.loads(text)
        for key in ("title", "evidence_ids", "observation", "interpretation", "confidence", "type"):
            assert key in data

    @pytest.mark.asyncio
    async def test_get_false_positive_context(self, server):
        result = await server.call_tool("get_false_positive_context", {
            "tool_name": "check_file", "finding_type": "unknown_file",
        })
        text = result[0].text
        data = json.loads(text)
        assert "common_benign_causes" in data
        assert "distinguishing_factors" in data

    @pytest.mark.asyncio
    async def test_get_collection_checklist_registry(self, server):
        result = await server.call_tool("get_collection_checklist", {"artifact_type": "registry"})
        text = result[0].text
        data = json.loads(text)
        assert data["artifact_type"] == "Windows Registry"
        assert len(data["files"]) > 0

    @pytest.mark.asyncio
    async def test_get_investigation_framework(self, server):
        result = await server.call_tool("get_investigation_framework", {})
        text = result[0].text
        data = json.loads(text)
        assert "principles" in data
        assert "workflow" in data
        assert "hitl_checkpoints" in data
        assert "golden_rules" in data
        assert "self_check" in data
        assert "never_decide_autonomously" in data


class TestEnhancedResponses:
    """Tests for enriched init_case and record_finding responses."""

    @pytest.fixture
    def case_manager(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        from forensic_mcp.case.manager import CaseManager
        return CaseManager()

    def test_init_case_includes_framework(self, case_manager):
        """init_case response should include investigation_framework."""
        from forensic_mcp.server import create_server
        # Use the manager directly for simpler testing
        result = case_manager.init_case("Test Case")
        # The framework is added by server.py, not manager. Let's test via server.
        # We'll test the server-level enhancement instead.
        assert result["status"] == "open"

    @pytest.mark.asyncio
    async def test_init_case_server_includes_framework(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        result = await server.call_tool("init_case", {"name": "Test Case"})
        text = result[0].text
        data = json.loads(text)
        assert "investigation_framework" in data
        fw = data["investigation_framework"]
        assert "principles" in fw
        assert "workflow" in fw
        assert "hitl_checkpoints" in fw
        assert "golden_rules" in fw

    @pytest.mark.asyncio
    async def test_record_finding_returns_considerations(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        # First create a case
        await server.call_tool("init_case", {"name": "Test"})
        # Stage a valid finding
        finding = {
            "title": "Suspicious binary found",
            "evidence_ids": ["ev-001", "ev-002"],
            "observation": "Binary found in temp directory",
            "interpretation": "Possible malware staging",
            "confidence": "HIGH",
            "confidence_justification": "Multiple corroborating sources",
            "type": "finding",
        }
        result = await server.call_tool("record_finding", {"finding": finding})
        text = result[0].text
        data = json.loads(text)
        assert data["status"] == "STAGED"
        assert "considerations" in data
        assert len(data["considerations"]) > 0
        assert "finding_status" in data
        assert "DRAFT" in data["finding_status"]

    @pytest.mark.asyncio
    async def test_record_finding_attribution_considerations(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        await server.call_tool("init_case", {"name": "Test"})
        finding = {
            "title": "APT29 attribution",
            "evidence_ids": ["ev-001", "ev-002", "ev-003"],
            "observation": "TTPs match APT29",
            "interpretation": "Likely APT29",
            "confidence": "HIGH",
            "confidence_justification": "Multiple TTPs + infrastructure",
            "type": "attribution",
        }
        result = await server.call_tool("record_finding", {"finding": finding})
        text = result[0].text
        data = json.loads(text)
        assert data["status"] == "STAGED"
        considerations = data["considerations"]
        # Should include premature_attribution anti-pattern for attribution findings
        has_attribution_warning = any("attribution" in c.lower() for c in considerations)
        assert has_attribution_warning

    @pytest.mark.asyncio
    async def test_validation_failure_includes_guidance(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        await server.call_tool("init_case", {"name": "Test"})
        # Submit an invalid finding — missing fields
        finding = {"title": "Bad finding"}
        result = await server.call_tool("record_finding", {"finding": finding})
        text = result[0].text
        data = json.loads(text)
        assert data["status"] == "VALIDATION_FAILED"
        assert "guidance" in data
        assert len(data["guidance"]) > 0


class TestGroundingInResponse:
    @pytest.mark.asyncio
    async def test_record_finding_includes_grounding(self, tmp_path, monkeypatch):
        """record_finding response includes grounding key when no audit trail exists (WEAK)."""
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        await server.call_tool("init_case", {"name": "Grounding Test"})
        finding = {
            "title": "Suspicious binary",
            "evidence_ids": ["ev-001", "ev-002"],
            "observation": "Binary in temp",
            "interpretation": "Possible malware",
            "confidence": "MEDIUM",
            "confidence_justification": "Two corroborating sources",
            "type": "finding",
        }
        result = await server.call_tool("record_finding", {"finding": finding})
        text = result[0].text
        data = json.loads(text)
        assert data["status"] == "STAGED"
        assert "grounding" in data
        assert data["grounding"]["level"] == "WEAK"
        assert len(data["grounding"]["sources_missing"]) == 3


class TestTodoTools:
    @pytest.mark.asyncio
    async def test_add_todo(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        await server.call_tool("init_case", {"name": "Test"})
        result = await server.call_tool("add_todo", {"description": "Run volatility"})
        data = json.loads(result[0].text)
        assert data["status"] == "created"
        assert data["todo_id"] == "TODO-001"

    @pytest.mark.asyncio
    async def test_list_todos(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        await server.call_tool("init_case", {"name": "Test"})
        await server.call_tool("add_todo", {"description": "A"})
        await server.call_tool("add_todo", {"description": "B"})
        result = await server.call_tool("list_todos", {})
        # FastMCP returns (list[TextContent], metadata) for list tools
        content = result[0] if isinstance(result, tuple) else result
        assert len(content) == 2

    @pytest.mark.asyncio
    async def test_complete_todo(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        await server.call_tool("init_case", {"name": "Test"})
        await server.call_tool("add_todo", {"description": "A"})
        result = await server.call_tool("complete_todo", {"todo_id": "TODO-001"})
        data = json.loads(result[0].text)
        assert data["status"] == "updated"

        # Verify it's completed
        result = await server.call_tool("list_todos", {"status": "completed"})
        content = result[0] if isinstance(result, tuple) else result
        assert len(content) == 1

    @pytest.mark.asyncio
    async def test_update_todo_with_note(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        await server.call_tool("init_case", {"name": "Test"})
        await server.call_tool("add_todo", {"description": "A"})
        result = await server.call_tool("update_todo", {
            "todo_id": "TODO-001",
            "note": "In progress",
        })
        data = json.loads(result[0].text)
        assert data["status"] == "updated"
