"""Tests for MCP server tool registration and basic calls."""

import json

import pytest

from forensic_mcp.server import create_server


@pytest.fixture
def server():
    """Server in default (resources) mode — 15 active tools."""
    return create_server()


@pytest.fixture
def tools_server():
    """Server in tools mode — 29 tools (15 active + 14 discipline)."""
    return create_server(reference_mode="tools")


class TestServerSetup:
    def test_server_name(self, server):
        assert server.name == "forensic-mcp"

    @pytest.mark.asyncio
    async def test_tool_count_resources_mode(self, server):
        tools = await server.list_tools()
        assert len(tools) == 12

    @pytest.mark.asyncio
    async def test_tool_count_tools_mode(self, tools_server):
        tools = await tools_server.list_tools()
        assert len(tools) == 26

    @pytest.mark.asyncio
    async def test_expected_tools_present(self, server):
        tools = await server.list_tools()
        names = {t.name for t in tools}
        expected = {
            "get_case_status", "list_cases",
            "record_finding", "record_timeline_event",
            "get_findings", "get_timeline", "get_actions",
            "add_todo", "list_todos", "update_todo", "complete_todo",
            "list_evidence",
        }
        assert names == expected

    @pytest.mark.asyncio
    async def test_removed_tools_not_present(self, server):
        """Tools moved to CLI should not appear in resources mode."""
        tools = await server.list_tools()
        names = {t.name for t in tools}
        removed = {
            "init_case", "close_case", "set_active_case",
            "register_evidence", "verify_evidence_integrity", "get_evidence_access_log",
            "get_audit_log", "get_audit_summary",
            "generate_full_report", "generate_executive_summary",
            "generate_timeline_report", "generate_ioc_report",
            "generate_findings_report", "generate_status_brief", "save_report",
        }
        assert names.isdisjoint(removed)

    @pytest.mark.asyncio
    async def test_tools_mode_includes_discipline(self, tools_server):
        """Tools mode adds discipline tools for legacy clients."""
        tools = await tools_server.list_tools()
        names = {t.name for t in tools}
        discipline = {
            "get_investigation_framework", "get_rules",
            "get_checkpoint_requirements", "validate_finding",
            "get_evidence_standards", "get_confidence_definitions",
            "get_anti_patterns", "get_evidence_template",
            "get_tool_guidance", "get_false_positive_context",
            "get_corroboration_suggestions", "list_playbooks",
            "get_playbook", "get_collection_checklist",
        }
        assert discipline.issubset(names)


class TestInvalidReferenceMode:
    def test_invalid_reference_mode_raises(self):
        with pytest.raises(ValueError, match="Invalid reference_mode"):
            create_server(reference_mode="invalid")

    def test_typo_reference_mode_raises(self):
        with pytest.raises(ValueError, match="Invalid reference_mode"):
            create_server(reference_mode="resource")


class TestResourceContent:
    """Verify MCP resources return valid content in resources mode."""

    @pytest.mark.asyncio
    async def test_investigation_framework_resource(self, server):
        result = await server.read_resource("forensic-mcp://investigation-framework")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert "principles" in data
        assert "workflow" in data

    @pytest.mark.asyncio
    async def test_rules_resource(self, server):
        result = await server.read_resource("forensic-mcp://rules")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_validation_schema_resource(self, server):
        result = await server.read_resource("forensic-mcp://validation-schema")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert "required_fields" in data
        assert "valid_types" in data
        assert "confidence_levels" in data

    @pytest.mark.asyncio
    async def test_playbooks_resource(self, server):
        result = await server.read_resource("forensic-mcp://playbooks")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert len(data) == 14

    @pytest.mark.asyncio
    async def test_playbook_by_name_resource(self, server):
        result = await server.read_resource("forensic-mcp://playbook/unusual_logon")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert data["name"] == "Unusual Logon Investigation"

    @pytest.mark.asyncio
    async def test_evidence_standards_resource(self, server):
        result = await server.read_resource("forensic-mcp://evidence-standards")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        for key in ("CONFIRMED", "INDICATED", "INFERRED", "UNKNOWN", "CONTRADICTED"):
            assert key in data

    @pytest.mark.asyncio
    async def test_confidence_definitions_resource(self, server):
        result = await server.read_resource("forensic-mcp://confidence-definitions")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        for key in ("HIGH", "MEDIUM", "LOW", "SPECULATIVE"):
            assert key in data

    @pytest.mark.asyncio
    async def test_anti_patterns_resource(self, server):
        result = await server.read_resource("forensic-mcp://anti-patterns")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert len(data) == 6

    @pytest.mark.asyncio
    async def test_evidence_template_resource(self, server):
        result = await server.read_resource("forensic-mcp://evidence-template")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        for key in ("title", "evidence_ids", "observation", "interpretation", "confidence", "type"):
            assert key in data

    @pytest.mark.asyncio
    async def test_collection_checklist_resource(self, server):
        result = await server.read_resource("forensic-mcp://collection-checklist/registry")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert data["artifact_type"] == "Windows Registry"
        assert len(data["files"]) > 0

    @pytest.mark.asyncio
    async def test_checkpoint_resource(self, server):
        result = await server.read_resource("forensic-mcp://checkpoint/attribution")
        data = json.loads(result[0].content if hasattr(result[0], "content") else result[0].text)
        assert data["min_evidence_ids"] == 3
        assert data["human_approval"] is True


class TestDisciplineTools:
    """Discipline tools in legacy tools mode."""

    @pytest.fixture
    def server(self):
        return create_server(reference_mode="tools")

    @pytest.mark.asyncio
    async def test_get_rules(self, server):
        result = await server.call_tool("get_rules", {})
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
    """Tests for enriched record_finding responses."""

    @pytest.mark.asyncio
    async def test_record_finding_returns_considerations(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        server._manager.init_case("Test")
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
        server._manager.init_case("Test")
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
        has_attribution_warning = any("attribution" in c.lower() for c in considerations)
        assert has_attribution_warning

    @pytest.mark.asyncio
    async def test_validation_failure_includes_guidance(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        server._manager.init_case("Test")
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
        server._manager.init_case("Grounding Test")
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
        server._manager.init_case("Test")
        result = await server.call_tool("add_todo", {"description": "Run volatility"})
        data = json.loads(result[0].text)
        assert data["status"] == "created"
        assert "TODO-" in data["todo_id"]

    @pytest.mark.asyncio
    async def test_list_todos(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        server._manager.init_case("Test")
        await server.call_tool("add_todo", {"description": "A"})
        await server.call_tool("add_todo", {"description": "B"})
        result = await server.call_tool("list_todos", {})
        content = result[0] if isinstance(result, tuple) else result
        assert len(content) == 2

    @pytest.mark.asyncio
    async def test_complete_todo(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        server._manager.init_case("Test")
        add_result = await server.call_tool("add_todo", {"description": "A"})
        todo_id = json.loads(add_result[0].text)["todo_id"]
        result = await server.call_tool("complete_todo", {"todo_id": todo_id})
        data = json.loads(result[0].text)
        assert data["status"] == "updated"

        result = await server.call_tool("list_todos", {"status": "completed"})
        content = result[0] if isinstance(result, tuple) else result
        assert len(content) == 1

    @pytest.mark.asyncio
    async def test_update_todo_with_note(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path / "cases"))
        server = create_server()
        server._manager.init_case("Test")
        add_result = await server.call_tool("add_todo", {"description": "A"})
        todo_id = json.loads(add_result[0].text)["todo_id"]
        result = await server.call_tool("update_todo", {
            "todo_id": todo_id,
            "note": "In progress",
        })
        data = json.loads(result[0].text)
        assert data["status"] == "updated"
