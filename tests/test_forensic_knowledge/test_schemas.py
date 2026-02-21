"""Schema validation tests — ensure all YAML files follow expected structure."""

import pytest
from forensic_knowledge import loader


@pytest.fixture(autouse=True)
def clear_cache():
    loader.clear_cache()
    yield
    loader.clear_cache()


# --- Artifact schema ---

REQUIRED_ARTIFACT_FIELDS = {"name", "description", "platform"}
OPTIONAL_ARTIFACT_FIELDS = {
    "locations", "proves", "does_not_prove", "timestamps",
    "common_misinterpretations", "corroborate_with", "related_tools", "references",
    "cross_mcp_checks",
}


class TestArtifactSchemas:
    def test_all_artifacts_have_required_fields(self):
        arts = loader.list_artifacts()
        assert len(arts) >= 1, "No artifacts found"
        for summary in arts:
            name = summary["name"]
            art = loader.get_artifact(name.lower().replace(" ", "_").replace("-", "_"))
            if art is None:
                # Try the description-based name
                continue
            for field in REQUIRED_ARTIFACT_FIELDS:
                assert field in art, f"Artifact '{name}' missing required field '{field}'"

    def test_all_artifacts_have_proves_or_does_not_prove(self):
        """Every artifact should document what it proves or doesn't."""
        for platform in ("windows", "linux"):
            for art in loader._load_all_in_dir(f"artifacts/{platform}"):
                name = art.get("name", "?")
                has_proves = bool(art.get("proves"))
                has_does_not = bool(art.get("does_not_prove"))
                assert has_proves or has_does_not, (
                    f"Artifact '{name}' must have 'proves' or 'does_not_prove'"
                )

    def test_artifact_timestamps_have_required_fields(self):
        for platform in ("windows", "linux"):
            for art in loader._load_all_in_dir(f"artifacts/{platform}"):
                for ts in art.get("timestamps", []):
                    assert "field" in ts, f"Timestamp in '{art['name']}' missing 'field'"
                    assert "meaning" in ts, f"Timestamp in '{art['name']}' missing 'meaning'"

    def test_artifact_misinterpretations_have_claim_and_correction(self):
        for platform in ("windows", "linux"):
            for art in loader._load_all_in_dir(f"artifacts/{platform}"):
                for m in art.get("common_misinterpretations", []):
                    assert "claim" in m, f"Misinterpretation in '{art['name']}' missing 'claim'"
                    assert "correction" in m, f"Misinterpretation in '{art['name']}' missing 'correction'"


# --- Tool schema ---

REQUIRED_TOOL_FIELDS = {"name", "category", "description"}


class TestToolSchemas:
    def test_all_tools_have_required_fields(self):
        tools = loader.list_tools()
        assert len(tools) >= 1, "No tools found"
        for summary in tools:
            name = summary["name"]
            tool = loader.get_tool(name)
            assert tool is not None, f"Tool '{name}' listed but not loadable"
            for field in REQUIRED_TOOL_FIELDS:
                assert field in tool, f"Tool '{name}' missing required field '{field}'"

    def test_tools_have_caveats(self):
        """Every tool should document at least one caveat."""
        tools = loader.list_tools()
        for summary in tools:
            tool = loader.get_tool(summary["name"])
            assert tool.get("caveats"), f"Tool '{summary['name']}' has no caveats"

    def test_tools_have_platform(self):
        """All tools should declare platform (list of OS names)."""
        tools = loader.list_tools()
        for summary in tools:
            assert summary.get("platform"), (
                f"Tool '{summary['name']}' has no platform field"
            )
            assert isinstance(summary["platform"], list), (
                f"Tool '{summary['name']}' platform should be a list"
            )

    def test_list_tools_platform_filter(self):
        """list_tools(platform=...) should filter correctly."""
        linux_tools = loader.list_tools(platform="linux")
        for tool in linux_tools:
            assert "linux" in tool["platform"], (
                f"Tool '{tool['name']}' returned for linux filter but platform={tool['platform']}"
            )


# --- Discipline schema ---

class TestDisciplineSchemas:
    def test_rules_have_required_fields(self):
        rules = loader.get_rules()
        for rule in rules:
            assert "id" in rule, f"Rule missing 'id'"
            assert "name" in rule, f"Rule '{rule.get('id', '?')}' missing 'name'"
            assert "severity" in rule, f"Rule '{rule['id']}' missing 'severity'"
            assert "description" in rule, f"Rule '{rule['id']}' missing 'description'"

    def test_confidence_levels_have_criteria(self):
        conf = loader.get_confidence_definitions()
        for level, defn in conf.items():
            assert "criteria" in defn, f"Confidence '{level}' missing 'criteria'"
            assert "min_evidence_ids" in defn, f"Confidence '{level}' missing 'min_evidence_ids'"

    def test_anti_patterns_have_required_fields(self):
        patterns = loader.get_anti_patterns()
        for ap in patterns:
            assert "name" in ap, "Anti-pattern missing 'name'"
            assert "description" in ap, f"Anti-pattern '{ap['name']}' missing 'description'"
            assert "severity" in ap, f"Anti-pattern '{ap['name']}' missing 'severity'"

    def test_checkpoints_have_required_fields(self):
        cps = loader.list_checkpoints()
        for cp_summary in cps:
            cp = loader.get_checkpoint(cp_summary["action_type"])
            assert cp is not None
            assert "min_evidence_ids" in cp
            assert "human_approval" in cp
            assert "guidance" in cp

    def test_playbooks_have_phases_with_steps(self):
        pbs = loader.list_playbooks()
        assert len(pbs) == 14, f"Expected 14 playbooks, got {len(pbs)}"
        for pb_summary in pbs:
            assert pb_summary["phases"] >= 2, f"Playbook '{pb_summary['name']}' has < 2 phases"

    def test_checklists_have_files_and_tools(self):
        cls = loader.list_collection_checklists()
        assert len(cls) >= 4
        for name in cls:
            cl = loader.get_collection_checklist(name)
            assert cl is not None, f"Checklist '{name}' not loadable"
            assert "files" in cl, f"Checklist '{name}' missing 'files'"
            assert "tools" in cl, f"Checklist '{name}' missing 'tools'"


# --- Framework schema ---

class TestFrameworkSchema:
    def test_framework_has_all_sections(self):
        fw = loader.get_investigation_framework()
        required_sections = [
            "principles", "workflow", "hitl_checkpoints",
            "never_decide_autonomously", "self_check", "golden_rules",
        ]
        for section in required_sections:
            assert section in fw, f"Framework missing section '{section}'"

    def test_framework_principles_have_name_and_description(self):
        fw = loader.get_investigation_framework()
        for p in fw["principles"]:
            assert "name" in p, "Principle missing 'name'"
            assert "description" in p, f"Principle '{p['name']}' missing 'description'"

    def test_framework_workflow_has_step_and_description(self):
        fw = loader.get_investigation_framework()
        for w in fw["workflow"]:
            assert "step" in w, "Workflow item missing 'step'"
            assert "description" in w, f"Workflow step '{w['step']}' missing 'description'"

    def test_framework_hitl_checkpoints_have_action_and_why(self):
        fw = loader.get_investigation_framework()
        for cp in fw["hitl_checkpoints"]:
            assert "action" in cp, "HITL checkpoint missing 'action'"
            assert "why" in cp, f"HITL checkpoint '{cp['action']}' missing 'why'"


# --- Cross-MCP checks schema ---

class TestCrossMcpChecks:
    VALID_MCPS = {"windows-triage", "opencti", "forensic-rag", "remnux"}

    def test_all_artifacts_have_cross_mcp_checks(self):
        """Every artifact should have cross_mcp_checks."""
        for platform in ("windows", "linux"):
            for art in loader._load_all_in_dir(f"artifacts/{platform}"):
                name = art.get("name", "?")
                assert "cross_mcp_checks" in art, (
                    f"Artifact '{name}' missing cross_mcp_checks"
                )
                assert len(art["cross_mcp_checks"]) >= 1, (
                    f"Artifact '{name}' has empty cross_mcp_checks"
                )

    def test_cross_mcp_checks_have_required_fields(self):
        """Each cross_mcp_check must have mcp, tool, when."""
        for platform in ("windows", "linux"):
            for art in loader._load_all_in_dir(f"artifacts/{platform}"):
                name = art.get("name", "?")
                for check in art.get("cross_mcp_checks", []):
                    assert "mcp" in check, f"cross_mcp_check in '{name}' missing 'mcp'"
                    assert "tool" in check, f"cross_mcp_check in '{name}' missing 'tool'"
                    assert "when" in check, f"cross_mcp_check in '{name}' missing 'when'"

    def test_cross_mcp_checks_use_valid_mcps(self):
        """MCP names must be from the allowed set."""
        for platform in ("windows", "linux"):
            for art in loader._load_all_in_dir(f"artifacts/{platform}"):
                name = art.get("name", "?")
                for check in art.get("cross_mcp_checks", []):
                    assert check["mcp"] in self.VALID_MCPS, (
                        f"Artifact '{name}' has invalid MCP '{check['mcp']}'"
                    )

    def test_cross_mcp_checks_count(self):
        """Should have 51 artifacts total with cross_mcp_checks."""
        count = 0
        for platform in ("windows", "linux"):
            for art in loader._load_all_in_dir(f"artifacts/{platform}"):
                if "cross_mcp_checks" in art:
                    count += 1
        assert count == 51


# --- Scenario playbook schema ---

class TestScenarioPlaybooks:
    def test_scenario_playbooks_have_mitre(self):
        """New scenario playbooks must have MITRE ATT&CK references."""
        pbs = loader.list_playbooks()
        for pb_summary in pbs:
            # Load by filesystem name
            name_key = pb_summary["name"].lower().replace(" ", "_")
            pb = loader.get_playbook(name_key)
            if pb is None:
                continue
            if pb.get("mitre"):
                for tid in pb["mitre"]:
                    assert tid.startswith("T"), (
                        f"Playbook '{pb_summary['name']}' has invalid MITRE ID '{tid}'"
                    )

    def test_scenario_playbooks_have_triggers(self):
        """New scenario playbooks must have triggers."""
        pbs = loader.list_playbooks()
        for pb_summary in pbs:
            name_key = pb_summary["name"].lower().replace(" ", "_")
            pb = loader.get_playbook(name_key)
            if pb is None:
                continue
            if name_key != "malware_analysis":
                assert pb.get("triggers"), (
                    f"Playbook '{pb_summary['name']}' missing triggers"
                )

    def test_scenario_playbooks_have_sources(self):
        """New scenario playbooks must have source references."""
        pbs = loader.list_playbooks()
        for pb_summary in pbs:
            name_key = pb_summary["name"].lower().replace(" ", "_")
            pb = loader.get_playbook(name_key)
            if pb is None:
                continue
            if name_key != "malware_analysis":
                assert pb.get("sources"), (
                    f"Playbook '{pb_summary['name']}' missing sources"
                )


# --- Tool cross-MCP schema ---

class TestToolCrossMcp:
    TOOLS_WITH_CROSS_MCP = [
        "PECmd", "AmcacheParser", "AppCompatCacheParser", "MFTECmd",
        "RECmd", "EvtxECmd", "Hayabusa", "Volatility 3",
        "densityscout", "sigcheck", "capa", "autorunsc",
        "tshark", "zeek", "HollowsHunter",
    ]

    def test_tools_have_cross_mcp_steps(self):
        """15 tools should have Cross-MCP investigation steps."""
        for tool_name in self.TOOLS_WITH_CROSS_MCP:
            tool = loader.get_tool(tool_name)
            assert tool is not None, f"Tool '{tool_name}' not found"
            seq = tool.get("investigation_sequence", [])
            cross_mcp = [s for s in seq if "Cross-MCP" in s]
            assert len(cross_mcp) >= 1, (
                f"Tool '{tool_name}' has no Cross-MCP steps in investigation_sequence"
            )
