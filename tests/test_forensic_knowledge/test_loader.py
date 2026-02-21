"""Tests for forensic_knowledge.loader — YAML loading and caching."""

import pytest
from forensic_knowledge import loader


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear loader cache before each test."""
    loader.clear_cache()
    yield
    loader.clear_cache()


# --- Artifacts ---

class TestArtifacts:
    def test_get_artifact_amcache(self):
        art = loader.get_artifact("amcache")
        assert art is not None
        assert art["name"] == "Amcache"
        assert art["platform"] == "windows"
        assert "File was present on the system" in art["proves"]
        assert "File was executed" in art["does_not_prove"]

    def test_get_artifact_missing(self):
        assert loader.get_artifact("nonexistent_artifact_xyz") is None

    def test_list_artifacts_windows(self):
        arts = loader.list_artifacts(platform="windows")
        assert len(arts) >= 32
        names = [a["name"] for a in arts]
        assert "Amcache" in names

    def test_list_artifacts_linux(self):
        arts = loader.list_artifacts(platform="linux")
        assert len(arts) >= 8
        names = [a["name"] for a in arts]
        assert "Shell History" in names
        assert "Authentication Log" in names

    def test_get_artifacts_for_tool(self):
        arts = loader.get_artifacts_for_tool("AmcacheParser")
        assert len(arts) >= 1
        assert arts[0]["name"] == "Amcache"

    def test_get_artifacts_for_unknown_tool(self):
        arts = loader.get_artifacts_for_tool("NonexistentTool")
        assert arts == []

    def test_artifact_has_corroboration(self):
        art = loader.get_artifact("amcache")
        assert "corroborate_with" in art
        assert "for_execution" in art["corroborate_with"]

    def test_artifact_has_timestamps(self):
        art = loader.get_artifact("amcache")
        assert len(art["timestamps"]) >= 1
        ts = art["timestamps"][0]
        assert "field" in ts
        assert "meaning" in ts


# --- Tools ---

class TestTools:
    def test_get_tool_amcacheparser(self):
        tool = loader.get_tool("AmcacheParser")
        assert tool is not None
        assert tool["name"] == "AmcacheParser"
        assert tool["category"] == "zimmerman"
        assert "amcache" in tool["artifacts_parsed"]

    def test_get_tool_case_insensitive(self):
        tool = loader.get_tool("amcacheparser")
        assert tool is not None
        assert tool["name"] == "AmcacheParser"

    def test_get_tool_missing(self):
        assert loader.get_tool("nonexistent_tool_xyz") is None

    def test_list_tools_all(self):
        tools = loader.list_tools()
        assert len(tools) >= 40
        names = [t["name"] for t in tools]
        assert "AmcacheParser" in names

    def test_list_tools_by_category(self):
        tools = loader.list_tools(category="zimmerman")
        assert len(tools) >= 1
        assert all(t["category"] == "zimmerman" for t in tools)

    def test_list_tools_returns_platform(self):
        tools = loader.list_tools()
        for t in tools:
            assert "platform" in t, f"Tool '{t['name']}' missing platform in list output"

    def test_list_tools_platform_filter(self):
        linux_tools = loader.list_tools(platform="linux")
        assert len(linux_tools) >= 1
        for t in linux_tools:
            assert "linux" in t["platform"]
        windows_only = loader.list_tools(platform="windows")
        assert len(windows_only) >= 1

    def test_tool_platform_is_list(self):
        tool = loader.get_tool("AmcacheParser")
        assert isinstance(tool["platform"], list)
        assert "windows" in tool["platform"]


# --- Discipline ---

class TestDiscipline:
    def test_get_rules(self):
        rules = loader.get_rules()
        assert len(rules) == 7
        ids = [r["id"] for r in rules]
        assert "FD-001" in ids
        assert "FD-007" in ids
        # All rules have when_to_apply/how_to_apply
        for r in rules:
            assert "when_to_apply" in r, f"rule missing when_to_apply: {r['id']}"
            assert "how_to_apply" in r, f"rule missing how_to_apply: {r['id']}"
            assert len(r["when_to_apply"]) > 0
            assert len(r["how_to_apply"]) > 0

    def test_get_confidence_definitions(self):
        conf = loader.get_confidence_definitions()
        assert "HIGH" in conf
        assert "SPECULATIVE" in conf
        assert conf["HIGH"]["min_evidence_ids"] == 2

    def test_get_anti_patterns(self):
        patterns = loader.get_anti_patterns()
        assert len(patterns) == 6
        names = [p["name"] for p in patterns]
        assert "confirmation_bias" in names
        # All anti-patterns have how_to_avoid
        for p in patterns:
            assert "how_to_avoid" in p, f"anti-pattern missing how_to_avoid: {p['name']}"
            assert len(p["how_to_avoid"]) > 0

    def test_get_evidence_standards(self):
        stds = loader.get_evidence_standards()
        assert "CONFIRMED" in stds
        assert stds["CONFIRMED"]["min_sources"] == 2

    def test_get_evidence_template(self):
        tmpl = loader.get_evidence_template()
        assert "title" in tmpl
        assert "evidence_ids" in tmpl
        assert "confidence" in tmpl

    def test_get_checkpoint_attribution(self):
        cp = loader.get_checkpoint("attribution")
        assert cp is not None
        assert cp["min_evidence_ids"] == 3
        assert cp["human_approval"] is True

    def test_get_checkpoint_missing(self):
        assert loader.get_checkpoint("nonexistent_action") is None

    def test_list_checkpoints(self):
        cps = loader.list_checkpoints()
        assert len(cps) == 4
        types = [c["action_type"] for c in cps]
        assert "attribution" in types
        assert "root_cause" in types


# --- Guidance ---

class TestGuidance:
    def test_get_corroboration_persistence(self):
        corr = loader.get_corroboration("persistence")
        assert corr is not None
        assert len(corr) >= 3

    def test_get_corroboration_missing(self):
        assert loader.get_corroboration("nonexistent_type") is None

    def test_get_false_positive_context(self):
        fp = loader.get_false_positive_context("check_file", "unknown_file")
        assert fp is not None
        assert "common_benign_causes" in fp

    def test_get_false_positive_context_missing(self):
        assert loader.get_false_positive_context("fake_tool", "fake_finding") is None

    def test_get_tool_interpretation(self):
        interp = loader.get_tool_interpretation("check_file")
        assert interp is not None
        assert "score_interpretation" in interp
        assert "UNKNOWN" in interp["score_interpretation"]

    def test_get_tool_interpretation_missing(self):
        assert loader.get_tool_interpretation("nonexistent_tool") is None


# --- Playbooks & Checklists ---

class TestPlaybooks:
    def test_get_playbook_unusual_logon(self):
        pb = loader.get_playbook("unusual_logon")
        assert pb is not None
        assert pb["name"] == "Unusual Logon Investigation"
        assert len(pb["phases"]) >= 4

    def test_get_playbook_missing(self):
        assert loader.get_playbook("nonexistent_playbook") is None

    def test_list_playbooks(self):
        pbs = loader.list_playbooks()
        assert len(pbs) == 14
        names = [p["name"] for p in pbs]
        assert "Unusual Logon Investigation" in names
        assert "Malware Analysis Investigation" in names

    def test_get_collection_checklist_registry(self):
        cl = loader.get_collection_checklist("registry")
        assert cl is not None
        assert cl["artifact_type"] == "Windows Registry"
        assert len(cl["files"]) >= 5

    def test_list_collection_checklists(self):
        cls = loader.list_collection_checklists()
        assert "registry" in cls


# --- Investigation Framework ---

class TestFramework:
    def test_get_investigation_framework(self):
        fw = loader.get_investigation_framework()
        assert fw is not None
        assert "principles" in fw
        assert "workflow" in fw
        assert "hitl_checkpoints" in fw
        assert "golden_rules" in fw
        assert "self_check" in fw
        assert "never_decide_autonomously" in fw

    def test_framework_principles(self):
        fw = loader.get_investigation_framework()
        principles = fw["principles"]
        assert len(principles) == 4
        names = [p["name"] for p in principles]
        assert "Evidence is sovereign" in names
        # All principles have when/how guidance
        for p in principles:
            assert "when" in p, f"principle missing when: {p['name']}"
            assert "how" in p, f"principle missing how: {p['name']}"

    def test_framework_workflow_steps(self):
        fw = loader.get_investigation_framework()
        steps = [s["step"] for s in fw["workflow"]]
        assert steps == ["Analyze", "Collect", "Corroborate", "Record", "Wait"]
        # All workflow steps have when/how guidance
        for s in fw["workflow"]:
            assert "when" in s, f"workflow step missing when: {s['step']}"
            assert "how" in s, f"workflow step missing how: {s['step']}"

    def test_framework_golden_rules(self):
        fw = loader.get_investigation_framework()
        assert len(fw["golden_rules"]) == 5
        rules = [r["rule"] for r in fw["golden_rules"]]
        assert "Show evidence for every claim" in rules
        # All golden rules have how guidance
        for r in fw["golden_rules"]:
            assert "how" in r, f"golden rule missing how: {r}"
            assert len(r["how"]) > 0


    def test_framework_hitl_checkpoints_have_guidance(self):
        fw = loader.get_investigation_framework()
        checkpoints = fw["hitl_checkpoints"]
        assert len(checkpoints) == 7
        for cp in checkpoints:
            assert "when" in cp, f"checkpoint missing when: {cp['action']}"
            assert "how" in cp, f"checkpoint missing how: {cp['action']}"

    def test_framework_self_check_has_how(self):
        fw = loader.get_investigation_framework()
        checks = fw["self_check"]
        assert len(checks) == 11
        for item in checks:
            assert isinstance(item, dict), f"self_check item should be dict: {item}"
            assert "question" in item
            assert "how" in item
            assert len(item["how"]) > 0


# --- Caching ---

class TestCaching:
    def test_cache_works(self):
        art1 = loader.get_artifact("amcache")
        art2 = loader.get_artifact("amcache")
        assert art1 is art2  # Same object — from cache

    def test_clear_cache(self):
        art1 = loader.get_artifact("amcache")
        loader.clear_cache()
        art2 = loader.get_artifact("amcache")
        assert art1 is not art2  # Different objects after cache clear
        assert art1 == art2  # But equal content


# --- Path Traversal ---

class TestPathTraversal:
    def test_artifact_dotdot_rejected(self):
        with pytest.raises(ValueError, match="path traversal"):
            loader.get_artifact("../../etc/passwd")

    def test_artifact_slash_rejected(self):
        with pytest.raises(ValueError, match="path traversal"):
            loader.get_artifact("windows/amcache")

    def test_artifact_backslash_rejected(self):
        with pytest.raises(ValueError, match="path traversal"):
            loader.get_artifact("windows\\amcache")

    def test_artifact_null_byte_rejected(self):
        with pytest.raises(ValueError, match="path traversal"):
            loader.get_artifact("amcache\x00.yaml")

    def test_playbook_dotdot_rejected(self):
        with pytest.raises(ValueError, match="path traversal"):
            loader.get_playbook("../../etc/passwd")

    def test_checklist_dotdot_rejected(self):
        with pytest.raises(ValueError, match="path traversal"):
            loader.get_collection_checklist("../../etc/passwd")

    def test_empty_name_rejected(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            loader.get_artifact("")
