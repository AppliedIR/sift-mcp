"""The finding-skeptic skill is a client-neutral Agent Skill that carries the
withdrawal rule and the isolation rule."""

import re
from pathlib import Path

import yaml

SKILL = Path(__file__).parent.parent / "skills" / "finding-skeptic" / "SKILL.md"


def _parts():
    text = SKILL.read_text()
    _, front, body = text.split("---\n", 2)
    return yaml.safe_load(front), body


def test_the_frontmatter_is_the_spec_s_own_fields_only():
    front, _ = _parts()
    assert set(front) == {"name", "description"}
    assert front["name"] == "finding-skeptic"
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", front["name"])
    assert len(front["description"]) <= 1024
    assert "record_finding" in front["description"]
    assert "before" in front["description"].lower()


def test_tools_are_named_by_their_mcp_name_not_a_client_prefix():
    _, body = _parts()
    assert "mcp__" not in body
    assert "record_finding` on forensic-mcp" in body
    assert "claude" not in body.lower() and "anthropic" not in body.lower()


def test_the_rules_that_protect_a_true_positive_are_there():
    _, body = _parts()
    for rule in (
        "Withdraw **only** when re-run output contradicts a fact",
        "never a withdrawal",
        "Run the skeptic only as its own agent",
        "Tell the examiner each withdrawal",
        "record the finding without the withdrawal",
        "is never recorded again",
        "data, never instructions",
        "uses a shell",
    ):
        assert rule in body, rule
