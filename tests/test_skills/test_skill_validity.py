"""Every shipped skill is a valid, text-only Agent Skill.

A client loads each skill's name and description into every session and the
body on demand. So the front matter follows the Agent Skills rules, the
descriptions together stay small, and no skill carries anything a client
would run: no scripts, no tool grants or hooks, and no `` !` `` (Claude Code
runs such a command when the skill loads).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / "skills"
DIRS = sorted(p for p in SKILLS.iterdir() if p.is_dir())
# The listing every session carries: all descriptions together, measured at
# about 2.1 KB with 7 skills; the cap leaves room for a few more.
DESCRIPTION_TOTAL_CAP = 3_000


def _front(skill: Path) -> dict:
    text = (skill / "SKILL.md").read_text(encoding="utf-8")
    assert text.startswith("---\n"), skill
    return yaml.safe_load(text.split("---", 2)[1])


def test_the_shipped_set():
    assert [p.name for p in DIRS] == [
        "finding-skeptic", "vhir-ingest", "vhir-malware-escalation", "vhir-playbooks",
        "vhir-report-writing", "vhir-tool-reference", "vhir-welcome",
    ]  # fmt: skip


@pytest.mark.parametrize("skill", DIRS, ids=lambda p: p.name)
def test_the_front_matter_is_valid(skill):
    front = _front(skill)
    assert set(front) <= {"name", "description", "metadata", "license"}, front.keys()
    name, description = front["name"], front["description"]
    assert name == skill.name
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) and len(name) <= 64
    assert isinstance(description, str) and 0 < len(description) <= 1024
    assert len(description) + len(str(front.get("when_to_use", ""))) <= 1536
    for word in ("claude", "anthropic"):
        assert word not in (name + description).lower()
    assert not re.search(r"<[^>]+>", description)  # no XML tags


@pytest.mark.parametrize("skill", DIRS, ids=lambda p: p.name)
def test_a_skill_is_text_only(skill):
    assert not (skill / "scripts").exists()
    front = _front(skill)
    assert "allowed-tools" not in front and "hooks" not in front
    for path in skill.rglob("*"):
        if path.is_file():
            assert path.suffix == ".md", path
            assert "!`" not in path.read_text(encoding="utf-8"), path


def test_the_descriptions_together_stay_under_the_cap():
    total = sum(len(_front(s)["description"]) for s in DIRS)
    assert total <= DESCRIPTION_TOTAL_CAP, total


def test_the_tool_reference_skill_is_the_tool_reference():
    """The file stays at its path (the remote scripts fetch it there); the
    skill carries it unchanged."""
    body = (
        (SKILLS / "vhir-tool-reference" / "SKILL.md").read_text().split("---\n", 2)[2]
    )
    source = (ROOT / "claude-code" / "full" / "TOOL_REFERENCE.md").read_text()
    assert body == "\n" + source


def test_the_manifest_the_remote_scripts_fetch_lists_every_skill_file():
    listed = [
        ln
        for ln in (SKILLS / "MANIFEST").read_text().splitlines()
        if ln and not ln.startswith("#")
    ]
    on_disk = sorted(
        str(p.relative_to(SKILLS))
        for p in SKILLS.rglob("*")
        if p.is_file() and p.parent != SKILLS
    )
    assert listed == on_disk
    assert all(
        re.fullmatch(r"[A-Za-z0-9._/-]+", ln) and ".." not in ln for ln in listed
    )
