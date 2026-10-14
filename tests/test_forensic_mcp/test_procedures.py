"""get_procedure serves the skills to a client that can't load them: only
what skills/MANIFEST lists, and never a file outside the procedure's folder."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from forensic_mcp import procedures
from forensic_mcp.server import (
    PROCEDURE_DESCRIPTION,
    _procedure_description,
    create_server,
)
from sift_common.instructions import FORENSIC_MCP

ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / "skills"


def _manifest() -> list[str]:
    lines = (SKILLS / "MANIFEST").read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def _names() -> list[str]:
    return sorted({p.split("/")[0] for p in _manifest() if p.endswith("/SKILL.md")})


def _front(name: str) -> dict:
    text = (SKILLS / name / "SKILL.md").read_text()
    return yaml.safe_load(text.split("---\n")[1])


def _tree(tmp_path: Path, manifest: str) -> Path:
    root = tmp_path / "skills"
    (root / "one" / "references").mkdir(parents=True)
    (root / "one" / "SKILL.md").write_text(
        "---\nname: one\ndescription: First.\n---\nbody\n"
    )
    (root / "one" / "references" / "a.md").write_text("a\n")
    (root / "one" / "unlisted.md").write_text("unlisted\n")
    (tmp_path / "outside.md").write_text("outside\n")
    (root / "MANIFEST").write_text(manifest)
    return root


def test_the_checkout_s_skills_are_found():
    assert procedures.SKILLS == SKILLS


def test_no_name_lists_each_procedure_with_its_description():
    got = procedures.get()
    assert [p["name"] for p in got["procedures"]] == _names()
    for p in got["procedures"]:
        assert p["description"] == _front(p["name"])["description"]


def test_a_name_gives_its_skill_and_lists_its_other_files():
    got = procedures.get("vhir-playbooks")
    assert got["content"] == (SKILLS / "vhir-playbooks" / "SKILL.md").read_text()
    listed = [
        p.split("/", 1)[1] for p in _manifest() if p.startswith("vhir-playbooks/")
    ]
    assert sorted(got["files"]) == sorted(f for f in listed if f != "SKILL.md")
    assert got["files"]


def test_a_name_and_a_file_gives_that_file():
    file = procedures.get("vhir-playbooks")["files"][0]
    got = procedures.get("vhir-playbooks", file)
    assert got["content"] == (SKILLS / "vhir-playbooks" / file).read_text()


def test_the_skeptic_is_served_and_says_first_it_runs_in_its_own_agent():
    content = procedures.get("finding-skeptic")["content"]
    first = content.split("\n## ")[1]
    assert first.startswith("A challenge is required")
    assert "its own agent" in first


@pytest.mark.parametrize(
    "name,file",
    [
        ("one", "unlisted.md"),
        ("one", "../outside.md"),
        ("one", "references/../unlisted.md"),
        ("one", "/etc/passwd"),
        ("..", "outside.md"),
        ("none", ""),
    ],
)
def test_only_what_the_manifest_lists_is_served(tmp_path, name, file):
    root = _tree(tmp_path, "# listed\none/SKILL.md\none/references/a.md\n")
    got = procedures.get(name, file, root=root)
    assert "error" in got and "content" not in got


def test_a_listed_file_that_leads_outside_the_folder_is_refused(tmp_path):
    root = _tree(tmp_path, "one/SKILL.md\none/link.md\n")
    (root / "one" / "link.md").symlink_to(tmp_path / "outside.md")
    got = procedures.get("one", "link.md", root=root)
    assert "outside the procedure's folder" in got["error"]
    assert "content" not in got


def test_a_listed_file_is_served_from_a_tree(tmp_path):
    root = _tree(tmp_path, "one/SKILL.md\none/references/a.md\n")
    assert procedures.get(root=root) == {
        "procedures": [{"name": "one", "description": "First."}]
    }
    assert procedures.get("one", root=root)["files"] == ["references/a.md"]
    assert procedures.get("one", "references/a.md", root=root)["content"] == "a\n"


@pytest.mark.parametrize("args", [(), ("finding-skeptic",), ("vhir-playbooks", "x")])
def test_without_skills_the_reply_says_procedures_aren_t_installed(tmp_path, args):
    got = procedures.get(*args, root=tmp_path / "absent")
    assert got == {"error": "procedures aren't installed with this forensic-mcp"}


def test_the_description_names_every_procedure(tmp_path):
    assert all(n in PROCEDURE_DESCRIPTION for n in _names())
    absent = _procedure_description(tmp_path / "absent")
    assert "procedures aren't installed with this forensic-mcp" in absent


@pytest.mark.asyncio
async def test_the_server_serves_get_procedure():
    server = create_server()
    tool = {t.name: t for t in await server.list_tools()}["get_procedure"]
    assert tool.description == PROCEDURE_DESCRIPTION
    result = await server.call_tool("get_procedure", {"name": "finding-skeptic"})
    content = result[0] if isinstance(result, tuple) else result
    assert "A challenge is required" in str(content)


@pytest.mark.parametrize("where", ["FORENSIC_MCP", "AGENTS.md"])
def test_the_instructions_name_get_procedure(where):
    text = FORENSIC_MCP if where == "FORENSIC_MCP" else (ROOT / "AGENTS.md").read_text()
    assert "get_procedure" in text


@pytest.mark.asyncio
async def test_the_server_says_so_when_procedures_aren_t_installed(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(procedures, "SKILLS", tmp_path / "absent")
    result = await create_server().call_tool("get_procedure", {"name": "x"})
    content = result[0] if isinstance(result, tuple) else result
    assert json.loads(content[0].text) == {"error": procedures.NOT_INSTALLED}
