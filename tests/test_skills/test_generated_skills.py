"""The playbook skill is rendered from the knowledge data, and the committed
copy is that rendering, byte for byte.

A data change reaches the skill only through a reviewed regeneration
(`python -m forensic_knowledge.skills skills`). Hand-written skills are left
alone, and none may take a generated skill's name.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from forensic_knowledge import loader, skills

SKILLS = Path(__file__).resolve().parents[2] / "skills"


@pytest.fixture
def copy(tmp_path):
    out = tmp_path / "skills"
    shutil.copytree(SKILLS, out)
    return out


def test_the_committed_skills_are_the_rendering():
    assert skills.drift(SKILLS) == []


def test_a_fresh_rendering_equals_the_committed_files(tmp_path):
    skills.write(tmp_path)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            rel = path.relative_to(tmp_path)
            assert (SKILLS / rel).read_bytes() == path.read_bytes(), rel


def test_one_playbook_reference_per_playbook_and_every_name_in_the_description():
    slugs = loader.list_playbook_slugs()
    assert len(slugs) == 14
    refs = sorted(
        p.stem for p in (SKILLS / "vhir-playbooks" / "references").glob("*.md")
    )
    assert refs == slugs
    head = (SKILLS / "vhir-playbooks" / "SKILL.md").read_text().split("---")[1]
    for slug in slugs:
        assert loader.get_playbook(slug)["name"] in head


def test_a_hand_written_skill_is_not_compared(copy):
    hand = copy / "finding-skeptic-like"
    hand.mkdir()
    (hand / "SKILL.md").write_text(
        "---\nname: finding-skeptic-like\ndescription: x\n---\n"
    )
    assert skills.drift(copy) == []


def test_an_edit_to_a_generated_reference_fails(copy):
    ref = copy / "vhir-playbooks" / "references" / "usb_activity.md"
    ref.write_text(ref.read_text() + "one more line\n")
    assert skills.drift(copy) == [
        "vhir-playbooks/references/usb_activity.md: differs from the data; regenerate the skills"
    ]


def test_a_hand_written_folder_with_a_generated_name_fails(copy):
    shutil.rmtree(copy / "vhir-playbooks")
    (copy / "vhir-playbooks").mkdir()
    (copy / "vhir-playbooks" / "SKILL.md").write_text(
        "---\nname: vhir-playbooks\ndescription: mine\n---\n"
    )
    assert skills.drift(copy) == [
        "vhir-playbooks: a hand-written folder has a generated skill's name"
    ]


def test_removing_the_marker_from_a_generated_skill_fails(copy):
    """A generated folder can't escape the comparison by losing its marker."""
    skill_md = copy / "vhir-playbooks" / "SKILL.md"
    skill_md.write_text(
        skill_md.read_text().replace("generated-by: valhuntir-generator", "")
    )
    assert skills.drift(copy)


def test_an_extra_file_in_a_generated_folder_fails(copy):
    (copy / "vhir-playbooks" / "references" / "extra.md").write_text("x")
    assert skills.drift(copy) == [
        "vhir-playbooks/references/extra.md: not generated; remove it or regenerate"
    ]


def test_a_planted_command_in_the_data_renders_inert(tmp_path, monkeypatch):
    """`` !`cmd` `` in a skill runs when a client loads it; data text can't."""
    data = tmp_path / "data"
    shutil.copytree(loader._find_data_dir(), data)
    pb = data / "discipline" / "playbooks" / "usb_activity.yaml"
    pb.write_text(pb.read_text().replace('description: "', 'description: "!`id` ', 1))
    monkeypatch.setattr(loader, "_DATA_DIR", data)
    monkeypatch.setattr(loader, "_cache", {})
    rendered = skills.render()
    assert all("!`" not in t for t in rendered.values())
    assert "!\\`id`" in rendered["vhir-playbooks/references/usb_activity.md"]
