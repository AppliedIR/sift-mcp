"""Agent Skills rendered from the knowledge data.

The playbooks in `data/discipline/playbooks/` reach the model two ways: the
forensic-mcp discipline tools serve them, and this module renders them as one
Agent Skill, `vhir-playbooks` (a `SKILL.md` naming every playbook, and one
`references/<slug>.md` per playbook). The rendered files are committed under
sift-mcp's `skills/`; a test renders them again and compares them byte for
byte, so a data change can't reach the skill without a reviewed regeneration.

Rendering is deterministic and copies the data text as it is. The one change:
the sequence `` !` `` is written as `` !\\` ``, so data text can't become a
command that a client runs when it loads the skill.

Regenerate with: ``python -m forensic_knowledge.skills <sift-mcp>/skills``
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from forensic_knowledge.loader import _find_data_dir

GENERATED_BY = "valhuntir-generator"
PLAYBOOKS_SKILL = "vhir-playbooks"
_SOURCE = "packages/forensic-knowledge/data/discipline/playbooks"


def text(value) -> str:
    """Data text as written, with `` !` `` made inert."""
    return str(value).replace("!`", "!\\`")


def _playbooks() -> list[tuple[str, dict]]:
    folder = _find_data_dir() / "discipline" / "playbooks"
    out = []
    for path in sorted(folder.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out.append((path.stem, data))
    return out


def _reference(data: dict) -> str:
    lines = [
        f"# {text(data.get('name', ''))}",
        "",
        text(data.get("description", "")),
        "",
    ]
    if data.get("mitre"):
        lines += ["MITRE ATT&CK: " + ", ".join(text(m) for m in data["mitre"]), ""]
    if data.get("triggers"):
        lines += ["## Triggers", ""] + [f"- {text(t)}" for t in data["triggers"]] + [""]
    for n, phase in enumerate(data.get("phases") or [], 1):
        lines += [f"## Phase {n}: {text(phase.get('phase', ''))}", ""]
        lines += [f"{i}. {text(s)}" for i, s in enumerate(phase.get("steps") or [], 1)]
        lines += [""]
    if data.get("sources"):
        lines += ["## Sources", ""] + [f"- {text(s)}" for s in data["sources"]] + [""]
    return "\n".join(lines)


def _skill(playbooks: list[tuple[str, dict]]) -> str:
    names = [text(d.get("name", slug)) for slug, d in playbooks]
    description = (
        "Investigation playbooks: step-by-step procedures, each with its triggers, "
        "phases and MITRE techniques. Use when an investigation needs one of: "
        + "; ".join(names)
        + "."
    )
    front = {
        "name": PLAYBOOKS_SKILL,
        "description": description,
        "metadata": {"generated-by": GENERATED_BY, "source": _SOURCE},
    }
    body = [
        "# Investigation playbooks",
        "",
        "Each playbook is in `references/`. Read the one that matches the activity "
        "you are investigating, and follow its phases with the MCP tools it names. "
        "forensic-mcp's `get_playbook` serves the same text.",
        "",
    ]
    for slug, data in playbooks:
        body.append(
            f"- `references/{slug}.md`: {text(data.get('name', slug))}. "
            f"{text(data.get('description', ''))}"
        )
    head = yaml.safe_dump(front, sort_keys=False, allow_unicode=True, width=10_000)
    return "---\n" + head + "---\n\n" + "\n".join(body) + "\n"


def render() -> dict[str, str]:
    """Every generated skill file: path relative to `skills/` → its text."""
    playbooks = _playbooks()
    files = {f"{PLAYBOOKS_SKILL}/SKILL.md": _skill(playbooks)}
    for slug, data in playbooks:
        files[f"{PLAYBOOKS_SKILL}/references/{slug}.md"] = _reference(data)
    return files


def generated_skill_names() -> set[str]:
    """The skill folders the generator writes."""
    return {path.split("/", 1)[0] for path in render()}


def write(out_dir: Path) -> list[Path]:
    """Render into `out_dir`, replacing the generated folders whole."""
    import shutil

    out_dir = Path(out_dir)
    for name in generated_skill_names():
        shutil.rmtree(out_dir / name, ignore_errors=True)
    written = []
    for rel, content in render().items():
        path = out_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def _marked(skill_md: Path) -> bool:
    """Whether a SKILL.md says the generator wrote it."""
    try:
        head = skill_md.read_text(encoding="utf-8").split("---", 2)[1]
        meta = (yaml.safe_load(head) or {}).get("metadata") or {}
    except (OSError, IndexError, yaml.YAMLError, AttributeError):
        return False
    return isinstance(meta, dict) and meta.get("generated-by") == GENERATED_BY


def drift(skills_dir: Path) -> list[str]:
    """Why the committed generated skills differ from a fresh rendering, or [].

    Only folders whose SKILL.md carries the generator's marker are compared;
    hand-written folders are skipped. Every folder the generator writes must
    exist and carry the marker (a hand-written folder can't take a generated
    name), and hold exactly the rendered files."""
    skills_dir = Path(skills_dir)
    rendered = render()
    problems = []
    for name in sorted(generated_skill_names()):
        folder = skills_dir / name
        if not (folder / "SKILL.md").is_file():
            problems.append(f"{name}: missing; regenerate the skills")
            continue
        if not _marked(folder / "SKILL.md"):
            problems.append(
                f"{name}: a hand-written folder has a generated skill's name"
            )
            continue
        want = {rel: t for rel, t in rendered.items() if rel.split("/", 1)[0] == name}
        have = {
            str(p.relative_to(skills_dir)): p for p in folder.rglob("*") if p.is_file()
        }
        for rel in sorted(set(want) - set(have)):
            problems.append(f"{rel}: missing; regenerate the skills")
        for rel in sorted(set(have) - set(want)):
            problems.append(f"{rel}: not generated; remove it or regenerate")
        for rel in sorted(set(want) & set(have)):
            if have[rel].read_text(encoding="utf-8") != want[rel]:
                problems.append(f"{rel}: differs from the data; regenerate the skills")
    for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
        name = skill_md.parent.name
        if _marked(skill_md) and name not in generated_skill_names():
            problems.append(
                f"{name}: marked as generated, but the generator writes no such skill"
            )
    return problems


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m forensic_knowledge.skills <sift-mcp>/skills")
    for p in write(Path(sys.argv[1])):
        print(p)
