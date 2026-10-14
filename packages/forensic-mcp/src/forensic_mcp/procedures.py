"""The procedures (the skills) for a client that can't load skills.

They are read from the sift-mcp checkout's skills/, and a file is served only
when skills/MANIFEST lists its exact path. An install without the checkout (a
wheel) has no skills/, and says so.
"""

from __future__ import annotations

from pathlib import Path

import yaml

import forensic_mcp

# packages/forensic-mcp/src/forensic_mcp/__init__.py → the checkout's skills/
SKILLS = Path(forensic_mcp.__file__).resolve().parents[4] / "skills"
NOT_INSTALLED = "procedures aren't installed with this forensic-mcp"


def _listed(root: Path) -> list[str] | None:
    """The MANIFEST's paths, or None without one."""
    try:
        text = (root / "MANIFEST").read_text(encoding="utf-8")
    except OSError:
        return None
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _procedures(root: Path) -> dict[str, list[str]] | None:
    """Each procedure's files, relative to its folder, SKILL.md first."""
    listed = _listed(root)
    if listed is None:
        return None
    found: dict[str, list[str]] = {}
    for path in listed:
        name, _, file = path.partition("/")
        found.setdefault(name, []).append(file)
    return {
        name: sorted(files, key=lambda f: f != "SKILL.md")
        for name, files in found.items()
        if "SKILL.md" in files
    }


def _read(root: Path, name: str, file: str) -> str:
    path = (root / name / file).resolve()
    if not path.is_relative_to((root / name).resolve()):
        raise OSError(f"{name}/{file} is outside the procedure's folder")
    return path.read_text(encoding="utf-8")


def _description(text: str) -> str:
    """The front matter's description."""
    if not text.startswith("---\n"):
        return ""
    head = text[4:].split("\n---", 1)[0]
    try:
        meta = yaml.safe_load(head)
    except yaml.YAMLError:
        return ""
    return str(meta.get("description", "")) if isinstance(meta, dict) else ""


def names(root: Path | None = None) -> list[str]:
    return sorted(_procedures(root or SKILLS) or {})


def get(name: str = "", file: str = "", root: Path | None = None) -> dict:
    """With no name, each procedure's name and description. With a name, its
    SKILL.md and its other files' names. With a file, that file. Never
    raises."""
    root = root or SKILLS
    procedures = _procedures(root)
    if procedures is None:
        return {"error": NOT_INSTALLED}
    try:
        if not name:
            return {
                "procedures": [
                    {"name": n, "description": _description(_read(root, n, "SKILL.md"))}
                    for n in sorted(procedures)
                ]
            }
        if name not in procedures:
            return {
                "error": f"no procedure named {name!r}",
                "procedures": sorted(procedures),
            }
        files = procedures[name]
        if not file:
            return {
                "name": name,
                "content": _read(root, name, "SKILL.md"),
                "files": files[1:],
            }
        if file not in files:
            return {
                "error": f"{file!r} isn't one of {name}'s files",
                "files": files,
            }
        return {"name": name, "file": file, "content": _read(root, name, file)}
    except (OSError, UnicodeDecodeError) as e:
        return {"error": f"a procedure's file can't be read: {e}"}
