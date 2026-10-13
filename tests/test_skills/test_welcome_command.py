"""`/welcome` keeps working on a full install.

The procedure is the `vhir-welcome` skill; `claude-code/full/commands/welcome.md`
is a thin command pointing to it, so the `/welcome` the installer and the
READMEs advertise exists. The skill's Codex check starts at the case folder.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_the_advertised_welcome_command_exists_and_runs_the_skill():
    command = (ROOT / "claude-code/full/commands/welcome.md").read_text()
    assert "`vhir-welcome` skill" in command
    assert (ROOT / "skills/vhir-welcome/SKILL.md").is_file()
    for doc in ("setup-sift.sh", "README.md"):
        assert "/welcome" in (ROOT / doc).read_text(), doc


def test_the_codex_check_starts_at_the_case_folder():
    skill = (ROOT / "skills/vhir-welcome/SKILL.md").read_text()
    assert "work/" not in skill
    assert "cd <case folder> && codex -p valhuntir" in skill


def test_the_skill_tells_no_read_the_full_settings_deny():
    """A read the settings deny would stop the welcome ("Stop on failure")."""
    import json
    import re

    settings = json.loads((ROOT / "claude-code/full/settings.json").read_text())
    denied = [
        r[5:-1] for r in settings["permissions"]["deny"] if r.startswith("Read(~/")
    ]
    skill = (ROOT / "skills/vhir-welcome/SKILL.md").read_text()
    assert denied
    for path in denied:
        assert not re.search(r"\bRead\s+`?" + re.escape(path), skill), path
