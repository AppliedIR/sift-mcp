"""The full template denies the Edit tool on the deployed skills and agents
and on the Codex folders, anchors its settings and vhir rules at the home
folder too, and keeps Bash from writing the Codex folders."""

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent


def _full():
    return json.loads((ROOT / "claude-code" / "full" / "settings.json").read_text())


def test_the_home_folders_are_denied_to_the_edit_tool():
    deny = set(_full()["permissions"]["deny"])
    for path in (
        "~/.claude/skills/**",
        "~/.claude/agents/**",
        "~/.agents/**",
        "~/.codex/**",
    ):
        assert f"Edit({path})" in deny
    folder = [r for r in deny if r.startswith(("Edit(**/.claude/", "Edit(**/.vhir/"))]
    assert folder and all(r.replace("Edit(**/.", "Edit(~/.") in deny for r in folder)


def test_bash_cant_write_the_codex_folders():
    deny_write = _full()["sandbox"]["filesystem"]["denyWrite"]
    assert "~/.agents" in deny_write and "~/.codex" in deny_write
