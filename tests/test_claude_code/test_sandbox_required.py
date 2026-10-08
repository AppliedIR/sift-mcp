"""The full template makes Claude Code refuse to start without a working
sandbox, instead of running Bash unsandboxed when bubblewrap can't start."""

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent


def test_the_template_requires_the_sandbox():
    sandbox = json.loads((ROOT / "claude-code" / "full" / "settings.json").read_text())[
        "sandbox"
    ]
    assert sandbox["enabled"] is True and sandbox["failIfUnavailable"] is True
