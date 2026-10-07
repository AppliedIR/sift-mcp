"""The shipped Claude Code settings allow the threat-intel backend under both
its names: threatintel-mcp, and opencti-mcp in configurations from before."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


@pytest.mark.parametrize("tier", ["full", "lite"])
def test_both_names_are_allowed(tier):
    settings = json.loads((ROOT / "claude-code" / tier / "settings.json").read_text())
    allow = settings["permissions"]["allow"]
    assert "mcp__threatintel-mcp__*" in allow
    assert "mcp__opencti-mcp__*" in allow
