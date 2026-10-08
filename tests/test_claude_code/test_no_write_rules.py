"""The full template ships no Write( deny rule: Claude Code's Edit rules
already cover the tools that write files. Where vhir is installed too, the
template's deny list is the same set as vhir's own client settings."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent


def _deny():
    p = ROOT / "claude-code" / "full" / "settings.json"
    return json.loads(p.read_text())["permissions"]["deny"]


def test_the_template_ships_no_write_rule():
    assert not [r for r in _deny() if r.startswith("Write(")]


def test_the_template_and_vhirs_client_settings_deny_the_same():
    cs = pytest.importorskip("vhir_cli.commands.client_setup")
    assert set(_deny()) == cs._FORENSIC_DENY_RULES
