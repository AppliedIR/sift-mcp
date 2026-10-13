"""Claude Code's full template keeps the AI from reading the gateway's tokens
(~/.vhir/gateway.yaml) and Claude Code's own state (~/.claude.json), as
Codex's shell is kept from them: Read rules for the Read tool, and the sandbox
read-denies both for a shell. vhir's client settings carry the same rules."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
READS = {
    "Read(**/.vhir/gateway.yaml)",
    "Read(~/.vhir/gateway.yaml)",
    "Read(~/.claude.json)",
}


def _full():
    return json.loads((ROOT / "claude-code" / "full" / "settings.json").read_text())


def test_the_read_tool_is_denied_both():
    assert set(_full()["permissions"]["deny"]) >= READS


def test_the_sandbox_read_denies_both():
    deny_read = _full()["sandbox"]["filesystem"]["denyRead"]
    assert {"~/.vhir/gateway.yaml", "~/.claude.json"} <= set(deny_read)


def test_vhirs_client_settings_carry_the_same_rules():
    cs = pytest.importorskip("vhir_cli.commands.client_setup")
    assert READS <= cs._FORENSIC_DENY_RULES
