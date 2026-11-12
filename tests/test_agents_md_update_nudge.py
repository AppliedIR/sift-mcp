"""U12: sift-mcp's AGENTS.md tells an AI assistant not to run `vhir update`.

This file is the source vhir deploys as ~/.claude/rules/AGENTS.md and builds
Codex's developer_instructions from, so the one line here reaches both. The
line must match byte for byte: vhir's rows look for it by its exact text.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPDATE_NUDGE = (
    "Don't run vhir update yourself. Ask the examiner to run it in their own"
    " terminal, where it can apply the forensic controls."
)


def test_agents_md_has_the_update_nudge_once_as_a_whole_line():
    lines = (ROOT / "AGENTS.md").read_bytes().split(b"\n")
    assert lines.count(UPDATE_NUDGE.encode()) == 1, ROOT / "AGENTS.md"
