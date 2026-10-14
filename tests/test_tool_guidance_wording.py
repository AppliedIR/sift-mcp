"""The same two sentences, verbatim, everywhere the AI reads how to run a tool:
sift-mcp's served instructions, the AGENTS.md core, the codex overlay, the
tool-reference skill and the LibreChat instructions. (vhir's copy of the
served block is checked in vhir.)"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELP_FIRST = (
    "Before building a tool's command line, call get_tool_help "
    "(get_windows_tool_help on Windows) and use a recipe for the installed "
    "version, or the tool's own help."
)
EXIT_CODES = (
    "Exit codes differ by tool and version: judge a run from its output and the "
    "files it wrote."
)


def _sift_mcp_instructions() -> str:
    src = (ROOT / "packages/sift-common/src/sift_common/instructions.py").read_text()
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and node.targets[0].id == "SIFT_MCP":
            return node.value.value
    raise AssertionError("no SIFT_MCP")


CHANNELS = {
    "sift-mcp instructions": _sift_mcp_instructions,
    "AGENTS.md": lambda: (ROOT / "AGENTS.md").read_text(),
    "codex overlay": lambda: (ROOT / "codex/OVERLAY.md").read_text(),
    "tool-reference skill": lambda: (
        ROOT / "skills/vhir-tool-reference/SKILL.md"
    ).read_text(),
    "LibreChat instructions": lambda: (ROOT / "docs/librechat-setup.md").read_text(),
}


@pytest.mark.parametrize("channel", sorted(CHANNELS))
@pytest.mark.parametrize("sentence", [HELP_FIRST, EXIT_CODES], ids=["help", "exit"])
def test_each_channel_says_it_verbatim(channel, sentence):
    text = " ".join(CHANNELS[channel]().split())  # wrapped lines read as one
    assert sentence in text
