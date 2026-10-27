"""The same two sentences, verbatim, everywhere the AI reads how to run a tool:
sift-mcp's served instructions, the AGENTS.md core, the codex overlay, the
tool-reference skill and the LibreChat instructions. (vhir's copy of the
served block is checked in vhir.) And the one owner of the rule for a failed
tool, which the other texts point to."""

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


# What to do when a tool, backend or gateway fails has one owner: its section
# in AGENTS.md. Lite's CLAUDE.md carries a byte-identical copy; every other text
# names the section by title instead of giving its own advice.
TITLE = "When a tool or the harness fails"
FAILED = "never in place of a call that failed"


def _section(text: str) -> str | None:
    lines = text.split("\n")
    if f"## {TITLE}" not in lines:
        return None
    i = lines.index(f"## {TITLE}")
    end = next(
        (j for j in range(i + 1, len(lines)) if lines[j][:3] in ("## ", "---")),
        len(lines),
    )
    return "\n".join(lines[i:end]).strip()


def test_agents_md_has_the_failure_section_once():
    agents = (ROOT / "AGENTS.md").read_text()
    assert agents.split("\n").count(f"## {TITLE}") == 1
    assert agents.count("failure stops the investigation") == 1


def test_lite_claude_md_carries_the_same_section():
    section = _section((ROOT / "AGENTS.md").read_text())
    assert section
    assert _section((ROOT / "claude-code/lite/CLAUDE.md").read_text()) == section


@pytest.mark.parametrize(
    "path",
    [
        "skills/vhir-tool-reference/SKILL.md",
        "claude-code/full/TOOL_REFERENCE.md",
        "claude-code/lite/TOOL_REFERENCE.md",
        "claude-code/full/CLAUDE.md",
    ],
)
def test_each_pointer_names_the_section(path):
    assert f'"{TITLE}"' in " ".join((ROOT / path).read_text().split())


def test_the_skeptic_and_shell_rules_defer_to_the_section():
    agents = (ROOT / "AGENTS.md").read_text().split("\n")
    (skeptic,) = [ln for ln in agents if ln.startswith("**Challenge before staging")]
    assert f'"{TITLE}"' in skeptic
    (shell,) = [ln for ln in agents if ln.startswith("- MCP first, by advice:")]
    assert FAILED in shell
