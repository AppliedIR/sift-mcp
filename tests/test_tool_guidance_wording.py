"""The same two sentences, verbatim, everywhere the AI reads how to run a tool:
sift-mcp's served instructions, the AGENTS.md core, the codex overlay, the
tool-reference skill and the LibreChat instructions. (vhir's copy of the
served block is checked in vhir.) And the one owner of the rule for a failed
tool, which the other texts point to."""

from __future__ import annotations

import ast
import re
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
# The section's clauses, in order: each is pinned by name, so a clause dropped
# from both copies fails.
CLAUSES = {
    "stop": (
        "A tool, backend or gateway failure stops the investigation: tell the "
        "examiner which tool failed and the exact error, and don't work around it "
        "with the shell or another tool."
    ),
    "what-fails": (
        "A failure is a lost or refused connection, a server the client says isn't "
        "connected, a tool you were given that the client or server no longer has, "
        "a call that timed out with no result, a status saying a background run "
        "failed, or an error naming nothing in your call to change; when unsure, "
        "it is one."
    ),
    "hands-off": (
        "After a failure, until the examiner says it is fixed, don't retry the call "
        "or restart, set up or repair anything yourself, even when the reply says "
        "how, or says to try again or to continue without it."
    ),
    "resume": (
        "Once the examiner says it is fixed, read the case's audit/<server>.jsonl "
        "for the failed call (none yet: ask the examiner), then call that tool "
        "again (not one it shows finished) and resume when it answers."
    ),
    "not-failures": (
        "Not failures: a refusal naming what to change in your call, any other "
        "result (empty or partial too), a result saying a program isn't installed "
        "(run another in that same tool), a threat-intel platform's error, "
        '"busy, wait", a result saying a run '
        "waits for the examiner's confirmation, and a result saying your command "
        "was stopped at its time limit (narrow it and run it again in that same "
        "tool)."
    ),
}
TOOL_REFS = [
    "skills/vhir-tool-reference/SKILL.md",
    "claude-code/full/TOOL_REFERENCE.md",
    "claude-code/lite/TOOL_REFERENCE.md",
]
POINTERS = TOOL_REFS + ["claude-code/full/CLAUDE.md"]
# The advice the section replaced, gone from every pointer and from lite's
# CLAUDE.md outside its copy of the section.
OLD_ADVICE = [
    "degrade gracefully",
    "skip its steps",
    "fallback",
    "retry with simpler",
    "restart backend",
    "restart claude code",
    "restart if tools stop responding",
]


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


@pytest.mark.parametrize("clause", sorted(CLAUSES))
def test_the_section_says_each_clause(clause):
    assert CLAUSES[clause] in _section((ROOT / "AGENTS.md").read_text())


def test_the_section_is_its_clauses_and_nothing_else():
    body = _section((ROOT / "AGENTS.md").read_text())
    assert body == f"## {TITLE}\n\n" + " ".join(CLAUSES.values())


def test_lite_claude_md_carries_the_same_section():
    section = _section((ROOT / "AGENTS.md").read_text())
    assert section
    assert _section((ROOT / "claude-code/lite/CLAUDE.md").read_text()) == section
    lite = (ROOT / "claude-code/lite/CLAUDE.md").read_text()
    assert not re.search(r"run.?command", lite, re.IGNORECASE)
    assert not re.search(r"get.?tool.?help|sift", section, re.IGNORECASE)


@pytest.mark.parametrize("path", POINTERS)
def test_each_pointer_names_the_section(path):
    assert f'"{TITLE}"' in " ".join((ROOT / path).read_text().split())


@pytest.mark.parametrize("path", POINTERS + ["claude-code/lite/CLAUDE.md"])
def test_no_old_failure_advice_is_left(path):
    text = (ROOT / path).read_text()
    section = _section(text)
    if section:
        text = text.replace(section, "")
    flat = " ".join(text.split()).lower()
    assert [p for p in OLD_ADVICE if p in flat] == []


@pytest.mark.parametrize("path", TOOL_REFS)
def test_the_failures_table_has_the_pointer_and_empty_results_only(path):
    lines = (ROOT / path).read_text().split("\n")
    rest = lines[lines.index("### MCP Failures") + 1 :]
    start = next(i for i, ln in enumerate(rest) if ln.startswith("|"))
    end = next(
        (i for i in range(start, len(rest)) if not rest[i].startswith("|")), len(rest)
    )
    rows = [ln.split("|")[1].strip() for ln in rest[start + 2 : end]]
    assert rows == ["Any tool, backend or gateway failure", "Empty results"]


def test_the_skeptic_and_shell_rules_defer_to_the_section():
    agents = (ROOT / "AGENTS.md").read_text().split("\n")
    (skeptic,) = [ln for ln in agents if ln.startswith("**Challenge before staging")]
    assert f'"{TITLE}"' in skeptic
    (shell,) = [ln for ln in agents if ln.startswith("- MCP first, by advice:")]
    assert FAILED in shell
