"""How to read a windows-triage verdict is served in the verdicts the tools
return: check_file gives EXPECTED, EXPECTED_LOLBIN, SUSPICIOUS or UNKNOWN, and
check_process_tree gives EXPECTED, SUSPICIOUS or UNKNOWN. The guidance named
RENAMED and UNEXPECTED, which no tool returns, and nothing the AI reads names
them now. The texts are the approved ones, served as written."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from forensic_mcp.server import create_server
from windows_triage.analysis.verdicts import Verdict

ROOT = Path(__file__).resolve().parents[2]

CHECK_FILE = {
    "EXPECTED": "The path, or a known directory for this filename, matches the "
    "Windows baseline. Without a hash this is a name-and-path match only; pass the "
    "hash to compare it with the baseline builds of that path. Default does not "
    "mean benign.",
    "EXPECTED_LOLBIN": "As EXPECTED, and the file is a known LOLBin that can be "
    "abused. Check how it was used.",
    "SUSPICIOUS": "A specific anomaly: a critical filename trick (Unicode or double "
    "extension), a known attack-tool name, a system binary's name in an unexpected "
    "directory (masquerading), a hash that matches no baseline build of that path, "
    "or another high-severity filename issue. The reply's reasons say which. "
    "Investigate further.",
    "UNKNOWN": "File NOT in baseline database. This is NEUTRAL — it means "
    "not-in-database, not suspicious. Custom software, user files, and enterprise "
    "tools will all be UNKNOWN. A filename without a folder is not checked: pass "
    "the full path.",
}
CHECK_PROCESS_TREE = {
    "EXPECTED": "Parent, path and user match the expectations for this process.",
    "SUSPICIOUS": "Unexpected parent, executable path or user context for a known "
    "process, or a filename anomaly; the reasons say which. May indicate process "
    "injection, living-off-the-land, or unusual execution.",
    "UNKNOWN": "Process not in the expectations database. Neutral.",
}


async def _served(tool: str, mode: str = "tools") -> dict:
    """As the AI reads it: the get_tool_guidance tool, or the resource."""
    if mode == "tools":
        server = create_server(reference_mode="tools")
        result = await server.call_tool("get_tool_guidance", {"tool_name": tool})
        raw = result[0].text
    else:
        server = create_server()
        result = await server.read_resource(f"forensic-mcp://tool-guidance/{tool}")
        raw = result[0].content if hasattr(result[0], "content") else result[0].text
    return json.loads(raw)["score_interpretation"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["tools", "resources"])
@pytest.mark.parametrize(
    "tool, texts",
    [("check_file", CHECK_FILE), ("check_process_tree", CHECK_PROCESS_TREE)],
)
async def test_the_verdict_guidance_is_served_as_approved(tool, texts, mode):
    assert await _served(tool, mode) == texts


@pytest.mark.asyncio
async def test_the_guidance_names_only_verdicts_the_tools_return():
    returned = {v.value for v in Verdict}
    assert set(await _served("check_file")) == returned
    assert set(await _served("check_process_tree")) <= returned


def test_nothing_the_ai_reads_names_a_verdict_no_tool_returns():
    """The served knowledge, instructions, skills and client texts."""
    places = [
        ROOT / "packages",
        ROOT / "skills",
        ROOT / "agents",
        ROOT / "codex",
        ROOT / "claude-code",
        ROOT / "AGENTS.md",
    ]
    old = re.compile(r"\b(RENAMED|UNEXPECTED)\b")
    named = [
        f"{path.relative_to(ROOT)}:{n}"
        for place in places
        for path in ([place] if place.is_file() else sorted(place.rglob("*")))
        if path.is_file()
        and path.suffix in {".yaml", ".yml", ".md", ".py", ".toml"}
        and "/tests/" not in str(path)
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1)
        if old.search(line)
    ]
    assert named == []
