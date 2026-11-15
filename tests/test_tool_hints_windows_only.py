"""Each hint the AI reads about where a Zimmerman tool runs says what is true:
PECmd and AmcacheParser run on SIFT, SrumECmd runs only on Windows, and
sigcheck and autorunsc are wintools-mcp's."""

from __future__ import annotations

from pathlib import Path

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.response import build_response, reset_call_counter
from sift_mcp.tools.discovery import get_tool_help

ROOT = Path(__file__).resolve().parents[1]


def _execution_hints() -> list[str]:
    reset_call_counter()
    try:
        resp = build_response(
            tool_name="PECmd",
            success=True,
            data={"output": ""},
            audit_id="sift-test-001",
            artifact_context="prefetch",
        )
    finally:
        reset_call_counter()
    return resp["related_tools"]


def _lines(rel: str) -> list[str]:
    return (ROOT / rel).read_text().splitlines()


def _under(rel: str, heading: str) -> list[str]:
    lines = _lines(rel)
    start = lines.index(heading) + 1
    end = next(
        (i for i in range(start, len(lines)) if lines[i].startswith("#")), len(lines)
    )
    return lines[start:end]


WINTOOLS = "### wintools-mcp (if available)"
SRUM_LINE = "- SrumECmd, the one Zimmerman tool that runs only on Windows"

ROWS = {
    "execution related tools": (
        _execution_hints,
        "sift-mcp run_command(PECmd/AmcacheParser): parse on SIFT",
        "run_windows_command(PECmd",
    ),
    "full tool reference": (
        lambda: _under("claude-code/full/TOOL_REFERENCE.md", WINTOOLS),
        SRUM_LINE,
        "PECmd",
    ),
    "lite tool reference": (
        lambda: _under("claude-code/lite/TOOL_REFERENCE.md", WINTOOLS),
        SRUM_LINE,
        "PECmd",
    ),
    "tool-reference skill": (
        lambda: _under("skills/vhir-tool-reference/SKILL.md", WINTOOLS),
        SRUM_LINE,
        "PECmd",
    ),
    "ingest skill": (
        lambda: _lines("skills/vhir-ingest/SKILL.md"),
        "6. Run PECmd on SIFT (run_command); use wintools-mcp for autorunsc, sigcheck and SrumECmd",
        "(autorunsc, sigcheck, PECmd)",
    ),
    "escalation skill, sigcheck": (
        lambda: _lines("skills/vhir-malware-escalation/SKILL.md"),
        "**From sigcheck / autorunsc (wintools-mcp):**",
        "**From sigcheck / autorunsc (wintools-mcp or sift-mcp):**",
    ),
    "escalation skill, PECmd": (
        lambda: _lines("skills/vhir-malware-escalation/SKILL.md"),
        "**From PECmd / AmcacheParser (sift-mcp or wintools-mcp):**",
        "**From PECmd / AmcacheParser (wintools-mcp or sift-mcp):**",
    ),
}


@pytest.mark.parametrize("name", list(ROWS))
def test_a_tool_hint_says_where_the_tool_runs(name):
    read, want, gone = ROWS[name]
    lines = read()
    assert want in lines
    assert not any(gone in line for line in lines)


OLD_BUILDS = (
    "Builds from 2022 until 2026.10 exit with code 0 when they refuse on Linux,"
    " so a run can look successful and produce no output."
)


def _check_pecmd_caveats(caveats: list[str]) -> None:
    for stale in (
        "Windows forensic workstation only",
        "Non-Windows platforms not supported",
    ):
        assert not any(stale in caveat for caveat in caveats), stale
    assert any(caveat.startswith(OLD_BUILDS) for caveat in caveats)


def test_a_pecmd_reply_warns_about_old_builds_and_does_not_call_it_windows_only():
    reset_call_counter()
    try:
        resp = build_response(
            tool_name="PECmd",
            success=True,
            data={"output": ""},
            audit_id="sift-test-002",
            artifact_context="prefetch",
        )
    finally:
        reset_call_counter()
    _check_pecmd_caveats(resp["caveats"])


def test_pecmd_tool_help_warns_about_old_builds_and_does_not_call_it_windows_only():
    clear_catalog_cache()
    try:
        info = get_tool_help("PECmd")
    finally:
        clear_catalog_cache()
    _check_pecmd_caveats(info["caveats"])
