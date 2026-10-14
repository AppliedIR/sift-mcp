"""Codex's finding-skeptic gets the tools Claude's skeptic is given and nothing
that writes or hands work on: the managed PreToolUse hook refuses (exit 2) a
call the skeptic makes ("agent_type": "finding-skeptic", which Codex sets) to
any MCP tool off claude.md's `tools:` list, to apply_patch or the shell, or to
spawn or message another agent. Calls by any other agent pass. It fails
closed, as the case-data guard does."""

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent.parent
HOOK = ROOT / "claude-code" / "shared" / "hooks" / "codex-skeptic-tools.sh"


def run(payload, path="/usr/bin:/bin"):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(["/bin/bash", str(HOOK)], input=text, capture_output=True, text=True,
                          env={"PATH": path}, timeout=30)  # fmt: skip


def call(tool, agent_type="finding-skeptic"):
    p = {"session_id": "s", "turn_id": "t", "cwd": "/tmp", "hook_event_name": "PreToolUse",
         "tool_name": tool, "tool_input": {}, "tool_use_id": "u"}  # fmt: skip
    if agent_type:
        p.update(agent_id="a", agent_type=agent_type)
    return p


REFUSED = [
    "mcp__forensic-mcp__record_finding",
    "mcp__forensic-mcp__record_timeline_event",
    "mcp__opensearch-mcp__idx_ingest",
    "mcp__case-mcp__case_activate",
    "mcp__case-mcp__import_bundle",
    "mcp__case-mcp__backup_case",
    "mcp__report-mcp__save_report",
    "apply_patch",
    "Bash",
    "exec_command",
    "write_stdin",
    "collaborationspawn_agent",  # code mode's spawn, as the hook names it
    "spawn_agent",
    "multi_agent_v1send_input",
    "collaborationsend_message",
    "collaborationfollowup_task",
    "mcp__other__run_command",  # another server's tool of an allowed name
    "mcp__forensic_mcp__run_command",  # an allowed name on the wrong server
    "mcp__sift_mcp__record_finding",
]
PASSED = [
    "mcp__forensic-mcp__get_findings",
    "mcp__sift-mcp__run_command",
    "mcp__opensearch-mcp__idx_search",
    "mcp__wintools-mcp__run_windows_command",
    "mcp__forensic_mcp__get_findings",  # as Codex names it: the server's "-" made "_"
    "mcp__sift_mcp__run_command",
    "mcp__windows_triage_mcp__check_file",
    "collaborationwait_agent",
    "read_mcp_resource",
    "view_image",
]


@pytest.mark.parametrize("tool", REFUSED)
def test_the_skeptic_is_refused_a_write_or_a_hand_on(tool):
    r = run(call(tool))
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert r.stderr.startswith("BLOCKED: the finding-skeptic reads and queries only")
    assert tool in r.stderr


@pytest.mark.parametrize("tool", PASSED)
def test_the_skeptic_keeps_its_read_and_query_tools(tool):
    r = run(call(tool))
    assert (r.returncode, r.stderr) == (0, "")


@pytest.mark.parametrize("agent_type", [None, "default", "explorer", "worker"])
@pytest.mark.parametrize("tool", REFUSED)
def test_any_other_agent_is_untouched(tool, agent_type):
    r = run(call(tool, agent_type))
    assert (r.returncode, r.stderr) == (0, "")


@pytest.mark.parametrize(
    "payload", ["", "not json", "[]", '{"agent_type": "finding-skeptic"}']
)
def test_an_unreadable_call_is_refused(payload):
    r = run(payload)
    assert r.returncode == 2 and "couldn't read this call" in r.stderr


def test_without_python_every_call_is_refused(tmp_path):
    r = run(call("mcp__forensic-mcp__get_findings", None), path=str(tmp_path))
    assert r.returncode == 2 and "couldn't run" in r.stderr


def test_the_allowlist_is_claude_s_skeptic_s():
    """The hook's server and tool pairs are claude.md's `tools:` line."""
    import ast

    head = (
        (ROOT / "agents" / "finding-skeptic" / "claude.md")
        .read_text()
        .split("---\n")[1]
    )
    claude = {
        tuple(t.split("__")[1:]) for t in yaml.safe_load(head)["tools"].split(", ")
    }
    block = re.search(r"^ALLOWED = (\{.*?\n\})", HOOK.read_text(), re.S | re.M).group(1)
    hook = {(s, n) for s, names in ast.literal_eval(block).items() for n in names}
    assert hook == claude
