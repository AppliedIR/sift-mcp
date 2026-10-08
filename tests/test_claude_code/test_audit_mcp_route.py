"""A shell command that has an MCP route is marked in its audit entry and
the model is told the route, by advice: never blocked. A command without one
gets neither. The route lookup runs after the entry is written, so a lookup
that fails still leaves the entry, and the hook still exits 0 with nothing
but JSON on stdout. Both clients. The route sidecar is a stand-in: it routes
`vol`, and can be made to fail; values are synthetic."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HOOKS = Path(__file__).parent.parent.parent / "claude-code" / "shared" / "hooks"
SIDECAR = """import json, os, sys
if os.environ.get("ROUTE_FAILS"):
    raise SystemExit(3)
cmd = sys.stdin.read().split()
if cmd and cmd[0] == "vol":
    print(json.dumps({"mcp_route": "sift-mcp run_command", "tool": "vol3", "command": "vol",
                      "advisory": "vol has an MCP route: sift-mcp run_command (vol3)."}))
"""


@pytest.fixture
def run(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for name in ("forensic-audit.sh", "codex-stdin-capture.sh"):
        shutil.copy(HOOKS / name, hooks / name)
    (hooks / "mcp-route.py").write_text(SIDECAR)
    case = tmp_path / "cases" / "INC-1"
    (case / "audit").mkdir(parents=True)
    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "active_case").write_text(str(case))

    def go(command, *args, fails=False):
        env = {k: v for k, v in os.environ.items() if not k.startswith("VHIR_")}
        env.update(
            HOME=str(tmp_path), VHIR_EXAMINER="tester", ROUTE_FAILS="1" if fails else ""
        )
        payload = {"hook_event_name": "PostToolUse", "session_id": "s", "tool_use_id": "t",
                   "cwd": str(case), "tool_name": "Bash", "tool_input": {"command": command},
                   "tool_response": "ok"}  # fmt: skip
        r = subprocess.run(["bash", str(hooks / "forensic-audit.sh"), *args],
                           input=json.dumps(payload), capture_output=True, text=True,
                           env=env, timeout=30)  # fmt: skip
        lines = (case / "audit" / "claude-code.jsonl").read_text().splitlines()
        return r, json.loads(lines[-1])

    return go


@pytest.mark.parametrize("args", [(), ("--client", "codex")], ids=["claude", "codex"])
def test_a_routed_command_is_marked_and_advised(run, args):
    r, entry = run("vol -f mem.raw windows.pslist", *args)
    assert r.returncode == 0
    assert entry["mcp_route"] == "sift-mcp run_command" and entry["mcp_tool"] == "vol3"
    out = json.loads(r.stdout)
    assert out["hookSpecificOutput"]["additionalContext"].startswith(
        "vol has an MCP route"
    )


def test_a_command_without_a_route_gets_neither(run):
    r, entry = run("ls -la")
    assert r.returncode == 0 and r.stdout == "" and "mcp_route" not in entry


def test_a_failing_lookup_still_leaves_the_entry_and_valid_output(run):
    r, entry = run("vol -f mem.raw windows.pslist", fails=True)
    assert r.returncode == 0 and r.stdout == ""
    assert entry["command"].startswith("vol -f") and "mcp_route" not in entry
