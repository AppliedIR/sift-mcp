"""A run_command child can't read the backend's MCP channel.

The deployed form: the gateway's own handler calls sift-mcp, which runs as
the gateway runs it (`python -m sift_mcp`, a real StdioMCPBackend) against a
temporary case. A child that reads stdin (`head` with no file, `7z` asking
for a password) gets /dev/null and returns at once. Before, it read the
channel: it took another call's request as its input, that call was never
answered and never audited, and the request came back in the child's stdout.

This file imports nothing the change added, so it runs against the code
before it.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time

import mcp.types as types
import pytest
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server
from sift_gateway.server import Gateway

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc/self/fd"
)

CALL_TIMEOUT = 20  # the gateway's reply; never a hang
RUN_TIMEOUT = 10  # run_command's own limit for the child


@pytest.fixture
async def sift_gateway(tmp_path, monkeypatch):
    """A gateway whose sift-mcp backend is the real one, on a temporary case."""
    # the gateway passes its own VHIR_* to a backend with an env
    for key in list(os.environ):
        if key.startswith("VHIR_"):
            monkeypatch.delenv(key)
    home, case = tmp_path / "home", tmp_path / "case"
    (home / ".vhir").mkdir(parents=True)
    (case / "audit").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.yaml").write_text("case_id: stdin\nstatus: open\n")
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    (home / ".vhir" / "active_case").write_text(f"{case}\n")
    env = {"HOME": str(home)}
    if os.environ.get("PYTHONPATH"):
        env["PYTHONPATH"] = os.environ["PYTHONPATH"]
    backend = StdioMCPBackend(
        "sift-mcp",
        {
            "type": "stdio",
            "command": sys.executable,
            "args": ["-m", "sift_mcp"],
            "env": env,
        },
    )
    await backend.start()
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {"sift-mcp": backend}
    gw._tool_map = {"run_command": "sift-mcp"}
    gw.case = case
    try:
        yield gw
    finally:
        await backend.stop()


async def _run(gw: Gateway, command: list[str]) -> dict:
    """run_command through the per-backend route; the reply, and its time."""
    handler = create_backend_mcp_server(gw, "sift-mcp").request_handlers[
        types.CallToolRequest
    ]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(
            name="run_command",
            arguments={"command": command, "purpose": "test", "timeout": RUN_TIMEOUT},
        ),
    )
    start = time.monotonic()
    result = (await asyncio.wait_for(handler(request), CALL_TIMEOUT)).root
    reply = json.loads(result.content[0].text)
    assert result.isError is False, reply
    reply["seconds"] = time.monotonic() - start
    return reply


def _stdout(reply: dict) -> str:
    return reply["data"]["stdout"]


def _no_request_in(*replies: dict) -> None:
    for reply in replies:
        lines = [ln for ln in _stdout(reply).splitlines() if '"jsonrpc"' in ln]
        assert not lines, f"{reply['data']['command']} read the channel: {lines}"


def _audited(gw: Gateway, command: list[str]) -> bool:
    log = gw.case / "audit" / "sift-mcp.jsonl"
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    return any(e["params"]["command"] == command for e in entries)


async def _with_two_more(gw: Gateway, first: list[str]):
    """`first`, and two calls made while it runs, from the same session."""
    calls = [first, ["echo", "b-canary"], ["echo", "c-canary"]]
    tasks = [asyncio.create_task(_run(gw, calls[0]))]
    await asyncio.sleep(0.3)  # the first child is running
    tasks += [asyncio.create_task(_run(gw, c)) for c in calls[1:]]
    replies = await asyncio.gather(*tasks, return_exceptions=True)
    for command, reply in zip(calls, replies, strict=True):
        assert not isinstance(reply, BaseException), (command, repr(reply))
    a, b, c = replies
    assert _stdout(b) == "b-canary\n"
    assert _stdout(c) == "c-canary\n"
    for command in calls[1:]:
        assert _audited(gw, command), f"no audit entry for {command}"
    _no_request_in(a, b, c)
    return a


async def test_a_child_reads_dev_null_as_stdin(sift_gateway):
    reply = await _run(sift_gateway, ["bash", "-c", "readlink /proc/self/fd/0"])
    assert reply["data"]["exit_code"] == 0
    assert _stdout(reply) == "/dev/null\n"
    _no_request_in(reply)


async def test_head_with_no_file_returns_at_once_with_nothing(sift_gateway):
    reply = await _run(sift_gateway, ["head", "-n", "1"])
    assert reply["seconds"] < 2, reply
    assert reply["data"]["exit_code"] == 0
    assert _stdout(reply) == ""
    _no_request_in(reply)


async def test_calls_made_while_a_stdin_reader_runs_are_answered(sift_gateway):
    a = await _with_two_more(sift_gateway, ["head", "-n", "1"])
    assert a["data"]["exit_code"] == 0
    assert _stdout(a) == ""


@pytest.mark.skipif(shutil.which("7z") is None, reason="needs 7z")
async def test_7z_asking_for_a_password_stops_and_others_are_answered(
    sift_gateway, tmp_path
):
    plain = tmp_path / "note.txt"
    plain.write_text("synthetic\n")
    archive = sift_gateway.case / "evidence" / "locked.7z"
    subprocess.run(
        ["7z", "a", "-pnot-a-secret", "-mhe=on", str(archive), str(plain)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=30,
    )
    a = await _with_two_more(sift_gateway, ["7z", "l", "-slt", str(archive)])
    assert a["data"]["elapsed_seconds"] < 1, a
