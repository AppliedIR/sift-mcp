"""A wintools reply that leaves a file unhashed (``hash_state: pending``) gets
it hashed on SIFT, in the active case, and recorded by the gateway: the
registry's hash for a registered file, else a hash made here (in the call, or
by a background job). Paths come from the remote's reply, so one that leads
outside the case is refused. The wintools session is a stand-in; the case,
the files and the audit log are real. Values are synthetic.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import mcp.types as types
import pytest
from mcp.types import CallToolResult, TextContent, Tool
from sift_common import file_identity
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server, create_mcp_server
from sift_gateway.server import Gateway

AUDIT_ID = "wintools-examiner-20261009-000001"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    case = tmp_path / "cases" / "CASE-1"
    (case / "audit").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-1\n")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    return case


def _reply(*files: dict) -> CallToolResult:
    body = {"audit_id": AUDIT_ID, "inputs": list(files), "outputs": []}
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(body))])


def _gateway(reply: CallToolResult, name: str = "wintools-mcp") -> Gateway:
    backend = HttpMCPBackend(name, {"url": "http://127.0.0.1:9/mcp"})
    backend._started = True
    backend._tools_cache = [Tool(name="run_windows_command", inputSchema={})]
    backend._session = MagicMock()
    backend._session.send_ping = AsyncMock()
    backend._session.call_tool = AsyncMock(return_value=reply)
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {name: backend}
    gw._tool_map = {"run_windows_command": name}
    return gw


async def _call(gw: Gateway, endpoint: str, name: str = "wintools-mcp"):
    if endpoint == "per-backend":
        server = create_backend_mcp_server(gw, name)
    else:
        server = create_mcp_server(gw)
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name="run_windows_command", arguments={}),
    )
    return (await server.request_handlers[types.CallToolRequest](request)).root


def _entries(case: Path, tool: str) -> list[dict]:
    out = []
    for log in (case / "audit").glob("*.jsonl"):
        for line in log.read_text().splitlines():
            entry = json.loads(line)
            if entry.get("tool") == tool:
                out.append(entry)
    return out


def _pending(rel: str) -> dict:
    return {
        "share_path": rel.replace("/", "\\"),
        "sift_path": rel,
        "hash_state": "pending",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["per-backend", "aggregate"])
async def test_a_pending_file_is_hashed_in_the_case_and_recorded(case, endpoint):
    disk = case / "evidence" / "disk.E01"
    disk.write_bytes(b"PRETEND-OVER-1GB")
    result = await _call(_gateway(_reply(_pending("evidence/disk.E01"))), endpoint)
    assert result.isError is False
    (entry,) = _entries(case, "wintools_pending_hashes")
    assert entry["params"]["backend_audit_id"] == AUDIT_ID
    (rec,) = entry["files"]
    assert rec["path"] == str(disk.resolve())
    assert rec["sha256"] == sha(disk.read_bytes())
    assert (rec["role"], rec["sift_path"]) == ("input", "evidence/disk.E01")


@pytest.mark.asyncio
async def test_a_registered_file_takes_the_registrys_hash_unread(case):
    disk = case / "evidence" / "disk.E01"
    disk.write_bytes(b"CONTENT")
    registry = {"files": [{"path": str(disk.resolve()), "sha256": "ab" * 32}]}
    (case / "evidence.json").write_text(json.dumps(registry))
    await _call(_gateway(_reply(_pending("evidence/disk.E01"))), "per-backend")
    (entry,) = _entries(case, "wintools_pending_hashes")
    (rec,) = entry["files"]
    assert rec["sha256"] == "ab" * 32 and rec["registered"] is True


@pytest.mark.asyncio
async def test_a_file_over_the_inline_limit_is_hashed_by_a_background_job(
    case, monkeypatch
):
    monkeypatch.setitem(file_identity.hash_for_call.__kwdefaults__, "inline_limit", 4)
    disk = case / "evidence" / "disk.E01"
    disk.write_bytes(b"PRETEND-OVER-THE-LIMIT")
    await _call(_gateway(_reply(_pending("evidence/disk.E01"))), "per-backend")
    (entry,) = _entries(case, "wintools_pending_hashes")
    (rec,) = entry["files"]
    assert rec["sha256"].startswith("pending:hash-")
    job = rec["sha256"].removeprefix("pending:")
    deadline = time.monotonic() + 10
    while not [e for e in _entries(case, "hash_complete") if e.get("job_id") == job]:
        assert time.monotonic() < deadline, "the job never closed"
        time.sleep(0.1)
    (done,) = [e for e in _entries(case, "hash_complete") if e.get("job_id") == job]
    assert done["sha256"] == sha(disk.read_bytes())
    assert done["requested_by"] == AUDIT_ID


@pytest.mark.asyncio
async def test_a_path_that_leads_outside_the_case_is_refused(case, tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"not the case's")
    (case / "evidence" / "link.bin").symlink_to(outside)
    paths = ["../../outside.bin", str(outside), "evidence/link.bin", "C:/x.bin"]
    await _call(_gateway(_reply(*[_pending(p) for p in paths])), "per-backend")
    (entry,) = _entries(case, "wintools_pending_hashes")
    assert len(entry["files"]) == 4
    for rec in entry["files"]:
        assert "error" in rec and "sha256" not in rec, rec


@pytest.mark.asyncio
async def test_without_a_case_nothing_is_recorded_and_the_call_answers(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    result = await _call(_gateway(_reply(_pending("evidence/disk.E01"))), "per-backend")
    assert result.isError is False
    assert AUDIT_ID in result.content[0].text


@pytest.mark.asyncio
async def test_only_wintools_replies_are_read_for_pending_files(case):
    disk = case / "evidence" / "disk.E01"
    disk.write_bytes(b"X")
    gw = _gateway(_reply(_pending("evidence/disk.E01")), name="other-mcp")
    await _call(gw, "per-backend", name="other-mcp")
    assert _entries(case, "wintools_pending_hashes") == []


@pytest.mark.asyncio
async def test_a_reply_with_nothing_pending_records_nothing(case):
    hashed = {"sift_path": "evidence/a.bin", "sha256": "cd" * 32}
    await _call(_gateway(_reply(hashed)), "per-backend")
    assert _entries(case, "wintools_pending_hashes") == []


# --- The case is the one the call started in; a reply never fails the call ----


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["per-backend", "aggregate"])
async def test_a_case_switched_during_the_call_doesnt_take_its_hashes(
    case, tmp_path, monkeypatch, endpoint
):
    disk = case / "evidence" / "disk.E01"
    disk.write_bytes(b"IN CASE ONE")
    other = tmp_path / "cases" / "CASE-2"
    (other / "audit").mkdir(parents=True)
    (other / "evidence").mkdir()
    (other / "CASE.yaml").write_text("case_id: CASE-2\n")
    (other / "evidence" / "disk.E01").write_bytes(b"A DIFFERENT FILE")
    gw = _gateway(_reply(_pending("evidence/disk.E01")))
    reply = gw.backends["wintools-mcp"]._session.call_tool.return_value

    async def switch_then_answer(*a, **k):
        monkeypatch.setenv("VHIR_CASE_DIR", str(other))  # switched mid-call
        return reply

    gw.backends["wintools-mcp"]._session.call_tool = AsyncMock(
        side_effect=switch_then_answer
    )
    await _call(gw, endpoint)
    (entry,) = _entries(case, "wintools_pending_hashes")
    assert entry["case_id"] == "CASE-1"
    assert entry["files"][0]["sha256"] == sha(b"IN CASE ONE")
    assert _entries(other, "wintools_pending_hashes") == []


@pytest.mark.asyncio
async def test_a_malformed_reply_never_fails_the_call(case):
    bad = CallToolResult(content=[TextContent(type="text", text=json.dumps(
        {"audit_id": AUDIT_ID, "inputs": 1, "note": "pending"}))])  # fmt: skip
    result = await _call(_gateway(bad), "per-backend")
    assert result.isError is False
    assert json.loads(result.content[0].text)["inputs"] == 1
    assert _entries(case, "wintools_pending_hashes") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["per-backend", "aggregate"])
async def test_an_error_reply_records_no_hashes(case, endpoint):
    (case / "evidence" / "disk.E01").write_bytes(b"X")
    reply = _reply(_pending("evidence/disk.E01"))
    reply.isError = True
    result = await _call(_gateway(reply), endpoint)
    assert result.isError is True
    assert _entries(case, "wintools_pending_hashes") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["per-backend", "aggregate"])
async def test_a_case_that_cant_be_read_never_fails_the_call(case, endpoint):
    gw = _gateway(_reply(_pending("evidence/disk.E01")))

    def unreadable(*a, **k):
        raise PermissionError(13, "Permission denied", str(case))

    gw._audit._get_audit_dir = unreadable
    result = await _call(gw, endpoint)
    assert result.isError is False  # the call answers; nothing is recorded
    assert json.loads(result.content[0].text)["audit_id"] == AUDIT_ID
    assert _entries(case, "wintools_pending_hashes") == []
