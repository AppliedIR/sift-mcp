"""A reference lookup (opencti lookup_ioc, a windows-triage check_*) keeps
what the source said: its raw response saved in the case, with the source,
its version and the response's SHA-256 on an entry of its own."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import types
from mcp.types import TextContent
from sift_common.audit import AuditWriter
from sift_gateway.backends.base import MCPBackend
from sift_gateway.mcp_endpoint import create_backend_mcp_server
from sift_gateway.server import Gateway

BODY = json.dumps({"ioc": "1.2.3.4", "providers": {"opencti": {"outcome": "NO_MATCH"}}})


class Source(MCPBackend):
    def __init__(self, name, version="", error=False):
        super().__init__(name, {"type": "stdio", "enabled": True})
        self._started, self._server_version, self._error = True, version, error

    async def start(self):
        self._started = True

    async def stop(self):
        self._started = False

    async def list_tools(self):
        return []

    async def call_tool(self, name, arguments):
        out = [TextContent(type="text", text=BODY)]
        if self._error:
            out = type("R", (list,), {"is_error": True})(out)
        return out

    async def health_check(self):
        return {"status": "ok"}


@pytest.fixture
def case(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner1")
    for var in ("VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    d = tmp_path / "case-a"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: case-a\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _gateway(backend) -> Gateway:
    gw = Gateway({"gateway": {}, "api_keys": {}, "backends": {}})
    gw.backends = {backend.name: backend}
    gw._tool_map = {"lookup_ioc": backend.name, "check_file": backend.name,
                    "search_threat_intel": backend.name}  # fmt: skip
    gw._audit = AuditWriter(mcp_name="sift-gateway")
    return gw


def _entries(case: Path) -> list[dict]:
    f = case / "audit" / "sift-gateway.jsonl"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


def _check(case: Path, tool: str, source: str, version: str) -> None:
    (e,) = [e for e in _entries(case) if "reference" in e]
    ref = e["reference"]
    saved = Path(ref["response"]["path"])
    assert e["tool"] == tool
    assert saved == case / "extractions" / e["audit_id"] / "response.json"
    assert saved.read_bytes() == BODY.encode()
    assert ref["response"]["sha256"] == hashlib.sha256(BODY.encode()).hexdigest()
    assert ref["source"] == source and ref["source_version"] == version


@pytest.mark.asyncio
async def test_a_lookup_through_the_gateway_keeps_its_response(case):
    gw = _gateway(Source("opencti-mcp", "0.6.4"))
    result = await gw.call_tool("lookup_ioc", {"ioc": "1.2.3.4"}, examiner="ann")
    assert [c.text for c in result] == [BODY]  # answered as before
    _check(case, "lookup_ioc", "opencti-mcp", "0.6.4")


@pytest.mark.asyncio
async def test_a_baseline_check_on_its_own_endpoint_keeps_its_response(case):
    backend = Source("windows-triage-mcp", "1.2.0")
    server = create_backend_mcp_server(_gateway(backend), backend.name)
    handler = server.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name="check_file", arguments={"path": "x"}),
    )
    await handler(request)
    _check(case, "check_file", "windows-triage-mcp", "1.2.0")


@pytest.mark.asyncio
async def test_the_alias_names_the_source(case):
    await _gateway(Source("threatintel-mcp")).call_tool("lookup_ioc", {"ioc": "x"})
    _check(case, "lookup_ioc", "opencti-mcp", "")


@pytest.mark.asyncio
async def test_other_calls_errors_and_no_case_record_nothing(case, monkeypatch):
    await _gateway(Source("opencti-mcp")).call_tool("search_threat_intel", {"q": "x"})
    await _gateway(Source("opencti-mcp", error=True)).call_tool("lookup_ioc", {})
    assert not [e for e in _entries(case) if "reference" in e]
    monkeypatch.delenv("VHIR_CASE_DIR")
    result = await _gateway(Source("opencti-mcp")).call_tool("lookup_ioc", {})
    assert [c.text for c in result] == [BODY]
    assert not (case / "extractions").exists()


def test_a_backend_keeps_the_version_it_reports_for_itself():
    from sift_gateway.backends.base import _version_of

    init = SimpleNamespace(serverInfo=SimpleNamespace(name="x", version="2.0.1"))
    assert _version_of(init) == "2.0.1"
    assert _version_of(SimpleNamespace()) == ""
