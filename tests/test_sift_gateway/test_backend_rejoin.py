"""A backend that joins, or joins again, while the gateway runs.

Each row runs the real gateway app with real streamable-HTTP backends on
loopback, and joins through the real join endpoints, with no restart in
between. Every backend endpoint keeps answering, and the endpoint calls the
backend the latest join loaded.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import threading
import time
import types

import pytest
import uvicorn
from mcp.server.fastmcp import FastMCP
from sift_gateway import join as join_mod
from sift_gateway import mcp_endpoint
from sift_gateway import server as server_mod
from sift_gateway.server import Gateway
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from .conftest import MockBackend, make_tool

OWNER = "vhir_gw_0123456789abcdef01234567"
ACCEPT = "application/json, text/event-stream"


class Remote:
    """A stand-in remote backend: one echo tool under `tool`, on loopback."""

    def __init__(self, tool: str):
        self.tool = tool
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}/mcp"
        self.server: uvicorn.Server | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> Remote:
        mcp = FastMCP("remote")

        def echo(x: str) -> str:
            return x

        mcp.add_tool(echo, name=self.tool, structured_output=False)
        app = mcp.streamable_http_app()

        async def activate(request):
            return JSONResponse({"status": "activated"})

        app.router.routes.append(Route("/cases/activate", activate, methods=["POST"]))
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True
        )
        self.thread.start()
        _until(lambda: self.server.started, "remote did not start")
        return self

    def stop(self) -> None:
        if self.server is not None:
            self.server.should_exit = True
            self.thread.join(10)


def _until(check, message: str, timeout: float = 30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.3)
    raise AssertionError(message)


def _data(resp) -> dict:
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    return resp.json()


def probe(client: TestClient, path: str) -> tuple[int, list[str], str]:
    """initialize, tools/list, then call the last tool, on one MCP endpoint."""
    headers = {"Authorization": f"Bearer {OWNER}", "Accept": ACCEPT}
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"},
        },
    }
    resp = client.post(path, json=init, headers=headers)
    if resp.status_code != 200:
        return resp.status_code, [], ""
    headers["mcp-session-id"] = resp.headers["mcp-session-id"]
    client.post(
        path,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=headers,
    )
    resp = client.post(
        path, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=headers
    )
    if resp.status_code != 200:
        return resp.status_code, [], ""
    tools = [t["name"] for t in _data(resp).get("result", {}).get("tools", [])]
    if not tools:
        return resp.status_code, tools, ""
    call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": tools[-1], "arguments": {"x": "hi"}},
    }
    resp = client.post(path, json=call, headers=headers)
    if resp.status_code != 200:
        return resp.status_code, tools, ""
    content = _data(resp).get("result", {}).get("content") or [{}]
    return resp.status_code, tools, content[0].get("text", "")


def join(client: TestClient, remote: Remote) -> None:
    code = client.post(
        "/api/v1/setup/join-code",
        headers={"Authorization": f"Bearer {OWNER}"},
        json={"expires_hours": 2},
    ).json()["code"]
    resp = client.post(
        "/api/v1/setup/join",
        json={
            "code": code,
            "machine_type": "wintools",
            "hostname": "wks",
            "wintools_url": remote.url,
            "wintools_token": f"tok-{remote.tool}",
        },
    )
    assert resp.status_code == 200, resp.text


@pytest.fixture
def env(tmp_path, monkeypatch, caplog):
    """An isolated HOME and join state, quick retries, and captured logs."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    monkeypatch.setattr(join_mod, "_STATE_DIR", tmp_path / ".vhir")
    monkeypatch.setattr(
        join_mod, "_STATE_FILE", tmp_path / ".vhir" / ".join_state.json"
    )
    monkeypatch.setattr(server_mod, "_LOAD_RETRY_SECONDS", 0.5, raising=False)
    # the rows poll faster than the per-client request limit allows
    monkeypatch.setattr(mcp_endpoint, "check_rate_limit", lambda ip: True)
    caplog.set_level(logging.WARNING)
    remotes: list[Remote] = []
    yield remotes
    for remote in remotes:
        remote.stop()


def gateway_app(*boot: tuple[str, Remote]):
    backends = {
        name: {
            "type": "http",
            "url": remote.url,
            "bearer_token": f"tok-{remote.tool}",
            "enabled": True,
        }
        for name, remote in boot
    }
    config = {
        "gateway": {"host": "127.0.0.1", "port": 4508},
        "api_keys": {OWNER: {"examiner": "owner", "role": "examiner"}},
        "backends": backends,
    }
    return Gateway(config).create_app()


def wintools_answers(client: TestClient, path: str, tool: str):
    return _until(
        lambda: (r := probe(client, path))[1][-1:] == [tool] and r[2] == "hi" and r,
        f"{path} never answered with {tool}",
    )


def no_task_errors(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if "different task" in r.getMessage() or "Task group is not" in r.getMessage()
    ]


def test_two_joins_in_one_process_leave_every_backend_endpoint_working(env, caplog):
    other = Remote("other_echo").start()
    first = Remote("first_echo").start()
    second = Remote("second_echo")  # not listening yet
    env.extend([other, first, second])
    with TestClient(gateway_app(("other-mcp", other))) as client:
        join(client, first)
        wintools_answers(client, "/mcp/wintools-mcp", "first_echo")

        # The remote is reinstalled: the old one goes, the second join comes
        # while the new one is still starting.
        first.stop()
        join(client, second)
        time.sleep(1)
        second.start()

        wintools_answers(client, "/mcp/wintools-mcp", "second_echo")
        assert probe(client, "/mcp/other-mcp") == (200, ["other_echo"], "hi")
    assert no_task_errors(caplog) == []


def test_a_rejoin_replaces_the_backend_its_endpoint_calls(env, caplog):
    other = Remote("other_echo").start()
    first = Remote("first_echo").start()
    second = Remote("second_echo").start()
    third = Remote("third_echo").start()
    env.extend([other, first, second, third])
    app = gateway_app(("other-mcp", other), ("wintools-mcp", first))
    with TestClient(app) as client:
        assert probe(client, "/mcp/wintools-mcp") == (200, ["first_echo"], "hi")
        join(client, second)
        wintools_answers(client, "/mcp/wintools-mcp", "second_echo")
        join(client, third)
        wintools_answers(client, "/mcp/wintools-mcp", "third_echo")
        assert probe(client, "/mcp/other-mcp") == (200, ["other_echo"], "hi")
    assert no_task_errors(caplog) == []


def test_a_rejoin_that_never_loads_keeps_the_previous_backend(env, caplog):
    first = Remote("first_echo").start()
    nowhere = Remote("never_echo")  # never listens
    env.extend([first, nowhere])
    with TestClient(gateway_app()) as client:
        join(client, first)
        wintools_answers(client, "/mcp/wintools-mcp", "first_echo")
        join(client, nowhere)
        _until(
            lambda: any("Could not load" in r.getMessage() for r in caplog.records),
            "the re-join never gave up",
        )
        # running again before any call reaches it
        assert client.app.state.gateway.backends["wintools-mcp"].started
        assert probe(client, "/mcp/wintools-mcp") == (200, ["first_echo"], "hi")
    assert no_task_errors(caplog) == []


def test_a_gateway_with_a_joined_backend_shuts_down_cleanly(env, caplog):
    first = Remote("first_echo").start()
    env.append(first)
    with TestClient(gateway_app()) as client:
        join(client, first)
        wintools_answers(client, "/mcp/wintools-mcp", "first_echo")
    assert no_task_errors(caplog) == []


def _service(client: TestClient, name: str, action: str):
    return client.post(
        f"/api/v1/services/{name}/{action}",
        headers={"Authorization": f"Bearer {OWNER}"},
    )


def every_endpoint_answers(client: TestClient, wintools_tool: str) -> None:
    wintools_answers(client, "/mcp/wintools-mcp", wintools_tool)
    assert probe(client, "/mcp/other-mcp") == (200, ["other_echo"], "hi")


def test_a_service_restart_of_a_joined_backend_keeps_every_endpoint_working(
    env, caplog
):
    other = Remote("other_echo").start()
    first = Remote("first_echo").start()
    second = Remote("second_echo").start()
    env.extend([other, first, second])
    with TestClient(gateway_app(("other-mcp", other))) as client:
        join(client, first)
        wintools_answers(client, "/mcp/wintools-mcp", "first_echo")
        r = _service(client, "wintools-mcp", "restart")
        assert r.status_code == 200, r.text
        every_endpoint_answers(client, "first_echo")
        join(client, second)  # and a re-join after it still loads
        every_endpoint_answers(client, "second_echo")
    assert no_task_errors(caplog) == []


def test_a_joined_backend_stopped_and_started_as_a_service_answers_again(env, caplog):
    other = Remote("other_echo").start()
    first = Remote("first_echo").start()
    env.extend([other, first])
    with TestClient(gateway_app(("other-mcp", other))) as client:
        join(client, first)
        wintools_answers(client, "/mcp/wintools-mcp", "first_echo")
        assert _service(client, "wintools-mcp", "stop").json()["status"] == "stopped"
        assert probe(client, "/mcp/other-mcp") == (200, ["other_echo"], "hi")
        assert _service(client, "wintools-mcp", "start").json()["status"] == "started"
        every_endpoint_answers(client, "first_echo")
    assert no_task_errors(caplog) == []


def test_restarting_every_service_with_a_joined_backend_keeps_every_endpoint_working(
    env, caplog
):
    other = Remote("other_echo").start()
    first = Remote("first_echo").start()
    env.extend([other, first])
    with TestClient(gateway_app(("other-mcp", other))) as client:
        join(client, first)
        wintools_answers(client, "/mcp/wintools-mcp", "first_echo")
        services = client.get(
            "/api/v1/services", headers={"Authorization": f"Bearer {OWNER}"}
        ).json()
        names = [s["name"] for s in services.get("services", services)]
        assert set(names) >= {"other-mcp", "wintools-mcp"}, services
        for name in names:  # what `vhir service restart` with no name does
            assert _service(client, name, "restart").status_code == 200
        every_endpoint_answers(client, "first_echo")
    assert no_task_errors(caplog) == []


def test_a_stopped_backend_started_again_by_a_call_keeps_every_endpoint_working(
    env, caplog
):
    other = Remote("other_echo").start()
    first = Remote("first_echo").start()
    env.extend([other, first])
    with TestClient(
        gateway_app(("other-mcp", other), ("wintools-mcp", first))
    ) as client:
        assert _service(client, "other-mcp", "stop").json()["status"] == "stopped"
        # the call starts it again, from the request
        assert probe(client, "/mcp/other-mcp") == (200, ["other_echo"], "hi")
        assert probe(client, "/mcp/wintools-mcp") == (200, ["first_echo"], "hi")
        assert _service(client, "other-mcp", "restart").status_code == 200
        assert probe(client, "/mcp/other-mcp") == (200, ["other_echo"], "hi")
        assert _service(client, "other-mcp", "stop").json()["status"] == "stopped"
        assert _service(client, "other-mcp", "start").json()["status"] == "started"
        assert probe(client, "/mcp/other-mcp") == (200, ["other_echo"], "hi")
    assert no_task_errors(caplog) == []


# The same lifecycle with in-memory backends, for the steps a live run can't
# time: what the loader does around a failed re-join, the retry task, and
# shutdown.


class Recording(MockBackend):
    """Records, at each start, whether the gateway still marks it reloading."""

    def __init__(self, gateway: Gateway, name: str, fail: bool = False):
        super().__init__(name, tools=[make_tool(f"{name}_tool")])
        self.gateway, self.fail, self.starts = gateway, fail, []

    async def start(self) -> None:
        self.starts.append(self.name in self.gateway._pending_backends)
        if self.fail:
            raise ConnectionError("nobody there")
        self._started = True


# The loader and the retry task only sleep through anyio: no waiting here
FAST = types.SimpleNamespace(sleep=lambda seconds: asyncio.sleep(0))


async def _wait_for(check, message: str):
    for _ in range(200):
        if check():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(message)


async def test_a_failed_rejoin_restarts_the_previous_backend_while_still_reloading(
    monkeypatch,
):
    monkeypatch.setattr(server_mod, "anyio", FAST)
    gw = Gateway({"backends": {}})
    previous = Recording(gw, "wt")
    made = iter([previous, *(Recording(gw, "wt", fail=True) for _ in range(6))])
    monkeypatch.setattr(server_mod, "create_backend", lambda name, conf: next(made))
    loader = asyncio.ensure_future(gw._backend_loader())
    try:
        gw._pending_backends["wt"] = {}
        gw._reload_event.set()
        await _wait_for(
            lambda: previous.started and not gw._pending_backends, "no load"
        )
        gw._pending_backends["wt"] = {}
        gw._reload_event.set()
        await _wait_for(lambda: not gw._pending_backends, "never gave up")
    finally:
        loader.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await loader
    assert gw.backends["wt"] is previous
    assert previous.starts == [True, True]  # loaded, then restarted, both while marked


async def test_the_retry_task_leaves_a_backend_that_is_reloading_alone(monkeypatch):
    monkeypatch.setattr(server_mod, "anyio", FAST)
    gw = Gateway({"backends": {}})
    reloading = Recording(gw, "wt")
    gw.backends["wt"] = reloading
    gw._pending_backends["wt"] = {}
    checker = asyncio.ensure_future(gw._late_start_checker())
    await asyncio.sleep(0.05)
    checker.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await checker
    assert reloading.starts == []


async def test_shutdown_stops_a_backend_a_rejoin_replaced():
    gw = Gateway({"backends": {}})
    replaced = Recording(gw, "wt")
    await replaced.start()
    gw._retired = [replaced]
    await gw.stop()
    assert not replaced.started
