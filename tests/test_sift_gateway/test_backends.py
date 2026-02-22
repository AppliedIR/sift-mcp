"""Tests for backend factory and lifecycle."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sift_gateway.backends import create_backend, MCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.server import Gateway
from .conftest import MockBackend, make_tool


# --- Backend factory ---

class TestBackendFactory:
    def test_create_stdio_backend(self):
        backend = create_backend("test", {"type": "stdio", "command": "python", "args": ["-m", "test"]})
        assert isinstance(backend, StdioMCPBackend)
        assert backend.name == "test"

    def test_create_http_backend(self):
        backend = create_backend("test", {"type": "http", "url": "http://localhost:9000/mcp"})
        assert isinstance(backend, HttpMCPBackend)
        assert backend.name == "test"

    def test_create_default_is_stdio(self):
        backend = create_backend("test", {"command": "python"})
        assert isinstance(backend, StdioMCPBackend)

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown backend type"):
            create_backend("test", {"type": "grpc"})


# --- Backend enabled flag ---

class TestBackendEnabled:
    def test_enabled_default_true(self):
        backend = StdioMCPBackend("test", {"type": "stdio"})
        assert backend.enabled is True

    def test_enabled_explicit_false(self):
        backend = StdioMCPBackend("test", {"type": "stdio", "enabled": False})
        assert backend.enabled is False


# --- StdioMCPBackend not-started guards ---

class TestStdioNotStarted:
    async def test_list_tools_raises_if_not_started(self):
        backend = StdioMCPBackend("test", {"type": "stdio"})
        with pytest.raises(RuntimeError, match="not started"):
            await backend.list_tools()

    async def test_call_tool_raises_if_not_started(self):
        backend = StdioMCPBackend("test", {"type": "stdio"})
        with pytest.raises(RuntimeError, match="not started"):
            await backend.call_tool("foo", {})

    async def test_health_check_when_stopped(self):
        backend = StdioMCPBackend("test", {"type": "stdio"})
        result = await backend.health_check()
        assert result["status"] == "stopped"


# --- HttpMCPBackend not-started guards ---

class TestHttpNotStarted:
    async def test_health_check_when_stopped(self):
        backend = HttpMCPBackend("test", {"type": "http", "url": "http://localhost:9000"})
        result = await backend.health_check()
        assert result["status"] == "stopped"
        assert "url" in result

    async def test_start_without_url_raises(self):
        backend = HttpMCPBackend("test", {"type": "http"})
        with pytest.raises(ValueError, match="url.*required"):
            await backend.start()


# --- Gateway tool map ---

class TestGatewayToolMap:
    async def test_build_tool_map_no_collisions(self):
        gw = Gateway({"backends": {}})
        gw.backends = {
            "a": MockBackend("a", tools=[make_tool("tool_a")]),
            "b": MockBackend("b", tools=[make_tool("tool_b")]),
        }
        for b in gw.backends.values():
            await b.start()
        await gw._build_tool_map()
        assert gw._tool_map == {"tool_a": "a", "tool_b": "b"}

    async def test_build_tool_map_with_collision(self):
        gw = Gateway({"backends": {}})
        gw.backends = {
            "a": MockBackend("a", tools=[make_tool("shared_tool")]),
            "b": MockBackend("b", tools=[make_tool("shared_tool")]),
        }
        for b in gw.backends.values():
            await b.start()
        await gw._build_tool_map()
        assert "a__shared_tool" in gw._tool_map
        assert "b__shared_tool" in gw._tool_map
        assert gw._tool_map["a__shared_tool"] == "a"
        assert gw._tool_map["b__shared_tool"] == "b"

    async def test_call_tool_routes_correctly(self):
        gw = Gateway({"backends": {}})
        backend_a = MockBackend("a", tools=[make_tool("my_tool")])
        gw.backends = {"a": backend_a}
        await backend_a.start()
        gw._tool_map = {"my_tool": "a"}
        result = await gw.call_tool("my_tool", {"arg": "val"})
        assert len(result) > 0
        assert backend_a._call_log[-1]["name"] == "my_tool"

    async def test_call_tool_strips_prefix_on_collision(self):
        gw = Gateway({"backends": {}})
        backend_a = MockBackend("a", tools=[make_tool("shared")])
        gw.backends = {"a": backend_a}
        await backend_a.start()
        gw._tool_map = {"a__shared": "a"}
        result = await gw.call_tool("a__shared", {})
        assert backend_a._call_log[-1]["name"] == "shared"

    async def test_call_unknown_tool_raises(self):
        gw = Gateway({"backends": {}})
        gw._tool_map = {}
        with pytest.raises(KeyError, match="Unknown tool"):
            await gw.call_tool("nonexistent", {})


# --- Lazy start ---

class TestLazyStart:
    async def test_lazy_start_skips_boot(self):
        """With lazy_start=true, gateway.start() should not start backends."""
        gw = Gateway({"gateway": {"lazy_start": True}, "backends": {}})
        backend = MockBackend("a", tools=[make_tool("tool_a")])
        gw.backends = {"a": backend}
        await gw.start()
        assert not backend.started
        assert gw._tool_map == {}

    async def test_eager_start_default(self):
        """Default behavior (lazy_start absent) starts backends immediately."""
        gw = Gateway({"backends": {}})
        backend = MockBackend("a", tools=[make_tool("tool_a")])
        gw.backends = {"a": backend}
        await gw.start()
        assert backend.started
        assert "tool_a" in gw._tool_map

    async def test_ensure_backend_started(self):
        """ensure_backend_started should start a cold backend."""
        gw = Gateway({"gateway": {"lazy_start": True}, "backends": {}})
        backend = MockBackend("a", tools=[make_tool("tool_a")])
        gw.backends = {"a": backend}
        assert not backend.started
        await gw.ensure_backend_started("a")
        assert backend.started
        assert backend.last_tool_call > 0
        assert "tool_a" in gw._tool_map

    async def test_ensure_backend_started_noop_if_running(self):
        """ensure_backend_started should just update timestamp if already running."""
        gw = Gateway({"backends": {}})
        backend = MockBackend("a", tools=[make_tool("tool_a")])
        gw.backends = {"a": backend}
        await backend.start()
        old_ts = backend.last_tool_call
        await gw.ensure_backend_started("a")
        assert backend.started
        assert backend.last_tool_call >= old_ts

    async def test_last_tool_call_initializes_to_zero(self):
        backend = MockBackend("a")
        assert backend.last_tool_call == 0.0

    async def test_lazy_start_property(self):
        gw = Gateway({"gateway": {"lazy_start": True}, "backends": {}})
        assert gw.lazy_start is True
        gw2 = Gateway({"backends": {}})
        assert gw2.lazy_start is False

    async def test_idle_timeout_property(self):
        gw = Gateway({"gateway": {"idle_timeout_seconds": 300}, "backends": {}})
        assert gw.idle_timeout == 300
        gw2 = Gateway({"backends": {}})
        assert gw2.idle_timeout == 0
