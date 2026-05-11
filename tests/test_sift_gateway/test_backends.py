"""Tests for backend factory and lifecycle."""

import asyncio

import pytest
from sift_gateway.backends import create_backend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.server import Gateway

from .conftest import MockBackend, make_tool

# --- Backend factory ---


class TestBackendFactory:
    def test_create_stdio_backend(self):
        backend = create_backend(
            "test", {"type": "stdio", "command": "python", "args": ["-m", "test"]}
        )
        assert isinstance(backend, StdioMCPBackend)
        assert backend.name == "test"

    def test_create_http_backend(self):
        backend = create_backend(
            "test", {"type": "http", "url": "http://localhost:9000/mcp"}
        )
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
        backend = HttpMCPBackend(
            "test", {"type": "http", "url": "http://localhost:9000"}
        )
        result = await backend.health_check()
        assert result["status"] == "stopped"
        assert "url" not in result  # F-132-13: no internal URLs in health

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


# --- Rev 2: _safe_cleanup helper + bounded initialize ---


class TestSafeCleanup:
    """Pins _safe_cleanup contract (CR Rev-2 spec).

    Pre-fix, three cleanup sites (start/list_tools/call_tool) had
    near-identical patterns with subtly different bugs:
      - start() logged WARNING on unavoidable cancel-scope errors
      - list_tools / call_tool used silent `pass`, swallowing real errors
      - stop() had the right pattern (downgrade on "cancel scope")
    Post-fix: all four call _safe_cleanup(context=...) — uniform.
    """

    @pytest.mark.asyncio
    async def test_safe_cleanup_handles_none_exit_stack(self):
        """_exit_stack already None → no exception, no log spam, state reset."""
        backend = StdioMCPBackend("test", {"command": "true"})
        backend._exit_stack = None
        backend._session = object()
        backend._started = True
        # Must not raise
        await backend._safe_cleanup(context="test cleanup")
        assert backend._session is None
        assert backend._started is False

    @pytest.mark.asyncio
    async def test_safe_cleanup_downgrades_cancel_scope_to_debug(self, caplog):
        """Cancel-scope error during cleanup → DEBUG, not WARNING."""
        import logging
        from contextlib import AsyncExitStack

        backend = StdioMCPBackend("test", {"command": "true"})
        backend._exit_stack = AsyncExitStack()

        async def _raise_cancel_scope():
            raise RuntimeError(
                "Attempted to exit cancel scope in a different task than it was entered in"
            )

        # Replace aclose with a method that raises the structural error
        backend._exit_stack.aclose = _raise_cancel_scope  # type: ignore[method-assign]

        with caplog.at_level(logging.DEBUG):
            await backend._safe_cleanup(context="cleanup after failed start")

        # Find the log record from this cleanup
        records = [
            r for r in caplog.records if "cleanup after failed start" in r.getMessage()
        ]
        assert records, "expected a cleanup log record"
        # All matching records must be DEBUG-level
        assert all(r.levelno == logging.DEBUG for r in records), (
            f"cancel-scope error logged at non-DEBUG: {[r.levelname for r in records]}"
        )

    @pytest.mark.asyncio
    async def test_safe_cleanup_logs_real_errors_at_warning(self, caplog):
        """Non-cancel-scope error → WARNING (real failure, not noise)."""
        import logging
        from contextlib import AsyncExitStack

        backend = StdioMCPBackend("test", {"command": "true"})
        backend._exit_stack = AsyncExitStack()

        async def _raise_real():
            raise RuntimeError("disk full")

        backend._exit_stack.aclose = _raise_real  # type: ignore[method-assign]

        with caplog.at_level(logging.WARNING):
            await backend._safe_cleanup(context="cleanup after failed start")

        records = [
            r for r in caplog.records if "cleanup after failed start" in r.getMessage()
        ]
        assert records
        assert all(r.levelno == logging.WARNING for r in records)

    @pytest.mark.asyncio
    async def test_safe_cleanup_always_resets_state_in_finally(self):
        """Even when aclose raises, _exit_stack/_session/_started reset."""
        from contextlib import AsyncExitStack

        backend = StdioMCPBackend("test", {"command": "true"})
        backend._exit_stack = AsyncExitStack()
        backend._session = object()
        backend._tools_cache = ["fake"]
        backend._started = True

        async def _raise():
            raise RuntimeError("boom")

        backend._exit_stack.aclose = _raise  # type: ignore[method-assign]

        await backend._safe_cleanup(context="test")
        assert backend._exit_stack is None
        assert backend._session is None
        assert backend._tools_cache is None
        assert backend._started is False


class TestStartInitializeBounded:
    """asyncio.wait_for(session.initialize(), _INITIALIZE_TIMEOUT=30)
    so a hung backend doesn't block the gateway's startup loop."""

    @pytest.mark.asyncio
    async def test_start_raises_timeout_after_initialize_timeout(self):
        """When session.initialize() hangs, start() raises TimeoutError
        within the bounded window — pre-fix it waited on the underlying
        socket timeout (300s+).
        """
        from unittest.mock import AsyncMock, patch

        from sift_gateway.backends import stdio_backend

        # Override the module constant for a fast test (3s instead of 30s)
        with patch.object(stdio_backend, "_INITIALIZE_TIMEOUT", 1):
            backend = StdioMCPBackend("test", {"command": "true"})

            # Mock the AsyncExitStack pipeline up to and including initialize()
            mock_session = AsyncMock()

            async def _hang(*a, **kw):
                # Block longer than _INITIALIZE_TIMEOUT
                import asyncio as _aio

                await _aio.sleep(60)

            mock_session.initialize = _hang

            mock_exit_stack = AsyncMock()
            mock_exit_stack.enter_async_context = AsyncMock(
                side_effect=[(object(), object()), mock_session]
            )
            mock_exit_stack.aclose = AsyncMock()

            with patch(
                "sift_gateway.backends.stdio_backend.AsyncExitStack",
                return_value=mock_exit_stack,
            ):
                with pytest.raises(asyncio.TimeoutError):
                    await backend.start()

            # Cleanup was invoked
            assert backend._started is False
            assert backend._exit_stack is None


class TestThreeSiteCleanupUsesSafeCleanup:
    """list_tools / call_tool / start error paths all route through
    _safe_cleanup — pins the canonical-helper contract so future bugs
    touch one site, not three."""

    @pytest.mark.asyncio
    async def test_list_tools_error_path_calls_safe_cleanup(self):
        """ConnectionError in list_tools → _safe_cleanup runs."""
        from unittest.mock import AsyncMock, MagicMock

        backend = StdioMCPBackend("test", {"command": "true"})
        backend._started = True
        backend._session = MagicMock()
        backend._session.list_tools = AsyncMock(
            side_effect=ConnectionError("backend hung")
        )
        backend._exit_stack = AsyncMock()
        backend._exit_stack.aclose = AsyncMock()

        with pytest.raises(ConnectionError):
            await backend.list_tools()

        # _safe_cleanup ran — state is reset
        assert backend._exit_stack is None
        assert backend._session is None
        assert backend._started is False

    @pytest.mark.asyncio
    async def test_call_tool_error_path_calls_safe_cleanup(self):
        """ConnectionError in call_tool → _safe_cleanup runs."""
        from unittest.mock import AsyncMock, MagicMock

        backend = StdioMCPBackend("test", {"command": "true"})
        backend._started = True
        backend._session = MagicMock()
        backend._session.call_tool = AsyncMock(
            side_effect=ConnectionError("backend hung")
        )
        backend._exit_stack = AsyncMock()
        backend._exit_stack.aclose = AsyncMock()

        with pytest.raises(ConnectionError):
            await backend.call_tool("x", {})

        assert backend._exit_stack is None
        assert backend._session is None
        assert backend._started is False
