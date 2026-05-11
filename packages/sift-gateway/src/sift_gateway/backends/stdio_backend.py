"""Stdio-based MCP backend — launches a subprocess and communicates via MCP stdio transport."""

import asyncio
import logging
import os
from contextlib import AsyncExitStack

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)

# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_STOP_TIMEOUT = 15
# Bound on session.initialize() so a hung backend doesn't block the
# gateway's own startup loop indefinitely. Pre-fix, an unreachable
# remote (e.g., OpenCTI off-network) caused initialize() to wait on
# the underlying backend's blocking I/O for 300s+ before the gateway
# noticed. 30s is generous for healthy backends, fail-fast for hung.
_INITIALIZE_TIMEOUT = 30


class StdioMCPBackend(MCPBackend):
    """Backend that manages a subprocess MCP server via stdio transport."""

    def __init__(self, name: str, config: dict):
        super().__init__(name, config)
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._tools_cache: list[Tool] | None = None

    async def _safe_cleanup(self, *, context: str) -> None:
        """Cleanup that handles None _exit_stack and downgrades cancel-scope noise.

        Single helper used by start() failed-cleanup, stop(), and the
        list_tools / call_tool error paths — all four sites previously
        had near-identical patterns with subtly different bugs:
          - start() logged at WARNING for unavoidable cancel-scope errors
          - list_tools / call_tool used silent `pass`, swallowing real errors
          - stop() had the right pattern (downgrade on "cancel scope")
        One canonical helper makes the cleanup contract uniform.

        Cancel-scope errors during cleanup are structurally inevitable
        when a hung backend is cancelled mid-startup or mid-call (anyio
        rule: cancel scope must exit in the same task it entered).
        Those are DEBUG-level. Other exceptions are real failures and
        log at WARNING.

        `context` describes which cleanup site is calling — interpolated
        into the log message so journalctl distinguishes start-cleanup
        from list_tools-cleanup from stop-cleanup.
        """
        if self._exit_stack is None:
            self._session = None
            self._tools_cache = None
            self._started = False
            return
        try:
            await self._exit_stack.aclose()
        except BaseException as exc:
            level = logging.DEBUG if "cancel scope" in str(exc) else logging.WARNING
            logger.log(
                level,
                "Backend %s %s: %s: %s",
                self.name,
                context,
                type(exc).__name__,
                exc,
            )
        finally:
            self._exit_stack = None
            self._session = None
            self._tools_cache = None
            self._started = False

    async def start(self) -> None:
        if self._started:
            return

        command = self.config.get("command", "python")
        args = self.config.get("args", [])
        env = self.config.get("env") or None

        # When config provides explicit env vars, merge VHIR_* from parent
        # so examiner identity and case dir propagate to backend subprocesses.
        if env is not None:
            for key, val in os.environ.items():
                if key.startswith("VHIR_") and key not in env:
                    env[key] = val
            # Remove empty values (from unset ${VAR} interpolation)
            env = {k: v for k, v in env.items() if v}

        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=env,
        )

        self._exit_stack = AsyncExitStack()
        try:
            transport = await self._exit_stack.enter_async_context(
                stdio_client(server_params)
            )
            read_stream, write_stream = transport
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            # Bound session.initialize() so a hung remote backend can't
            # block the gateway's startup loop indefinitely (UAT 2026-04-25
            # repro: unreachable OpenCTI caused initialize() to wait for
            # the underlying socket timeout before the gateway noticed).
            result = await asyncio.wait_for(
                self._session.initialize(), timeout=_INITIALIZE_TIMEOUT
            )
            self._instructions = result.instructions
            self._started = True
            logger.info("Backend %s started (stdio)", self.name)
        except asyncio.TimeoutError:
            logger.error(
                "Backend %s session.initialize() timed out after %ds",
                self.name,
                _INITIALIZE_TIMEOUT,
            )
            await self._safe_cleanup(context="cleanup after initialize timeout")
            raise
        except BaseException as exc:
            logger.error(
                "Backend %s failed to start: %s: %s", self.name, type(exc).__name__, exc
            )
            await self._safe_cleanup(context="cleanup after failed start")
            raise

    async def stop(self) -> None:
        if not self._started:
            return
        if self._exit_stack is not None:
            try:
                await asyncio.wait_for(self._exit_stack.aclose(), timeout=_STOP_TIMEOUT)
                # Successful close: state-reset still runs in finally below
            except asyncio.TimeoutError:
                logger.warning(
                    "Backend %s stop timed out after %ds", self.name, _STOP_TIMEOUT
                )
            except BaseException as exc:
                level = logging.DEBUG if "cancel scope" in str(exc) else logging.ERROR
                logger.log(
                    level,
                    "Backend %s error during stop: %s: %s",
                    self.name,
                    type(exc).__name__,
                    exc,
                )
        self._exit_stack = None
        self._session = None
        self._tools_cache = None
        self._started = False
        logger.info("Backend %s stopped", self.name)

    async def list_tools(self) -> list[Tool]:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        if self._tools_cache is None:
            try:
                result = await asyncio.wait_for(
                    self._session.list_tools(), timeout=_TOOL_LIST_TIMEOUT
                )
                self._tools_cache = result.tools
            except (ConnectionError, OSError):
                await self._safe_cleanup(context="list_tools cleanup after error")
                raise
        return self._tools_cache

    async def call_tool(self, name: str, arguments: dict) -> list:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        try:
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments), timeout=_TOOL_CALL_TIMEOUT
            )
            return result.content
        except (ConnectionError, OSError):
            await self._safe_cleanup(context="call_tool cleanup after error")
            raise

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "stdio"}
        try:
            await self.list_tools()
            return {
                "status": "ok",
                "type": "stdio",
                "tools": len(self._tools_cache or []),
            }
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
            logger.warning(
                "Backend %s health check failed: %s: %s",
                self.name,
                type(exc).__name__,
                exc,
            )
            return {"status": "error", "type": "stdio", "error": type(exc).__name__}
