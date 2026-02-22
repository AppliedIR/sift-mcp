"""Stdio-based MCP backend — launches a subprocess and communicates via MCP stdio transport."""

import asyncio
import logging
import os
from contextlib import AsyncExitStack

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)

# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_STOP_TIMEOUT = 15


class StdioMCPBackend(MCPBackend):
    """Backend that manages a subprocess MCP server via stdio transport."""

    def __init__(self, name: str, config: dict):
        super().__init__(name, config)
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._tools_cache: list[Tool] | None = None

    async def start(self) -> None:
        if self._started:
            return

        command = self.config.get("command", "python")
        args = self.config.get("args", [])
        env = self.config.get("env") or None

        # When config provides explicit env vars, merge AIIR_* from parent
        # so examiner identity and case dir propagate to backend subprocesses.
        if env is not None:
            for key, val in os.environ.items():
                if key.startswith("AIIR_") and key not in env:
                    env[key] = val

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
            await self._session.initialize()
            self._started = True
            logger.info("Backend %s started (stdio)", self.name)
        except Exception as exc:
            logger.error("Backend %s failed to start: %s: %s", self.name, type(exc).__name__, exc)
            try:
                await self._exit_stack.aclose()
            except Exception as cleanup_exc:
                logger.warning("Backend %s cleanup after failed start also failed: %s", self.name, cleanup_exc)
            self._exit_stack = None
            self._session = None
            raise

    async def stop(self) -> None:
        if not self._started:
            return
        if self._exit_stack:
            try:
                await asyncio.wait_for(self._exit_stack.aclose(), timeout=_STOP_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning("Backend %s stop timed out after %ds", self.name, _STOP_TIMEOUT)
            except Exception as exc:
                logger.error("Backend %s error during stop: %s: %s", self.name, type(exc).__name__, exc)
        self._exit_stack = None
        self._session = None
        self._tools_cache = None
        self._started = False
        logger.info("Backend %s stopped", self.name)

    async def list_tools(self) -> list[Tool]:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        if self._tools_cache is None:
            result = await asyncio.wait_for(
                self._session.list_tools(), timeout=_TOOL_LIST_TIMEOUT
            )
            self._tools_cache = result.tools
        return self._tools_cache

    async def call_tool(self, name: str, arguments: dict) -> list:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        try:
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments), timeout=_TOOL_CALL_TIMEOUT
            )
            return result.content
        except (ConnectionError, OSError) as exc:
            self._tools_cache = None
            raise

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "stdio"}
        try:
            await self.list_tools()
            return {"status": "ok", "type": "stdio", "tools": len(self._tools_cache or [])}
        except Exception as exc:
            logger.warning("Backend %s health check failed: %s: %s", self.name, type(exc).__name__, exc)
            return {"status": "error", "type": "stdio", "error": str(exc)}
