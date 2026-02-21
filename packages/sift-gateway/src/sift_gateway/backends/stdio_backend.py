"""Stdio-based MCP backend — launches a subprocess and communicates via MCP stdio transport."""

import logging
import os
from contextlib import AsyncExitStack

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)


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
        except Exception:
            await self._exit_stack.aclose()
            self._exit_stack = None
            self._session = None
            raise

    async def stop(self) -> None:
        if not self._started:
            return
        if self._exit_stack:
            await self._exit_stack.aclose()
        self._exit_stack = None
        self._session = None
        self._tools_cache = None
        self._started = False
        logger.info("Backend %s stopped", self.name)

    async def list_tools(self) -> list[Tool]:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        if self._tools_cache is None:
            result = await self._session.list_tools()
            self._tools_cache = result.tools
        return self._tools_cache

    async def call_tool(self, name: str, arguments: dict) -> list:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        result = await self._session.call_tool(name, arguments)
        return result.content

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "stdio"}
        try:
            await self.list_tools()
            return {"status": "ok", "type": "stdio", "tools": len(self._tools_cache or [])}
        except Exception as exc:
            return {"status": "error", "type": "stdio", "error": str(exc)}
