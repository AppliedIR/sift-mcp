"""HTTP-based MCP backend — connects to a remote MCP server via Streamable HTTP transport."""

import logging
from contextlib import AsyncExitStack

from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)


class HttpMCPBackend(MCPBackend):
    """Backend that connects to a remote MCP server via Streamable HTTP."""

    def __init__(self, name: str, config: dict):
        super().__init__(name, config)
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._tools_cache: list[Tool] | None = None

    async def start(self) -> None:
        if self._started:
            return

        url = self.config.get("url")
        if not url:
            raise ValueError(f"Backend {self.name}: 'url' is required for http type")

        headers = {}
        bearer_token = self.config.get("bearer_token")
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        extra_headers = self.config.get("headers") or {}
        headers.update(extra_headers)

        self._exit_stack = AsyncExitStack()
        try:
            transport = await self._exit_stack.enter_async_context(
                streamablehttp_client(url, headers=headers if headers else None)
            )
            read_stream, write_stream, _ = transport
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await self._session.initialize()
            self._started = True
            logger.info("Backend %s started (http -> %s)", self.name, url)
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
            return {"status": "stopped", "type": "http", "url": self.config.get("url")}
        try:
            await self.list_tools()
            return {
                "status": "ok",
                "type": "http",
                "url": self.config.get("url"),
                "tools": len(self._tools_cache or []),
            }
        except Exception as exc:
            return {
                "status": "error",
                "type": "http",
                "url": self.config.get("url"),
                "error": str(exc),
            }
