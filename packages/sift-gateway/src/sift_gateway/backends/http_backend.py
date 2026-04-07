"""HTTP-based MCP backend — connects to a remote MCP server via Streamable HTTP transport."""

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from urllib.parse import urlparse

from anyio import BrokenResourceError, ClosedResourceError
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)

# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_STOP_TIMEOUT = 15


def _make_pinned_tls_factory(cert_path: str):
    """Return an httpx_client_factory that pins TLS verification to a specific cert."""
    import httpx
    from mcp.shared._httpx_utils import (
        MCP_DEFAULT_SSE_READ_TIMEOUT,
        MCP_DEFAULT_TIMEOUT,
    )

    def factory(headers=None, timeout=None, auth=None):
        kwargs = {"follow_redirects": True, "verify": cert_path}
        if headers is not None:
            kwargs["headers"] = headers
        if timeout is None:
            kwargs["timeout"] = httpx.Timeout(
                MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT
            )
        else:
            kwargs["timeout"] = timeout
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


class HttpMCPBackend(MCPBackend):
    """Backend that connects to a remote MCP server via Streamable HTTP."""

    def __init__(self, name: str, config: dict):
        super().__init__(name, config)
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._tools_cache: list[Tool] | None = None

        # Validate URL format at construction time
        url = config.get("url")
        if url:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(
                    f"Backend {name}: URL must use http or https scheme, got {parsed.scheme!r}"
                )

    @property
    def base_url(self) -> str:
        """HTTP base URL (without /mcp path)."""
        url = self.config.get("url", "")
        return url.rsplit("/mcp", 1)[0] if "/mcp" in url else url

    @property
    def bearer_token(self) -> str:
        """Bearer token for authentication."""
        return self.config.get("bearer_token", "")

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
            client_factory_kwargs = {}
            tls_cert = self.config.get("tls_cert")
            if tls_cert:
                tls_cert = os.path.expanduser(tls_cert)
                client_factory_kwargs["httpx_client_factory"] = (
                    _make_pinned_tls_factory(tls_cert)
                )

            transport = await self._exit_stack.enter_async_context(
                streamablehttp_client(
                    url,
                    headers=headers if headers else None,
                    terminate_on_close=False,
                    **client_factory_kwargs,
                )
            )
            read_stream, write_stream, _ = transport
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            result = await self._session.initialize()
            self._instructions = result.instructions
            # Verify session is usable before declaring started — prevents
            # race where initialize() succeeds but call_tool() gets 404.
            tools_result = await self._session.list_tools()
            self._tools_cache = tools_result.tools
            self._started = True
            logger.info("Backend %s started (http -> %s)", self.name, url)
        except BaseException as exc:
            # CancelledError from streamablehttp_client often masks HTTP
            # auth failures (401/403). Add actionable guidance.
            exc_name = type(exc).__name__
            hint = ""
            if "Cancel" in exc_name or "cancel" in str(exc).lower():
                hint = (
                    " — if this is an auth issue, check bearer_token "
                    "in gateway.yaml matches the remote server"
                )
            logger.error(
                "Backend %s failed to start (http -> %s): %s: %s%s",
                self.name,
                url,
                exc_name,
                exc,
                hint,
            )
            try:
                await self._exit_stack.aclose()
            except BaseException as cleanup_exc:
                logger.warning(
                    "Backend %s cleanup after failed start also failed: %s",
                    self.name,
                    cleanup_exc,
                )
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
            return self._tools_cache or []

        if self._tools_cache is None:
            result = await asyncio.wait_for(
                self._session.list_tools(), timeout=_TOOL_LIST_TIMEOUT
            )
            self._tools_cache = result.tools
        return self._tools_cache

    async def _teardown(self) -> None:
        """Clean up session state so the backend can be restarted.

        The old exit stack is closed in a detached background task to
        prevent cancel-scope errors from poisoning the current task's
        asyncio state — which would make the *new* session appear closed.
        """
        stack = self._exit_stack
        self._tools_cache = None
        self._session = None
        self._exit_stack = None
        self._started = False
        if stack:
            async def _close_detached():
                try:
                    await asyncio.wait_for(stack.aclose(), timeout=5)
                except BaseException:
                    pass

            asyncio.ensure_future(_close_detached())

    async def call_tool(self, name: str, arguments: dict) -> list:
        if not self._started or not self._session:
            await self.start()

        for attempt in range(2):
            try:
                result = await asyncio.wait_for(
                    self._session.call_tool(name, arguments),
                    timeout=_TOOL_CALL_TIMEOUT,
                )
                return result.content
            except (ConnectionError, OSError, ClosedResourceError, BrokenResourceError) as exc:
                if attempt > 0:
                    await self._teardown()
                    raise
                logger.warning(
                    "Backend %s connection lost, reconnecting: %s",
                    self.name,
                    exc,
                )
                await self._teardown()
                await self.start()
                self._tool_map_stale = True
                continue
            except Exception as exc:
                exc_str = str(exc).lower()
                if attempt == 0 and any(
                    phrase in exc_str
                    for phrase in (
                        "session terminated",
                        "session not found",
                        "connection closed",
                        "stream ended",
                        "closed resource",
                        "broken resource",
                        "connection reset",
                        "forcibly closed",
                    )
                ):
                    logger.warning(
                        "Backend %s session stale, reconnecting: %s",
                        self.name,
                        exc,
                    )
                    await self._teardown()
                    await self.start()
                    self._tool_map_stale = True
                    continue
                raise
        raise RuntimeError(f"Backend {self.name}: call_tool failed after reconnect")

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "http"}
        try:
            await self.list_tools()
            return {
                "status": "ok",
                "type": "http",
                "tools": len(self._tools_cache or []),
            }
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
            logger.warning(
                "Backend %s health check failed: %s: %s",
                self.name,
                type(exc).__name__,
                exc,
            )
            return {
                "status": "error",
                "type": "http",
                "error": type(exc).__name__,
            }
