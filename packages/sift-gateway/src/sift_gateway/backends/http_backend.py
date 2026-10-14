"""HTTP-based MCP backend — connects to a remote MCP server via Streamable HTTP transport."""

import asyncio
import logging
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from urllib.parse import urlparse

from anyio import BrokenResourceError, ClosedResourceError
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend, ToolResult, _version_of

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup

logger = logging.getLogger(__name__)

# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_STOP_TIMEOUT = 15
# Connecting and the first answer, for a start or a reconnect
_CONNECT_TIMEOUT = 5.0
# A ping before each call, and for health
_PING_TIMEOUT = 3.0


def _chain(exc: BaseException):
    """``exc``, then each exception inside it (a group's) or behind it (its
    cause or context), once each."""
    seen: set[int] = set()
    queue: list[BaseException] = [exc]
    while queue:
        e = queue.pop(0)
        if id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        queue.extend(getattr(e, "exceptions", None) or ())
        queue.extend(x for x in (e.__cause__, e.__context__) if x is not None)


def describe(exc: BaseException) -> str:
    """The real error behind ``exc``: anyio reports a failed connection as
    a ``CancelledError`` or an exception group, with the TLS or connect
    error inside it, or in its cause or context."""
    found = [
        e
        for e in _chain(exc)
        if not isinstance(e, (asyncio.CancelledError, BaseExceptionGroup))
    ]
    named = [
        e
        for e in found
        if any(k in type(e).__name__ for k in ("SSL", "Connect", "Timeout"))
    ]
    best = (named or found or [exc])[0]
    return f"{type(best).__name__}: {best}" if str(best) else type(best).__name__


TOKEN_REFUSED = "rejected the gateway's token"


def refused_status(exc: BaseException) -> int | None:
    """401 or 403 when the remote answered the gateway's token with one,
    anywhere in ``exc``, else None."""
    for e in _chain(exc):
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status in (401, 403):
            return status
    return None


def token_refused_text(name: str, status: int) -> str:
    """What a refused token means, and its fix, in the backend's words."""
    reason = "Unauthorized" if status == 401 else "Forbidden"
    return (
        f"{name} {TOKEN_REFUSED} ({status} {reason}): the bearer token in "
        "gateway.yaml isn't one it accepts. To fix, join it again: a code from "
        f"`vhir setup join-code` on this box, then the join on {name}'s host"
    )


def _make_pinned_tls_factory(cert_path: str, pem: str | None = None):
    """Return an httpx_client_factory that pins TLS verification to a specific
    cert: its PEM text when given, else the file at ``cert_path``."""
    import ssl

    import httpx
    from mcp.shared._httpx_utils import (
        MCP_DEFAULT_SSE_READ_TIMEOUT,
        MCP_DEFAULT_TIMEOUT,
    )

    def factory(headers=None, timeout=None, auth=None):
        verify = ssl.create_default_context(cadata=pem) if pem else cert_path
        kwargs = {"follow_redirects": True, "verify": verify}
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


def _session_refused(exc: BaseException) -> bool:
    """The MCP client's own answer when the remote gives a request on a
    session it doesn't know a 404, before running it (mcp's streamable HTTP
    _send_session_terminated_error). That exact type and code only, never
    message text: a tool's output can carry any text, and an error raised
    after it ran (a result that fails validation) can quote it."""
    error = getattr(exc, "error", None)
    return (
        isinstance(exc, McpError)
        and getattr(error, "code", None) == 32600
        and getattr(error, "message", None) == "Session terminated"
    )


class HttpMCPBackend(MCPBackend):
    """Backend that connects to a remote MCP server via Streamable HTTP."""

    def __init__(self, name: str, config: dict):
        super().__init__(name, config)
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._tools_cache: list[Tool] | None = None
        self._cleanup_tasks: set[asyncio.Task] = set()
        # The task that opens this backend's connection, holds it, and closes it
        self._runner: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self._liveness_lock: asyncio.Lock | None = None
        # Calls sent and not yet answered
        self._in_flight = 0
        # Bumped by each reconnect: a reconnect decided on an older session
        # than the current one is not made
        self._generation = 0
        # Why the last start or connection failed; None once connected
        self.last_error: str | None = None
        # The pinned cert as it is when the backend is made (a join's comes
        # with it): a later join never changes the pin of a backend already
        # made. An unreadable pin keeps the backend, failing with its name.
        self._pinned_pem: str | None = config.get("tls_cert_pem")
        tls_cert = config.get("tls_cert")
        if tls_cert and self._pinned_pem is None:
            try:
                self._pinned_pem = Path(os.path.expanduser(tls_cert)).read_text()
            except (OSError, UnicodeDecodeError):
                self.last_error = f"pinned certificate unreadable: {tls_cert}"

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
        """Connect, in a runner task that also closes the connection.

        Every transport scope is opened and closed in that one task, whoever
        asks for the start or the stop; a request or the loader only waits.
        """
        if self._started:
            return

        url = self.config.get("url")
        if not url:
            raise ValueError(f"Backend {self.name}: 'url' is required for http type")
        if self.config.get("tls_cert") and self._pinned_pem is None:
            logger.error("Backend %s failed to start: %s", self.name, self.last_error)
            raise RuntimeError(f"{self.name}: {self.last_error}")

        headers = {}
        bearer_token = self.config.get("bearer_token")
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        extra_headers = self.config.get("headers") or {}
        headers.update(extra_headers)

        ready = asyncio.get_running_loop().create_future()
        self._stop_event = asyncio.Event()
        runner = asyncio.ensure_future(self._run(url, headers, ready, self._stop_event))
        self._runner = runner
        try:
            # connecting and the first answers, within the start budget
            await asyncio.wait_for(ready, timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            runner.cancel()
            self.last_error = f"no answer in {_CONNECT_TIMEOUT:.0f}s"
            logger.error(
                "Backend %s failed to start (http -> %s): %s",
                self.name,
                url,
                self.last_error,
            )
            raise RuntimeError(
                f"{self.name} unreachable at {url}: {self.last_error}"
            ) from None
        except asyncio.CancelledError:
            runner.cancel()
            raise
        except _StartFailed as exc:
            self.last_error = str(exc)
            logger.error(
                "Backend %s failed to start (http -> %s): %s", self.name, url, exc
            )
            if TOKEN_REFUSED in str(exc):  # it answered: not "unreachable"
                raise RuntimeError(str(exc)) from None
            raise RuntimeError(f"{self.name} unreachable at {url}: {exc}") from None

    async def _run(
        self, url: str, headers: dict, ready: asyncio.Future, stop: asyncio.Event
    ) -> None:
        me = asyncio.current_task()
        try:
            client_factory_kwargs = {}
            tls_cert = self.config.get("tls_cert")
            if tls_cert:
                client_factory_kwargs["httpx_client_factory"] = (
                    _make_pinned_tls_factory(
                        os.path.expanduser(tls_cert), self._pinned_pem
                    )
                )
            async with AsyncExitStack() as stack:
                read_stream, write_stream, _ = await stack.enter_async_context(
                    streamablehttp_client(
                        url,
                        headers=headers if headers else None,
                        timeout=_CONNECT_TIMEOUT,
                        terminate_on_close=False,
                        **client_factory_kwargs,
                    )
                )
                session = await stack.enter_async_context(
                    ClientSession(read_stream, write_stream)
                )
                result = await session.initialize()
                self._server_version = _version_of(result)
                # Verify session is usable before declaring started — prevents
                # race where initialize() succeeds but call_tool() gets 404.
                tools_result = await session.list_tools()
                self._instructions = result.instructions
                self._session = session
                self._tools_cache = tools_result.tools
                self._started = True
                self.last_error = None
                logger.info("Backend %s started (http -> %s)", self.name, url)
                if not ready.done():
                    ready.set_result(None)
                await stop.wait()
        except BaseException as exc:  # noqa: BLE001 - handed to start() or logged
            if not ready.done():
                ready.set_exception(_StartFailed(self._why(exc)))
            elif not isinstance(exc, asyncio.CancelledError) and not stop.is_set():
                self.last_error = self._why(exc)
                logger.warning(
                    "Backend %s connection ended: %s", self.name, self.last_error
                )
        finally:
            if self._runner is me:  # not replaced by a newer start
                self._runner = None
                self._session = None
                self._started = False

    async def stop(self) -> None:
        runner, stop = self._runner, self._stop_event
        if runner is None:
            self._session = None
            self._started = False
            return
        stop.set()
        try:
            await asyncio.wait_for(asyncio.shield(runner), timeout=_STOP_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning(
                "Backend %s stop timed out after %ds", self.name, _STOP_TIMEOUT
            )
            runner.cancel()
        if self._runner is runner:
            self._runner = None
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
        """Drop the session so the backend can be started again; its runner
        closes the old connection in its own task."""
        runner, stop = self._runner, self._stop_event
        self._tools_cache = None
        self._session = None
        self._runner = None
        self._started = False
        if runner is not None and stop is not None:
            stop.set()
            self._cleanup_tasks.add(runner)
            runner.add_done_callback(self._cleanup_tasks.discard)

    async def _reconnect(self, reason: str) -> None:
        logger.warning(
            "Backend %s connection lost, reconnecting: %s", self.name, reason
        )
        self._generation += 1
        await self._teardown()
        try:
            await asyncio.wait_for(self.start(), timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            self.last_error = f"no answer in {_CONNECT_TIMEOUT:.0f}s"
            raise RuntimeError(
                f"{self.name} unreachable at {self.config.get('url')}: "
                f"no answer in {_CONNECT_TIMEOUT:.0f}s"
            ) from None
        self._tool_map_stale = True

    def _why(self, exc: BaseException) -> str:
        """describe(exc), or by name when the remote refused our token."""
        status = refused_status(exc)
        return (
            describe(exc) if status is None else token_refused_text(self.name, status)
        )

    async def _alive(self) -> str | None:
        """None when the remote answers a ping in time, else why it doesn't."""
        session = self._session
        if not self._started or session is None:
            return self.last_error or "not connected"
        try:
            await asyncio.wait_for(session.send_ping(), timeout=_PING_TIMEOUT)
            return None
        except asyncio.TimeoutError:
            return f"no answer to a ping in {_PING_TIMEOUT:.0f}s"
        except Exception as exc:  # noqa: BLE001 - the reason is the answer
            return self._why(exc)

    async def heal(self) -> None:
        """Reconnect when the remote doesn't answer a ping: it ended the
        session (a restart, a guest revert) or the connection is gone. A ping
        that times out while a call is running is left alone: a busy remote
        can be slow to answer, and a reconnect would end the running call's
        session. Each call heals first; the gateway's 30 s checker heals an
        idle backend."""
        async with self._lock():  # one reconnect for concurrent calls
            generation = self._generation
            why = await self._alive()
            if why is None or (
                self._in_flight and why.startswith("no answer to a ping")
            ):
                return
            if self._generation == generation:  # not reconnected meanwhile
                await self._reconnect(why)

    def _lock(self) -> asyncio.Lock:
        if self._liveness_lock is None:
            self._liveness_lock = asyncio.Lock()
        return self._liveness_lock

    async def _reconnect_since(self, generation: int, why: str) -> None:
        """A call's reconnect, under the same lock as heal(): made only if no
        reconnect came since the call read `generation` (or the one that
        came failed), so it never closes a fresh session a retry is on."""
        async with self._lock():
            if self._generation == generation or self._session is None:
                await self._reconnect(why)

    async def call_tool(self, name: str, arguments: dict) -> list:
        await self.heal()
        self._in_flight += 1
        try:
            return await self._send(name, arguments)
        finally:
            self._in_flight -= 1

    async def _send(self, name: str, arguments: dict) -> list:
        for attempt in range(2):
            generation = self._generation
            try:
                if self._session is None:
                    await self._reconnect_since(generation, "not connected")
                result = await asyncio.wait_for(
                    self._session.call_tool(name, arguments),
                    timeout=_TOOL_CALL_TIMEOUT,
                )
                return ToolResult(result.content, is_error=bool(result.isError))
            except asyncio.TimeoutError:
                # before OSError, which a TimeoutError is from Python 3.11: the
                # call may still be running on the remote, so it's never sent again
                raise asyncio.TimeoutError(
                    f"Backend {self.name}: {name} gave no answer in "
                    f"{_TOOL_CALL_TIMEOUT}s; it wasn't sent again, as it may still be running"
                ) from None
            except Exception as exc:
                text = str(exc).lower()
                # Sent again only when the remote refused the session before
                # running anything; any other loss may come after it ran
                if attempt == 0 and _session_refused(exc):
                    await self._reconnect_since(generation, describe(exc))
                    continue
                if isinstance(
                    exc,
                    (
                        ConnectionError,
                        OSError,
                        ClosedResourceError,
                        BrokenResourceError,
                    ),
                ) or any(
                    phrase in text
                    for phrase in (
                        "connection closed",
                        "stream ended",
                        "closed resource",
                        "broken resource",
                        "connection reset",
                        "forcibly closed",
                    )
                ):
                    raise RuntimeError(
                        f"Backend {self.name}: the connection was lost during {name} ({describe(exc)}); "
                        "it wasn't sent again: the call may have run on the guest; check before re-running"
                    ) from exc
                raise
        raise RuntimeError(f"Backend {self.name}: call_tool failed after reconnect")

    async def health_check(self) -> dict:
        """A ping, not the cached tool list: a remote that stopped answering
        is an error even while its tools are still cached."""
        why = await self._alive()
        if why is None:
            return {
                "status": "ok",
                "type": "http",
                "tools": len(self._tools_cache or []),
            }
        if not self._started and self.last_error is None:
            return {"status": "stopped", "type": "http"}
        if TOKEN_REFUSED not in why:
            why = f"unreachable: {why}"
        return {"status": "error", "type": "http", "error": why}


class _StartFailed(Exception):
    """A start that never got to a usable session, with the real cause."""
