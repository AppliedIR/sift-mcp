"""Stdio-based MCP backend — launches a subprocess and communicates via MCP stdio transport."""

import asyncio
import logging
import math
import os
import sys
import weakref
from contextlib import AsyncExitStack

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import McpError
from mcp.types import CONNECTION_CLOSED, Tool

from sift_gateway.backends.base import (
    MCPBackend,
    ToolResult,
    _version_of,
    call_timeout,
)

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup

logger = logging.getLogger(__name__)


def _gone(exc: BaseException) -> bool:
    """Whether `exc` says the child is gone: the transport closed or broke
    under the session (a dead pipe, the session ending mid-call). A timeout
    never does (on 3.12 TimeoutError is an OSError): a busy child is alive."""
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return False
    if isinstance(exc, McpError):
        return exc.error.code == CONNECTION_CLOSED
    return isinstance(exc, (ConnectionError, OSError, anyio.ClosedResourceError,
                            anyio.BrokenResourceError, anyio.EndOfStream))  # fmt: skip


def _closed(exc: McpError) -> bool:
    """The session's own close error, sent to every pending call when its
    receive loop ends (mcp shared/session.py): not a reply from the child."""
    error = exc.error
    return error.code == CONNECTION_CLOSED and error.message == "Connection closed"


def _lost(stream) -> bool:
    """Whether the gateway lost its connection to the child: the session's read
    stream has no open writer, so the transport's stdout reader closed it (the
    child ended, wrote bytes that aren't UTF-8, or its transport failed)."""
    return stream is not None and stream.statistics().open_send_streams == 0


def _one(exc: BaseException | None) -> BaseException | None:
    """A group of one error is named by that error."""
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    return exc


def _cause(failure: BaseException | None) -> Exception | None:
    """The error that failed a start's own task group, from what its cleanup
    raised; None when that was a cancellation alone (the caller's)."""
    if isinstance(failure, BaseExceptionGroup):
        failure = failure.split(asyncio.CancelledError)[1]
    failure = _one(failure)
    if not isinstance(failure, Exception) or "cancel scope" in str(failure):
        return None
    return failure


def _cancelled_within(guard: anyio.CancelScope) -> bool:
    """Whether a scope the current task entered inside `guard` is cancelled: a
    cancellation from there is the start's own, not its caller's. Shielding
    `guard` for the look hides every scope outside it."""
    guard.shield = True
    try:
        return anyio.current_effective_deadline() == -math.inf
    finally:
        guard.shield = False


def _before_text(backend: str, tool: str) -> str:
    return (
        f"The gateway lost its connection to backend {backend}'s process before {tool} "
        f"was sent, so {tool} didn't run. The gateway starts the backend again on the "
        "next call."
    )


def _during_text(backend: str, tool: str) -> str:
    return (
        f"The gateway lost its connection to backend {backend}'s process while {tool} "
        "was running. The gateway didn't send it again, and it may have run in part: "
        "check the case audit before running it again. The gateway starts the backend "
        "again on the next call."
    )


def _stopped_text(backend: str, tool: str) -> str:
    return (
        f"The gateway stopped backend {backend} (a service stop or restart, an idle stop "
        f"or shutdown) while {tool} was running. The gateway didn't send it again, and "
        "it may have run in part: check the case audit before running it again."
    )


# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_PING_TIMEOUT = 5  # health: no answer in time is busy, not gone
_STOP_TIMEOUT = 15
_POLL = 1  # a call looks at its connection this often
_FINISH = 1  # after the connection is lost, a call may still be answered this long
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
        self._generation = 0  # bumped by each start: which session a call ran on
        self._stream = None  # the read stream of _session, stored with it
        self._stopped = weakref.WeakSet()  # sessions the gateway closed itself

    async def _reset_if_current(self, generation: int, *, context: str) -> None:
        """Reset after the child of session `generation` is gone. A newer
        session (another request restarted the backend meanwhile) is left
        alone: this failure was the old child's."""
        if generation == self._generation:
            await self._safe_cleanup(context=context)

    async def _safe_cleanup(self, *, context: str) -> BaseException | None:
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

        Returns what the close raised (a failed start reads its cause there).
        """
        # Detach this session's state before awaiting its close: a second
        # cleanup of the same session (two failed requests) finds nothing to
        # close, and a request that restarts the backend meanwhile keeps its
        # new session; a close finishing later never clears it.
        stack, self._exit_stack = self._exit_stack, None
        self._session = self._stream = None
        self._tools_cache = None
        self._started = False
        if stack is None:
            return None
        try:
            await stack.aclose()
        except BaseException as exc:
            named = _one(exc)
            quiet = _cause(exc) is None  # a cancellation, or cancel-scope noise
            logger.log(
                logging.DEBUG if quiet else logging.WARNING,
                "Backend %s %s: %s: %s",
                self.name,
                context,
                type(named).__name__,
                named,
            )
            return exc
        return None

    async def start(self) -> None:
        if self._started:
            return
        # a new generation before anything of the new session is published: a
        # call still in flight on the old one is already stale
        self._generation += 1

        command = self.config.get("command", "python")
        args = self.config.get("args", [])
        env = self.config.get("env") or None
        # Python backends run isolated: the gateway's cwd is never on sys.path.
        # Not one whose env sets PYTHONPATH, which -I would ignore.
        if (
            args[:1] == ["-m"]
            and os.path.basename(command).startswith("python")
            and "PYTHONPATH" not in (env or {})
        ):
            args = ["-I", *args]

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
        # the transport's and the session's scopes open inside this one, so a
        # failure of theirs is told from the caller's cancellation
        guard = self._exit_stack.enter_context(anyio.CancelScope())
        try:
            transport = await self._exit_stack.enter_async_context(
                stdio_client(server_params)
            )
            read_stream, write_stream = transport
            session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            # in one step: a session is never paired with another start's stream
            self._session, self._stream = session, read_stream
            # Bound session.initialize() so a hung remote backend can't
            # block the gateway's startup loop indefinitely (UAT 2026-04-25
            # repro: unreachable OpenCTI caused initialize() to wait for
            # the underlying socket timeout before the gateway noticed).
            result = await asyncio.wait_for(
                session.initialize(), timeout=_INITIALIZE_TIMEOUT
            )
            self._instructions = result.instructions
            self._server_version = _version_of(result)
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
            # asked before the cleanup closes the scopes it looks at
            own = isinstance(exc, asyncio.CancelledError) and _cancelled_within(guard)
            failure = await self._safe_cleanup(context="cleanup after failed start")
            if isinstance(exc, asyncio.CancelledError):
                # The start's own task group failing cancels this await; its
                # cleanup raises that failure. Any other cancellation is the
                # caller's, and goes on as one, whatever the cleanup raised.
                cause = _cause(failure) if own else None
                if cause is None:
                    logger.debug("Backend %s start cancelled", self.name)
                    raise
                logger.error(
                    "Backend %s failed to start: %s: %s",
                    self.name,
                    type(cause).__name__,
                    cause,
                )
                raise cause from None
            logger.error(
                "Backend %s failed to start: %s: %s", self.name, type(exc).__name__, exc
            )
            raise

    async def close(self) -> None:
        """The one close of a stdio session by the gateway: SB.stop() and the
        loader (in its own task, as the stack's cancel scopes are that task's)
        both close through it. It marks the session stopped by the gateway
        before anything is closed, and runs in the calling task with no
        timeout of its own."""
        if self._session is not None:
            self._stopped.add(self._session)
        await self._safe_cleanup(context="close")

    async def stop(self) -> None:
        if not self._started:
            return
        try:
            await asyncio.wait_for(self.close(), timeout=_STOP_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning(
                "Backend %s stop timed out after %ds", self.name, _STOP_TIMEOUT
            )
        logger.info("Backend %s stopped", self.name)

    async def list_tools(self, *, reset: bool = True) -> list[Tool]:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        if self._tools_cache is None:
            result = await asyncio.wait_for(
                self._session.list_tools(), timeout=_TOOL_LIST_TIMEOUT
            )
            self._tools_cache = result.tools
        return self._tools_cache

    def _on_stream_closed(self) -> None:
        """A test seam, and nothing else: a call's wait has seen its stream
        closed and starts the bounded finish."""

    async def _finish(self, task: asyncio.Task, deadline: float) -> None:
        """Let a call whose connection was lost be answered. A receive loop
        that ends by EOF or an error answers every pending call, with the
        child's reply or the session's close error; one that was cancelled
        answers none. So a time bound, never past the call's deadline."""
        left = deadline - asyncio.get_running_loop().time()
        if left > 0:
            await asyncio.wait({task}, timeout=min(_FINISH, left))

    def _ended(self, session: ClientSession, stream) -> bool:
        return _lost(stream) or session in self._stopped

    async def _drop(self, session: ClientSession, generation: int, name: str):
        """The call's connection is gone: reset, and the text that says so."""
        text = _stopped_text if session in self._stopped else _during_text
        await self._reset_if_current(generation, context="call_tool cleanup after loss")
        return RuntimeError(text(self.name, name))

    async def call_tool(self, name: str, arguments: dict) -> list:
        # this call's own session and stream: a restart by another call never
        # makes this one take the new child for its own
        session, stream, generation = self._session, self._stream, self._generation
        if not self._started or session is None:
            raise RuntimeError(_before_text(self.name, name))
        if _lost(stream):  # nothing sent: the next call starts a new child
            await self._reset_if_current(generation, context="call_tool cleanup")
            raise RuntimeError(_before_text(self.name, name))

        # The call and the loss of its connection, awaited together up to the
        # one deadline. A session with no stream is judged by the deadline alone.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _TOOL_CALL_TIMEOUT
        task = asyncio.ensure_future(session.call_tool(name, arguments))
        try:
            while not task.done():
                left = deadline - loop.time()
                if left <= 0:
                    if self._ended(session, stream):  # the known loss wins
                        raise await self._drop(session, generation, name)
                    # the child may still be running it: alive
                    raise call_timeout(self.name, name, _TOOL_CALL_TIMEOUT)
                await asyncio.wait({task}, timeout=min(_POLL, left))
                if not task.done() and self._ended(session, stream):
                    if _lost(stream):
                        self._on_stream_closed()
                    await self._finish(task, deadline)
                    if not task.done():
                        raise await self._drop(session, generation, name)
            try:
                result = task.result()
            except Exception as exc:
                if (
                    stream is not None
                    and isinstance(exc, McpError)
                    and not _closed(exc)
                ):  # the child's own error reply: it lives on
                    raise RuntimeError(
                        f"Backend {self.name} answered {name} with an error: "
                        f"{exc.error.message}."
                    ) from exc
                if not _gone(exc):
                    raise
                if stream is None:  # restarted lazily by the gateway's next call
                    await self._reset_if_current(
                        generation, context="call_tool cleanup after error"
                    )
                    raise
                raise await self._drop(session, generation, name) from exc
            return ToolResult(result.content, is_error=bool(result.isError))
        finally:  # no task from the wait outlives the call
            if not task.done():
                task.cancel()
                with anyio.CancelScope(shield=True):
                    await asyncio.wait({task})
            if not task.cancelled():
                task.exception()  # retrieved: never "never retrieved"

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "stdio"}
        if _lost(self._stream):  # reported, not reset: the next call says so
            return {"status": "error", "type": "stdio",
                    "error": "the connection to the process was lost"}  # fmt: skip
        try:
            await self.list_tools(reset=False)
            # the cache answers without the child: ask the child itself
            await asyncio.wait_for(self._session.send_ping(), timeout=_PING_TIMEOUT)
            return {
                "status": "ok",
                "type": "stdio",
                "tools": len(self._tools_cache or []),
            }
        except (asyncio.TimeoutError, TimeoutError):  # a call may be running: alive
            return {"status": "busy", "type": "stdio",
                    "error": f"no answer to a ping within {_PING_TIMEOUT} s"}  # fmt: skip
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
            logger.warning(
                "Backend %s health check failed: %s: %s",
                self.name,
                type(exc).__name__,
                exc,
            )
            return {"status": "error", "type": "stdio", "error": type(exc).__name__}
