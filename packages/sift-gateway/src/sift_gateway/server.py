"""Gateway class: backend management, tool aggregation, Starlette app."""

import asyncio
import contextlib
import logging
import sys
import time
from pathlib import Path

import anyio
from mcp.types import Tool
from sift_common.audit import AuditWriter
from starlette.applications import Starlette
from starlette.routing import Mount

from sift_gateway.auth import AuthMiddleware

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup


class _NormalizeMCPPath:
    """Append trailing slash to per-backend MCP paths.

    Starlette Mount("/mcp/name") returns a 307 redirect for the exact
    path /mcp/name (no trailing slash). MCP streaming clients don't
    follow redirects, so the request falls through to the aggregate
    /mcp mount instead. This middleware rewrites the path in-place.
    """

    def __init__(self, app, backend_paths: frozenset[str] = frozenset()):
        self.app = app
        self.backend_paths = backend_paths

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path", "") in self.backend_paths:
            scope = dict(scope)
            scope["path"] += "/"
            if scope.get("raw_path"):
                scope["raw_path"] = scope["raw_path"] + b"/"
        await self.app(scope, receive, send)


from sift_gateway.audit_helpers import (
    POLL_TOOLS,
    _extract_audit_id,
    _summarize_result,
    _truncate_params,
)
from sift_gateway.backends import MCPBackend, create_backend
from sift_gateway.backends.base import in_own_task
from sift_gateway.backends.http_backend import TOKEN_REFUSED, HttpMCPBackend
from sift_gateway.health import health_routes
from sift_gateway.mcp_endpoint import (
    ANALYST_TOOLS,
    MCPAuthASGIApp,
    create_backend_mcp_server,
    create_mcp_server,
    create_session_manager,
)
from sift_gateway.rest import rest_routes, save_joined_backend
from sift_gateway.unsendable import UnsendableArguments, check_sendable

logger = logging.getLogger(__name__)

# A backend's earlier name, still served as a route to it when only the new
# name is configured.
BACKEND_ALIASES: dict[str, str] = {"threatintel-mcp": "opencti-mcp"}

# Pause between attempts to load a backend that joined after boot
_LOAD_RETRY_SECONDS = 10

# How often the late-start checker runs, and retries a join that isn't loaded
_LATE_START_SECONDS = 30

# Backends the join API can add while the gateway runs. Their per-backend
# endpoint exists from boot, so a first join is served there, never by the
# aggregate endpoint.
JOINABLE: tuple[str, ...] = ("wintools-mcp",)


async def _close_in_this_task(backend: MCPBackend) -> None:
    """Close a backend's connection from the task that opened it.

    Its transport's cancel scopes belong to that task; ``stop()`` of an HTTP
    backend closes them from a ``wait_for`` task before Python 3.12, which
    anyio refuses, and the error tears down the gateway's lifespan.
    An HTTP backend's runner task opens and closes its connection, so a
    stop only asks it to.
    """
    if isinstance(backend, HttpMCPBackend):
        with anyio.CancelScope(shield=True):  # bounded by its stop timeout
            await backend.stop()
        return
    stack = getattr(backend, "_exit_stack", None)
    backend._exit_stack = None
    backend._session = None
    backend._started = False
    if stack is None:
        return
    try:
        # No scope of its own around this: the stack's scopes must be the
        # task's innermost when they exit
        await stack.aclose()
    except (Exception, BaseExceptionGroup) as exc:
        logger.debug("Closing backend %s: %s", backend.name, exc)


class Gateway:
    """Aggregates multiple MCP backends behind a single HTTP service.

    Manages backend lifecycles, builds a unified tool map, and routes
    tool calls to the appropriate backend.
    """

    def __init__(self, config: dict):
        self.config = config
        self.backends: dict[str, MCPBackend] = {}
        self._tool_map: dict[str, str] = {}  # tool_name -> backend_name
        self._tool_cache: dict[str, Tool] = {}  # tool_name -> Tool object
        self._start_locks: dict[str, asyncio.Lock] = {}
        self._reload_event = asyncio.Event()
        self._pending_backends: dict[str, dict] = {}
        # Backends a re-join replaced that were started in another task: kept
        # referenced so they're never finalised from the wrong task.
        self._retired: list[MCPBackend] = []
        # Backends the loader started, by config: only its task may stop them
        self._hot: dict[str, dict] = {}
        self._reloaded: dict[str, asyncio.Event] = {}
        # A joined backend the loader couldn't load (yet), by its config, and
        # why: /health shows it, the late-start checker retries it, and a
        # service restart loads it
        self._unloaded: dict[str, dict] = {}
        self._load_errors: dict[str, str] = {}
        # Loads the checker or a restart queued, by the config queued: one
        # attempt each (a join gets 6), and a checker's retry loads the new
        # backend before closing the one still serving
        self._single_attempt: dict[str, dict] = {}
        self._retrying: dict[str, dict] = {}
        self._audit = AuditWriter(mcp_name="sift-gateway")

        # Create backend instances from config
        backends_config = config.get("backends", {})
        for name, backend_conf in backends_config.items():
            if not backend_conf.get("enabled", True):
                logger.info("Backend %s is disabled, skipping", name)
                continue
            try:
                backend = create_backend(name, backend_conf)
                self.backends[name] = backend
            except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                logger.error("Failed to create backend %s: %s", name, exc)
        for name, alias in BACKEND_ALIASES.items():
            if name in self.backends and alias in self.backends:
                logger.error(
                    "Both %s and %s are configured: they are one threat-intel "
                    "backend under two names, so every tool they share gets a "
                    "backend prefix and the plain tool names (lookup_ioc) stop "
                    "working. Keep one entry in gateway.yaml.",
                    name,
                    alias,
                )

    @property
    def lazy_start(self) -> bool:
        """Whether backends start on first request instead of on boot."""
        gw_config = self.config.get("gateway", {})
        return gw_config.get("lazy_start", False)

    @property
    def idle_timeout(self) -> int:
        """Seconds of idle time before a backend is stopped. 0 = never."""
        gw_config = self.config.get("gateway", {})
        return gw_config.get("idle_timeout_seconds", 0)

    async def start(self) -> None:
        """Start all enabled backends and build the tool map.

        When ``lazy_start`` is enabled in gateway config, backends are
        not started here. They start on first request instead.
        """
        if self.lazy_start:
            logger.info("Lazy start enabled. Backends start on first request.")
            return

        async def _start_one(name: str, backend) -> None:
            try:
                await asyncio.wait_for(backend.start(), timeout=60.0)
                logger.info("Started backend: %s", name)
            except asyncio.TimeoutError:
                logger.error("Backend %s start timed out after 60s", name)
            except (ConnectionError, OSError) as exc:
                logger.error("Failed to start backend %s (connection): %s", name, exc)
            except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                logger.error(
                    "Failed to start backend %s: %s: %s",
                    name,
                    type(exc).__name__,
                    exc,
                )

        await asyncio.gather(
            *(_start_one(name, bk) for name, bk in self.backends.items())
        )
        await self._build_tool_map()

        # Push active case to all started HTTP backends on startup
        for _name, backend in self.backends.items():
            if backend.started:
                await self._notify_backend_case(backend)

    async def stop(self) -> None:
        """Stop all backends."""
        retired = [(backend.name, backend) for backend in self._retired]
        for name, backend in [*self.backends.items(), *retired]:
            try:
                await asyncio.wait_for(backend.stop(), timeout=10.0)
                logger.info("Stopped backend: %s", name)
            except asyncio.TimeoutError:
                logger.error("Backend %s stop timed out after 10s", name)
            except (ConnectionError, OSError) as exc:
                logger.error("Error stopping backend %s (connection): %s", name, exc)
            except BaseException as exc:
                logger.error(
                    "Error stopping backend %s: %s: %s", name, type(exc).__name__, exc
                )
        self._tool_map.clear()
        self._tool_cache.clear()

    async def _build_tool_map(self) -> None:
        """Build a map from tool names to backend names.

        If two backends expose the same tool name, both get prefixed
        with their backend name: {backend}__toolname.
        """
        raw_map: dict[str, list[str]] = {}  # tool_name -> [backend_names]
        tool_objects: dict[str, Tool] = {}  # tool_name -> Tool

        for name, backend in self.backends.items():
            if not backend.started:
                continue
            try:
                tools = await asyncio.wait_for(backend.list_tools(), timeout=15.0)
                for tool in tools:
                    raw_map.setdefault(tool.name, []).append(name)
                    tool_objects[tool.name] = tool
            except asyncio.TimeoutError:
                logger.error("Timeout listing tools for backend %s", name)
            except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                logger.error("Failed to list tools for %s: %s", name, exc)

        new_map: dict[str, str] = {}
        for tool_name, backend_names in raw_map.items():
            if len(backend_names) == 1:
                new_map[tool_name] = backend_names[0]
            else:
                # Collision: prefix with backend name
                logger.warning(
                    "Tool name collision for %r across backends: %s — prefixing",
                    tool_name,
                    backend_names,
                )
                for bname in backend_names:
                    prefixed = f"{bname}__{tool_name}"
                    new_map[prefixed] = bname

        self._tool_map = new_map  # atomic reference swap
        # Cache Tool objects for get_tools_list fallback
        new_cache: dict[str, Tool] = {}
        for mapped_name in new_map:
            original = (
                mapped_name.split("__", 1)[1] if "__" in mapped_name else mapped_name
            )
            if original in tool_objects:
                new_cache[mapped_name] = Tool(
                    name=mapped_name,
                    description=tool_objects[original].description or "",
                    inputSchema=tool_objects[original].inputSchema,
                )
        self._tool_cache = new_cache

        logger.info(
            "Tool map built: %d tools across %d backends",
            len(self._tool_map),
            len(self.backends),
        )

    async def ensure_backend_started(self, backend_name: str) -> None:
        """Start a backend if it's not running (for lazy start mode).

        Uses a per-backend asyncio.Lock with double-check to prevent
        concurrent requests from spawning duplicate subprocesses.
        Also rebuilds the tool map after starting.
        """
        backend = self.backends.get(backend_name)
        if backend is None:
            return
        if backend.started:
            backend.last_tool_call = time.monotonic()
            return
        if backend_name in self._pending_backends:
            # The loader is replacing it; a start from here would race it
            raise RuntimeError(f"Backend {backend_name} is reloading; retry shortly")
        lock = self._start_locks.setdefault(backend_name, asyncio.Lock())
        async with lock:
            if backend.started:
                backend.last_tool_call = time.monotonic()
                return
            logger.info("Lazy-starting backend: %s", backend_name)
            await asyncio.wait_for(in_own_task(backend.start()), timeout=60.0)
            backend.last_tool_call = time.monotonic()
            await self._build_tool_map()

    async def _idle_reaper(self) -> None:
        """Background task that stops backends idle longer than the timeout."""
        timeout = self.idle_timeout
        if timeout <= 0:
            return
        logger.info("Idle reaper started (timeout=%ds)", timeout)
        while True:
            await asyncio.sleep(60)
            now = time.monotonic()
            reaped = False
            for name, backend in list(self.backends.items()):
                # Skip HTTP backends — they're remote servers, disconnecting
                # just drops our session for no benefit (server keeps running)
                if isinstance(backend, HttpMCPBackend):
                    continue
                if backend.started and backend.last_tool_call > 0:
                    idle = now - backend.last_tool_call
                    if idle > timeout:
                        logger.info(
                            "Stopping idle backend: %s (idle %.0fs)", name, idle
                        )
                        try:
                            await backend.stop()
                            reaped = True
                        except (
                            Exception,
                            asyncio.CancelledError,
                            BaseExceptionGroup,
                        ) as exc:
                            logger.error(
                                "Error stopping idle backend %s: %s", name, exc
                            )
            if reaped:
                await self._build_tool_map()

    async def audit_refusal(
        self,
        backend_name: str,
        tool: str,
        arguments: dict,
        exc: Exception,
        examiner=None,
    ) -> None:
        """An audit entry for a call the gateway refused before sending it."""
        try:
            await asyncio.to_thread(
                self._audit.log,
                tool=tool,
                params=_truncate_params(arguments or {}),
                result_summary=f"refused, not sent: {exc}",
                source="gateway_proxy",
                elapsed_ms=0.0,
                extra={"backend": backend_name, "examiner": examiner},
            )
        except Exception as audit_exc:
            logger.warning("Gateway audit failed for %s: %s", tool, audit_exc)

    async def _late_start_checker(self) -> None:
        """Periodically retry failed backends and re-sync case on started ones."""
        while True:
            try:
                await anyio.sleep(_LATE_START_SECONDS)
                for name, conf in list(self._unloaded.items()):
                    if name not in self._pending_backends:
                        self._single_attempt[name] = conf
                        self._retrying[name] = conf
                        self._pending_backends[name] = conf
                        self._reload_event.set()
                for name, backend in list(self.backends.items()):
                    if name in self._pending_backends:
                        continue  # the loader is replacing it
                    if not backend.started:
                        try:
                            await asyncio.wait_for(
                                in_own_task(backend.start()), timeout=30.0
                            )
                            logger.info("Late-started backend: %s", name)
                            await self._build_tool_map()
                            logger.info(
                                "Tool map rebuilt after late-starting: %s", name
                            )
                        except (
                            Exception,
                            asyncio.CancelledError,
                            BaseExceptionGroup,
                        ) as exc:
                            logger.warning("Late-start failed for %s: %s", name, exc)
                            continue
                    # A session the remote ended (a restart, a guest revert)
                    # is reconnected here, with no tool call needed
                    if isinstance(backend, HttpMCPBackend):
                        try:
                            await backend.heal()
                        except (Exception, BaseExceptionGroup) as exc:
                            logger.warning("Reconnect failed for %s: %s", name, exc)
                            continue
                    # Rebuild tool map if backend reconnected with new code
                    if getattr(backend, "_tool_map_stale", False):
                        backend._tool_map_stale = False
                        await self._build_tool_map()
                        logger.info("Tool map rebuilt after %s reconnected", name)
                    # Re-sync case on wintools only (/cases/activate is wintools-specific)
                    if name == "wintools-mcp":
                        await self._notify_backend_case(backend)
            except (Exception, BaseExceptionGroup) as exc:
                logger.error("Late-start checker error (will retry): %s", exc)

    def _get_active_case(self) -> str:
        """Read the current active case ID."""
        try:
            p = Path.home() / ".vhir" / "active_case"
            if p.exists():
                return Path(p.read_text().strip()).name
        except Exception:
            pass
        return ""

    async def _notify_backend_case(self, backend) -> None:
        """Send case activation to an HTTP backend after reconnect."""
        from sift_gateway.backends.http_backend import HttpMCPBackend

        if not isinstance(backend, HttpMCPBackend):
            return
        active_case = self._get_active_case()
        if not active_case:
            return
        try:
            import httpx

            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.post(
                    f"{backend.base_url}/cases/activate",
                    json={"case_id": active_case},
                    headers={"Authorization": f"Bearer {backend.bearer_token}"},
                    timeout=5,
                )
            # Only log at INFO on actual state change, DEBUG for heartbeat no-ops
            body = resp.json() if resp.status_code == 200 else {}
            if body.get("status") == "already_active":
                logger.debug("Case %s already active on %s", active_case, backend.name)
            else:
                logger.info(
                    "Case %s activated on backend %s", active_case, backend.name
                )
        except Exception as e:
            logger.debug("Case activation to %s failed: %s", backend.name, e)

    async def _backend_loader(self) -> None:
        """Start backends added after gateway boot (e.g. wintools after join).

        Runs inside an anyio task group so that streamablehttp_client's
        cancel scopes are properly managed.  Backends started here are
        closed in this task, when a re-join replaces them and in the
        finally block, to avoid cancel-scope mismatch between start() and
        stop().  A re-join that never loads leaves the previous backend.
        """
        dynamic: dict[str, MCPBackend] = {}
        try:
            while True:
                await self._reload_event.wait()
                self._reload_event.clear()
                pending = dict(self._pending_backends)
                for name, conf in pending.items():
                    prev = self.backends.get(name)
                    # a retry leaves the backend serving now until the new one is up
                    retry = conf is not None and self._retrying.pop(name, None) is conf
                    if prev is not None and dynamic.get(name) is prev and not retry:
                        del dynamic[name]
                        await _close_in_this_task(prev)
                    if conf is None:  # a stop: closed above, nothing to load
                        self._done_with(name, conf)
                        continue
                    loaded = False
                    attempts = 1 if self._single_attempt.pop(name, None) is conf else 6
                    for attempt in range(attempts):
                        if self._pending_backends.get(name) is not conf:
                            break  # a newer join for this name came: load that
                        if attempt > 0:
                            await anyio.sleep(_LOAD_RETRY_SECONDS)
                        try:
                            bk = create_backend(name, conf)
                            if not retry:
                                self.backends[name] = bk
                            await bk.start()
                            if retry and prev is not None and dynamic.get(name) is prev:
                                del dynamic[name]
                                await _close_in_this_task(prev)
                            self.backends[name] = bk
                            await self._build_tool_map()
                            dynamic[name] = bk
                            # only the newest join is written: a newer one
                            # waiting is loaded next, and saved if it loads
                            newest = self._pending_backends.get(name) is conf
                            self._hot[name] = (
                                self._made_live(name, conf) if newest else conf
                            )
                            self._unloaded.pop(name, None)
                            self._load_errors.pop(name, None)
                            loaded = True
                            logger.info("Loaded backend: %s", name)
                            break
                        except (
                            Exception,
                            asyncio.CancelledError,
                            BaseExceptionGroup,
                        ) as exc:
                            if prev is not None:
                                self.backends[name] = prev
                            else:
                                self.backends.pop(name, None)
                            # kept from the first failure: /health shows it now
                            self._unloaded[name] = conf
                            self._load_errors[name] = str(exc) or type(exc).__name__
                            logger.warning(
                                "Backend %s attempt %d/%d: %s",
                                name,
                                attempt + 1,
                                attempts,
                                exc,
                            )
                    if loaded and prev is not None and prev.started:
                        self._retired.append(prev)
                    if (
                        not loaded
                        and not retry
                        and prev is not None
                        and not prev.started
                    ):
                        # The previous backend was closed for the re-join:
                        # bring it back from this task, as it was
                        try:
                            await prev.start()
                            dynamic[name] = prev
                            await self._build_tool_map()
                        except (
                            Exception,
                            asyncio.CancelledError,
                            BaseExceptionGroup,
                        ) as exc:
                            logger.warning("Backend %s not restored: %s", name, exc)
                    self._done_with(name, conf)
                    if not loaded:
                        await self._build_tool_map()
                        logger.warning(
                            "Could not load %s yet (%s); retrying every %ds, or "
                            "run 'vhir service restart %s' once it is up",
                            name,
                            self._load_errors.get(name, "no answer"),
                            _LATE_START_SECONDS,
                            name,
                        )
        finally:
            for bk in reversed(list(dynamic.values())):
                await _close_in_this_task(bk)

    def _done_with(self, name: str, conf: dict | None) -> None:
        """A load (or stop) of ``conf`` has finished: clear its slot, unless a
        newer one for this name was queued meanwhile; that one stays, and
        the loader runs again for it."""
        if self._pending_backends.get(name, conf) is conf:
            self._pending_backends.pop(name, None)
            if name in self._reloaded:
                self._reloaded[name].set()
        else:
            self._reload_event.set()

    def _made_live(self, name: str, conf: dict) -> dict:
        """A join that loaded is written to disk now, and only now: until
        then the files still hold the backend that served before it."""
        if not conf.get("joined"):
            return conf
        try:
            return save_joined_backend(name, conf)
        except Exception as exc:  # noqa: BLE001 - it serves; a restart re-joins
            logger.error("Could not save the %s join: %s", name, exc)
            return conf

    async def case_at_start(self, backend_name: str) -> str:
        """The active case when a wintools call starts ("" for none, or for
        another backend): its pending hashes are recorded there."""
        if backend_name not in JOINABLE:
            return ""
        try:
            audit_dir = await asyncio.to_thread(self._audit._get_audit_dir)
            case_dir = audit_dir.parent if audit_dir else None
            ok = bool(case_dir) and (case_dir / "CASE.yaml").is_file()
        except Exception as exc:  # noqa: BLE001 - a case that can't be read never fails the call
            logger.warning("No case for %s's pending hashes: %s", backend_name, exc)
            return ""
        return str(case_dir) if ok else ""

    async def record_pending_hashes(
        self, backend_name: str, result, case_dir: str
    ) -> None:
        """Hash, in the case active when the call started (`case_dir`), the
        files a wintools reply left pending, and record them there. An error
        reply has none. Never fails the call, whatever the reply holds."""
        if backend_name not in JOINABLE or getattr(result, "is_error", False):
            return
        from sift_gateway.pending_hashes import hash_in_case, pending_files

        try:
            files = pending_files(result)
            if not files:
                return
            if not case_dir:
                logger.warning(
                    "%d pending %s hashes not recorded: no active case",
                    len(files),
                    backend_name,
                )
                return
            source = _extract_audit_id(result)
            records = await asyncio.to_thread(
                hash_in_case, Path(case_dir), files, source or backend_name
            )
            await asyncio.to_thread(
                self._audit.log,
                tool="wintools_pending_hashes",
                params={"backend": backend_name, "backend_audit_id": source},
                result_summary={"files": len(records)},
                source="gateway_proxy",
                extra={"files": records},
                case_dir=case_dir,
            )
        except Exception as exc:  # noqa: BLE001 - the call's answer stands
            logger.error("Pending %s hashes not recorded: %s", backend_name, exc)

    def unserved_text(self, tool: str) -> str | None:
        """For a tool that isn't in the map while a backend's token is
        refused: both facts, as the name may be a typo. Else None (the
        plain "not found")."""
        whys = [
            (name, getattr(b, "last_error", None))
            for name, b in self.backends.items()
            if not b.started
        ]
        whys += [(name, self._load_errors.get(name)) for name in self._unloaded]
        for name, why in whys:
            if why and TOKEN_REFUSED in why:
                return (
                    f"Tool {tool} was not found. {why}. Until that's fixed, "
                    f"{name}'s tools can't be listed."
                )
        return None

    def not_loaded_text(self, name: str) -> str:
        """Why ``name`` isn't served: joined but not loaded, or never joined."""
        if name in self._unloaded:
            why = self._load_errors.get(name) or "no answer yet"
            return (
                f"{name} is joined but not loaded: {why} (it is kept until "
                "the gateway restarts; after a restart, join again with a new "
                "join code)"
            )
        return f"{name} is not joined to this gateway"

    async def reload_backend(self, name: str, conf: dict | None) -> None:
        """Have the loader stop (``conf`` None) or reload a backend it started,
        in its own task, and wait until it has."""
        done = self._reloaded.setdefault(name, asyncio.Event())
        done.clear()
        self._pending_backends[name] = conf
        self._reload_event.set()
        await done.wait()

    async def list_tools(self) -> dict[str, str]:
        """Return the current tool map (tool_name -> backend_name)."""
        return dict(self._tool_map)

    async def get_tools_list(self) -> list[Tool]:
        """Return MCP ``Tool`` objects for all aggregated tools.

        Collision-prefixed names are used where applicable.  Shared by
        both the REST and MCP surfaces.
        """
        # Collect raw Tool objects from each backend
        by_name: dict[str, Tool] = {}
        for backend in self.backends.values():
            if not backend.started:
                continue
            try:
                for t in await backend.list_tools():
                    by_name[t.name] = t
            except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                logger.error("get_tools_list: backend error: %s", exc)

        tools: list[Tool] = []
        for mapped_name in self._tool_map:
            # Strip prefix to find the original tool object
            if "__" in mapped_name:
                original = mapped_name.split("__", 1)[1]
            else:
                original = mapped_name

            src = by_name.get(original)
            if src is None:
                # Use cached Tool from _build_tool_map if available
                cached = self._tool_cache.get(mapped_name)
                if cached:
                    tools.append(cached)
                else:
                    tools.append(
                        Tool(
                            name=mapped_name,
                            description="",
                            inputSchema={"type": "object", "properties": {}},
                        )
                    )
            else:
                tools.append(
                    Tool(
                        name=mapped_name,
                        description=src.description or "",
                        inputSchema=src.inputSchema,
                    )
                )
        return tools

    async def call_tool(
        self, name: str, arguments: dict, examiner: str | None = None
    ) -> list:
        """Route a tool call to the correct backend.

        Args:
            name: The (possibly prefixed) tool name.
            arguments: Tool arguments dict.
            examiner: Optional examiner identity for auditing.

        Returns:
            List of content items from the backend.

        Raises:
            KeyError: If the tool name is not in the tool map.
            RuntimeError: If the backend is not started.
        """
        if name not in self._tool_map:
            raise KeyError(f"Unknown tool: {name}")

        backend_name = self._tool_map[name]
        backend = self.backends[backend_name]
        try:  # before any backend sees it, whatever its transport
            check_sendable(backend_name, name, arguments)
        except UnsendableArguments as exc:
            await self.audit_refusal(backend_name, name, arguments, exc, examiner)
            raise

        # Lazy recovery — restart backend if it crashed
        if not backend.started:
            await self.ensure_backend_started(backend_name)

        # If the tool was prefixed due to collision, strip the prefix for the actual call
        actual_name = name
        prefix = f"{backend_name}__"
        if name.startswith(prefix):
            actual_name = name[len(prefix) :]

        # Inject examiner identity into tools that accept analyst_override.
        # Always overwrite to prevent identity spoofing.
        # Role-based filtering (e.g., restricting certain tools by role) is
        # deferred — currently all authenticated users can call any tool.
        if examiner:
            if actual_name in ANALYST_TOOLS:
                arguments = {**arguments, "analyst_override": examiner}

        backend.last_tool_call = time.monotonic()

        logger.info(
            "Routing tool %s -> backend %s (examiner=%s)",
            actual_name,
            backend_name,
            examiner,
        )
        case_at_start = await self.case_at_start(backend_name)
        from sift_gateway import reference

        ref_case = reference.case_for(backend_name, actual_name)  # as it starts
        _start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                backend.call_tool(actual_name, arguments), timeout=300.0
            )
        except asyncio.TimeoutError as exc:
            logger.error(
                "Tool call %s on backend %s timed out after 300s",
                actual_name,
                backend_name,
            )
            if isinstance(backend, HttpMCPBackend):
                elapsed_ms = (time.monotonic() - _start) * 1000
                try:
                    await asyncio.to_thread(
                        self._audit.log,
                        tool=actual_name,
                        params=_truncate_params(arguments),
                        result_summary="timeout after 300s",
                        source="gateway_proxy",
                        elapsed_ms=round(elapsed_ms, 1),
                        extra={"backend": backend_name, "examiner": examiner},
                    )
                except Exception:
                    pass
            raise RuntimeError(f"Tool call {actual_name} timed out after 300s") from exc

        # Centralized audit for HTTP backends (stdio backends audit themselves)
        if isinstance(backend, HttpMCPBackend) and actual_name not in POLL_TOOLS:
            elapsed_ms = (time.monotonic() - _start) * 1000
            try:
                await asyncio.to_thread(
                    self._audit.log,
                    tool=actual_name,
                    params=_truncate_params(arguments),
                    result_summary=_summarize_result(result),
                    source="gateway_proxy",
                    elapsed_ms=round(elapsed_ms, 1),
                    extra={
                        "backend": backend_name,
                        "examiner": examiner,
                        "backend_audit_id": _extract_audit_id(result),
                    },
                )
            except Exception as exc:
                logger.warning("Gateway audit failed for %s: %s", actual_name, exc)
        if isinstance(backend, HttpMCPBackend):  # a poll's final reply has them too
            await self.record_pending_hashes(backend_name, result, case_at_start)

        if not getattr(result, "is_error", False):
            await asyncio.to_thread(
                reference.record, self._audit, backend_name, backend, actual_name,
                arguments, result, examiner, ref_case,
            )  # fmt: skip
        return result

    def create_app(self) -> Starlette:
        """Build a Starlette application with all routes and middleware.

        The app manages the gateway lifecycle via lifespan events.
        Includes both REST and Streamable HTTP MCP surfaces.

        Each backend gets a dedicated MCP endpoint at ``/mcp/{name}``
        alongside the aggregate endpoint at ``/mcp``.
        """
        gateway = self
        api_keys = self.config.get("api_keys", {})
        self._api_keys = api_keys

        # Build aggregate MCP endpoint components
        mcp_server = create_mcp_server(gateway)
        session_manager = create_session_manager(mcp_server)
        mcp_asgi_app = MCPAuthASGIApp(session_manager, api_keys=api_keys)

        # Build per-backend MCP endpoints
        backend_session_managers = []
        per_backend_routes = []
        for name in [*self.backends, *(n for n in JOINABLE if n not in self.backends)]:
            b_server = create_backend_mcp_server(gateway, name)
            b_sm = create_session_manager(b_server)
            b_asgi = MCPAuthASGIApp(b_sm, api_keys=api_keys)
            backend_session_managers.append(b_sm)
            per_backend_routes.append(Mount(f"/mcp/{name}", app=b_asgi))
            # The threat-intel backend's earlier name keeps working: a route to
            # the same backend, not a second backend.
            alias = BACKEND_ALIASES.get(name)
            if alias and alias not in self.backends:
                per_backend_routes.append(Mount(f"/mcp/{alias}", app=b_asgi))

        @contextlib.asynccontextmanager
        async def lifespan(app):
            """Start backends → all MCP session managers → yield → stop."""
            await gateway.start()
            reaper_task = None
            if gateway.idle_timeout > 0:
                reaper_task = asyncio.create_task(gateway._idle_reaper())
            late_start_task = asyncio.create_task(gateway._late_start_checker())
            async with contextlib.AsyncExitStack() as stack:
                await stack.enter_async_context(session_manager.run())
                for b_sm in backend_session_managers:
                    try:
                        await stack.enter_async_context(b_sm.run())
                    except (
                        Exception,
                        asyncio.CancelledError,
                        BaseExceptionGroup,
                    ) as exc:
                        logger.error(
                            "Per-backend session manager failed to start: %s", exc
                        )
                # Backend loader runs in anyio task group so that
                # streamablehttp_client cancel scopes are properly managed.
                async with anyio.create_task_group() as loader_tg:
                    loader_tg.start_soon(gateway._backend_loader)
                    yield
                    loader_tg.cancel_scope.cancel()
            if reaper_task is not None:
                reaper_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reaper_task
            late_start_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await late_start_task
            await gateway.stop()

        routes = []
        routes.extend(health_routes())
        routes.extend(rest_routes())

        # Examiner Portal (optional — installed separately); the retired legacy
        # dashboard's paths redirect to it
        try:
            from case_dashboard.routes import (
                create_dashboard_v2_app,
                retired_dashboard_routes,
            )

            routes.append(Mount("/portal", app=create_dashboard_v2_app()))
            routes.extend(retired_dashboard_routes())
        except ImportError:
            pass

        # Per-backend routes BEFORE aggregate (Starlette matches first)
        routes.extend(per_backend_routes)
        routes.append(Mount("/mcp", app=mcp_asgi_app))

        app = Starlette(
            routes=routes,
            lifespan=lifespan,
        )

        # Attach gateway to app state so endpoints can access it
        app.state.gateway = gateway

        # Add auth middleware (skips /mcp — handled by MCPAuthASGIApp)
        app.add_middleware(AuthMiddleware, api_keys=api_keys)

        # Normalize per-backend MCP paths (must be outermost = added last)
        backend_paths = frozenset(
            route.path for route in per_backend_routes
        )  # the aliases too
        app.add_middleware(_NormalizeMCPPath, backend_paths=backend_paths)

        return app
