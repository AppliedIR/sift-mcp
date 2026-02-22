"""Gateway class: backend management, tool aggregation, Starlette app."""

import asyncio
import contextlib
import logging
from starlette.applications import Starlette
from starlette.routing import Mount, Route

from mcp.types import Tool

from sift_gateway.backends import create_backend, MCPBackend
from sift_gateway.auth import AuthMiddleware
from sift_gateway.health import health_routes
from sift_gateway.mcp_endpoint import (
    ANALYST_TOOLS,
    MCPAuthASGIApp,
    create_backend_mcp_server,
    create_mcp_server,
    create_session_manager,
)
from sift_gateway.rest import rest_routes

logger = logging.getLogger(__name__)


class Gateway:
    """Aggregates multiple MCP backends behind a single HTTP service.

    Manages backend lifecycles, builds a unified tool map, and routes
    tool calls to the appropriate backend.
    """

    def __init__(self, config: dict):
        self.config = config
        self.backends: dict[str, MCPBackend] = {}
        self._tool_map: dict[str, str] = {}  # tool_name -> backend_name

        # Create backend instances from config
        backends_config = config.get("backends", {})
        for name, backend_conf in backends_config.items():
            if not backend_conf.get("enabled", True):
                logger.info("Backend %s is disabled, skipping", name)
                continue
            try:
                backend = create_backend(name, backend_conf)
                self.backends[name] = backend
            except Exception as exc:
                logger.error("Failed to create backend %s: %s", name, exc)

    async def start(self) -> None:
        """Start all enabled backends and build the tool map."""
        for name, backend in self.backends.items():
            try:
                await asyncio.wait_for(backend.start(), timeout=30.0)
                logger.info("Started backend: %s", name)
            except asyncio.TimeoutError:
                logger.error("Backend %s start timed out after 30s", name)
            except (ConnectionError, OSError) as exc:
                logger.error("Failed to start backend %s (connection): %s", name, exc)
            except Exception as exc:
                logger.error("Failed to start backend %s: %s: %s", name, type(exc).__name__, exc)

        await self._build_tool_map()

    async def stop(self) -> None:
        """Stop all backends."""
        for name, backend in self.backends.items():
            try:
                await asyncio.wait_for(backend.stop(), timeout=10.0)
                logger.info("Stopped backend: %s", name)
            except asyncio.TimeoutError:
                logger.error("Backend %s stop timed out after 10s", name)
            except (ConnectionError, OSError) as exc:
                logger.error("Error stopping backend %s (connection): %s", name, exc)
            except Exception as exc:
                logger.error("Error stopping backend %s: %s: %s", name, type(exc).__name__, exc)
        self._tool_map.clear()

    async def _build_tool_map(self) -> None:
        """Build a map from tool names to backend names.

        If two backends expose the same tool name, both get prefixed
        with their backend name: {backend}__toolname.
        """
        raw_map: dict[str, list[str]] = {}  # tool_name -> [backend_names]

        for name, backend in self.backends.items():
            if not backend.started:
                continue
            try:
                tools = await asyncio.wait_for(backend.list_tools(), timeout=15.0)
                for tool in tools:
                    raw_map.setdefault(tool.name, []).append(name)
            except asyncio.TimeoutError:
                logger.error("Timeout listing tools for backend %s", name)
            except Exception as exc:
                logger.error("Failed to list tools for %s: %s", name, exc)

        self._tool_map.clear()
        for tool_name, backend_names in raw_map.items():
            if len(backend_names) == 1:
                self._tool_map[tool_name] = backend_names[0]
            else:
                # Collision: prefix with backend name
                logger.warning(
                    "Tool name collision for %r across backends: %s — prefixing",
                    tool_name,
                    backend_names,
                )
                for bname in backend_names:
                    prefixed = f"{bname}__{tool_name}"
                    self._tool_map[prefixed] = bname

        logger.info("Tool map built: %d tools across %d backends",
                     len(self._tool_map), len(self.backends))

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
            except Exception as exc:
                logger.error("get_tools_list: backend error: %s", exc)

        tools: list[Tool] = []
        for mapped_name, backend_name in self._tool_map.items():
            # Strip prefix to find the original tool object
            if "__" in mapped_name:
                original = mapped_name.split("__", 1)[1]
            else:
                original = mapped_name

            src = by_name.get(original)
            if src is None:
                tools.append(Tool(
                    name=mapped_name,
                    description="",
                    inputSchema={"type": "object", "properties": {}},
                ))
            else:
                tools.append(Tool(
                    name=mapped_name,
                    description=src.description or "",
                    inputSchema=src.inputSchema,
                ))
        return tools

    async def call_tool(self, name: str, arguments: dict, examiner: str | None = None) -> list:
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

        # If the tool was prefixed due to collision, strip the prefix for the actual call
        actual_name = name
        prefix = f"{backend_name}__"
        if name.startswith(prefix):
            actual_name = name[len(prefix):]

        # Inject examiner identity into tools that accept analyst_override.
        # Always overwrite to prevent identity spoofing.
        # Role-based filtering (e.g., restricting certain tools by role) is
        # deferred — currently all authenticated users can call any tool.
        if examiner:
            if actual_name in ANALYST_TOOLS:
                arguments = {**arguments, "analyst_override": examiner}

        logger.info("Routing tool %s -> backend %s (examiner=%s)", actual_name, backend_name, examiner)
        try:
            return await asyncio.wait_for(backend.call_tool(actual_name, arguments), timeout=300.0)
        except asyncio.TimeoutError:
            logger.error("Tool call %s on backend %s timed out after 300s", actual_name, backend_name)
            raise RuntimeError(f"Tool call {actual_name} timed out after 300s")

    def create_app(self) -> Starlette:
        """Build a Starlette application with all routes and middleware.

        The app manages the gateway lifecycle via lifespan events.
        Includes both REST and Streamable HTTP MCP surfaces.

        Each backend gets a dedicated MCP endpoint at ``/mcp/{name}``
        alongside the aggregate endpoint at ``/mcp``.
        """
        gateway = self
        api_keys = self.config.get("api_keys", {})

        # Build aggregate MCP endpoint components
        mcp_server = create_mcp_server(gateway)
        session_manager = create_session_manager(mcp_server)
        mcp_asgi_app = MCPAuthASGIApp(session_manager, api_keys=api_keys)

        # Build per-backend MCP endpoints
        backend_session_managers = []
        per_backend_routes = []
        for name in self.backends:
            b_server = create_backend_mcp_server(gateway, name)
            b_sm = create_session_manager(b_server)
            b_asgi = MCPAuthASGIApp(b_sm, api_keys=api_keys)
            backend_session_managers.append(b_sm)
            per_backend_routes.append(Mount(f"/mcp/{name}", app=b_asgi))

        @contextlib.asynccontextmanager
        async def lifespan(app):
            """Start backends → all MCP session managers → yield → stop."""
            await gateway.start()
            async with contextlib.AsyncExitStack() as stack:
                await stack.enter_async_context(session_manager.run())
                for b_sm in backend_session_managers:
                    await stack.enter_async_context(b_sm.run())
                yield
            await gateway.stop()

        routes = []
        routes.extend(health_routes())
        routes.extend(rest_routes())
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

        return app
