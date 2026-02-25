"""REST API routes for /api/v1/."""

import asyncio
import json
import logging
import os
import socket
import tempfile
import threading
from urllib.parse import urlparse

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from sift_gateway.auth import resolve_examiner
from sift_gateway.join import (
    check_join_rate_limit,
    generate_join_code,
    record_join_failure,
    store_join_code,
    validate_and_consume_join_code,
)
from sift_gateway.rate_limit import check_rate_limit
from sift_gateway.token_gen import generate_gateway_token

logger = logging.getLogger(__name__)

# Maximum request body size (10 MB)
_MAX_REQUEST_BYTES = 10 * 1024 * 1024


async def list_tools(request: Request) -> JSONResponse:
    """GET /api/v1/tools — list all aggregated tools.

    Query params:
        backend: filter tools by backend name
    """
    gateway = request.app.state.gateway
    backend_filter = request.query_params.get("backend")

    # Reuse gateway.get_tools_list() for descriptions and schemas
    all_tools = await gateway.get_tools_list()

    tools = []
    for t in sorted(all_tools, key=lambda x: x.name):
        backend_name = gateway._tool_map.get(t.name, "")
        if backend_filter and backend_name != backend_filter:
            continue
        tools.append(
            {
                "name": t.name,
                "backend": backend_name,
                "description": t.description or "",
                "input_schema": t.inputSchema,
            }
        )

    return JSONResponse({"tools": tools, "count": len(tools)})


async def call_tool(request: Request) -> JSONResponse:
    """POST /api/v1/tools/{tool_name} — call a tool.

    Body:
        {"arguments": {...}}
    """
    # Rate limit check (before any body processing)
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        return JSONResponse(
            {"error": "Rate limit exceeded"},
            status_code=429,
        )

    gateway = request.app.state.gateway
    tool_name = request.path_params["tool_name"]
    identity = resolve_examiner(request)

    # Read the raw body and enforce actual size limit.
    # Checking Content-Length alone is insufficient because the header
    # can be absent or spoofed; reading the body is authoritative.
    raw_body = await request.body()
    if len(raw_body) > _MAX_REQUEST_BYTES:
        return JSONResponse(
            {"error": f"Request body too large (max {_MAX_REQUEST_BYTES} bytes)"},
            status_code=413,
        )

    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    arguments = body.get("arguments", {})
    if not isinstance(arguments, dict):
        return JSONResponse({"error": "arguments must be an object"}, status_code=400)

    if tool_name not in gateway._tool_map:
        return JSONResponse(
            {"error": f"Tool not found: {tool_name}"},
            status_code=404,
        )

    try:
        result = await gateway.call_tool(
            tool_name, arguments, examiner=identity.get("examiner")
        )
        # Serialize content items
        serialized = []
        for item in result:
            if hasattr(item, "model_dump"):
                serialized.append(item.model_dump())
            elif hasattr(item, "__dict__"):
                serialized.append(item.__dict__)
            else:
                serialized.append(str(item))

        return JSONResponse(
            {
                "tool": tool_name,
                "backend": gateway._tool_map[tool_name],
                "result": serialized,
            }
        )
    except KeyError as exc:
        logger.error("Tool call failed — tool not in map: %s — %s", tool_name, exc)
        return JSONResponse(
            {"error": f"Tool not found: {tool_name}"},
            status_code=404,
        )
    except Exception as exc:
        logger.error(
            "Tool call failed: %s — %s: %s",
            tool_name,
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        return JSONResponse(
            {
                "error": "Tool call failed",
                "tool": tool_name,
                "error_type": type(exc).__name__,
            },
            status_code=500,
        )


async def list_backends(request: Request) -> JSONResponse:
    """GET /api/v1/backends — list all backends with status."""
    gateway = request.app.state.gateway

    backends = []
    for name, backend in gateway.backends.items():
        try:
            health = await backend.health_check()
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.warning("Health check failed for backend %s: %s", name, e)
            health = {"status": "error", "detail": str(e)}
        except Exception as e:
            logger.warning("Health check unexpected error for backend %s: %s", name, e)
            health = {"status": "error"}

        backends.append(
            {
                "name": name,
                "type": backend.config.get("type", "stdio"),
                "enabled": backend.enabled,
                "health": health,
            }
        )

    return JSONResponse({"backends": backends, "count": len(backends)})


# ---------------------------------------------------------------------------
# Service management endpoints
# ---------------------------------------------------------------------------


async def list_services(request: Request) -> JSONResponse:
    """GET /api/v1/services — list all backends with health and started status."""
    gateway = request.app.state.gateway

    services = []
    for name, backend in gateway.backends.items():
        try:
            health = await backend.health_check()
        except Exception as e:
            logger.warning("Health check failed for service %s: %s", name, e)
            health = {"status": "error"}

        services.append(
            {
                "name": name,
                "type": backend.config.get("type", "stdio"),
                "started": backend.started,
                "health": health,
            }
        )

    return JSONResponse({"services": services, "count": len(services)})


async def start_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/start — start a backend and rebuild tool map."""
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    if name not in gateway.backends:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends[name]
    if backend.started:
        return JSONResponse({"status": "already_running", "name": name})

    try:
        await asyncio.wait_for(backend.start(), timeout=30.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Start timed out for {name}"}, status_code=504)
    except Exception as e:
        logger.error("Failed to start service %s: %s", name, e)
        return JSONResponse({"error": f"Failed to start: {e}"}, status_code=500)

    await gateway._build_tool_map()
    return JSONResponse({"status": "started", "name": name})


async def stop_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/stop — stop a backend and rebuild tool map."""
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    if name not in gateway.backends:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends[name]
    if not backend.started:
        return JSONResponse({"status": "already_stopped", "name": name})

    try:
        await asyncio.wait_for(backend.stop(), timeout=10.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Stop timed out for {name}"}, status_code=504)
    except Exception as e:
        logger.error("Failed to stop service %s: %s", name, e)
        return JSONResponse({"error": f"Failed to stop: {e}"}, status_code=500)

    await gateway._build_tool_map()
    return JSONResponse({"status": "stopped", "name": name})


async def restart_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/restart — stop + start a backend."""
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    if name not in gateway.backends:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends[name]

    # Stop if running
    if backend.started:
        try:
            await asyncio.wait_for(backend.stop(), timeout=10.0)
        except Exception as e:
            logger.error("Failed to stop service %s during restart: %s", name, e)
            return JSONResponse(
                {"error": f"Failed to stop during restart: {e}"}, status_code=500
            )

    # Start
    try:
        await asyncio.wait_for(backend.start(), timeout=30.0)
    except asyncio.TimeoutError:
        await gateway._build_tool_map()
        return JSONResponse({"error": f"Start timed out for {name}"}, status_code=504)
    except Exception as e:
        logger.error("Failed to start service %s during restart: %s", name, e)
        await gateway._build_tool_map()
        return JSONResponse(
            {"error": f"Failed to start during restart: {e}"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "restarted", "name": name})


# ---------------------------------------------------------------------------
# Join code endpoints
# ---------------------------------------------------------------------------


async def create_join_code(request: Request) -> JSONResponse:
    """POST /api/v1/setup/join-code — generate a one-time join code.

    Requires bearer token auth (authenticated examiner).
    """
    expires_hours = 2
    body = await request.body()
    if body:
        try:
            data = json.loads(body)
            expires_hours = data.get("expires_hours", 2)
        except json.JSONDecodeError:
            pass

    if (
        not isinstance(expires_hours, (int, float))
        or expires_hours < 1
        or expires_hours > 48
    ):
        return JSONResponse(
            {"error": "expires_hours must be between 1 and 48"},
            status_code=400,
        )

    code = generate_join_code()
    store_join_code(code, expires_hours=expires_hours)

    gateway = request.app.state.gateway
    gw_url = _get_gateway_url(gateway)
    parsed = urlparse(gw_url)
    host_port = f"{parsed.hostname}:{parsed.port}"

    return JSONResponse(
        {
            "code": code,
            "expires_hours": expires_hours,
            "instructions": f"aiir join --sift {host_port} --code {code}",
        }
    )


async def join_gateway(request: Request) -> JSONResponse:
    """POST /api/v1/setup/join — exchange join code for gateway credentials.

    Unauthenticated — the join code is the auth mechanism.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not check_join_rate_limit(client_ip):
        return JSONResponse(
            {"error": "Too many failed attempts. Try again later."},
            status_code=429,
        )

    try:
        body = json.loads(await request.body())
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    code = body.get("code", "")
    machine_type = body.get("machine_type", "examiner")
    hostname = body.get("hostname", "")
    wintools_url = body.get("wintools_url")
    wintools_token = body.get("wintools_token")

    matched_hash = validate_and_consume_join_code(code)
    if not matched_hash:
        record_join_failure(client_ip)
        return JSONResponse(
            {"error": "Invalid or expired join code"},
            status_code=403,
        )

    examiner_name = hostname or machine_type
    gateway = request.app.state.gateway

    # Generate a bearer token only for non-wintools joins
    if machine_type != "wintools":
        new_token = generate_gateway_token()
        _add_api_key_to_config(gateway, new_token, examiner_name)
    else:
        new_token = None

    # If wintools: add wintools backend to config
    wintools_registered = False
    if machine_type == "wintools" and wintools_url and wintools_token:
        parsed = urlparse(wintools_url)
        if parsed.scheme not in ("http", "https"):
            return JSONResponse(
                {"error": "wintools_url must use http or https scheme"},
                status_code=400,
            )
        if not parsed.hostname:
            return JSONResponse(
                {"error": "wintools_url must include a hostname"},
                status_code=400,
            )
        _add_wintools_backend(gateway, wintools_url, wintools_token)
        wintools_registered = True

    # Build response
    backends = list(gateway.backends.keys())
    gw_url = _get_gateway_url(gateway)

    response = {
        "gateway_url": gw_url,
        "backends": backends,
        "examiner": examiner_name,
    }
    if new_token:
        response["gateway_token"] = new_token

    if wintools_registered:
        response["wintools_registered"] = True
        response["restart_required"] = True

    return JSONResponse(response)


async def join_status(request: Request) -> JSONResponse:
    """GET /api/v1/setup/join-status — check pending join codes (authenticated)."""
    import time

    from sift_gateway.join import _load_state

    state = _load_state()
    now = time.time()
    active = 0
    for info in state.get("codes", {}).values():
        if not info.get("used", False) and now <= info.get("expires_ts", 0):
            active += 1

    return JSONResponse({"active_codes": active})


_CONFIG_LOCK = threading.Lock()


def _atomic_yaml_write(config_path, config: dict) -> None:
    """Write YAML config atomically via temp file + fsync + os.replace."""
    import yaml

    config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(config_path.parent), suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(config_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _add_api_key_to_config(gateway, token: str, examiner: str) -> None:
    """Add a new API key to the gateway config and write to disk."""
    from pathlib import Path

    with _CONFIG_LOCK:
        config_path = Path.home() / ".aiir" / "gateway.yaml"
        if config_path.exists():
            import yaml

            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
            except (yaml.YAMLError, OSError):
                config = {}
        else:
            config = {}

        if "api_keys" not in config:
            config["api_keys"] = {}

        config["api_keys"][token] = {
            "examiner": examiner,
            "role": "examiner",
        }

        try:
            _atomic_yaml_write(config_path, config)
        except OSError as e:
            logger.error("Failed to write gateway config: %s", e)
            raise HTTPException(
                status_code=500, detail="Failed to save configuration"
            ) from e

    # Also update the in-memory gateway auth keys
    if hasattr(gateway, "_app"):
        # Walk middleware stack to find AuthMiddleware
        app = gateway._app
        while hasattr(app, "app"):
            if hasattr(app, "api_keys"):
                app.api_keys[token] = {"examiner": examiner, "role": "examiner"}
                break
            app = app.app


def _add_wintools_backend(gateway, url: str, token: str) -> None:
    """Add a wintools-mcp HTTP backend to the gateway config."""
    from pathlib import Path

    import yaml

    with _CONFIG_LOCK:
        config_path = Path.home() / ".aiir" / "gateway.yaml"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
            except (yaml.YAMLError, OSError):
                config = {}
        else:
            config = {}

        if "backends" not in config:
            config["backends"] = {}

        config["backends"]["wintools-mcp"] = {
            "type": "http",
            "url": url,
            "bearer_token": token,
            "enabled": True,
        }

        try:
            _atomic_yaml_write(config_path, config)
        except OSError as e:
            logger.error("Failed to write gateway config: %s", e)
            raise HTTPException(
                status_code=500, detail="Failed to save configuration"
            ) from e


def _get_gateway_url(gateway) -> str:
    """Build the gateway URL from config."""
    gw_config = gateway.config.get("gateway", {})
    host = gw_config.get("host", "127.0.0.1")
    port = gw_config.get("port", 4508)
    tls = gw_config.get("tls", {})

    if host == "0.0.0.0":
        try:
            host = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            host = "127.0.0.1"

    scheme = "https" if tls.get("certfile") else "http"
    return f"{scheme}://{host}:{port}"


def rest_routes() -> list[Route]:
    """Return REST API v1 routes."""
    return [
        Route("/api/v1/tools", list_tools, methods=["GET"]),
        Route("/api/v1/tools/{tool_name}", call_tool, methods=["POST"]),
        Route("/api/v1/backends", list_backends, methods=["GET"]),
        Route("/api/v1/services", list_services, methods=["GET"]),
        Route("/api/v1/services/{name}/start", start_service, methods=["POST"]),
        Route("/api/v1/services/{name}/stop", stop_service, methods=["POST"]),
        Route("/api/v1/services/{name}/restart", restart_service, methods=["POST"]),
        Route("/api/v1/setup/join-code", create_join_code, methods=["POST"]),
        Route("/api/v1/setup/join", join_gateway, methods=["POST"]),
        Route("/api/v1/setup/join-status", join_status, methods=["GET"]),
    ]
