"""REST API routes for /api/v1/."""

import asyncio
import contextlib
import hmac
import json
import logging
import os
import socket
import sys
import tempfile
import threading
from urllib.parse import urlparse

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from sift_gateway.auth import resolve_examiner
from sift_gateway.backends.base import in_own_task
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.join import (
    _join_code_lock,
    check_join_rate_limit,
    find_join_code,
    generate_join_code,
    join_name,
    mark_code_used,
    record_join_failure,
    revoke_unused_join_codes,
    store_join_code,
    valid_name,
)
from sift_gateway.rate_limit import check_rate_limit
from sift_gateway.token_gen import generate_gateway_token

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup

logger = logging.getLogger(__name__)

# Maximum request body size (10 MB)
_MAX_REQUEST_BYTES = 10 * 1024 * 1024

# An examiner name is taken when a gateway token or an enrolled credential
# holds it (vhir's credential folders)
_PASSWORDS_DIR = "/var/lib/vhir/passwords"
_KEYS_DIR = "/var/lib/vhir/keys"
NAME_IN_USE = (
    "{name} is already in use. To re-join under your own name, ask the box owner "
    "for a code from `vhir setup join-code --name {name}`. Otherwise choose another "
    "name with `vhir join --name`."
)


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
    # Trust X-Forwarded-For only from localhost (proxy on same machine)
    client_ip = request.client.host if request.client else "unknown"
    if client_ip in ("127.0.0.1", "::1"):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
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
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
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
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
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
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
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
    if name in gateway._hot:  # started by the loader: only its task starts it
        await gateway.reload_backend(name, gateway._hot[name])
        if not gateway.backends[name].started:
            return JSONResponse(
                {"error": f"Failed to start service {name}"}, status_code=500
            )
        return JSONResponse({"status": "started", "name": name})

    try:
        await asyncio.wait_for(in_own_task(backend.start()), timeout=30.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Start timed out for {name}"}, status_code=504)
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
        logger.error("Failed to start service %s: %s", name, e)
        return JSONResponse(
            {"error": f"Failed to start service {name}"}, status_code=500
        )

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
    if name in gateway._hot:  # started by the loader: only its task stops it
        await gateway.reload_backend(name, None)
    if not gateway.backends[name].started:
        await gateway._build_tool_map()
        return JSONResponse({"status": "stopped", "name": name})

    try:
        await asyncio.wait_for(in_own_task(backend.stop()), timeout=10.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Stop timed out for {name}"}, status_code=504)
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
        logger.error("Failed to stop service %s: %s", name, e)
        return JSONResponse(
            {"error": f"Failed to stop service {name}"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "stopped", "name": name})


async def restart_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/restart — stop + start a backend."""
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    # A join the loader gave up on, or a backend pasted into gateway.yaml by
    # hand: load it now, through the loader
    conf = gateway._unloaded.get(name)
    if conf is None and name not in gateway.backends:
        conf = _configured_backend(name)
    if conf is not None:
        gateway._single_attempt[name] = conf
        if not await _reloaded_in_time(gateway, name, conf):
            return JSONResponse(
                {"error": f"{name} is still loading; see /health"}, status_code=504
            )
        loaded = gateway.backends.get(name)
        if name not in gateway._unloaded and loaded is not None and loaded.started:
            return JSONResponse({"status": "restarted", "name": name})
        return JSONResponse({"error": gateway.not_loaded_text(name)}, status_code=500)

    if name not in gateway.backends:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends[name]
    if name in gateway._hot or isinstance(backend, HttpMCPBackend):
        # reloaded as a new backend, which reads its pinned cert again
        if name not in gateway._hot and backend.started:
            await asyncio.wait_for(in_own_task(backend.stop()), timeout=20.0)
        conf = gateway._hot.get(name, backend.config)
        if not await _reloaded_in_time(gateway, name, conf):
            return JSONResponse(
                {"error": f"{name} is still loading; see /health"}, status_code=504
            )
        if not gateway.backends[name].started:
            return JSONResponse(
                {"error": f"Failed to start service {name} during restart"},
                status_code=500,
            )
        return JSONResponse({"status": "restarted", "name": name})

    # Stop if running
    if backend.started:
        try:
            await asyncio.wait_for(in_own_task(backend.stop()), timeout=10.0)
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
            logger.error("Failed to stop service %s during restart: %s", name, e)
            return JSONResponse(
                {"error": f"Failed to stop service {name} during restart"},
                status_code=500,
            )

    # Start
    try:
        await asyncio.wait_for(in_own_task(backend.start()), timeout=30.0)
    except asyncio.TimeoutError:
        await gateway._build_tool_map()
        return JSONResponse({"error": f"Start timed out for {name}"}, status_code=504)
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
        logger.error("Failed to start service %s during restart: %s", name, e)
        await gateway._build_tool_map()
        return JSONResponse(
            {"error": f"Failed to start service {name} during restart"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "restarted", "name": name})


# ---------------------------------------------------------------------------
# Join code endpoints
# ---------------------------------------------------------------------------


async def create_join_code(request: Request) -> JSONResponse:
    """POST /api/v1/setup/join-code — generate a one-time join code.

    Only the gateway owner's key (the first api_keys entry, the one
    `vhir setup join-code` sends) may mint one. Single-user mode has no keys.
    """
    api_keys = getattr(request.app.state.gateway, "_api_keys", None) or {}
    token = request.headers.get("authorization", "")[7:].strip()
    if api_keys and not hmac.compare_digest(token, next(iter(api_keys))):
        return JSONResponse(
            {"error": "Only the gateway owner can create join codes"},
            status_code=403,
        )
    expires_hours = 2
    bound_name = None
    body = await request.body()
    if body:
        try:
            data = json.loads(body)
            expires_hours = data.get("expires_hours", 2)
            bound_name = data.get("name") if isinstance(data, dict) else None
        except json.JSONDecodeError:
            pass

    if bound_name is not None:
        # a bound code ends that name's earlier tokens: only with API keys,
        # never for the owner's own name (that token mints codes)
        if not api_keys:
            return JSONResponse(
                {"code": "NO_API_KEYS",
                 "error": "A join code bound to a name needs gateway API keys."},
                status_code=403,
            )  # fmt: skip
        if not valid_name(bound_name):
            return JSONResponse(
                {"error": f"Invalid examiner name: {bound_name!r} (lower-case letters, "
                          "digits and hyphens, at most 20 characters)"},
                status_code=400,
            )  # fmt: skip
        owner = (next(iter(api_keys.values())) or {}).get("examiner")
        if bound_name == owner:
            return JSONResponse(
                {"error": f"{bound_name} is the box owner's name; a join code can't take it."},
                status_code=400,
            )  # fmt: skip

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
    store_join_code(code, expires_hours=expires_hours, bound_name=bound_name)

    gateway = request.app.state.gateway
    gw_url = _get_gateway_url(gateway)
    parsed = urlparse(gw_url)
    host_port = f"{parsed.hostname}:{parsed.port}"

    out = {
        "code": code,
        "expires_hours": expires_hours,
        "instructions": f"vhir join --sift {host_port} --code {code}",
    }
    if bound_name is not None:
        out["name"] = bound_name
    return JSONResponse(out)


# How long a service restart waits on the loader: one start's budget, plus
# the tool map and a stop before it
_RESTART_WAIT = 15.0


async def _reloaded_in_time(gateway, name: str, conf: dict) -> bool:
    """Have the loader load ``conf`` now; False if it isn't done in time (it
    goes on, and /health shows the result)."""
    try:
        await asyncio.wait_for(
            asyncio.shield(gateway.reload_backend(name, conf)), _RESTART_WAIT
        )
    except asyncio.TimeoutError:
        return False
    return True


def _configured_backend(name: str) -> dict | None:
    """``name``'s enabled entry in gateway.yaml, or None."""
    from pathlib import Path

    from sift_gateway.config import load_config

    try:
        config = load_config(str(Path.home() / ".vhir" / "gateway.yaml"))
    except Exception:  # noqa: BLE001 - no usable file: nothing to load
        return None
    entry = (config.get("backends") or {}).get(name)
    if isinstance(entry, dict) and entry.get("enabled", True):
        return entry
    return None


async def revoke_join_codes(request: Request) -> JSONResponse:
    """DELETE /api/v1/setup/join-code — end every unused join code.

    Only the gateway owner's key may, as for creating one.
    """
    api_keys = getattr(request.app.state.gateway, "_api_keys", None) or {}
    token = request.headers.get("authorization", "")[7:].strip()
    if api_keys and not hmac.compare_digest(token, next(iter(api_keys))):
        return JSONResponse(
            {"error": "Only the gateway owner can revoke join codes"},
            status_code=403,
        )
    loop = asyncio.get_running_loop()
    async with _join_code_lock:
        revoked = await loop.run_in_executor(None, revoke_unused_join_codes)
    return JSONResponse({"revoked": revoked})


def _cert_text(cert) -> str | None:
    """The PEM text of a join's ``wintools_cert``, or None if it has none.

    It is a string (a UTF-8 BOM is dropped), or the object PowerShell 5.1
    makes of a string that carries note properties (``{"value": ...}``), or
    ``{"cert": ...}``.
    """
    if isinstance(cert, dict):
        cert = cert.get("value", cert.get("cert"))
    if not isinstance(cert, str):
        return None
    cert = cert.lstrip("\ufeff")
    if not cert.strip().startswith("-----BEGIN CERTIFICATE-----"):
        return None
    import ssl

    try:  # a certificate that can actually be pinned, not just its marker
        ssl.create_default_context(cadata=cert)
    except (ssl.SSLError, ValueError):
        return None
    return cert


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
    wintools_cert = body.get("wintools_cert")
    if machine_type == "wintools" and wintools_cert:
        # checked before the code is looked up, so a refusal leaves it usable
        wintools_cert = _cert_text(wintools_cert)
        if wintools_cert is None:
            return JSONResponse(
                {"error": "wintools_cert must be a PEM certificate"},
                status_code=400,
            )

    gateway = request.app.state.gateway
    raw_name = body.get("name") or hostname or machine_type
    loop = asyncio.get_running_loop()
    # Check the code and settle the name in one step, so a refused name
    # leaves the code usable (the bcrypt work runs off the event loop)
    async with _join_code_lock:
        found = await loop.run_in_executor(None, find_join_code, code)
        if not found:
            record_join_failure(client_ip)
            return JSONResponse(
                {"error": "Invalid or expired join code"},
                status_code=403,
            )
        bound = "bound_name" in found[1]
        if machine_type == "wintools":
            if bound:
                return JSONResponse(
                    {"error": "A join code bound to an examiner name can't join a wintools host."},
                    status_code=403,
                )  # fmt: skip
            examiner_name = hostname or machine_type
        elif bound:
            # the name comes from the read that checked the code, never again
            examiner_name = found[1]["bound_name"]
            if not valid_name(examiner_name):
                await loop.run_in_executor(None, mark_code_used, code)
                return JSONResponse(
                    {"error": "This join code names an invalid examiner name; ask the "
                              "box owner for a new code."},
                    status_code=403,
                )  # fmt: skip
        else:
            examiner_name = join_name(raw_name)
            if not valid_name(examiner_name):
                return JSONResponse(
                    {"error": f"{str(raw_name)[:64]!r} doesn't make an examiner name; choose "
                              "one with `vhir join --name NAME` (lower-case letters, digits "
                              "and hyphens, at most 20 characters)."},
                    status_code=400,
                )  # fmt: skip
            if _name_in_use(gateway, examiner_name):
                return JSONResponse(
                    {"code": "NAME_IN_USE", "error": NAME_IN_USE.format(name=examiner_name)},
                    status_code=409,
                )  # fmt: skip
        await loop.run_in_executor(None, mark_code_used, code)

    # Generate a bearer token only for non-wintools joins
    if machine_type != "wintools":
        new_token = generate_gateway_token()
        try:
            _add_api_key_to_config(
                gateway, new_token, examiner_name, replace=bound, refuse_held=not bound
            )
        except NameHeld:
            return JSONResponse(
                {"code": "NAME_IN_USE", "error": NAME_IN_USE.format(name=examiner_name)},
                status_code=409,
            )  # fmt: skip
    else:
        new_token = None

    # If wintools: add wintools backend to config and hot-load
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
        # Nothing is written yet: the backend serving now, its gateway.yaml
        # entry and its pinned cert stay as they are until this join loads
        # (the loader writes them then). A damaged gateway.yaml refuses it now.
        from pathlib import Path

        with _CONFIG_LOCK:
            _read_config_for_join(Path.home() / ".vhir" / "gateway.yaml")
        wintools_registered = True

        # Schedule background loading.  The backend loader retries until
        # wintools-mcp is online (Windows installer starts it after
        # receiving this join response).
        backend_config = {
            "type": "http",
            "url": wintools_url,
            "bearer_token": wintools_token,
            "enabled": True,
            "joined": True,
        }
        if wintools_cert:
            backend_config["tls_cert"] = str(_live_pin_path())
            backend_config["tls_cert_pem"] = wintools_cert
        gateway._pending_backends["wintools-mcp"] = backend_config
        gateway._reload_event.set()

    # Build response (after hot-load so backends list is current)
    backends = list(gateway.backends.keys())
    gw_url = _get_gateway_url(gateway)

    response = {
        "gateway_url": gw_url,
        "backends": backends,
        "examiner": examiner_name,
        "sift_examiner": os.environ.get("VHIR_EXAMINER", ""),
    }
    if new_token:
        response["gateway_token"] = new_token
        response["bound"] = bound
        response["enrol_command"] = f"vhir enrol --name {examiner_name}"

    if wintools_registered:
        response["wintools_registered"] = True
        samba_config = _load_samba_config()
        if samba_config:
            smb_host = _get_sift_ip()
            share_name = samba_config.get("share_name", "")
            smb_user = samba_config.get("smb_user", "")
            if smb_host and share_name and smb_user:
                response["smb_share"] = share_name
                response["smb_user"] = smb_user
                response["smb_host"] = smb_host

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
    fd, tmp_path = tempfile.mkstemp(dir=str(config_path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            # Owner's key first: local readers take the first api_key.
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
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


def _read_config_for_join(config_path) -> dict:
    """gateway.yaml as a mapping; {} when absent. Refuses a file it can't use."""
    import yaml

    if not os.path.lexists(config_path):  # a dangling link is refused below
        return {}
    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as e:
        config = e
    if not isinstance(config, dict):
        # The type only: a parsed value (a list, say) can hold the bearer tokens.
        logger.error(
            "Join refused: cannot use %s: %s", config_path, type(config).__name__
        )
        raise HTTPException(
            status_code=500,
            detail="Join refused: gateway.yaml could not be read or parsed. "
            "Fix the file, then create a new join code.",
        )
    return config


class NameHeld(Exception):
    """The examiner name is already held by a token or a credential."""


def _name_in_use(gateway, name: str) -> bool:
    from pathlib import Path

    tokens = getattr(gateway, "_api_keys", None) or {}
    if any((v or {}).get("examiner") == name for v in tokens.values()):
        return True
    return any((Path(d) / f"{name}.json").exists() for d in (_PASSWORDS_DIR, _KEYS_DIR))


def _add_api_key_to_config(
    gateway, token: str, examiner: str, replace: bool = False, refuse_held: bool = False
) -> None:
    """Add a new API key to the gateway config and write to disk. `replace`:
    a bound join, which first removes every earlier token of `examiner`.
    `refuse_held`: raise NameHeld if the name is taken meanwhile. The file
    and the running gateway change together, inside the config lock."""
    from pathlib import Path

    with _CONFIG_LOCK:
        if refuse_held and _name_in_use(gateway, examiner):
            raise NameHeld(examiner)
        config_path = Path.home() / ".vhir" / "gateway.yaml"
        config = _read_config_for_join(config_path)

        if not isinstance(config.get("api_keys"), dict):
            config["api_keys"] = {}
        earlier = (
            [t for t, v in config["api_keys"].items() if (v or {}).get("examiner") == examiner]
            if replace
            else []
        )  # fmt: skip
        for t in earlier:
            del config["api_keys"][t]

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

        # The in-memory gateway auth keys too (shared dict reference), in
        # the same span, so the file and the running gateway agree
        if hasattr(gateway, "_api_keys"):
            if replace:
                for t in [
                    t
                    for t, v in gateway._api_keys.items()
                    if (v or {}).get("examiner") == examiner
                ]:
                    del gateway._api_keys[t]
            gateway._api_keys[token] = {"examiner": examiner, "role": "examiner"}


def _live_pin_path():
    from pathlib import Path

    return Path.home() / ".vhir" / "tls" / "wintools-cert.pem"


def save_joined_backend(name: str, conf: dict) -> dict:
    """Write a join that has loaded: its pinned cert, then its gateway.yaml
    entry. Returns the entry as written."""
    from pathlib import Path

    entry = {k: v for k, v in conf.items() if k not in ("joined", "tls_cert_pem")}
    with _CONFIG_LOCK:
        config_path = Path.home() / ".vhir" / "gateway.yaml"
        config = _read_config_for_join(config_path)
        pem = conf.get("tls_cert_pem")
        pin = Path(entry["tls_cert"]) if pem else None
        old_pin = pin.read_bytes() if pin is not None and pin.is_file() else None
        if pem:
            pin.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=str(pin.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(pem)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(tmp, 0o600)
                os.replace(tmp, pin)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            logger.info("Stored wintools TLS cert at %s", pin)
        config.setdefault("backends", {})[name] = entry
        try:
            _atomic_yaml_write(config_path, config)
        except BaseException:
            # never the old entry with the new pin: put the old pin back
            if pin is not None and old_pin is not None:
                _atomic_write_bytes(pin, old_pin)
            raise
    return entry


def _atomic_write_bytes(path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _get_gateway_url(gateway) -> str:
    """Build the gateway URL from config."""
    gw_config = gateway.config.get("gateway", {})
    host = gw_config.get("host", "127.0.0.1")
    port = gw_config.get("port", 4508)
    tls = gw_config.get("tls", {})

    if host == "0.0.0.0":
        # UDP connect trick: queries routing table without sending packets
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                host = s.getsockname()[0]
        except OSError:
            host = "127.0.0.1"

    scheme = "https" if tls.get("certfile") else "http"
    return f"{scheme}://{host}:{port}"


def _load_samba_config() -> dict | None:
    """Read ~/.vhir/samba.yaml if it exists."""
    from pathlib import Path

    import yaml

    path = Path.home() / ".vhir" / "samba.yaml"
    if not path.is_file():
        return None
    try:
        return yaml.safe_load(path.read_text())
    except Exception:
        return None


def _get_sift_ip() -> str | None:
    """Read static IP from ~/.vhir/network.yaml, fall back to primary interface IP."""
    from pathlib import Path

    import yaml

    path = Path.home() / ".vhir" / "network.yaml"
    if path.is_file():
        try:
            doc = yaml.safe_load(path.read_text())
            ip = doc.get("static_ip")
            if ip:
                return ip
        except Exception:
            pass
    # Fall back to primary interface IP (same as hostname -I)
    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


async def reload_backends(request: Request) -> JSONResponse:
    """POST /api/v1/backends/reload — schedule loading of new backends.

    Re-reads gateway.yaml and starts any backends not yet loaded.
    Does not restart existing backends (safe for active sessions).
    """
    from pathlib import Path

    import yaml

    from sift_gateway.config import load_config

    gateway = request.app.state.gateway
    config_path = Path.home() / ".vhir" / "gateway.yaml"
    if not config_path.exists():
        return JSONResponse({"status": "no_config", "pending": []})
    try:
        config = load_config(str(config_path))
    except (ValueError, yaml.YAMLError, OSError):
        return JSONResponse({"error": "failed to read gateway.yaml"}, status_code=500)

    pending = []
    for name, conf in config.get("backends", {}).items():
        if not conf.get("enabled", True):
            continue
        existing = gateway.backends.get(name)
        if existing and existing.started:
            continue
        gateway._pending_backends[name] = conf
        pending.append(name)

    if pending:
        gateway._reload_event.set()
    return JSONResponse({"status": "reload_scheduled", "pending": pending})


def rest_routes() -> list[Route]:
    """Return REST API v1 routes."""
    return [
        Route("/api/v1/tools", list_tools, methods=["GET"]),
        Route("/api/v1/tools/{tool_name}", call_tool, methods=["POST"]),
        Route("/api/v1/backends", list_backends, methods=["GET"]),
        Route("/api/v1/backends/reload", reload_backends, methods=["POST"]),
        Route("/api/v1/services", list_services, methods=["GET"]),
        Route("/api/v1/services/{name}/start", start_service, methods=["POST"]),
        Route("/api/v1/services/{name}/stop", stop_service, methods=["POST"]),
        Route("/api/v1/services/{name}/restart", restart_service, methods=["POST"]),
        Route("/api/v1/setup/join-code", create_join_code, methods=["POST"]),
        Route("/api/v1/setup/join-code", revoke_join_codes, methods=["DELETE"]),
        Route("/api/v1/setup/join", join_gateway, methods=["POST"]),
        Route("/api/v1/setup/join-status", join_status, methods=["GET"]),
    ]
