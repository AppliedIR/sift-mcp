"""A wintools link on loopback, for the rows in test_wintools_link.py.

The real gateway app (``Gateway(config).create_app()``) is served by uvicorn
with TLS in this process, so its PID is the test's own. The wintools remotes
are FastMCP streamable-HTTP servers with TLS, each with throwaway certs, and
each tool answers ``<tool>:<label>`` so a row knows which remote answered.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path

import httpx
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse
from starlette.routing import Route

OWNER = "vhir_gw_0123456789abcdef01234567"
EXAMINER = "vhir_gw_76543210fedcba9876543210"
ACCEPT = "application/json, text/event-stream"
WINTOOLS_TOOLS = ["get_share_info", "list_windows_tools"]
PER_BACKEND = "sift-gateway/wintools-mcp"


def make_cert(folder: Path, name: str, ips=("127.0.0.1",)) -> tuple[str, str]:
    """A self-signed cert and key for ``ips`` (its SAN), written to ``folder``."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    san = [x509.DNSName(name)] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    folder.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = folder / f"{name}.pem", folder / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class Logs(logging.Handler):
    """Every sift_gateway log record, from any thread."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)

    def lines(self, text: str = "", logger: str = "") -> list[str]:
        out = []
        for r in list(self.records):
            msg = r.getMessage()
            if text in msg and r.name.startswith(logger):
                out.append(msg)
        return out

    def task_errors(self) -> list[str]:
        return [
            m
            for m in self.lines()
            if "different task" in m or "Task group is not initialized" in m
        ]


def until(check, message: str, timeout: float = 30.0, every: float = 0.3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(every)
    raise AssertionError(message)


def _socket(port: int = 0) -> socket.socket:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    return s


class _Served:
    """An ASGI app served by uvicorn with TLS, in a thread of its own."""

    def __init__(self, app, sock: socket.socket, cert: tuple[str, str]):
        config = uvicorn.Config(
            app, log_level="warning", ssl_certfile=cert[0], ssl_keyfile=cert[1]
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [sock]}, daemon=True
        )
        self.thread.start()
        until(lambda: self.server.started, "server did not start", 20)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(15)


class _BearerOnly:
    """Refuse any request whose bearer token isn't ``token``."""

    def __init__(self, app, token: str):
        self.app, self.token = app, token

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            auth = dict(scope.get("headers") or []).get(b"authorization", b"")
            if auth.decode("latin-1") != f"Bearer {self.token}":
                await JSONResponse({"error": "bad token"}, 401)(scope, receive, send)
                return
        await self.app(scope, receive, send)


class Remote:
    """A stand-in wintools-mcp with TLS: its tools answer '<tool>:<label>'."""

    def __init__(self, label: str, cert: tuple[str, str], tools=WINTOOLS_TOOLS):
        self.label, self.cert, self.tools = label, cert, list(tools)
        self.token = f"tok-{label}"
        self.sock: socket.socket | None = _socket()
        self.port = self.sock.getsockname()[1]
        self.served: _Served | None = None

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}/mcp"

    @property
    def pem(self) -> str:
        return Path(self.cert[0]).read_text()

    def _answer(self, tool: str):
        def answer(x: str = "") -> str:
            return f"{tool}:{self.label}"

        return answer

    def _app(self):
        mcp = FastMCP("wintools-mcp")
        for tool in self.tools:
            mcp.add_tool(self._answer(tool), name=tool, structured_output=False)
        app = mcp.streamable_http_app()

        async def activate(request):
            return JSONResponse({"status": "activated"})

        app.router.routes.append(Route("/cases/activate", activate, methods=["POST"]))
        return _BearerOnly(app, self.token)

    def start(self) -> Remote:
        if self.sock is None:
            self.sock = _socket(self.port)
        self.served = _Served(self._app(), self.sock, self.cert)
        return self

    def stop(self) -> None:
        if self.served is not None:
            self.served.stop()
            self.served = None
            self.sock = None

    def restart(self) -> None:
        self.stop()
        time.sleep(0.3)
        self.start()


class Blackhole:
    """A TCP forwarder in front of a remote. ``hold()``: the host is gone,
    and nothing comes back on new or open connections. ``release()``: it's
    back, as after a reboot: held connections are reset."""

    def __init__(self, target_port: int):
        self.target = target_port
        self.sock = _socket()
        self.port = self.sock.getsockname()[1]
        self.held = False
        self.conns: list = []
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        asyncio.run_coroutine_threadsafe(self._serve(), self.loop).result(5)

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}/mcp"

    async def _serve(self):
        self.srv = await asyncio.start_server(self._client, sock=self.sock)

    async def _client(self, reader, writer):
        self.conns.append(writer)
        while self.held:
            await asyncio.sleep(0.1)
            if writer.is_closing():
                return
        try:
            up_r, up_w = await asyncio.open_connection("127.0.0.1", self.target)
        except OSError:
            writer.close()
            return
        self.conns.append(up_w)

        async def pump(src, dst):
            try:
                while data := await src.read(65536):
                    while self.held:
                        await asyncio.sleep(0.1)
                        if dst.is_closing():
                            return
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                dst.close()

        await asyncio.gather(pump(reader, up_w), pump(up_r, writer))

    def hold(self) -> None:
        self.held = True

    def release(self) -> None:
        def reset():
            for w in self.conns:
                try:
                    sock = w.get_extra_info("socket")
                    if sock is not None:  # RST, not FIN
                        sock.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, b"\x01" + b"\x00" * 7
                        )
                    w.close()
                except Exception:
                    pass
            self.conns.clear()
            self.held = False

        self.loop.call_soon_threadsafe(reset)
        time.sleep(0.3)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.srv.close)
        self.loop.call_soon_threadsafe(self.loop.stop)


def backend_entry(remote: Remote | Blackhole, token: str, cert: str) -> dict:
    url = remote.url
    return {
        "type": "http",
        "url": url,
        "bearer_token": token,
        "tls_cert": cert,
        "enabled": True,
    }


def gateway_config(backends: dict[str, dict]) -> dict:
    return {
        "gateway": {"host": "127.0.0.1", "port": 4508},
        "api_keys": {
            OWNER: {"examiner": "owner", "role": "lead"},
            EXAMINER: {"examiner": "second", "role": "examiner"},
        },
        "backends": backends,
    }


class GatewayServer:
    """The real gateway app with TLS on loopback, in this process."""

    def __init__(self, backends: dict[str, dict], cert: tuple[str, str]):
        from sift_gateway.server import Gateway

        self.gateway = Gateway(gateway_config(backends))
        app = self.gateway.create_app()
        sock = _socket()
        self.port = sock.getsockname()[1]
        self.cert = cert
        self.pid = os.getpid()
        self.served = _Served(app, sock, cert)

    @property
    def base(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def http(self, timeout: float = 30.0) -> httpx.Client:
        return httpx.Client(base_url=self.base, verify=self.cert[0], timeout=timeout)

    def health(self) -> dict:
        with self.http() as c:
            return c.get("/health").json()

    def post(self, path: str, key: str = OWNER, **kw) -> httpx.Response:
        with self.http() as c:
            return c.post(path, headers={"Authorization": f"Bearer {key}"}, **kw)

    def join_code(self) -> str:
        r = self.post("/api/v1/setup/join-code", json={"expires_hours": 2})
        assert r.status_code == 200, r.text
        return r.json()["code"]

    def join(self, remote: Remote | Blackhole, token: str, cert, code=None):
        """POST /api/v1/setup/join as the Windows installer does."""
        body = {
            "code": code or self.join_code(),
            "machine_type": "wintools",
            "hostname": "wks",
            "wintools_url": remote.url,
            "wintools_token": token,
        }
        if cert is not None:
            body["wintools_cert"] = cert
        with self.http() as c:
            return c.post("/api/v1/setup/join", json=body)

    def stop(self) -> None:
        self.served.stop()


def _data(resp: httpx.Response) -> dict:
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    return resp.json()


class McpClient:
    """A streamable-HTTP MCP client session to one gateway path, over TLS."""

    def __init__(self, gw: GatewayServer, path: str):
        self.gw, self.path = gw, path
        self.headers = {"Authorization": f"Bearer {OWNER}", "Accept": ACCEPT}
        self.server_name = ""
        self.statuses: list[int] = []
        self._id = 0

    def _post(self, body: dict, timeout: float = 30.0) -> httpx.Response:
        with self.gw.http(timeout) as c:
            r = c.post(self.path, json=body, headers=self.headers)
        self.statuses.append(r.status_code)
        return r

    def _try_post(self, body: dict, timeout: float):
        try:
            return self._post(body, timeout)
        except httpx.HTTPError as e:
            return e

    def initialize(self) -> McpClient:
        r = self._post(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "row", "version": "0"},
                },
            }
        )
        assert r.status_code == 200, (r.status_code, r.text[:300])
        self.headers["mcp-session-id"] = r.headers["mcp-session-id"]
        self.server_name = _data(r)["result"]["serverInfo"]["name"]
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    def tools(self) -> list[str] | str:
        """The sorted tool names, or the error text."""
        self._id += 1
        r = self._post({"jsonrpc": "2.0", "id": self._id, "method": "tools/list"})
        if r.status_code != 200:
            return f"HTTP {r.status_code}"
        d = _data(r)
        if "error" in d:
            return f"error: {d['error'].get('message')}"
        return sorted(t["name"] for t in d["result"]["tools"])

    def call(self, tool: str, timeout: float = 30.0) -> dict:
        """``{"http", "is_error", "text", "secs"}`` of one tools/call."""
        self._id += 1
        t0 = time.monotonic()
        body = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": {"x": "1"}},
        }
        # A total deadline: an open event stream keeps each read alive
        done: list = []
        worker = threading.Thread(
            target=lambda: done.append(self._try_post(body, timeout)), daemon=True
        )
        worker.start()
        worker.join(timeout)
        r = done[0] if done else None
        if not isinstance(r, httpx.Response):
            return {
                "http": None,
                "is_error": None,
                "text": "no answer",
                "secs": timeout,
            }
        out = {"http": r.status_code, "secs": round(time.monotonic() - t0, 1)}
        if r.status_code != 200:
            return {**out, "is_error": None, "text": r.text[:300]}
        result = _data(r).get("result", {})
        text = ((result.get("content") or [{}])[0]).get("text", "")
        return {**out, "is_error": bool(result.get("isError")), "text": text}


def per_backend(gw: GatewayServer) -> McpClient:
    return McpClient(gw, "/mcp/wintools-mcp").initialize()


def aggregate(gw: GatewayServer) -> McpClient:
    return McpClient(gw, "/mcp/").initialize()


def answers(gw: GatewayServer, label: str, timeout: float = 30.0) -> McpClient:
    """Wait until a fresh per-backend session lists exactly wintools' tools and
    a call is answered by remote ``label``; return that session."""

    def check():
        c = per_backend(gw)
        if c.server_name != PER_BACKEND or c.tools() != WINTOOLS_TOOLS:
            return None
        r = c.call("get_share_info")
        return c if r["text"] == f"get_share_info:{label}" else None

    return until(check, f"/mcp/wintools-mcp never answered from {label}", timeout, 0.5)
