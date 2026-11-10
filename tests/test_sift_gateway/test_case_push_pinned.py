"""The case push to a pinned backend verifies the backend's pinned certificate.

The gateway posts the backend's bearer token to ``/cases/activate`` at start,
on the 30 s re-sync and after a reconnect. That request must reach only a
server presenting the pinned certificate, as the MCP connection does.
"""

from __future__ import annotations

import datetime
import socket
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from sift_gateway.server import Gateway

from .wintools_rig import Remote, backend_entry, gateway_config, make_cert


class _Counting(Remote):
    """A Remote that counts every request reaching it, and the activations."""

    def __init__(self, label, cert):
        super().__init__(label, cert)
        self.requests: list[tuple[str, str]] = []

    def _app(self):
        inner = super()._app()

        async def app(scope, receive, send):
            if scope["type"] == "http":
                auth = dict(scope.get("headers") or []).get(b"authorization", b"")
                self.requests.append((scope["path"], auth.decode("latin-1")))
            await inner(scope, receive, send)

        return app

    def activations(self) -> list[str]:
        return [a for p, a in self.requests if p == "/cases/activate"]


@pytest.fixture
def certs(tmp_path):
    return {n: make_cert(tmp_path, n) for n in ("pinned", "other")}


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    (h / ".vhir").mkdir(parents=True)
    (h / ".vhir" / "active_case").write_text(str(h / "cases" / "case-one"))
    monkeypatch.setenv("HOME", str(h))
    return h


async def _push(remote: _Counting, pin: str | None) -> None:
    gw = Gateway(
        gateway_config({"wintools-mcp": backend_entry(remote, remote.token, pin)})
    )
    await gw._notify_backend_case(gw.backends["wintools-mcp"])


async def test_case_push_reaches_the_pinned_server(certs, home):
    remote = _Counting("a", certs["pinned"]).start()
    try:
        await _push(remote, certs["pinned"][0])
    finally:
        remote.stop()
    assert remote.activations() == [f"Bearer {remote.token}"]


@pytest.mark.parametrize("trust_other", [False, True], ids=["untrusted", "ca-trusted"])
async def test_case_push_never_reaches_a_server_with_another_cert(
    certs, home, monkeypatch, trust_other
):
    # ca-trusted: the other certificate is trusted by the system store, so only
    # the pin (not general verification) keeps the token from it.
    if trust_other:
        monkeypatch.setenv("SSL_CERT_FILE", certs["other"][0])
    remote = _Counting("b", certs["other"]).start()
    try:
        await _push(remote, certs["pinned"][0])
    finally:
        remote.stop()
    assert remote.requests == []


async def test_case_push_without_a_pin_verifies_against_the_system_store(certs, home):
    # No tls_cert, https URL: the push verifies as the MCP connection does
    # (system CAs), so a self-signed server the store doesn't trust gets nothing.
    remote = _Counting("c", certs["other"]).start()
    try:
        await _push(remote, None)
    finally:
        remote.stop()
    assert remote.requests == []


async def test_case_push_without_a_pin_reaches_a_server_the_store_trusts(
    certs, home, monkeypatch
):
    # No tls_cert, and the system store trusts the server's certificate.
    monkeypatch.setenv("SSL_CERT_FILE", certs["pinned"][0])
    remote = _Counting("s", certs["pinned"]).start()
    try:
        await _push(remote, None)
    finally:
        remote.stop()
    assert remote.activations() == [f"Bearer {remote.token}"]


def _expired_cert(folder: Path) -> tuple[str, str]:
    """A cert like make_cert's for 127.0.0.1, whose validity ended yesterday."""
    cert_path, key_path = make_cert(folder, "expired")
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), None)
    old = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(old.subject)
        .issuer_name(old.issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now - datetime.timedelta(days=1))
    )
    for ext in old.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    cert = builder.sign(key, hashes.SHA256())
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


@pytest.mark.parametrize("bad", ["another-name", "expired"])
async def test_case_push_never_reaches_a_pinned_cert_that_fails_verification(
    tmp_path, home, bad
):
    # The server presents the pinned certificate itself, so only the name and
    # expiry checks keep the token from it.
    if bad == "another-name":
        cert = make_cert(tmp_path, "elsewhere.example.invalid", ips=())
    else:
        cert = _expired_cert(tmp_path)
    remote = _Counting("v", cert).start()
    try:
        await _push(remote, cert[0])
    finally:
        remote.stop()
    assert remote.requests == []


async def test_the_pin_is_the_cert_read_when_the_backend_was_made(
    certs, home, tmp_path
):
    pin = tmp_path / "pin.pem"
    pin.write_text(Path(certs["pinned"][0]).read_text())
    remote = _Counting("p", certs["pinned"]).start()
    try:
        gw = Gateway(
            gateway_config(
                {"wintools-mcp": backend_entry(remote, remote.token, str(pin))}
            )
        )
        pin.write_text(Path(certs["other"][0]).read_text())  # the file changes after
        await gw._notify_backend_case(gw.backends["wintools-mcp"])
    finally:
        remote.stop()
    assert remote.activations() == [f"Bearer {remote.token}"]


class _Redirecting(_Counting):
    """A pinned server that answers the case push with a 307 to another server."""

    def __init__(self, label, cert, to: str):
        super().__init__(label, cert)
        self.to = to

    def _app(self):
        inner = super()._app()

        async def app(scope, receive, send):
            if scope["type"] == "http" and scope["path"] == "/cases/activate":
                auth = dict(scope.get("headers") or []).get(b"authorization", b"")
                self.requests.append((scope["path"], auth.decode("latin-1")))
                await send(
                    {
                        "type": "http.response.start",
                        "status": 307,
                        "headers": [(b"location", self.to.encode())],
                    }
                )
                await send({"type": "http.response.body", "body": b""})
                return
            await inner(scope, receive, send)

        return app


async def test_case_push_never_follows_a_redirect(certs, home):
    # Both servers present the pin: only the redirect flag stops the follow.
    target = _Counting("t", certs["pinned"]).start()
    to = target.url.removesuffix("/mcp") + "/cases/activate"
    remote = _Redirecting("r", certs["pinned"], to).start()
    try:
        await _push(remote, certs["pinned"][0])
    finally:
        remote.stop()
        target.stop()
    assert len(remote.activations()) == 1
    assert target.requests == []


class _RawListener:
    """A plain TCP listener (no TLS) that keeps every byte it is sent."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.chunks: list[bytes] = []
        self.conns = 0
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            self.conns += 1
            c.settimeout(0.5)
            deadline = time.monotonic() + 0.6
            try:
                while time.monotonic() < deadline:
                    b = c.recv(65536)
                    if not b:
                        break
                    self.chunks.append(b)
                    if b.startswith(b"\x16"):  # a TLS ClientHello: refuse it
                        break
            except OSError:
                pass
            c.close()

    def stop(self):
        self._stop = True
        self.thread.join(2)
        self.sock.close()


async def test_a_second_push_to_another_cert_is_refused(certs, home):
    # The 30 s re-sync after a first push that reached the pinned server.
    a = _Counting("a", certs["pinned"]).start()
    b = _Counting("b", certs["other"]).start()
    try:
        gw = Gateway(
            gateway_config(
                {"wintools-mcp": backend_entry(a, a.token, certs["pinned"][0])}
            )
        )
        backend = gw.backends["wintools-mcp"]
        await gw._notify_backend_case(backend)
        backend.config["url"] = b.url  # the next connection goes elsewhere
        await gw._notify_backend_case(backend)
    finally:
        a.stop()
        b.stop()
    assert a.activations() == [f"Bearer {a.token}"]
    assert b.requests == []


async def test_the_bearer_never_reaches_a_refusing_peer_in_clear(certs, home):
    raw = _RawListener()
    entry = {
        "type": "http",
        "url": f"https://127.0.0.1:{raw.port}/mcp",
        "bearer_token": "tok-raw-secret",
        "tls_cert": certs["pinned"][0],
        "enabled": True,
    }
    try:
        gw = Gateway(gateway_config({"wintools-mcp": entry}))
        await gw._notify_backend_case(gw.backends["wintools-mcp"])
    finally:
        raw.stop()
    assert raw.conns >= 1
    assert b"tok-raw-secret" not in b"".join(raw.chunks)


async def test_the_startup_push_to_any_https_backend_is_verified(certs, home):
    # The startup push goes to every started HTTP backend, not only wintools.
    remote = _Counting("o", certs["other"]).start()
    entry = {
        "type": "http",
        "url": remote.url,
        "bearer_token": remote.token,
        "enabled": True,
    }
    try:
        gw = Gateway(gateway_config({"other-mcp": entry}))
        await gw._notify_backend_case(gw.backends["other-mcp"])
    finally:
        remote.stop()
    assert remote.requests == []
