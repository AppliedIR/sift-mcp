"""The wintools link, end to end on loopback, with TLS and no restart.

Each row serves the real gateway app with TLS in this process and joins
wintools stand-ins through the real join endpoints. Every row checks the
per-backend endpoint Claude Code uses (``/mcp/wintools-mcp``) by its server
name and its exact tools, so the aggregate endpoint can't answer for it, and
ends with the gateway's PID unchanged, no ``sudo``/``systemctl`` run, and no
transport closed from a task that didn't open it.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import pytest
import yaml
from sift_gateway import join as join_mod
from sift_gateway import mcp_endpoint
from sift_gateway import server as server_mod

from .wintools_rig import (
    EXAMINER,
    OWNER,
    PER_BACKEND,
    WINTOOLS_TOOLS,
    Blackhole,
    GatewayServer,
    Logs,
    Remote,
    SilentRemote,
    aggregate,
    answers,
    backend_entry,
    gateway_config,
    make_cert,
    per_backend,
    until,
)

pytestmark = pytest.mark.timeout(180)

STUB = """#!/bin/sh
echo "$0 $*" >> "{log}"
exit 1
"""


class Link:
    """One row's isolated HOME, certs, stand-ins and gateway."""

    def __init__(self, home: Path, logs: Logs):
        self.home, self.logs = home, logs
        self.vhir = home / ".vhir"
        self.config = self.vhir / "gateway.yaml"
        self.certs = home / "certs"
        self.stub_log = home / "stub-calls.log"
        self.gateway_cert = make_cert(self.certs, "gateway")
        self._remotes: list[Remote] = []
        self._holes: list[Blackhole] = []
        self._gateways: list[GatewayServer] = []

    def remote(
        self, label: str, ips=("127.0.0.1",), start=True, tools=WINTOOLS_TOOLS
    ) -> Remote:
        r = Remote(label, make_cert(self.certs, f"wintools-{label}", ips), tools)
        self._remotes.append(r)
        return r.start() if start else r

    def blackhole(self, remote: Remote) -> Blackhole:
        hole = Blackhole(remote.port)
        self._holes.append(hole)
        return hole

    def boot(self, **backends: dict) -> GatewayServer:
        gw = GatewayServer(
            {k.replace("_", "-"): v for k, v in backends.items()}, self.gateway_cert
        )
        self._gateways.append(gw)
        return gw

    def live(self, remote: Remote) -> dict:
        """Make ``remote`` the live wintools join on disk: its entry in
        gateway.yaml and its cert as the pin, as a join that loaded leaves
        them. Returns the files' bytes."""
        cert = self.vhir / "tls" / "wintools-cert.pem"
        cert.parent.mkdir(parents=True, exist_ok=True)
        cert.write_text(remote.pem)
        entry = backend_entry(remote, remote.token, str(cert))
        self.config.write_text(yaml.safe_dump(gateway_config({"wintools-mcp": entry})))
        return self.live_files()

    def live_files(self) -> dict:
        cert = self.vhir / "tls" / "wintools-cert.pem"
        return {"gateway.yaml": self.config.read_bytes(), "pin": cert.read_bytes()}

    def start_from_files(self) -> GatewayServer:
        """A gateway start: it reads gateway.yaml as the service does."""
        from sift_gateway.config import load_config

        config = load_config(str(self.config))
        return self.boot(
            **{k.replace("-", "_"): v for k, v in config["backends"].items()}
        )

    def other(self) -> dict:
        """A second backend, so the aggregate has a tool wintools doesn't."""
        r = self.remote("other", tools=["other_echo"])
        return backend_entry(r, r.token, r.cert[0])

    def untouched(self, gw: GatewayServer) -> None:
        """Nothing restarted: same PID, no sudo or systemctl, and every
        transport closed in the task that opened it."""
        assert os.getpid() == gw.pid
        calls = self.stub_log.read_text() if self.stub_log.exists() else ""
        assert calls == "", calls
        assert self.logs.task_errors() == []

    def close(self) -> None:
        for gw in self._gateways:
            gw.stop()
        for r in self._remotes:
            r.stop()
        for hole in self._holes:
            hole.close()


@pytest.fixture
def link(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    assert Path.home() == home
    monkeypatch.setattr(join_mod, "_STATE_DIR", home / ".vhir")
    monkeypatch.setattr(join_mod, "_STATE_FILE", home / ".vhir" / ".join_state.json")
    monkeypatch.setattr(mcp_endpoint, "check_rate_limit", lambda ip: True)
    monkeypatch.setattr(server_mod, "_LOAD_RETRY_SECONDS", 0.5)
    # a restart anywhere would reach these first
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name in ("sudo", "systemctl"):
        (stubs / name).write_text(STUB.format(log=home / "stub-calls.log"))
        (stubs / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{stubs}:{os.environ.get('PATH', '')}")

    logs = Logs()
    gw_logger = logging.getLogger("sift_gateway")
    gw_logger.addHandler(logs)
    level = gw_logger.level
    gw_logger.setLevel(logging.DEBUG)
    rows = Link(home, logs)
    try:
        yield rows
    finally:
        rows.close()
        gw_logger.removeHandler(logs)
        gw_logger.setLevel(level)


def test_a_first_join_is_served_by_its_own_endpoint_with_exactly_its_tools(link):
    gw = link.boot(other_mcp=link.other())
    # before any join, the endpoint exists and says wintools isn't joined
    before = per_backend(gw)
    assert before.server_name == PER_BACKEND
    r = before.call("get_share_info")
    assert r["is_error"] is True and "wintools-mcp" in r["text"], r

    a = link.remote("A")
    resp = gw.join(a, a.token, a.pem)
    assert resp.status_code == 200, resp.text
    c = answers(gw, "A")
    assert c.server_name == PER_BACKEND
    assert c.tools() == WINTOOLS_TOOLS  # not the aggregate's other_echo
    assert c.call("list_windows_tools")["text"] == "list_windows_tools:A"
    # the session opened before the join now reaches it too
    assert before.call("get_share_info")["text"] == "get_share_info:A"
    link.untouched(gw)


def test_a_rejoin_with_a_new_url_token_and_cert_reaches_the_new_remote_everywhere(
    link,
):
    a = link.remote("A")
    gw = link.boot(
        other_mcp=link.other(), wintools_mcp=backend_entry(a, a.token, a.cert[0])
    )
    early = answers(gw, "A")
    b = link.remote("B")
    resp = gw.join(b, b.token, b.pem)
    assert resp.status_code == 200, resp.text

    fresh = answers(gw, "B")
    assert fresh.server_name == PER_BACKEND and fresh.tools() == WINTOOLS_TOOLS
    assert early.call("get_share_info")["text"] == "get_share_info:B"
    assert aggregate(gw).call("get_share_info")["text"] == "get_share_info:B"
    conf = yaml.safe_load((link.home / ".vhir" / "gateway.yaml").read_text())
    entry = conf["backends"]["wintools-mcp"]
    assert (entry["url"], entry["bearer_token"]) == (b.url, b.token)
    assert Path(entry["tls_cert"]).read_text() == b.pem
    assert 404 not in early.statuses + fresh.statuses
    link.untouched(gw)


@pytest.mark.parametrize(
    "form",
    ["string", "bom", "powershell-object", "cert-object"],
)
def test_each_form_of_the_join_cert_is_stored_as_pem(link, form):
    a = link.remote("A")
    gw = link.boot()
    sent = {
        "string": a.pem,
        "bom": "\ufeff" + a.pem,
        "powershell-object": {"value": a.pem, "PSPath": "C:\\vhir\\tls\\cert.pem"},
        "cert-object": {"cert": a.pem},
    }[form]
    resp = gw.join(a, a.token, sent)
    assert resp.status_code == 200, resp.text
    c = answers(gw, "A")
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    stored = link.home / ".vhir" / "tls" / "wintools-cert.pem"
    assert stored.read_text() == a.pem  # written once the join loaded
    link.untouched(gw)


GARBLED = "-----BEGIN CERTIFICATE-----\nMIIBnotacert\n-----END CERTIFICATE-----\n"


@pytest.mark.parametrize("bad", [5, ["x"], "not a certificate", {"value": 5}, GARBLED])
def test_a_join_cert_that_is_not_pem_is_refused_and_the_code_stays_usable(link, bad):
    a = link.remote("A")
    gw = link.boot()
    code = gw.join_code()
    resp = gw.join(a, a.token, bad, code=code)
    assert resp.status_code == 400, resp.text
    assert "wintools_cert" in resp.json()["error"]
    assert not (link.home / ".vhir" / "gateway.yaml").exists()
    resp = gw.join(a, a.token, a.pem, code=code)  # the same code
    assert resp.status_code == 200, resp.text
    c = answers(gw, "A")
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    link.untouched(gw)


def test_a_remote_whose_cert_lacks_its_address_is_named_in_health_and_the_log(link):
    gw = link.boot(other_mcp=link.other())
    wrong = link.remote("wrong", ips=("10.9.9.9",))  # served on 127.0.0.1
    resp = gw.join(wrong, wrong.token, wrong.pem)
    assert resp.status_code == 200, resp.text

    def named():
        h = gw.health()
        wt = h["backends"].get("wintools-mcp", {})
        return (
            wt.get("status") == "error"
            and "CERTIFICATE_VERIFY_FAILED" in wt.get("error", "")
            and h
        )

    h = until(named, "health never named the TLS failure", 20)
    assert h["status"] == "degraded"
    assert "joined but not loaded" in h["backends"]["wintools-mcp"]["error"]
    assert h["tools_count"] == 1  # other_echo only
    # the gateway's own start failure carries the TLS error, not a cancel
    started = link.logs.lines("failed to start", "sift_gateway.backends.http_backend")
    assert started and all("CERTIFICATE_VERIFY_FAILED" in m for m in started), started
    assert not link.logs.lines("check bearer_token")
    c = per_backend(gw)
    r = c.call("get_share_info")
    assert r["is_error"] is True and "joined but not loaded" in r["text"], r
    link.untouched(gw)


def test_an_unreachable_remote_is_named_fast_and_the_first_call_after_it_works(link):
    a = link.remote("A")
    hole = link.blackhole(a)
    gw = link.boot(wintools_mcp=backend_entry(hole, a.token, a.cert[0]))
    session = answers(gw, "A")
    agg = aggregate(gw)
    assert agg.call("get_share_info")["text"] == "get_share_info:A"

    hole.hold()
    t0 = time.monotonic()

    def down():
        wt = gw.health()["backends"]["wintools-mcp"]
        return wt["status"] != "ok" and wt

    wt = until(down, "health still says ok", 15, 0.5)
    assert time.monotonic() - t0 <= 15
    assert "unreachable" in wt["error"] and "tools" not in wt, wt
    r = session.call("get_share_info", timeout=20)
    assert r["is_error"] is True, r
    assert r["secs"] <= 10, r
    assert "wintools-mcp" in r["text"] and "unreachable" in r["text"], r
    r = agg.call("get_share_info", timeout=20)
    assert r["is_error"] is True and r["secs"] <= 10, r

    hole.release()
    r = session.call("get_share_info")
    assert (r["is_error"], r["text"]) == (False, "get_share_info:A"), r
    assert session.tools() == WINTOOLS_TOOLS
    until(lambda: gw.health()["backends"]["wintools-mcp"]["status"] == "ok", "not ok")
    assert 404 not in session.statuses
    link.untouched(gw)


def _three_calls_after_a_restart(link, gw, remote, session):
    remote.restart()
    results = [session.call("get_share_info") for _ in range(3)]
    for r in results:
        assert (r["http"], r["is_error"], r["text"]) == (
            200,
            False,
            "get_share_info:A",
        ), results
    assert session.server_name == PER_BACKEND
    assert session.tools() == WINTOOLS_TOOLS
    assert len(link.logs.lines("reconnecting")) <= 1, link.logs.lines("reconnecting")
    assert 404 not in session.statuses
    link.untouched(gw)


def test_calls_after_a_remote_restart_reconnect_at_most_once(link):
    a = link.remote("A")
    gw = link.boot(wintools_mcp=backend_entry(a, a.token, a.cert[0]))
    _three_calls_after_a_restart(link, gw, a, answers(gw, "A"))


def test_a_joined_backend_reconnects_at_most_once_after_its_remote_restarts(link):
    gw = link.boot()
    a = link.remote("A")
    assert gw.join(a, a.token, a.pem).status_code == 200
    _three_calls_after_a_restart(link, gw, a, answers(gw, "A"))


def test_a_session_the_remote_ended_heals_with_no_tool_call(link, monkeypatch):
    """A wintools restart (or a guest revert) ends the session: the checker
    reconnects it, so /health reads ok again with no tool call."""
    monkeypatch.setattr(server_mod, "_LATE_START_SECONDS", 1, raising=False)
    a = link.remote("A")
    gw = link.boot(wintools_mcp=backend_entry(a, a.token, a.cert[0]))
    answers(gw, "A")
    a.restart()
    until(
        lambda: (
            link.logs.lines("reconnecting")
            and gw.health()["backends"]["wintools-mcp"]["status"] == "ok"
        ),
        "health never recovered with no tool call",
    )
    for _ in range(3):
        assert gw.health()["backends"]["wintools-mcp"]["status"] == "ok"
    assert len(link.logs.lines("reconnecting")) == 1, link.logs.lines("reconnecting")
    assert link.logs.lines("Tool map rebuilt after wintools-mcp reconnected")
    link.untouched(gw)


@pytest.mark.parametrize("route", [per_backend, aggregate], ids=["direct", "aggregate"])
def test_a_lone_surrogate_argument_is_refused_by_name_within_1s(
    link, monkeypatch, route
):
    """It used to wait out the 300 s call timeout: the transport couldn't
    encode it and failed in its writer task. The refusal is audited, and the
    same session goes on working."""
    from sift_common.audit import AuditWriter

    entries = []
    log = AuditWriter.log

    def recording(self, **kw):
        entries.append(kw)
        return log(self, **kw)

    monkeypatch.setattr(AuditWriter, "log", recording)
    a = link.remote("A")
    gw = link.boot(wintools_mcp=backend_entry(a, a.token, a.cert[0]))
    answers(gw, "A")
    session = route(gw)
    entries.clear()
    r = session.call("get_share_info", timeout=10, arguments={"x": "\ud800"})
    assert (r["http"], r["is_error"]) == (200, True), r
    assert r["secs"] <= 1, r
    assert (
        "get_share_info wasn't sent: its argument 'x' holds a lone surrogate"
        in r["text"]
    ), r
    refused = [e for e in entries if e.get("source") == "gateway_proxy"]
    assert len(refused) == 1, entries
    assert refused[0]["tool"] == "get_share_info"
    assert refused[0]["result_summary"].startswith("refused, not sent: "), refused
    assert refused[0]["extra"]["backend"] == "wintools-mcp"

    # a pair (an emoji) is sendable text, on the same session
    r = session.call("get_share_info", arguments={"x": "é 😀"})
    assert (r["http"], r["is_error"], r["text"]) == (200, False, "get_share_info:A"), r
    link.untouched(gw)


def test_a_refused_token_is_named_with_its_fix_in_health_and_on_every_route(link):
    """It showed as "unreachable: HTTPStatusError: Client error '401
    Unauthorized'" with a developer.mozilla.org link on /health, and as
    "Tool not found" on a call (dev3's C5)."""
    a = link.remote("A")
    gw = link.boot(wintools_mcp=backend_entry(a, "tok-wrong", a.cert[0]))
    named = "wintools-mcp rejected the gateway's token (401 Unauthorized)"
    fix = "`vhir setup join-code` on this box"

    def refused():
        wt = gw.health()["backends"].get("wintools-mcp", {})
        return named in wt.get("error", "") and wt

    wt = until(refused, "health never named the refused token", 20)
    assert wt["status"] == "error" and fix in wt["error"], wt
    assert "unreachable" not in wt["error"] and "mozilla" not in wt["error"], wt

    # a wintools tool, or a typo: both facts, so the reply is true either way
    for tool in ("get_share_info", "no_such_tool"):
        both = f"Tool {tool} was not found. {named}"
        listed = "Until that's fixed, wintools-mcp's tools can't be listed."
        r = gw.post(f"/api/v1/tools/{tool}", json={"arguments": {}})
        assert r.status_code == 404, r.text
        err = r.json()["error"]
        assert err.startswith(both) and fix in err and err.endswith(listed), err
        c = aggregate(gw).call(tool, timeout=20)
        assert c["is_error"] is True and c["text"].startswith(f"Error: {both}"), c
        assert c["text"].endswith(listed), c
    c = per_backend(gw).call("get_share_info", timeout=20)
    assert c["is_error"] is True and named in c["text"] and fix in c["text"], c

    # fixed (a join with the right token): plain "not found" again
    assert gw.join(a, a.token, a.pem).status_code == 200
    answers(gw, "A")
    r = gw.post("/api/v1/tools/no_such_tool", json={"arguments": {}})
    assert (r.status_code, r.json()) == (404, {"error": "Tool not found: no_such_tool"})
    c = aggregate(gw).call("no_such_tool")
    assert c["text"] == "Error: unknown tool no_such_tool", c
    link.untouched(gw)


def test_an_unknown_tool_is_still_not_found_when_no_token_was_refused(link):
    a = link.remote("A")
    gw = link.boot(wintools_mcp=backend_entry(a, a.token, a.cert[0]))
    answers(gw, "A")
    r = gw.post("/api/v1/tools/no_such_tool", json={"arguments": {}})
    assert (r.status_code, r.json()) == (404, {"error": "Tool not found: no_such_tool"})
    c = aggregate(gw).call("no_such_tool")
    assert c["text"] == "Error: unknown tool no_such_tool", c
    link.untouched(gw)


@pytest.mark.parametrize("route", [per_backend, aggregate], ids=["direct", "aggregate"])
def test_polls_of_a_run_get_no_gateway_audit_entry_and_other_calls_do(
    link, monkeypatch, route
):
    """wintools audits a run once; get_windows_run polls are status lookups."""
    from sift_common.audit import AuditWriter

    entries = []
    log = AuditWriter.log

    def recording(self, **kw):
        entries.append(kw)
        return log(self, **kw)

    monkeypatch.setattr(AuditWriter, "log", recording)
    a = link.remote("A", tools=[*WINTOOLS_TOOLS, "get_windows_run"])
    gw = link.boot(wintools_mcp=backend_entry(a, a.token, a.cert[0]))
    session = until(
        lambda: (
            (c := route(gw)).call("get_windows_run")["text"] == "get_windows_run:A"
            and c
        ),
        "the poll tool never answered",
    )
    entries.clear()
    for _ in range(5):
        r = session.call("get_windows_run", arguments={"run_id": "r1"})
        assert (r["is_error"], r["text"]) == (False, "get_windows_run:A"), r
    proxied = [e for e in entries if e.get("source") == "gateway_proxy"]
    assert proxied == [], proxied

    r = session.call("get_share_info")
    assert r["text"] == "get_share_info:A", r
    proxied = [e["tool"] for e in entries if e.get("source") == "gateway_proxy"]
    assert proxied == ["get_share_info"], entries
    link.untouched(gw)


def _gave_up(link) -> bool:
    return bool(link.logs.lines("Could not load wintools-mcp"))


def test_a_remote_that_comes_up_after_the_load_window_loads_without_a_restart(
    link, monkeypatch
):
    monkeypatch.setattr(server_mod, "_LATE_START_SECONDS", 2, raising=False)
    gw = link.boot()
    a = link.remote("A", start=False)
    assert gw.join(a, a.token, a.pem).status_code == 200
    until(lambda: _gave_up(link), "the loader never gave up", 20)
    wt = gw.health()["backends"]["wintools-mcp"]
    assert wt["status"] == "error" and "joined but not loaded" in wt["error"], wt

    a.start()
    c = answers(gw, "A", timeout=40)
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    assert gw.health()["backends"]["wintools-mcp"]["status"] == "ok"
    link.untouched(gw)


def test_the_printed_remedy_loads_a_join_the_loader_gave_up_on(link):
    gw = link.boot()
    a = link.remote("A", start=False)
    assert gw.join(a, a.token, a.pem).status_code == 200
    until(lambda: _gave_up(link), "the loader never gave up", 20)
    gave_up = link.logs.lines("Could not load wintools-mcp")
    assert all("restart gateway" not in m for m in gave_up), gave_up
    assert any("vhir service restart wintools-mcp" in m for m in gave_up), gave_up

    a.start()
    r = gw.post("/api/v1/services/wintools-mcp/restart")
    assert r.status_code == 200, r.text
    c = per_backend(gw)  # at once, not after a retry
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    assert c.call("get_share_info")["text"] == "get_share_info:A"
    link.untouched(gw)


def test_the_printed_remedy_loads_a_backend_pasted_into_gateway_yaml(link):
    gw = link.boot()
    a = link.remote("A")
    pasted = {"backends": {"wintools-mcp": backend_entry(a, a.token, a.cert[0])}}
    (link.home / ".vhir" / "gateway.yaml").write_text(yaml.safe_dump(pasted))

    r = gw.post("/api/v1/services/wintools-mcp/restart")
    assert r.status_code == 200, r.text
    c = per_backend(gw)
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    assert c.call("get_share_info")["text"] == "get_share_info:A"
    assert aggregate(gw).call("list_windows_tools")["text"] == "list_windows_tools:A"
    link.untouched(gw)


def test_the_owner_can_revoke_every_unused_join_code(link):
    gw = link.boot()
    a = link.remote("A")
    first, second = gw.join_code(), gw.join_code()
    used = gw.join_code()
    assert gw.join(a, a.token, a.pem, code=used).status_code == 200

    def revoke(key):
        with gw.http() as c:
            return c.delete(
                "/api/v1/setup/join-code", headers={"Authorization": f"Bearer {key}"}
            )

    r = revoke(EXAMINER)
    assert r.status_code == 403, r.text
    r = revoke(EXAMINER.replace("7", "8"))  # not a key at all
    assert r.status_code in (401, 403), r.text
    r = revoke(OWNER)
    assert (r.status_code, r.json()) == (200, {"revoked": 2}), r.text
    for code in (first, second):
        resp = gw.join(a, a.token, a.pem, code=code)
        assert resp.status_code == 403, resp.text
    assert gw.join(a, a.token, a.pem).status_code == 200  # a new code works
    link.untouched(gw)


def test_a_rejoin_that_fails_after_the_old_remote_went_away_drops_its_tools(link):
    gw = link.boot(other_mcp=link.other())
    a = link.remote("A")
    assert gw.join(a, a.token, a.pem).status_code == 200
    answers(gw, "A")
    assert gw.health()["tools_count"] == 3

    a.stop()  # the host moved: its old address is gone
    wrong = link.remote("wrong", ips=("10.9.9.9",))
    assert gw.join(wrong, wrong.token, wrong.pem).status_code == 200
    until(lambda: _gave_up(link), "the loader never gave up", 30)
    h = gw.health()
    assert h["status"] == "degraded"
    wt = h["backends"]["wintools-mcp"]
    assert "CERTIFICATE_VERIFY_FAILED" in wt["error"], wt
    assert "serving_previous" not in wt
    assert h["tools_count"] == 1  # other_echo only, none of the old remote's
    link.untouched(gw)


def _wait_for_retries(link, session, label: str, retries: int = 3) -> None:
    """Calls on ``session`` answer from ``label`` through ``retries`` more of
    the checker's retries of a staged join."""
    start = len(link.logs.lines("attempt 1/1"))
    deadline = time.monotonic() + 30
    while len(link.logs.lines("attempt 1/1")) < start + retries:
        r = session.call("get_share_info")
        assert (r["is_error"], r["text"]) == (False, f"get_share_info:{label}"), r
        assert time.monotonic() < deadline, "the checker never retried"
        time.sleep(0.2)


def _failed_rejoin(link, monkeypatch):
    """A serving, as gateway.yaml and its pin left it; a re-join to a host
    whose cert lacks its address. Returns the gateway, the session, and the
    files before."""
    monkeypatch.setattr(server_mod, "_LATE_START_SECONDS", 1, raising=False)
    a = link.remote("A")
    before = link.live(a)
    gw = link.start_from_files()
    session = answers(gw, "A")
    wrong = link.remote("wrong", ips=("10.9.9.9",))
    assert gw.join(wrong, wrong.token, wrong.pem).status_code == 200
    until(lambda: _gave_up(link), "the loader never gave up", 30)
    return gw, session, before


def test_a_failed_tls_rejoin_keeps_serving_the_previous_remote_and_its_files(
    link, monkeypatch
):
    gw, session, before = _failed_rejoin(link, monkeypatch)
    wt = gw.health()["backends"]["wintools-mcp"]
    assert wt["status"] == "error" and wt.get("serving_previous") is True, wt
    assert "CERTIFICATE_VERIFY_FAILED" in wt["error"], wt
    assert "new join code" in wt["error"], wt
    _wait_for_retries(link, session, "A")  # retried without dropping A
    assert session.tools() == WINTOOLS_TOOLS
    assert not link.logs.lines("Backend wintools-mcp stopped")
    assert answers(gw, "A").server_name == PER_BACKEND
    assert link.live_files() == before
    gw.stop()
    assert answers(link.start_from_files(), "A")  # what a later start serves
    link.untouched(gw)


@pytest.mark.parametrize("a_alive", [True, False], ids=["A-serving", "A-gone"])
def test_a_join_is_written_to_disk_only_once_it_loads(link, monkeypatch, a_alive):
    monkeypatch.setattr(server_mod, "_LATE_START_SECONDS", 1, raising=False)
    a = link.remote("A")
    before = link.live(a)
    gw = link.start_from_files()
    answers(gw, "A")
    if not a_alive:
        a.stop()  # the host moved: its old address is gone
    b = link.remote("B", start=False)
    assert gw.join(b, b.token, b.pem).status_code == 200
    until(lambda: _gave_up(link), "the loader never gave up", 30)
    assert link.live_files() == before
    if a_alive:
        assert answers(gw, "A").call("get_share_info")["text"] == "get_share_info:A"

    b.start()  # comes up later: the checker loads it, with no restart
    c = answers(gw, "B", timeout=40)
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    conf = yaml.safe_load(link.config.read_text())["backends"]["wintools-mcp"]
    assert (conf["url"], conf["bearer_token"]) == (b.url, b.token)
    assert set(conf) == {"type", "url", "bearer_token", "enabled", "tls_cert"}
    assert Path(conf["tls_cert"]).read_text() == b.pem
    assert gw.health()["backends"]["wintools-mcp"]["status"] == "ok"
    gw.stop()
    assert answers(link.start_from_files(), "B")  # what a later start serves
    link.untouched(gw)


def test_an_unreadable_pin_keeps_the_backend_and_names_the_file(link):
    a = link.remote("A")
    missing = link.vhir / "tls" / "gone.pem"
    gw = link.boot(wintools_mcp=backend_entry(a, a.token, str(missing)))
    c = per_backend(gw)
    assert c.server_name == PER_BACKEND
    r = c.call("get_share_info")
    assert r["is_error"] is True, r
    assert f"pinned certificate unreadable: {missing}" in r["text"], r
    wt = gw.health()["backends"]["wintools-mcp"]
    assert wt["status"] == "error" and str(missing) in wt["error"], wt
    link.untouched(gw)


def test_a_service_restart_reads_the_pinned_cert_file_again(link):
    a = link.remote("A")
    pin = link.vhir / "tls" / "wintools-cert.pem"
    pin.parent.mkdir(parents=True, exist_ok=True)
    pin.write_text(link.remote("other").pem)  # the wrong cert for A
    gw = link.boot(wintools_mcp=backend_entry(a, a.token, str(pin)))
    r = per_backend(gw).call("get_share_info")
    assert r["is_error"] is True and "CERTIFICATE_VERIFY_FAILED" in r["text"], r

    pin.write_text(a.pem)  # the examiner puts the right cert in place
    r = gw.post("/api/v1/services/wintools-mcp/restart")
    assert r.status_code == 200, r.text
    c = per_backend(gw)
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    assert c.call("get_share_info")["text"] == "get_share_info:A"
    link.untouched(gw)


def test_a_rejoin_queued_while_a_load_runs_is_loaded_next(link):
    gw = link.boot()
    a = link.remote("A", start=False)  # the loader keeps retrying it
    assert gw.join(a, a.token, a.pem).status_code == 200
    until(lambda: link.logs.lines("attempt 1/6"), "the first load never started", 10)
    b = link.remote("B")
    assert gw.join(b, b.token, b.pem).status_code == 200  # while A's load runs
    c = answers(gw, "B", timeout=40)
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    conf = yaml.safe_load(link.config.read_text())["backends"]["wintools-mcp"]
    assert (conf["url"], conf["bearer_token"]) == (b.url, b.token)
    link.untouched(gw)


def test_a_remote_that_never_answers_leaves_the_loader_free_within_5s(link):
    gw = link.boot()
    silent = SilentRemote("silent", make_cert(link.certs, "wintools-silent"))
    link._remotes.append(silent.start())
    t0 = time.monotonic()
    assert gw.join(silent, silent.token, silent.pem).status_code == 200
    first = until(
        lambda: link.logs.lines("attempt 1/6"), "no answer was never named", 12
    )
    assert time.monotonic() - t0 < 9
    assert "no answer in 5s" in first[0], first
    b = link.remote("B")
    assert gw.join(b, b.token, b.pem).status_code == 200
    c = answers(gw, "B", timeout=20)
    assert c.server_name == PER_BACKEND and c.tools() == WINTOOLS_TOOLS
    link.untouched(gw)


def test_a_failed_config_write_puts_the_old_pin_back(link, monkeypatch):
    from sift_gateway import rest

    a, b = link.remote("A", start=False), link.remote("B", start=False)
    before = link.live(a)
    pin = link.vhir / "tls" / "wintools-cert.pem"
    conf = {"type": "http", "url": b.url, "bearer_token": b.token, "enabled": True,
            "joined": True, "tls_cert": str(pin), "tls_cert_pem": b.pem}  # fmt: skip

    def full(*args, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(rest, "_atomic_yaml_write", full)
    with pytest.raises(OSError):
        rest.save_joined_backend("wintools-mcp", conf)
    assert link.live_files() == before  # A's entry with A's pin, never B's
