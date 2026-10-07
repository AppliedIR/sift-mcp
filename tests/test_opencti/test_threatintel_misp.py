"""The MISP provider passes MISP's own attributes through for an exact match,
with the warninglists that list the value, and no verdict.

Replies were recorded from MISP 2.4.198 and 2.5.48 instances seeded with
synthetic events (the DNS-resolver warninglist and the NIDS decaying model
enabled); stubs stand in only for injected faults. Nothing reaches a network.
"""

from __future__ import annotations

import gzip
import json
import ssl
import time

import httpx
import opencti_mcp.providers.misp as misp_provider
import pytest
from opencti_mcp import providers

from .threatintel_rig import (
    MISP_REPLIES,
    MISP_SHA,
    lookup,
    misp_env,
    misp_recorded,
    recorded,
    server,
)

VERSIONS = ["24", "25"]
NEVER_SENT = {
    "to_ids",
    "published",
    "deleted",
    "excludeDecayed",
    "enforceWarninglist",
    "decayingModel",
    "type",
    "includeWarninglistHits",
}


async def _misp(monkeypatch, ioc, **env):
    misp_env(monkeypatch, **env)
    resp = await lookup(server(["misp"], cfg=None), ioc)
    return resp, resp["providers"]["misp"]


@pytest.mark.parametrize("version", VERSIONS)
async def test_every_attribute_with_the_value_is_returned_with_its_event(
    misp_transport, monkeypatch, version
):
    misp_transport(misp_recorded(version))
    resp, answer = await _misp(monkeypatch, "11.0.113.10")
    assert resp["outcome"] == answer["outcome"] == "MATCH"
    assert sorted(m["type"] for m in answer["matches"]) == ["ip-dst", "ip-src"]
    assert sorted(m["to_ids"] for m in answer["matches"]) == [False, True]
    for m in answer["matches"]:
        assert set(m) == {"uuid", "type", "value", "to_ids", "decay_score", "Event"}
        assert set(m["Event"]) == {"uuid", "threat_level_id", "analysis", "published"}
    assert {m["Event"]["published"] for m in answer["matches"]} == {False, True}
    assert answer["version"] == {"24": "2.4.198", "25": "2.5.48"}[version]
    assert "verdict" not in json.dumps(resp).lower()


@pytest.mark.parametrize("version", VERSIONS)
async def test_the_search_asks_for_context_and_decay_and_filters_nothing(
    misp_transport, monkeypatch, version
):
    t = misp_transport(misp_recorded(version))
    await _misp(monkeypatch, "11.0.113.10")
    (search,) = [r for r in t.requests if r["path"] == "/attributes/restSearch"]
    assert search["method"] == "POST"
    assert search["body"] == {
        "returnFormat": "json",
        "value": "11.0.113.10",
        "includeContext": 1,
        "includeDecayScore": 1,
        "limit": 101,
    }
    assert not NEVER_SENT & set(search["body"])
    assert search["headers"]["Authorization"] == "0" * 40


@pytest.mark.parametrize("version", VERSIONS)
async def test_a_value_on_a_warninglist_names_the_list(
    misp_transport, monkeypatch, version
):
    t = misp_transport(misp_recorded(version))
    _, answer = await _misp(monkeypatch, "8.8.8.8")
    (hit,) = answer["warninglist_hits"]["8.8.8.8"]
    assert hit["name"] == "List of known IPv4 public DNS resolvers"
    assert answer["matches"][0]["to_ids"] is False  # listed even though not to_ids
    checks = [r for r in t.requests if r["path"] == "/warninglists/checkValue"]
    assert [c["body"] for c in checks] == [{"value": "8.8.8.8"}]


@pytest.mark.parametrize("version", VERSIONS)
async def test_a_value_on_no_warninglist_has_no_hits(
    misp_transport, monkeypatch, version
):
    misp_transport(misp_recorded(version))
    _, answer = await _misp(monkeypatch, "11.0.113.10")
    assert answer["warninglist_hits"] == []


@pytest.mark.parametrize("version", VERSIONS)
async def test_decay_scores_pass_through_only_where_misp_gives_them(
    misp_transport, monkeypatch, version
):
    misp_transport(misp_recorded(version))
    _, ip = await _misp(monkeypatch, "11.0.113.10")
    recorded_ip = MISP_REPLIES[f"misp{version}:search:ip2"]["body"]["response"]
    assert [m["decay_score"] for m in ip["matches"]] == [
        a["decay_score"] for a in recorded_ip["Attribute"]
    ]
    _, sha = await _misp(monkeypatch, MISP_SHA)
    assert "decay_score" not in sha["matches"][0]
    assert ip["decaying_models_enabled"] == 1
    assert ip["warninglists_enabled"] == 1


@pytest.mark.parametrize("version", VERSIONS)
async def test_no_enabled_models_or_lists_count_zero(
    misp_transport, monkeypatch, version
):
    base = misp_recorded(version)

    def disabled(items, key):
        return [{key: {**item[key], "enabled": False}} for item in items]

    def route(method, path, body):
        if path == "/decayingModel/index":
            models = MISP_REPLIES[f"misp{version}:models"]["body"]
            return disabled(models, "DecayingModel")
        if path == "/warninglists/index":
            lists = MISP_REPLIES[f"misp{version}:warninglists"]["body"]["Warninglists"]
            return {"Warninglists": disabled(lists, "Warninglist")}
        return base(method, path, body)

    misp_transport(route)
    _, answer = await _misp(monkeypatch, "11.0.113.10")
    assert answer["decaying_models_enabled"] == 0
    assert answer["warninglists_enabled"] == 0


@pytest.mark.parametrize("version", VERSIONS)
async def test_either_half_of_a_composite_matches(misp_transport, monkeypatch, version):
    misp_transport(misp_recorded(version))
    _, answer = await _misp(monkeypatch, "11.0.113.20")
    assert answer["outcome"] == "MATCH"
    assert answer["matches"][0]["value"] == "c2-sample.example|11.0.113.20"


@pytest.mark.parametrize("version", VERSIONS)
async def test_a_value_misp_doesnt_hold_is_no_match(
    misp_transport, monkeypatch, version
):
    misp_transport(misp_recorded(version))
    resp, answer = await _misp(monkeypatch, "11.0.113.99")
    assert resp["outcome"] == answer["outcome"] == "NO_MATCH"
    assert answer["matches"] == []


@pytest.mark.parametrize("version", VERSIONS)
async def test_a_domain_in_another_case_matches(misp_transport, monkeypatch, version):
    misp_transport(misp_recorded(version))
    _, answer = await _misp(monkeypatch, "EVIL-SAMPLE.EXAMPLE")
    assert answer["outcome"] == "MATCH"
    assert answer["matches"][0]["value"] == "evil-sample.example"


def _search_reply(attributes):
    return lambda m, p, b: (
        {"response": {"Attribute": attributes}}
        if p == "/attributes/restSearch"
        else ([] if p == "/warninglists/checkValue" else {})
    )


async def test_a_pipe_inside_a_plain_attribute_is_not_split(
    misp_transport, monkeypatch
):
    misp_transport(
        _search_reply([{"type": "text", "value": "note|11.0.113.20", "uuid": "u"}])
    )
    _, answer = await _misp(monkeypatch, "11.0.113.20")
    assert answer["outcome"] == "NO_MATCH"


async def test_an_attribute_that_only_contains_the_value_is_not_a_match(
    misp_transport, monkeypatch
):
    misp_transport(
        _search_reply([{"type": "url", "value": "http://11.0.113.20/x", "uuid": "u"}])
    )
    _, answer = await _misp(monkeypatch, "11.0.113.20")
    assert answer["outcome"] == "NO_MATCH"


async def test_more_than_a_hundred_attributes_are_capped_and_say_so(
    misp_transport, monkeypatch
):
    attributes = [
        {"type": "ip-dst", "value": "11.0.113.55", "uuid": f"u{i}"} for i in range(101)
    ]
    misp_transport(_search_reply(attributes))
    _, answer = await _misp(monkeypatch, "11.0.113.55")
    assert len(answer["matches"]) == 100
    assert answer["truncated"] is True and "100" in answer["note"]


# --- couldn't ask ------------------------------------------------------------


def _fail_search(answer):
    def route(method, path, body):
        if path == "/attributes/restSearch":
            return answer
        return misp_recorded("25")(
            method, path, {"value": "11.0.113.10", **(body or {})}
        )

    return route


@pytest.mark.parametrize(
    "answer, reason",
    [
        (
            httpx.Response(403, text=MISP_REPLIES["misp25:bad_key"]["body"]),
            "HTTP 403: Authentication failed",
        ),
        (
            httpx.Response(403, text=MISP_REPLIES["misp24:bad_key"]["body"]),
            "HTTP 403: Authentication failed",
        ),
        (
            httpx.Response(500, text=MISP_REPLIES["misp24:db_down"]["body"]),
            "HTTP 500: An Internal Error Has Occurred.",
        ),
        (httpx.ConnectError("[Errno 111] Connection refused"), "can't reach MISP"),
        (
            httpx.ConnectError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate"
            ),
            "CERTIFICATE_VERIFY_FAILED",
        ),
        (httpx.ReadTimeout("read timed out"), "timed out"),
        (httpx.Response(200, text="<html>login</html>"), "not JSON"),
        (httpx.Response(200, json={"response": []}), "unexpected shape"),
        (
            httpx.Response(200, json={"response": {"Attribute": [None]}}),
            "unexpected shape",
        ),
        (httpx.Response(200, json=[]), "unexpected shape"),
    ],
    ids=[
        "bad key 2.5",
        "bad key 2.4",
        "database down",
        "unreachable",
        "self-signed",
        "timeout",
        "not json",
        "response a list",
        "null attribute",
        "reply a list",
    ],
)
async def test_a_search_that_couldnt_ask_is_unavailable(
    misp_transport, monkeypatch, answer, reason
):
    misp_transport(_fail_search(answer))
    resp, answer_ = await _misp(monkeypatch, "11.0.113.10")
    assert resp["outcome"] == answer_["outcome"] == "UNAVAILABLE"
    assert reason in answer_["reason"], answer_
    assert answer_["matches"] == []


async def test_a_failed_warninglist_check_keeps_the_match(misp_transport, monkeypatch):
    base = misp_recorded("25")

    def route(method, path, body):
        if path == "/warninglists/checkValue":
            return httpx.Response(500, json={"message": "boom"})
        return base(method, path, body)

    misp_transport(route)
    _, answer = await _misp(monkeypatch, "11.0.113.10")
    assert answer["outcome"] == "MATCH"
    assert answer["warninglist_hits"] is None
    assert "HTTP 500" in answer["warninglists_unavailable"]


async def test_unreadable_facts_are_none_and_decide_nothing(
    misp_transport, monkeypatch
):
    base = misp_recorded("25")

    def route(method, path, body):
        if method == "GET":
            return httpx.Response(404, text="not here")
        return base(method, path, body)

    misp_transport(route)
    _, answer = await _misp(monkeypatch, "11.0.113.10")
    assert answer["outcome"] == "MATCH"
    assert answer["version"] is None
    assert answer["warninglists_enabled"] is None
    assert answer["decaying_models_enabled"] is None


async def test_facts_are_read_once_a_minute_and_the_search_every_time(
    misp_transport, monkeypatch
):
    t = misp_transport(misp_recorded("25"))
    misp_env(monkeypatch)
    srv = server(["misp"], cfg=None)
    await lookup(srv, "11.0.113.10")
    await lookup(srv, "11.0.113.10")
    paths = t.paths()
    assert paths.count("/attributes/restSearch") == 2
    assert paths.count("/warninglists/checkValue") == 2
    assert paths.count("/servers/getVersion") == 1
    srv.providers["misp"]._facts_at -= misp_provider.FACTS_SECONDS
    await lookup(srv, "11.0.113.10")
    assert t.paths().count("/servers/getVersion") == 2


# --- configuration -----------------------------------------------------------


@pytest.mark.parametrize(
    "env, words",
    [
        ({"MISP_URL": ""}, "MISP_URL is not set"),
        ({"MISP_KEY": ""}, "MISP_KEY is not set"),
        ({"MISP_URL": "ftp://misp.example"}, "not an http(s) URL"),
        ({"MISP_TIMEOUT": "soon"}, "MISP_TIMEOUT is not a number"),
        ({"MISP_TIMEOUT": "0"}, "MISP_TIMEOUT must be positive"),
        ({"MISP_SSL_VERIFY": "/no/such/ca.pem"}, "CA bundle that doesn't exist"),
    ],
)
async def test_misp_without_usable_settings_is_unavailable_with_the_reason(
    monkeypatch, env, words
):
    resp, answer = await _misp(monkeypatch, "11.0.113.10", **env)
    assert answer["outcome"] == "UNAVAILABLE"
    assert answer["reason"].startswith("misp is not configured:")
    assert words in answer["reason"]


def test_misp_settings(monkeypatch, tmp_path):
    misp_env(monkeypatch, MISP_URL="https://misp.example/", MISP_TIMEOUT="5")
    adapter = misp_provider.create()
    assert adapter.url == "https://misp.example"
    assert adapter.verify is True and adapter.timeout == 5
    monkeypatch.setenv("MISP_TIMEOUT", "60")
    monkeypatch.setenv("MISP_SSL_VERIFY", "false")
    adapter = misp_provider.create()
    assert (
        adapter.verify is False and adapter.timeout == providers.LOOKUP_BUDGET_SECONDS
    )


def test_a_ca_bundle_path_is_used_to_verify(monkeypatch):
    import certifi

    misp_env(monkeypatch, MISP_SSL_VERIFY=certifi.where())
    assert isinstance(misp_provider.create().verify, ssl.SSLContext)


async def test_the_configured_tls_setting_is_used(misp_transport, monkeypatch):
    t = misp_transport(misp_recorded("25"))
    await _misp(monkeypatch, "11.0.113.10", MISP_SSL_VERIFY="false")
    assert {r["verify"] for r in t.requests} == {False}


# --- with OpenCTI --------------------------------------------------------------


async def test_both_platforms_answer_side_by_side(
    provider_transport, misp_transport, monkeypatch
):
    provider_transport(recorded("6"))
    misp_transport(misp_recorded("25"))
    misp_env(monkeypatch)
    resp = await lookup(server(["opencti", "misp"]), "11.0.113.10")
    assert resp["outcome"] == "MATCH"
    assert len(resp["providers"]["opencti"]["matches"]) == 3
    assert len(resp["providers"]["misp"]["matches"]) == 2
    assert resp["confidence"] == 90  # OpenCTI's summary is OpenCTI's alone


async def test_a_misconfigured_misp_doesnt_hide_opencti_s_match(
    provider_transport, monkeypatch
):
    provider_transport(recorded("6"))
    monkeypatch.delenv("MISP_URL", raising=False)
    resp = await lookup(server(["opencti", "misp"]), "11.0.113.10")
    assert resp["outcome"] == "MATCH"
    assert resp["providers"]["misp"]["outcome"] == "UNAVAILABLE"


async def test_too_many_candidates_with_no_exact_one_is_unavailable(
    misp_transport, monkeypatch
):
    attributes = [
        {"type": "ssdeep", "value": "96:AbCd:EfGh".swapcase(), "uuid": f"u{i}"}
        for i in range(101)
    ]
    misp_transport(_search_reply(attributes))
    _, answer = await _misp(monkeypatch, "96:AbCd:EfGh")
    assert answer["outcome"] == "UNAVAILABLE"
    assert "too many candidate matches" in answer["reason"]


@pytest.mark.parametrize("value", [None, 7], ids=["null", "number"])
async def test_an_attribute_without_a_value_is_unavailable(
    misp_transport, monkeypatch, value
):
    misp_transport(
        _search_reply(
            [
                {"type": "ip-dst", "value": "11.0.113.20", "uuid": "a"},
                {"type": "ip-dst", "value": value, "uuid": "b"},
            ]
        )
    )
    _, answer = await _misp(monkeypatch, "11.0.113.20")
    assert answer["outcome"] == "UNAVAILABLE"
    assert "malformed provider data" in answer["reason"]


async def test_a_gzip_compressed_reply_is_read(monkeypatch):
    def route(request):
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        answer = misp_recorded("25")(request.method, path, body)
        return httpx.Response(
            answer.status_code,
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
            content=gzip.compress(answer.content),
        )

    monkeypatch.setattr(misp_provider, "_http_request", misp_provider._send)
    monkeypatch.setattr(misp_provider, "_transport", httpx.MockTransport(route))
    _, answer = await _misp(monkeypatch, "8.8.8.8")
    assert answer["outcome"] == "MATCH"
    assert answer["warninglist_hits"]["8.8.8.8"][0]["id"] == "162"
    assert answer["version"] == "2.5.48"


# --- the warninglist check and the facts never cost the match --------------


async def test_follow_ups_are_left_out_when_the_time_has_run_out(
    misp_transport, monkeypatch
):
    monkeypatch.setattr(misp_provider, "FOLLOW_UP_MIN_SECONDS", 60)
    t = misp_transport(misp_recorded("25"))
    _, answer = await _misp(monkeypatch, "11.0.113.10")
    assert answer["outcome"] == "MATCH" and len(answer["matches"]) == 2
    assert answer["warninglist_hits"] is None
    assert "time ran out" in answer["warninglists_unavailable"]
    assert answer["version"] is None
    assert t.paths() == ["/attributes/restSearch"]


async def test_a_warninglist_check_that_times_out_keeps_the_match(
    misp_transport, monkeypatch
):
    base = misp_recorded("25")

    def route(method, path, body):
        if path == "/warninglists/checkValue":
            return httpx.ReadTimeout("read timed out")
        return base(method, path, body)

    misp_transport(route)
    _, answer = await _misp(monkeypatch, "11.0.113.10")
    assert answer["outcome"] == "MATCH"
    assert answer["warninglist_hits"] is None
    assert "timed out" in answer["warninglists_unavailable"]


async def test_facts_that_timed_out_are_read_again_next_time(
    misp_transport, monkeypatch
):
    base = misp_recorded("25")
    state = {"slow": True}

    def route(method, path, body):
        if path == "/servers/getVersion" and state["slow"]:
            return httpx.ReadTimeout("read timed out")
        return base(method, path, body)

    t = misp_transport(route)
    misp_env(monkeypatch)
    srv = server(["misp"], cfg=None)
    first = (await lookup(srv, "11.0.113.10"))["providers"]["misp"]
    assert first["outcome"] == "MATCH" and first["version"] is None
    assert first["warninglists_enabled"] == 1
    state["slow"] = False
    second = (await lookup(srv, "11.0.113.10"))["providers"]["misp"]
    assert second["version"] == "2.5.48"
    assert t.paths().count("/servers/getVersion") == 2


async def test_facts_that_cant_be_read_are_not_asked_for_again_within_a_minute(
    misp_transport, monkeypatch
):
    base = misp_recorded("25")

    def route(method, path, body):
        if path == "/servers/getVersion":
            return httpx.Response(403, json={"message": "not allowed"})
        return base(method, path, body)

    t = misp_transport(route)
    misp_env(monkeypatch)
    srv = server(["misp"], cfg=None)
    await lookup(srv, "11.0.113.10")
    await lookup(srv, "11.0.113.10")
    assert t.paths().count("/servers/getVersion") == 1


async def test_a_lookup_never_waits_for_another_reading_the_facts(
    misp_transport, monkeypatch
):
    t = misp_transport(misp_recorded("25"))
    misp_env(monkeypatch)
    srv = server(["misp"], cfg=None)
    adapter = srv.providers["misp"]
    assert adapter._facts_lock.acquire(blocking=False)
    try:
        answer = (await lookup(srv, "11.0.113.10"))["providers"]["misp"]
    finally:
        adapter._facts_lock.release()
    assert answer["outcome"] == "MATCH" and answer["version"] is None
    assert "/servers/getVersion" not in t.paths()


# --- follow-ups never hold back the match; samples are composites ----------


class _Trickle(httpx.SyncByteStream):
    def __init__(self, body: bytes, chunk: int, delay: float):
        self.body, self.chunk, self.delay = body, chunk, delay

    def __iter__(self):
        for i in range(0, len(self.body), self.chunk):
            time.sleep(self.delay)
            yield self.body[i : i + self.chunk]


def _trickling(slow_paths):
    """Recorded 2.5 replies; the paths named come in 250 ms chunks and take far
    longer than a 2 s budget."""
    base = misp_recorded("25")

    def route(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        answer = base(request.method, request.url.path, body)
        if request.url.path in slow_paths:
            data = answer.content
            return httpx.Response(200, stream=_Trickle(data, len(data) // 40 + 1, 0.25))
        return answer

    return route


@pytest.mark.parametrize(
    "slow",
    [
        ["/warninglists/checkValue"],
        ["/servers/getVersion", "/warninglists/index", "/decayingModel/index"],
    ],
    ids=["warninglist check", "facts"],
)
async def test_a_trickling_follow_up_still_returns_the_match(monkeypatch, slow):
    monkeypatch.setattr(misp_provider, "_http_request", misp_provider._send)
    monkeypatch.setattr(
        misp_provider, "_transport", httpx.MockTransport(_trickling(slow))
    )
    monkeypatch.setattr(misp_provider, "FOLLOW_UP_MIN_SECONDS", 0.1)
    start = time.monotonic()
    _, answer = await _misp(monkeypatch, "8.8.8.8", MISP_TIMEOUT="2")
    assert time.monotonic() - start < 2 + providers.GRACE_SECONDS
    assert answer["outcome"] == "MATCH" and len(answer["matches"]) == 1
    if "/warninglists/checkValue" in slow:
        assert answer["warninglist_hits"] is None
        assert "timed out" in answer["warninglists_unavailable"]
    else:
        assert answer["version"] is None  # nothing read before


async def test_an_md5_held_only_as_a_malware_sample_matches(
    misp_transport, monkeypatch
):
    md5 = "5f0c2a9e1b7d4c3a8e6f9b0d2c4a6e81"
    misp_transport(
        _search_reply(
            [{"type": "malware-sample", "value": f"dropper.exe|{md5}", "uuid": "s1"}]
        )
    )
    _, answer = await _misp(monkeypatch, md5)
    assert answer["outcome"] == "MATCH"
    assert answer["matches"][0]["value"] == f"dropper.exe|{md5}"
