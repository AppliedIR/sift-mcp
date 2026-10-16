"""case_status's platform_capabilities says what was checked, never `true`.

Nothing is contacted: a package that imports is "installed" (opensearch,
forensic_rag, opencti, sift_tools), a backend named in gateway.yaml (or
~/.claude.json for REMnux) is "configured" (remnux, wintools), and anything
else is False. Before, each was `true` on the same checks, so a REMnux listed at
an address nothing answers read as available. The guidance lines say
"If connected:".
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import os

import case_mcp.server as cms
import pytest
import yaml

from .test_timeline_reads import _make_case

MODULES = {
    "opensearch": "opensearch_mcp",
    "forensic_rag": "rag_mcp",
    "opencti": "opencti_mcp",
    "sift_tools": "sift_mcp",
}
KEYS = ("opensearch", "remnux", "wintools", "forensic_rag", "opencti", "sift_tools")
HEADER = (
    "Investigation capabilities installed or configured here"
    " (none was contacted, so one may be down):"
)
LINES = {
    "sift_tools": "- If connected: SIFT forensic tools via run_command (65+ tools)",
    "opensearch": "- If connected: evidence indexing: idx_ingest for structured"
    " querying at scale",
    "remnux": "- If connected: malware analysis on REMnux, each step logged with"
    " log_external_action (recorded as declared): upload_from_host + analyze_file",
    "wintools": "- If connected: Windows offline analysis: run_windows_command on"
    " forensic workstation",
    "forensic_rag": "- If connected: knowledge search: search_knowledge (Sigma,"
    " MITRE ATT&CK, KAPE)",
    "opencti": "- If connected: threat intel: lookup_ioc, search_threat_intel on OpenCTI",
}


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    (h / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(h))
    return h


def _packages(monkeypatch, present):
    """find_spec answers for the four packages as `present` says; others as real."""
    real = importlib.util.find_spec
    names = {MODULES[k]: k for k in MODULES}

    def fake(name, *a, **kw):
        if name in names:
            return object() if names[name] in present else None
        return real(name, *a, **kw)

    monkeypatch.setattr(importlib.util, "find_spec", fake)


def _gateway(home, backends):
    (home / ".vhir" / "gateway.yaml").write_text(yaml.safe_dump({"backends": backends}))


def _claude_json(home, servers):
    (home / ".claude.json").write_text(json.dumps({"mcpServers": servers}))


def _caps():
    out = cms._build_platform_capabilities()
    return out["platform_capabilities"], out["investigation_guidance"].splitlines()


# --- the measured RED shape (pd15_caps) ---------------------------------------


def test_remnux_listed_where_nothing_answers_is_configured_not_true(home, monkeypatch):
    _claude_json(
        home, {"remnux-mcp": {"type": "http", "url": "http://127.0.0.1:9/mcp"}}
    )
    for k in [k for k in os.environ if k.startswith("OPENCTI")]:
        monkeypatch.delenv(k)
    caps, guidance = _caps()
    assert caps["remnux"] == "configured"
    assert caps["opencti"] in ("installed", False)
    assert caps["opencti"] is not True
    assert LINES["remnux"] in guidance


# --- every combination: exact values, never True, guidance follows -------------


@pytest.mark.parametrize(
    "present,gw,cj",
    [
        (set(p), gw, cj)
        for n in range(len(MODULES) + 1)
        for p in itertools.combinations(MODULES, n)
        for gw in (
            (),
            ("remnux-mcp",),
            ("wintools-mcp",),
            ("remnux-mcp", "wintools-mcp"),
        )
        for cj in ((), ("remnux-mcp",))
    ],
)
def test_each_key_names_its_check_and_the_guidance_follows(
    home, monkeypatch, present, gw, cj
):
    _packages(monkeypatch, present)
    _gateway(home, {name: {"url": "http://127.0.0.1:9/mcp"} for name in gw})
    if cj:
        _claude_json(home, {name: {} for name in cj})
    caps, guidance = _caps()
    want = {k: ("installed" if k in present else False) for k in MODULES}
    want["remnux"] = "configured" if ("remnux-mcp" in gw or cj) else False
    want["wintools"] = "configured" if "wintools-mcp" in gw else False
    assert caps == want
    assert not any(v is True for v in caps.values())
    assert guidance[0] == HEADER
    for key in KEYS:
        assert (LINES[key] in guidance) == bool(want[key]), key
    assert guidance[-1].startswith("Do not rely solely on OpenSearch queries.")
    shown = [g for g in guidance if g.startswith("- ")]
    assert all(g.startswith("- If connected: ") for g in shown)
    assert len(shown) == sum(bool(v) for v in want.values())


def test_no_gateway_yaml_and_no_claude_json_leaves_both_false(home, monkeypatch):
    _packages(monkeypatch, set())
    caps, guidance = _caps()
    assert caps == dict.fromkeys(KEYS, False)
    assert guidance == [
        HEADER,
        "",
        "Do not rely solely on OpenSearch queries. "
        "Call suggest_tools(artifact_type='...') for deep analysis recommendations.",
    ]


# --- odd shapes of the two config files: never True, never raises --------------

GATEWAY_SHAPES = {
    "dict": ({"remnux-mcp": {}, "wintools-mcp": {}}, "configured"),
    "list": (["remnux-mcp", "wintools-mcp"], "configured"),
    "empty dict": ({}, False),
    "none": (None, False),
    "number": (5, False),
    "empty string": ("", False),
    "other names": ({"remnux-mcp-old": {}, "wintools": {}}, False),
    "non-ascii": ({"rémnux-mcp": {}, "wintools-mcp‮": {}}, False),
}


@pytest.mark.parametrize("shape", GATEWAY_SHAPES)
def test_gateway_backends_shapes(home, monkeypatch, shape):
    backends, want = GATEWAY_SHAPES[shape]
    _packages(monkeypatch, set())
    _gateway(home, backends)
    caps, guidance = _caps()
    assert caps["remnux"] == want and caps["wintools"] == want
    assert (LINES["remnux"] in guidance) == bool(want)
    assert (LINES["wintools"] in guidance) == bool(want)


@pytest.mark.parametrize(
    "text",
    [
        "- just a list\n",
        "backends: [unclosed\n",
        "\x00\x1b\x85\t\r",
        "plain string",
        "",
    ],
    ids=["top-level list", "broken yaml", "control chars", "scalar", "empty file"],
)
def test_unreadable_gateway_yaml_is_false_not_an_error(home, monkeypatch, text):
    _packages(monkeypatch, set())
    (home / ".vhir" / "gateway.yaml").write_text(text)
    caps, _ = _caps()
    assert caps["remnux"] is False and caps["wintools"] is False


CLAUDE_SHAPES = {
    "dict": ({"remnux-mcp": {}}, "configured"),
    "list": (["remnux-mcp"], "configured"),
    "none": (None, False),
    "number": (7, False),
    "other names": ({"remnux": {}, "wintools-mcp": {}}, False),
}


@pytest.mark.parametrize("shape", CLAUDE_SHAPES)
def test_claude_json_shapes(home, monkeypatch, shape):
    servers, want = CLAUDE_SHAPES[shape]
    _packages(monkeypatch, set())
    _claude_json(home, servers)
    caps, guidance = _caps()
    assert caps["remnux"] == want
    assert caps["wintools"] is False  # ~/.claude.json is read for REMnux only
    assert (LINES["remnux"] in guidance) == bool(want)


def test_broken_claude_json_is_false(home, monkeypatch):
    _packages(monkeypatch, set())
    (home / ".claude.json").write_text("{not json")
    caps, _ = _caps()
    assert caps["remnux"] is False


def test_claude_json_is_not_read_when_gateway_yaml_names_remnux(home, monkeypatch):
    _packages(monkeypatch, set())
    _gateway(home, {"remnux-mcp": {}})
    (home / ".claude.json").write_text("{not json")
    caps, _ = _caps()
    assert caps["remnux"] == "configured"


# --- the caller: case_status (server.py, the MCP tool) --------------------------


def test_case_status_returns_the_checked_values(tmp_path, home, monkeypatch):
    _make_case(tmp_path, "INC-CAPS", [], [], monkeypatch)
    _packages(monkeypatch, {"opensearch", "sift_tools"})
    _gateway(home, {"wintools-mcp": {"url": "http://127.0.0.1:9/mcp"}})
    _claude_json(home, {"remnux-mcp": {"url": "http://127.0.0.1:9/mcp"}})
    out = cms.create_server()._tool_manager._tools["case_status"].fn()
    assert out["platform_capabilities"] == {
        "opensearch": "installed",
        "remnux": "configured",
        "wintools": "configured",
        "forensic_rag": False,
        "opencti": False,
        "sift_tools": "installed",
    }
    guidance = out["investigation_guidance"].splitlines()
    assert guidance[0] == HEADER
    for key in ("opensearch", "remnux", "wintools", "sift_tools"):
        assert LINES[key] in guidance
    for key in ("forensic_rag", "opencti"):
        assert LINES[key] not in guidance
