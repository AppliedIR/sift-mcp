"""A reference reply belongs to its caller, at every depth.

The loader caches what it read; a getter that hands out the cached object
lets one caller's change reach every later reply in the process. The
framework reply took a call's audit warning that way and kept it for the
life of forensic-mcp.
"""

from __future__ import annotations

import inspect

import pytest
from forensic_knowledge import loader


def _first(d):
    return next(iter(d or {}), None)


def _args() -> dict[str, tuple]:
    y = loader._load_yaml
    fp = _first(
        (y("discipline/guidance/false_positives.yaml") or {}).get("false_positives")
    )
    corr = (y("discipline/guidance/corroboration.yaml") or {}).get("corroboration")
    tools = (y("discipline/guidance/tool_interpretation.yaml") or {}).get("tools")
    return {
        "get_artifact": ("prefetch",),
        "get_tool": ("PECmd",),
        "get_artifacts_for_tool": ("PECmd",),
        "get_playbook": (loader.list_playbook_slugs()[0],),
        "get_collection_checklist": (loader.list_collection_checklists()[0],),
        "get_checkpoint": (loader.list_checkpoints()[0]["action_type"],),
        "get_corroboration": (_first(corr),),
        "get_false_positive_context": tuple(fp.split("/", 1)),
        "get_tool_interpretation": (_first(tools),),
    }


ARGS = _args()
GETTERS = sorted(
    name
    for name, fn in inspect.getmembers(loader, inspect.isfunction)
    if not name.startswith("_")
    and name != "clear_cache"
    and fn.__module__ == loader.__name__
)


def _mutate(obj) -> int:
    """Change every dict and list in the reply, deepest first; how many."""
    n = 0
    if isinstance(obj, dict):
        for value in list(obj.values()):
            n += _mutate(value)
        obj["changed by a caller"] = True
        n += 1
    elif isinstance(obj, list):
        for value in list(obj):
            n += _mutate(value)
        obj.append("changed by a caller")
        n += 1
    return n


@pytest.mark.parametrize("name", GETTERS)
def test_changing_a_reply_never_changes_a_later_one(name):
    getter, args = getattr(loader, name), ARGS.get(name, ())
    reply = getter(*args)
    assert reply, f"{name}{args} answered nothing to change"
    if not isinstance(reply, (dict, list)):
        pytest.skip(f"{name} answers a {type(reply).__name__}")
    assert _mutate(reply)
    again = getter(*args)
    loader.clear_cache()
    assert again == getter(*args)


def test_the_framework_reply_keeps_nothing_from_an_earlier_call(tmp_path, monkeypatch):
    from forensic_mcp.server import create_server

    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    framework = (
        create_server("tools")._tool_manager._tools["get_investigation_framework"].fn
    )
    first = framework()  # no case: this reply carries the call's note
    first["changed by a caller"] = True
    case = tmp_path / "case-a"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: case-a\n")
    (home / ".vhir" / "active_case").write_text(str(case))
    second = framework()
    loader.clear_cache()
    from forensic_mcp.discipline.rules import get_investigation_framework

    assert second == get_investigation_framework()
