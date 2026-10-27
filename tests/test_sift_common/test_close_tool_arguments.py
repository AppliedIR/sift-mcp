"""close_tool_arguments: a tool refuses an argument name it doesn't declare
instead of dropping it, and a tool it can't close stops the server, by name.

The helper is looked up rather than imported, so the rows that don't depend
on it (aliased names published and accepted by alias, a Context parameter
never published or demanded) also run against the code before it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pydantic
import pytest
import sift_common
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError


def _close(server) -> None:
    close = getattr(sift_common, "close_tool_arguments", None)
    if close is not None:
        close(server)


def _server() -> tuple[FastMCP, list]:
    """A server with an aliased parameter, a Context parameter and none;
    each body records the arguments it ran with."""
    ran: list = []
    m = FastMCP("probe")

    @m.tool()
    def aliased(json: str) -> dict:  # shadows BaseModel.json: field_json, alias json
        ran.append(("aliased", json))
        return {}

    @m.tool()
    async def with_context(query: str, ctx: Context) -> dict:
        ran.append(("with_context", query))
        return {}

    @m.tool()
    def no_parameters() -> dict:
        ran.append(("no_parameters",))
        return {}

    _close(m)
    return m, ran


def _schema(m: FastMCP, name: str) -> dict:
    return m._tool_manager.get_tool(name).parameters


async def _refusal(m: FastMCP, name: str, arguments: dict) -> list[tuple]:
    with pytest.raises(ToolError) as raised:
        await m.call_tool(name, arguments)
    cause = raised.value.__cause__
    assert isinstance(cause, pydantic.ValidationError), repr(raised.value)
    return [(e["type"], e["loc"]) for e in cause.errors()]


async def test_an_aliased_parameter_is_refused_under_its_field_name():
    m, ran = _server()
    errors = await _refusal(m, "aliased", {"json": "x", "field_json": "y"})
    assert ("extra_forbidden", ("field_json",)) in errors
    assert ran == []


async def test_an_aliased_parameter_is_published_by_its_alias():
    m, _ = _server()
    assert set(_schema(m, "aliased")["properties"]) == {"json"}
    assert _schema(m, "aliased")["required"] == ["json"]


async def test_an_aliased_parameter_is_accepted_by_its_alias():
    m, ran = _server()
    await m.call_tool("aliased", {"json": "x"})
    assert ran == [("aliased", "x")]


async def test_a_context_parameter_is_never_published_or_demanded():
    m, ran = _server()
    schema = _schema(m, "with_context")
    assert set(schema["properties"]) == {"query"}
    assert schema["required"] == ["query"]
    await m.call_tool("with_context", {"query": "q"})
    assert ran == [("with_context", "q")]


async def test_a_tool_with_no_parameters_refuses_any_name():
    m, ran = _server()
    errors = await _refusal(m, "no_parameters", {"anything": 1})
    assert errors == [("extra_forbidden", ("anything",))]
    assert ran == []
    await m.call_tool("no_parameters", {})
    assert ran == [("no_parameters",)]


async def test_every_published_schema_is_closed():
    m, _ = _server()
    for tool in m._tool_manager.list_tools():
        assert tool.parameters.get("additionalProperties") is False, tool.name


def test_a_tool_it_cant_close_stops_the_server_naming_the_tool():
    m = FastMCP("probe")

    @m.tool()
    def fine(query: str) -> dict:
        return {}

    @m.tool()
    def unreachable(query: str) -> dict:
        return {}

    tool = m._tool_manager.get_tool("unreachable")
    tool.fn_metadata = object()  # no argument model to close
    with pytest.raises(RuntimeError, match="'unreachable'"):
        sift_common.close_tool_arguments(m)


def test_its_version_is_past_the_last_one_without_the_helper():
    pyproject = Path(__file__).parents[2] / "packages/sift-common/pyproject.toml"
    version = re.search(r'^version = "([\d.]+)"', pyproject.read_text(), re.M)
    assert tuple(int(p) for p in version.group(1).split(".")) > (0, 6, 5, 1)
