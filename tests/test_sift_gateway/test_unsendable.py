"""A call whose name or arguments hold a lone surrogate (half of a UTF-16 pair)
is refused by name, and audited, where it enters the gateway, before any
backend sees it. Such text can't be sent as UTF-8. An HTTP backend's call
waited out the 300 s call timeout. A stdio backend's session broke for every
later call while its health still read ok, so hostile
evidence text copied into record_finding's arguments could leave
forensic-mcp unusable until a gateway restart.

The stdio rows are in test_unsendable_stdio.py, which imports nothing new, so
they can run against the code before this change.
"""

from __future__ import annotations

import pytest
from sift_gateway.unsendable import (
    UnsendableArguments,
    check_sendable,
    lone_surrogate_in,
)


@pytest.mark.parametrize(
    ("arguments", "where"),
    [
        ({"x": "\ud800"}, "'x'"),
        ({"x": "ok", "cmd": "dir \udcff"}, "'cmd'"),
        ({"x": ["ok", {"k": "\udfff"}]}, "'x'"),
        ({"x": {"k\ud83d": 1}}, "'x'"),  # in a key
        ({"x": ("ok", "\ud800")}, "'x'"),
        ({"\udc80": "ok"}, "'\\udc80'"),  # the top-level key, shown escaped
    ],
)
def test_a_lone_surrogate_anywhere_names_its_argument(arguments, where):
    assert lone_surrogate_in(arguments) == where


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"x": "é 😀 😀".encode("utf-16", "surrogatepass").decode("utf-16")},
        {"x": 1, "y": None, "z": [1.5, True, {"k": "v"}]},
    ],
)
def test_text_that_can_be_sent_passes(arguments):
    assert lone_surrogate_in(arguments) is None
    check_sendable("wintools-mcp", "get_share_info", arguments)


def test_deep_nesting_is_walked_without_recursion():
    deep = ["\ud800"]
    for _ in range(100_000):
        deep = [deep]
    assert lone_surrogate_in({"x": deep}) == "'x'"


def test_the_refusal_names_the_backend_the_tool_and_the_argument():
    with pytest.raises(UnsendableArguments) as e:
        check_sendable("wintools-mcp", "run_windows_command", {"command": "dir \ud800"})
    assert str(e.value) == (
        "Backend wintools-mcp: run_windows_command wasn't sent: its argument "
        "'command' holds a lone surrogate (half of a UTF-16 pair), which can't "
        "be sent as UTF-8; send that text without it"
    )
    assert isinstance(e.value, RuntimeError)


def test_a_lone_surrogate_in_the_tool_name_is_named_and_shown_escaped():
    with pytest.raises(UnsendableArguments) as e:
        check_sendable("wintools-mcp", "get_share_info\udc00", {})
    assert "get_share_info\\udc00 wasn't sent: its name holds" in str(e.value)
    str(e.value).encode("utf-8")  # the message itself can be sent
