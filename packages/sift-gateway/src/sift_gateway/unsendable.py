"""Text that can't be sent to a backend: a lone surrogate (half of a UTF-16
pair) has no UTF-8 form. Sent anyway, it fails in the transport's writer: an
HTTP backend's call waited out the 300 s call timeout, and a stdio backend's
session broke for every later call while its health still read ok. So each
route refuses such a call by name where it enters the gateway, before any
backend sees it: Gateway.call_tool (the aggregate MCP route and REST) and the
per-backend MCP handler."""

from __future__ import annotations


class UnsendableArguments(RuntimeError):
    """A call refused before it was sent: its text can't be sent as UTF-8."""


def _unsendable(s: str) -> bool:
    try:
        s.encode("utf-8")
        return False
    except UnicodeEncodeError:
        return True


def lone_surrogate_in(arguments: dict) -> str | None:
    """The top-level argument with a lone surrogate (half of a UTF-16 pair) in
    a key or a value at any depth, or None. Such text can't be sent as UTF-8:
    the transport fails in its writer task, and the call waits out the call
    timeout. The name comes escaped, so it's safe to show."""
    for top, value in arguments.items():
        stack = [top, value]
        while stack:
            v = stack.pop()
            if isinstance(v, str):
                if _unsendable(v):
                    return ascii(top)
            elif isinstance(v, dict):
                stack.extend(v.keys())
                stack.extend(v.values())
            elif isinstance(v, (list, tuple)):
                stack.extend(v)
    return None


def check_sendable(backend_name: str, name: str, arguments: dict | None) -> None:
    """Raise UnsendableArguments, naming what can't be sent, or return."""
    where = "its name" if _unsendable(name) else None
    if where is None and (arg := lone_surrogate_in(arguments or {})) is not None:
        where = f"its argument {arg}"
    if where is not None:
        raise UnsendableArguments(
            f"Backend {backend_name}: {ascii(name)[1:-1]} wasn't sent: {where} holds a "
            "lone surrogate (half of a UTF-16 pair), which can't be sent as UTF-8; "
            "send that text without it"
        )
