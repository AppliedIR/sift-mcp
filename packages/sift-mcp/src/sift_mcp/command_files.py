"""The files a command names: what it reads and where it says it writes.

Read from the command itself, never from a list the caller gives: an input
is an argument naming an existing file or folder, bare or as the value of a
``--flag=value``; an output flag's value is where the tool writes, never an
input. dd-style operands (``if=``, ``of=``) are read the same way.
"""

from __future__ import annotations

import os

_DD_IN = frozenset({"if", "ifs"})
_DD_OUT = frozenset({"of", "ofs", "hof", "hofs", "log", "hlog", "mlog"})


def absolute(path: str, base: str | None = None) -> str:
    """A relative path resolved against the run's working folder."""
    return path if os.path.isabs(path) else os.path.join(base or os.getcwd(), path)


def named(command: list[str], output_flags, base: str | None = None):
    """``(candidates, outputs)``: every path an argument names as something
    read, and every output flag's value, each made absolute against ``base``."""
    reads: list[str] = []
    writes: list[str] = []
    after_output_flag = False
    for tok in command[1:]:
        if after_output_flag:
            after_output_flag = False
            writes.append(absolute(tok, base))
            continue
        if tok.startswith("-"):
            if "=" in tok:
                flag, value = tok.split("=", 1)
                if value:
                    (writes if flag in output_flags else reads).append(
                        absolute(value, base)
                    )
            else:
                after_output_flag = tok in output_flags
            continue
        key, eq, value = tok.partition("=")
        if eq and value and key in _DD_OUT:
            writes.append(absolute(value, base))
        elif eq and value and key in _DD_IN:
            reads.append(absolute(value, base))
        elif tok:
            reads.append(absolute(tok, base))
    return reads, writes


def inputs(command: list[str], output_flags, base: str | None = None) -> list[str]:
    """The existing files and folders the command reads, once each, in order."""
    seen: set[str] = set()
    out = []
    for p in named(command, output_flags, base)[0]:
        if os.path.exists(p) and os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            out.append(p)
    return out
