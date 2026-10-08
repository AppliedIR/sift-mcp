"""Whether a shell command has an MCP route, for the audit hooks.

Reads the command on stdin. When its first executable is in mcp-routes.tsv
(beside this file), prints one JSON object: {"mcp_route", "tool", "command",
"advisory"}. Otherwise prints nothing. Exits 0 either way: the hooks mark and
advise, never block. Run as `python3 -I mcp-route.py`; standard library only.

Only the first command is looked at, by its executable's basename, after
sudo, env, nohup, nice, time, command, exec and VAR=value prefixes. A routed
tool later in a pipe or chain, or run through another interpreter or script,
isn't marked.
"""

import json
import re
import shlex
import sys
from pathlib import Path

# each wrapper, and its options that take a separate value
WRAPPERS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"},
    "env": {"-u", "-C", "-S"},
    "nice": {"-n"},
    "nohup": set(),
    "time": {"-f", "-o"},
    "command": set(),
    "exec": {"-a"},
}
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _routes():
    out = {}
    try:
        text = Path(__file__).with_name("mcp-routes.tsv").read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            out[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
    return out


def _first_command(command):
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        words = command.split()
    for i, w in enumerate(words):
        if w in (";", "&&", "||", "|", "&"):
            words = words[:i]
            break
    while words:
        w = words[0]
        if ASSIGNMENT.match(w):
            words = words[1:]
        elif w.rsplit("/", 1)[-1] in WRAPPERS:
            takes_value = WRAPPERS[w.rsplit("/", 1)[-1]]
            words = words[1:]
            while words and (words[0].startswith("-") or ASSIGNMENT.match(words[0])):
                if words[0] == "--":
                    words = words[1:]
                    break
                words = words[2:] if words[0] in takes_value else words[1:]
        else:
            break
    return words


def route(command):
    """The route for a command, as the hooks report it, or None."""
    words = _first_command(command)
    if not words:
        return None
    name = words[0].rsplit("/", 1)[-1]
    routes = _routes()
    key = name
    if name == "vhir" and len(words) > 1:
        key = f"vhir {words[1]}"
    if key not in routes:
        return None
    mcp_route, tool = routes[key]
    server, _, mcp_tool = mcp_route.partition(" ")
    via = f"{server}'s {mcp_tool}" + (f" (catalog tool {tool})" if tool else "")
    return {
        "mcp_route": mcp_route,
        "tool": tool,
        "command": key,
        "advisory": (
            f"`{key}` has an MCP route: {via}. Prefer it: the call and its "
            "output go into the case audit, and a finding can cite its audit "
            "id. The shell stays allowed when the MCP tool can't do the job or "
            "the output is too large for it."
        ),
    }


if __name__ == "__main__":
    try:
        found = route(sys.stdin.read())
    except Exception:
        found = None
    if found:
        print(json.dumps(found))
