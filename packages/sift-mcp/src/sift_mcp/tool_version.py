"""The installed tool's own version and help, asked of what actually runs.

Every call asks again: SIFT's tools are often wrappers (a script that execs a
versioned binary, an EZ tool run as `dotnet X.dll`), so a cache keyed on the
file that was found can't see an update. A probe or a help run never writes
into the case: it runs with subprocess directly, not through the executor.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time

from sift_mcp.environment import find_binary
from sift_mcp.executor import _read_pipe

PROBE_TIMEOUT = 10  # seconds, for each version or help run
HELP_INLINE = 8192  # bytes of help shown in a reply
READ_CAP = 1 << 16  # bytes read from a version or help run, both streams together
# stdout, then this line, then stderr: as the help fixtures are written
STDERR_LABEL = "# --- stderr ---"
# A version as tools print it, tried in this order: dotted, optionally after a
# "v" (v3.9.0, ver 4.11.1, 16.02); a date stamp (libyal's 20140816, plaso's
# "version 20240308"); a dashed date (xxd 2021-10-22)
_VERSIONS = (
    re.compile(r"(?<![\w.])v?\.?(\d+(?:\.\d+){1,3})(?![\w.])"),
    re.compile(r"(?<![\w.-])((?:19|20)\d{6})(?![\w.-])"),
    re.compile(r"(?<![\w.-])((?:19|20)\d{2}-\d{2}-\d{2})(?![\w.-])"),
)


def _version(text: str) -> str | None:
    """The version on the first line that has one: a tool names its version
    near the top, and a usage text further down holds other numbers (1.4 GiB)."""
    for line in text.splitlines():
        for pattern in _VERSIONS:
            m = pattern.search(line)
            if m:
                return m.group(1)
    return None


def _interpreter(path: str) -> list[str] | None:
    """The script's own interpreter, from its #! line (a tool whose version is
    its package's, as Volatility 3's is)."""
    try:
        with open(path, "rb") as f:
            first = f.readline(512).decode("utf-8", "replace")
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    words = first[2:].split()
    return words or None


SUBCOMMAND = re.compile(r"^[a-z][a-z0-9-]{0,40}$")


def subcommand_error(td, subcommand: str) -> str | None:
    """Why a subcommand's help can't be asked for, before anything runs."""
    if not SUBCOMMAND.match(subcommand):
        return (
            f"subcommand {subcommand!r} isn't a subcommand name "
            "(lowercase letters, digits and hyphens, starting with a letter)"
        )
    if not td.subcommand_help:
        return (
            f"{td.name} has no subcommands in the catalog: ask for its help without one"
        )
    return None


def as_shown(out: str, err: str) -> str:
    """Both streams, stdout first, stderr under its label."""
    return f"{out}\n{STDERR_LABEL}\n{err}\n"


def launch(tool) -> tuple[list[str], str] | None:
    """(the argv prefix that runs it, the path that runs) or None when it
    isn't installed. `tool` is the binary a run names, or a catalog entry:
    its binary, then the names other versions install under (plaso
    20260720's log2timeline for 20240308's log2timeline.py). An EZ tool
    whose .dll is installed runs as `dotnet X.dll`, as run_command runs it:
    the .dll is what runs."""
    from sift_mcp.tools.generic import _ez_launcher

    names = [tool] if isinstance(tool, str) else tool.binaries
    for binary in names:
        resolved = find_binary(binary)
        if resolved:
            prefix = _ez_launcher(binary, resolved)
            return prefix, prefix[-1] if len(prefix) > 1 else resolved
    return None


def _run(
    argv: list[str], cap: int = READ_CAP
) -> tuple[int | None, str, str, bool, bool]:
    """(exit code, stdout, stderr, cut, late): at most `cap` bytes are read,
    both streams together, and a child still writing then is stopped (cut).
    One with no answer within PROBE_TIMEOUT is stopped too (late, exit code
    None), and what it printed by then is kept."""
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as e:
        return None, "", str(e), False, False
    out: list[bytes] = []
    err: list[bytes] = []
    total = [0]
    readers = [
        threading.Thread(
            target=_read_pipe, args=(pipe, chunks, cap, total), daemon=True
        )
        for pipe, chunks in ((proc.stdout, out), (proc.stderr, err))
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + PROBE_TIMEOUT
    late = False
    while proc.poll() is None:
        late = time.monotonic() >= deadline
        if late or total[0] >= cap:
            proc.kill()
            break
        time.sleep(0.01)
    proc.wait()
    for reader in readers:  # a grandchild holding a pipe isn't waited for
        reader.join(timeout=1)
    cut = total[0] >= cap
    late = late and not cut
    text = (
        b"".join(out).decode("utf-8", "replace"),
        b"".join(err).decode("utf-8", "replace"),
    )
    return None if late else proc.returncode, *text, cut, late


def _first_line(text: str) -> str:
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:200]


def probe(td, binary: str = "") -> dict:
    """{installed_version, resolved_path} for a catalog tool, and
    `version_output` (what it printed) when no version could be read. {} when
    the tool isn't installed. `binary`: the one a run names, which is what
    runs. Never raises."""
    found = launch(binary or td)
    if not found:
        return {}
    prefix, path = found
    # the tool's own way first ([]: run it bare), then the defaults
    tries = [td.version_argv] if td.version_argv is not None else []
    tries += [["--version"], ["-V"]]
    printed = ""
    for argv in tries:
        if argv and argv[0] == "{interpreter}":
            interp = _interpreter(path)
            if not interp:
                continue
            command = interp + argv[1:]
        else:
            command = prefix + argv
        _, out, err, _, _ = _run(command)
        version = _version(out) or _version(err)
        if version:
            return {"installed_version": version, "resolved_path": path}
        printed = _first_line(err) or _first_line(out) or printed
    return {
        "installed_version": "unknown",
        "resolved_path": path,
        "version_output": printed,
    }


def help_text(td, subcommand: str = "") -> dict:
    """{help, help_exit_code, help_cut, help_note} from the installed tool, or
    {error}. The help is what the tool printed, stdout then stderr under
    STDERR_LABEL, with its exit code: nothing here judges whether it is help
    (TSK's usage comes after "invalid option", exit 1; Hayabusa 3.9.0 answers
    dfir-timeline with "unrecognized subcommand", exit 2). The next way of
    asking is tried only when the tool printed nothing at all and answered
    in time."""
    if subcommand and (why := subcommand_error(td, subcommand)):
        return {"error": why}
    found = launch(td)
    if not found:
        return {"error": f"{td.binary} isn't installed"}
    prefix, _ = found
    if subcommand:
        tries = [[a.replace("{subcommand}", subcommand) for a in td.subcommand_help]]
    else:
        tries = [td.help_argv] if td.help_argv else [["--help"], ["-h"]]
    for argv in tries:
        code, out, err, cut, late = _run(prefix + argv, max(READ_CAP, HELP_INLINE + 1))
        if code is None and not late:  # it didn't run at all
            return {"error": f"{td.binary} couldn't be run: {err}"}
        if out.strip() or err.strip():
            break
        if late:
            return {"error": f"{td.binary} gave no answer within {PROBE_TIMEOUT}s"}
    notes = []
    if late:
        notes.append(
            f"{td.binary} gave no answer within {PROBE_TIMEOUT}s and was stopped. "
            "This is what it printed by then."
        )
    text = as_shown(out, err)
    data = text.encode("utf-8")
    if len(data) <= HELP_INLINE and not cut:
        reply = {"help": text, "help_exit_code": code}
    else:
        shown = data[:HELP_INLINE].decode("utf-8", "ignore")
        shown = shown[: shown.rfind("\n") + 1] or shown  # at a line's end
        reply = {"help": shown, "help_exit_code": code, "help_cut": True}
        notes.append(
            f"The first {len(shown.encode())} bytes of the help are shown. "
            "Run the tool's help through run_command (save_output) for the rest."
        )
    if notes:
        reply["help_note"] = " ".join(notes)
    return reply
