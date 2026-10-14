"""The installed tool's own version and help, asked of what actually runs.

Every call asks again: SIFT's tools are often wrappers (a script that execs a
versioned binary, an EZ tool run as `dotnet X.dll`), so a cache keyed on the
file that was found can't see an update. A probe or a help run never writes
into the case: it runs with subprocess directly, not through the executor.
"""

from __future__ import annotations

import re
import subprocess

from sift_mcp.environment import find_binary

PROBE_TIMEOUT = 10  # seconds, for each version or help run
HELP_INLINE = 8192  # bytes of help shown in a reply
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
# What a tool says when it refuses the argv rather than giving help: clap's
# "error: unrecognized subcommand" (Hayabusa 3.9.0 has no dfir-timeline),
# getopt's "invalid option", Perl's "Unknown option"
_REFUSAL = re.compile(
    r"^error\b|unrecognized (subcommand|option|argument)|unexpected argument"
    r"|invalid option|unknown option",
    re.IGNORECASE,
)


def _refused(rc: int | None, text: str) -> bool:
    """The tool answered this argv with an error, not help: it failed and its
    first line says so."""
    return rc != 0 and bool(_REFUSAL.search(_first_line(text)))


def launch(binary: str) -> tuple[list[str], str] | None:
    """(the argv prefix that runs `binary`, the path that runs) or None when
    it isn't installed. An EZ tool whose .dll is installed runs as `dotnet
    X.dll`, as run_command runs it: the .dll is what runs."""
    from sift_mcp.tools.generic import _ez_launcher

    resolved = find_binary(binary)
    if not resolved:
        return None
    prefix = _ez_launcher(binary, resolved)
    path = prefix[-1] if len(prefix) > 1 else resolved
    return prefix, path


def _run(argv: list[str]) -> tuple[int | None, str, str]:
    try:
        r = subprocess.run(
            argv,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=PROBE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None, "", f"no answer within {PROBE_TIMEOUT}s"
    except OSError as e:
        return None, "", str(e)
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    return r.returncode, out, err


def _first_line(text: str) -> str:
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:200]


def probe(td) -> dict:
    """{installed_version, resolved_path} for a catalog tool, and
    `version_output` (what it printed) when no version could be read. {} when
    the tool isn't installed. Never raises."""
    found = launch(td.binary)
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
        _, out, err = _run(command)
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
    """{help, help_cut, help_note} from the installed tool; {help_error} when
    every way of asking was refused; or {error}. Usage printed on stderr with
    a non-zero exit is still help (TSK's -h); an error for that argv isn't,
    and the next way is tried."""
    if subcommand and not SUBCOMMAND.match(subcommand):
        return {
            "error": f"subcommand {subcommand!r} isn't a subcommand name "
            "(lowercase letters, digits and hyphens, starting with a letter)"
        }
    found = launch(td.binary)
    if not found:
        return {"error": f"{td.binary} isn't installed"}
    prefix, _ = found
    if subcommand:
        shape = td.subcommand_help or ["{subcommand}", "--help"]
        tries = [[a.replace("{subcommand}", subcommand) for a in shape]]
    else:
        tries = [td.help_argv] if td.help_argv else [["--help"], ["-h"]]
    text = refusal = ""
    for argv in tries:
        rc, out, err = _run(prefix + argv)
        said = out if out.strip() else err
        if _refused(rc, err if err.strip() else out):
            refusal = refusal or (err if err.strip() else out).strip()
            continue
        if said.strip():
            text = said
            break
    if not text and refusal:
        return {"help_error": refusal[:1000]}
    data = text.encode("utf-8")
    if len(data) <= HELP_INLINE:
        return {"help": text}
    cut = data[:HELP_INLINE].decode("utf-8", "ignore")
    cut = cut[: cut.rfind("\n") + 1] or cut  # at a line's end
    return {
        "help": cut,
        "help_cut": True,
        "help_note": f"The help is {len(data)} bytes; the first {len(cut.encode())} "
        "are shown. Run the tool's help through run_command (save_output) for "
        "the rest.",
    }
