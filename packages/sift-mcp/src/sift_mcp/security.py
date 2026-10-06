"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

import os
import re
from pathlib import Path

from sift_mcp.catalog import load_security_policy
from sift_mcp.config import resolve_case_dir

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${"]


def _get_policy() -> dict:
    """Lazy-load security policy from YAML catalog."""
    return load_security_policy()


# awk can execute arbitrary commands via language syntax (not flags).
# Scan program text for dangerous constructs.
_AWK_DANGEROUS_RE = re.compile(
    r"system\s*\(|getline|\".*\||\|.*\"|>\s*\"|>>\s*\"", re.IGNORECASE
)

# Tools whose positional args are program text and need content scanning
_PROGRAM_TEXT_TOOLS = {"awk", "gawk", "mawk", "nawk"}


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    """Validate extra_args to block dangerous flags and shell metacharacters.

    Raises ValueError if a dangerous flag or pattern is detected.
    """
    if not extra_args:
        return []

    policy = _get_policy()
    tool_allowed = policy["tool_allowed_flags"].get(tool_name, set())
    tool_blocked = policy["tool_blocked_flags"].get(tool_name, set())

    sanitized = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(f"Non-string argument in extra_args: {type(arg).__name__}")
        flag = arg.lower().split("=")[0]
        if flag in tool_blocked:
            raise ValueError(f"Blocked dangerous flag '{arg}' for {tool_name}")
        if flag in policy["dangerous_flags"] and flag not in tool_allowed:
            raise ValueError(
                f"Blocked dangerous flag '{arg}' in extra_args for {tool_name}"
            )
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in arg:
                raise ValueError(
                    f"Blocked shell metacharacter in extra_args for {tool_name}"
                )
        sanitized.append(arg)

    # Scan awk program text for dangerous constructs (system(), getline, pipes)
    if tool_name in _PROGRAM_TEXT_TOOLS:
        for arg in sanitized:
            if arg.startswith("-"):
                continue  # skip flags
            if _AWK_DANGEROUS_RE.search(arg):
                raise ValueError(
                    f"Blocked dangerous awk construct in program text for {tool_name}: "
                    f"system(), getline, and pipe operators are not allowed"
                )

    return sanitized


# Directories where rm is blocked (evidence storage, case data)
def _get_protected_dirs() -> tuple[str, ...]:
    """Resolve protected directories at runtime from env/defaults."""
    cases_dir = os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases"))
    return (
        str(Path(cases_dir).resolve()),
        "/cases",
        "/evidence",
    )


def is_denied(binary_name: str) -> bool:
    """Check if a binary is on the hard denylist."""
    return binary_name.lower() in _get_policy()["denied_binaries"]


def validate_rm_targets(args: list[str]) -> None:
    """Block rm from targeting evidence storage directories.

    rm is allowed for general cleanup but blocked inside evidence
    storage locations. Also blocks rm -rf / patterns.
    """
    _RM_GUIDANCE = (
        " File deletion in case/evidence directories requires human action "
        "outside the AI session (forensic integrity control). "
        "Exit Claude Code, run the rm command directly, then return."
    )
    path_args = [a for a in args if not a.startswith("-")]
    for arg in path_args:
        resolved = str(Path(arg).resolve())
        if resolved == "/":
            raise ValueError("Blocked: rm targeting filesystem root")
        for protected in _get_protected_dirs():
            if (
                resolved == protected
                or resolved.startswith(protected + "/")
                or protected.startswith(resolved.rstrip("/") + "/")
            ):
                raise ValueError(
                    f"Blocked: rm in protected directory '{protected}'." + _RM_GUIDANCE
                )
        case_dir = resolve_case_dir()
        if case_dir:
            case_resolved = str(Path(case_dir).resolve())
            if (
                resolved == case_resolved
                or resolved.startswith(case_resolved + "/")
                or case_resolved.startswith(resolved.rstrip("/") + "/")
            ):
                raise ValueError("Blocked: rm in case directory." + _RM_GUIDANCE)


# Case records, as protected by the Bash case-data guard hook
# (claude-code/shared/hooks/case-data-guard.sh). Keep the two lists the same.
_CASE_RECORDS = frozenset(
    {
        "findings.json",
        "timeline.json",
        "approvals.jsonl",
        "iocs.json",
        "evidence.json",
        "todos.json",
        "CASE.yaml",
        "actions.jsonl",
        "pending-reviews.json",
    }
)
_WRAPPERS = frozenset({"sudo", "nice", "nohup", "time", "timeout", "stdbuf"})


def _harms_case_data(path: str, new_ok: bool = False) -> bool:
    """Whether deleting or overwriting path harms protected case data."""
    cases = os.path.realpath(
        os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases"))
    )
    real = os.path.realpath(path)
    if real == "/" or cases.startswith(real.rstrip("/") + "/"):
        return True  # an ancestor of the cases root
    if real != cases and not real.startswith(cases + "/"):
        return False
    parts = [x for x in real[len(cases) :].split("/") if x]
    if not parts:  # the cases root
        return True
    if len(parts) == 1:  # a case root, while it holds anything
        return os.path.isdir(real) and bool(os.listdir(real))
    top = parts[1]
    if top == "audit" or (top in _CASE_RECORDS and len(parts) == 2):
        return True
    if top == "evidence":
        if len(parts) == 2:  # evidence/ itself, while it holds anything
            return os.path.isdir(real) and bool(os.listdir(real))
        return os.path.lexists(real) or not new_ok
    return False


def validate_case_data_targets(command: list[str]) -> None:
    """Refuse commands that delete or overwrite case records, audit/ or evidence.

    Moving other files into the case's DELETE/ directory, filing new files
    into evidence/, and reading anything stay allowed. A best-effort check of
    the listed commands (no shell runs here, so there are no redirections).
    Not checked: a wrapper option that takes a value (timeout -s KILL,
    stdbuf -o 0, sudo --user), an attached or combined -t (-t<dir>, -ft <dir>),
    and an evidence file that is a symlink to a file outside the cases dir.
    """
    cmd = list(command)
    while cmd and os.path.basename(cmd[0]) in _WRAPPERS:
        w = os.path.basename(cmd.pop(0))
        while cmd and (
            cmd[0].startswith("-")
            or "=" in cmd[0]
            or (w == "timeout" and cmd[0][:1].isdigit())
        ):
            o = cmd.pop(0)
            if (w, o) in (("sudo", "-u"), ("sudo", "-g"), ("nice", "-n")) and cmd:
                cmd.pop(0)
    if not cmd:
        return
    name = os.path.basename(cmd[0])
    args, dd, tdir, no_t, it = [], False, None, False, iter(cmd[1:])
    for a in it:
        if a == "--" and not dd:
            dd = True
        elif not dd and (
            a == "--no-target-directory"
            or (a[:2] != "--" and a[:1] == "-" and "T" in a)
        ):
            no_t = True
        elif not dd and a in ("-t", "--target-directory"):
            tdir = next(it, None)
        elif not dd and a.startswith("--target-directory="):
            tdir = a.split("=", 1)[1]
        elif dd or not a.startswith("-"):
            args.append(a)
    if tdir is not None:
        args.append(tdir)
    bad = []
    if name in ("rm", "shred", "unlink", "truncate", "tee"):
        bad = [a for a in args if _harms_case_data(a, new_ok=name == "tee")]
    elif name in ("mv", "cp", "install", "ln") and len(args) >= 2:
        dst = args[-1]
        into = not no_t and os.path.isdir(dst)
        for s in args[:-1]:
            if name == "mv" and _harms_case_data(s):
                bad.append(s)
            tgt = os.path.join(dst, os.path.basename(s)) if into else dst
            if _harms_case_data(tgt, new_ok=True):
                bad.append(tgt)
    if bad:
        raise ValueError(
            f"Blocked: {name} would delete or overwrite case data at '{bad[0]}'. "
            "Case records, audit/ and evidence files are protected; move other "
            "files to the case's DELETE/ directory instead."
        )


_BLOCKED_DIRECTORIES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    os.path.expanduser("~/.vhir"),
)

# Exceptions within blocked directories (evidence data, not config)
_BLOCKED_EXCEPTIONS = (
    os.path.expanduser("~/.vhir/cases"),
    os.path.expanduser("~/.vhir/hayabusa-output"),
)


def get_output_flags() -> frozenset:
    """Return the set of flags that take output path values."""
    return _get_policy()["output_flags"]


# Directories blocked for output (superset of _BLOCKED_DIRECTORIES)
_OUTPUT_BLOCKED_DIRECTORIES = _BLOCKED_DIRECTORIES + (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/var",
    "/home",
)


def validate_output_path(path: str) -> str:
    """Validate that an output path is safe to write to.

    Stricter than validate_input_path. When VHIR_CASE_DIR is set, the
    output path must be inside the case directory. When not set, only
    /tmp and the current working directory are allowed.

    Case-dir containment is checked first so that case directories
    under /home are allowed.
    """
    resolved = str(Path(path).resolve())

    # Case-dir containment: if inside case dir, it's allowed
    case_dir = resolve_case_dir()
    if case_dir:
        case_resolved = str(Path(case_dir).resolve())
        if resolved == case_resolved or resolved.startswith(case_resolved + "/"):
            return resolved
        raise ValueError(
            f"Output path '{path}' resolves to '{resolved}' which is "
            f"outside the case directory '{case_resolved}'"
        )

    # No case dir: allow /tmp and cwd before checking blocked dirs
    if resolved.startswith("/tmp/") or resolved == "/tmp":
        return resolved
    cwd = str(Path.cwd().resolve())
    if resolved == cwd or resolved.startswith(cwd + "/"):
        return resolved

    # Block system directories
    for blocked in _OUTPUT_BLOCKED_DIRECTORIES:
        if resolved == blocked or resolved.startswith(blocked + "/"):
            raise ValueError(
                f"Output denied: path '{path}' resolves to '{resolved}' "
                f"which is inside blocked directory '{blocked}'"
            )

    raise ValueError(
        f"Output denied: path '{path}' resolves to '{resolved}'. "
        f"Without an active case, output is only allowed in /tmp or "
        f"the current working directory"
    )


def validate_input_path(path: str) -> str:
    """Validate that an input file path is not in a blocked system directory.

    Resolves symlinks, then checks against a blocklist of sensitive system
    directories. Also parses flag=value arguments and validates the value
    portion as a path. Raises ValueError if the resolved path falls within
    a blocked directory. Returns the resolved path string if valid.
    """
    # Handle flag=value arguments: validate the value portion as a path
    if "=" in path and path.startswith("-"):
        value = path.split("=", 1)[1]
        if value and (value.startswith("/") or value.startswith("..") or "/" in value):
            return validate_input_path(value)
        return path

    resolved = str(Path(path).resolve())
    for blocked in _BLOCKED_DIRECTORIES:
        if resolved == blocked or resolved.startswith(blocked + "/"):
            # Check if path falls within an allowed exception (evidence data)
            if any(
                resolved == exc or resolved.startswith(exc + "/")
                for exc in _BLOCKED_EXCEPTIONS
            ):
                break  # Allowed exception
            raise ValueError(
                f"Access denied: path '{path}' resolves to '{resolved}' "
                f"which is inside blocked system directory '{blocked}'"
            )
    return resolved
