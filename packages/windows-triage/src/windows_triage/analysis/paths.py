"""
Path Normalization and Analysis Utilities for Windows Forensics

This module provides utilities for normalizing and analyzing Windows file paths.
Consistent path normalization is critical for baseline matching since paths
from different sources may have different formats.

Normalization Rules:
    1. Lowercase the entire path (Windows paths are case-insensitive)
    2. Remove drive letter (C:\\Windows -> \\windows)
    3. Normalize separators (/ -> \\)
    4. Remove trailing slashes

Examples:
    C:\\Windows\\System32\\cmd.exe -> \\windows\\system32\\cmd.exe
    c:\\WINDOWS\\system32\\CMD.EXE -> \\windows\\system32\\cmd.exe
    C:/Users/Admin/file.txt -> \\users\\admin\\file.txt

System Directory Detection:
    - \\windows\\system32 (primary system binaries)
    - \\windows\\syswow64 (32-bit binaries on 64-bit Windows)
    - \\windows\\winsxs (side-by-side assembly cache)
    - \\program files, \\program files (x86) (installed applications)

Suspicious Directory Detection:
    - Temp folders (\\temp, \\windows\\temp, \\appdata\\local\\temp)
    - User-writable locations (\\users\\public, \\programdata)
    - Common staging areas (\\perflogs, \\intel, \\recycler)
"""

import re

# Env-var and system-path placeholders commonly found in registry
# persistence values (Run keys, Service ImagePath, Active Setup
# StubPath, NetSh Helper DLLs, Scheduled Tasks). Registry stores these
# un-expanded; downstream path-match needs the resolved forms or
# legitimate Microsoft binaries get flagged SUSPICIOUS via the
# "System binary in unexpected directory (masquerade indicator)"
# fallback in verdicts.py.
#
# Match is case-insensitive — callers lowercase before lookup, so keys
# are lowercase here. First-match-wins; order does not matter (each
# placeholder is unique).
_ENV_EXPANSIONS = {
    "%windir%": r"\windows",
    "%systemroot%": r"\windows",
    "%programfiles%": r"\program files",
    "%programfiles(x86)%": r"\program files (x86)",
    "%programdata%": r"\programdata",
    "%allusersprofile%": r"\programdata",  # maps to ProgramData on Vista+
    "%systemdrive%": "",  # drive letter; leaves the rest of the path intact
    "\\systemroot\\": "\\windows\\",
}


def normalize_path(path: str) -> str:
    r"""
    Normalize a Windows path for database storage and lookup.

    Transformations:
    - Lowercase the entire path
    - Expand environment-variable placeholders (%windir%,
      %SystemRoot%, %ProgramFiles%, %ProgramFiles(x86)%, %ProgramData%,
      %SystemDrive%, %AllUsersProfile%, and the \SystemRoot\ kernel
      prefix). Must run BEFORE drive-letter strip so
      %SystemDrive%\windows\... resolves correctly.
    - Remove drive letter (C:\Windows -> \windows)
    - Normalize separators (/ -> \)
    - Remove trailing slashes

    Pre-fix, registry values like `%windir%\system32\cmd.exe` matched
    none of the baseline rows (which store `\windows\system32\...`),
    fell through to the filename-match fallback, and hit the
    _MASQUERADE_TARGETS check — producing false SUSPICIOUS verdicts on
    every Windows 10/11 autorun that uses unexpanded placeholders
    (SecurityHealthSystray and friends). See
    `specs/windows-triage-env-var-normalize-2026-04-24.md`.

    Examples:
        %windir%\System32\cmd.exe         -> \windows\system32\cmd.exe
        %SystemRoot%\System32\cmd.exe     -> \windows\system32\cmd.exe
        %ProgramFiles%\App\app.exe        -> \program files\app\app.exe
        C:\Windows\System32\cmd.exe       -> \windows\system32\cmd.exe
        c:\WINDOWS\system32\CMD.EXE       -> \windows\system32\cmd.exe
        C:/Users/Admin/file.txt           -> \users\admin\file.txt
    """
    if not path:
        return path

    # Lowercase first so env-var matching is case-insensitive.
    path = path.lower()

    # Env-var / system-path expansion. Runs before drive-strip so
    # `%systemdrive%\windows\...` (placeholder produces "", leaving the
    # trailing `\windows\...` intact) is handled correctly.
    for placeholder, replacement in _ENV_EXPANSIONS.items():
        if path.startswith(placeholder):
            path = replacement + path[len(placeholder):]
            break

    # Remove drive letter (C:\Windows -> \windows)
    if len(path) > 2 and path[1] == ":":
        path = path[2:]

    # Normalize separators (/ -> \)
    path = path.replace("/", "\\")

    # Remove trailing slashes, but preserve root directory
    stripped = path.rstrip("\\")
    if not stripped:
        # Path was just backslashes (root directory) - preserve single backslash
        return "\\"

    return stripped


def extract_filename(path: str) -> str:
    """
    Extract the filename from a Windows path.

    Args:
        path: Windows file path

    Returns:
        The filename portion, lowercase
    """
    if not path:
        return ""

    # Normalize separators first
    path = path.replace("/", "\\")

    # Get last component
    parts = path.split("\\")
    return parts[-1].lower() if parts else ""


def extract_directory(path: str) -> str:
    """
    Extract the directory portion from a Windows path.

    Args:
        path: Windows file path

    Returns:
        The directory portion, normalized. Returns empty string if path
        has no directory component (just a filename).
    """
    if not path:
        return ""

    normalized = normalize_path(path)
    if not normalized:
        return ""

    # Find last backslash
    last_sep = normalized.rfind("\\")
    if last_sep < 0:
        # No separator - just a filename, no directory
        return ""
    if last_sep == 0:
        # Root directory (e.g., \windows from \windows\cmd.exe)
        return "\\"
    return normalized[:last_sep]


# Windows system directories (expected locations for system binaries)
SYSTEM_DIRECTORIES = [
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\winsxs",
    "\\windows",
    "\\program files",
    "\\program files (x86)",
]


def is_system_path(path: str) -> bool:
    """
    Check if a path is in a Windows system directory.

    Args:
        path: Windows file path

    Returns:
        True if path is in a system directory
    """
    normalized = normalize_path(path)
    if not normalized:
        return False
    for sys_dir in SYSTEM_DIRECTORIES:
        # Must match directory boundary: either exact match or followed by backslash
        if normalized == sys_dir or normalized.startswith(sys_dir + "\\"):
            return True
    return False


# Paths commonly used by malware for staging
SUSPICIOUS_DIRECTORIES = [
    "\\temp",
    "\\tmp",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
    "\\users\\public",
    "\\programdata",
    "\\windows\\temp",
    "\\downloads",
    "\\desktop",
    "\\perflogs",
    "\\intel",
    "\\recycler",
    "\\$recycle.bin",
]


def check_suspicious_path(path: str) -> list[dict]:
    """
    Check if a file path is in a commonly-abused location.

    Args:
        path: Windows file path

    Returns:
        List of findings with type, severity, and description
    """
    findings = []
    normalized = normalize_path(path)

    for suspicious in SUSPICIOUS_DIRECTORIES:
        # Check if the suspicious directory is in the path
        if suspicious in normalized:
            findings.append(
                {
                    "type": "suspicious_directory",
                    "severity": "low",
                    "matched": suspicious.lstrip("\\"),
                    "description": "File in commonly-abused directory",
                }
            )
            break  # Only report once

    return findings


def parse_service_binary_path(image_path: str) -> str:
    r"""
    Parse a Windows service ImagePath value to extract the executable.

    Service ImagePath can contain:
    - Quoted paths: "C:\Path\service.exe" -args
    - Unquoted paths: C:\Path\service.exe
    - System paths: \SystemRoot\System32\svc.exe
    - Environment variables: %SystemRoot%\System32\svc.exe

    Args:
        image_path: Raw ImagePath value from registry

    Returns:
        Normalized path to the executable
    """
    if not image_path:
        return ""

    path = image_path.strip()

    # Handle quoted paths
    if path.startswith('"'):
        end_quote = path.find('"', 1)
        if end_quote > 0:
            path = path[1:end_quote]
        else:
            path = path[1:]  # No closing quote, take rest
    else:
        # Unquoted - take up to first space (if any)
        # But be careful: "C:\Program Files\..." has spaces in path
        # Heuristic: if starts with drive letter or \, find .exe/.sys/.dll
        exe_match = re.search(r'^([^"]*?\.(exe|sys|dll|ocx))', path, re.IGNORECASE)
        if exe_match:
            path = exe_match.group(1)
        else:
            # Fall back to first space
            space_idx = path.find(" ")
            if space_idx > 0:
                path = path[:space_idx]

    # Expand common system paths. The %SystemRoot%\ / \SystemRoot\
    # prefixes used to live here; they now live in normalize_path's
    # _ENV_EXPANSIONS so every caller benefits (Run keys, Active Setup,
    # NetSh DLLs, scheduled tasks — not just service ImagePaths).
    # `system32\...` relative-path expansion stays local to this
    # function because it's not an env var — it's the special case
    # where a bare ImagePath starts with `system32\` and implicitly
    # resolves against %SystemRoot%.
    path_lower = path.lower()
    if path_lower.startswith("system32\\"):
        path = "\\windows\\system32\\" + path[9:]

    return normalize_path(path)
