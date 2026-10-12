"""Importer for HijackLibs (DLL hijacking opportunities) data."""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import yaml

from ..db.schemas import CONTEXT_SCHEMA

logger = logging.getLogger(__name__)


def import_hijacklibs(db_path: Path, hijacklibs_dir: Path) -> dict:
    """
    Import HijackLibs data into context.db.

    Args:
        db_path: Path to context.db
        hijacklibs_dir: Path to cloned HijackLibs repository

    Returns:
        Dict with import statistics
    """
    stats = {
        "dlls_imported": 0,
        "entries_imported": 0,
        "duplicates": 0,
        "errors": 0,
        "skipped": 0,
    }

    yml_dir = hijacklibs_dir / "yml"
    if not yml_dir.exists():
        logger.error(f"HijackLibs yml directory not found: {yml_dir}")
        return stats

    # Parse everything first: the table is replaced only when there is data
    parsed = []
    for yml_file in sorted(yml_dir.rglob("*.yml")):
        try:
            entries = _parse_hijacklib_yaml(yml_file)
        except Exception as e:
            stats["errors"] += 1
            if stats["errors"] <= 10:
                logger.warning(f"Error processing {yml_file}: {e}")
            continue
        if entries:
            parsed.append(entries)
        else:
            stats["skipped"] += 1
    if not parsed:
        logger.error(
            f"HijackLibs: 0 entries parsed from {yml_dir}; hijackable_dlls left unchanged"
        )
        return stats

    conn = sqlite3.connect(db_path)
    try:
        # One transaction: a context.db made before 0.6.5 gets the (dll, exe
        # path, type) key, and the old table survives any failure before commit
        conn.executescript(
            "BEGIN; DROP TABLE IF EXISTS hijackable_dlls;" + CONTEXT_SCHEMA
        )
        cursor = conn.cursor()
        for entries in parsed:
            stats["dlls_imported"] += 1
            for entry in entries:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO hijackable_dlls (
                        dll_name_lower, hijack_type, vulnerable_exe,
                        vulnerable_exe_path, expected_paths, vendor
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        entry["dll_name_lower"],
                        entry["hijack_type"],
                        entry["vulnerable_exe"],
                        entry["vulnerable_exe_path"],
                        json.dumps(entry["expected_paths"]),
                        entry["vendor"],
                    ),
                )
                stats["entries_imported" if cursor.rowcount else "duplicates"] += 1
        conn.commit()
        logger.info(
            f"Imported {stats['dlls_imported']} hijackable DLLs "
            f"({stats['entries_imported']} vulnerable exe entries; "
            f"{stats['duplicates']} duplicate entries not stored)"
        )

    finally:
        conn.close()

    return stats


def _parse_hijacklib_yaml(yml_path: Path) -> list[dict[str, Any]]:
    """
    Parse a single HijackLibs YAML file.

    Args:
        yml_path: Path to YAML file

    Returns:
        List of dicts with parsed hijackable DLL entries
    """
    with open(yml_path, encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {yml_path}: {e}")
            return []

    if not data or not data.get("Name"):
        return []

    dll_name = data["Name"]
    dll_name_lower = dll_name.lower()
    vendor = data.get("Vendor", "Unknown")

    # Get expected locations
    expected_paths = []
    for loc in data.get("ExpectedLocations", []):
        # Normalize path variables
        normalized = _normalize_path_var(loc)
        if normalized:
            expected_paths.append(normalized)

    entries = []

    # Process each vulnerable executable
    for vuln_exe in data.get("VulnerableExecutables", []):
        exe_path = vuln_exe.get("Path", "")
        if not exe_path:
            continue

        # Normalize the path
        exe_path_normalized = _normalize_path_var(exe_path)

        # Extract executable name from path
        exe_name = (
            exe_path_normalized.split("\\")[-1].lower() if exe_path_normalized else ""
        )

        hijack_type = vuln_exe.get("Type", "Unknown")

        entries.append(
            {
                "dll_name_lower": dll_name_lower,
                "hijack_type": hijack_type,
                "vulnerable_exe": exe_name,
                "vulnerable_exe_path": exe_path_normalized.lower(),
                "expected_paths": expected_paths,
                "vendor": vendor,
                "auto_elevate": vuln_exe.get("AutoElevate", False),
                "privilege_escalation": vuln_exe.get("PrivilegeEscalation", False),
            }
        )

    return entries


def _normalize_path_var(path: str) -> str:
    """
    Normalize Windows path variables to lowercase paths.

    Args:
        path: Path with potential environment variables

    Returns:
        Normalized lowercase path
    """
    if not path:
        return ""

    # Common Windows path variable mappings
    replacements = {
        "%SYSTEM32%": "\\windows\\system32",
        "%SYSWOW64%": "\\windows\\syswow64",
        "%SYSTEMROOT%": "\\windows",
        "%WINDIR%": "\\windows",
        "%PROGRAMFILES%": "\\program files",
        "%PROGRAMFILES(X86)%": "\\program files (x86)",
        "%COMMONPROGRAMFILES%": "\\program files\\common files",
        "%COMMONPROGRAMFILES(X86)%": "\\program files (x86)\\common files",
        "%APPDATA%": "\\users\\<user>\\appdata\\roaming",
        "%LOCALAPPDATA%": "\\users\\<user>\\appdata\\local",
        "%USERPROFILE%": "\\users\\<user>",
        "%TEMP%": "\\users\\<user>\\appdata\\local\\temp",
        "%TMP%": "\\users\\<user>\\appdata\\local\\temp",
        "%PROGRAMDATA%": "\\programdata",
        "%ALLUSERSPROFILE%": "\\programdata",
    }

    result = path
    for var, replacement in replacements.items():
        result = result.replace(var, replacement)

    # Normalize slashes and case
    result = result.replace("/", "\\").lower()

    # Remove drive letter if present
    if len(result) > 2 and result[1] == ":":
        result = result[2:]

    return result


def get_hijack_types() -> list[str]:
    """
    Get list of DLL hijacking types.
    """
    return [
        "Phantom",  # DLL doesn't exist, can be planted
        "Sideloading",  # DLL loaded from same directory as exe
        "Search Order",  # Exploits DLL search order
        "Environment Variable",  # Exploits environment variable path
    ]
