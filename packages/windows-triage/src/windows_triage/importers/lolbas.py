"""
Importer for LOLBAS (Living Off The Land Binaries and Scripts) Data

This module imports LOLBin definitions from the LOLBAS project
(github.com/LOLBAS-Project/LOLBAS) into context.db.

What are LOLBins?
    Living Off The Land Binaries (LOLBins) are legitimate, signed Windows
    executables that attackers abuse to:
    - Download malicious payloads (certutil.exe, bitsadmin.exe)
    - Execute arbitrary code (mshta.exe, regsvr32.exe)
    - Bypass application whitelisting
    - Access credentials (procdump.exe)
    - Perform reconnaissance

    These are NOT malware - they're built-in Windows tools. The risk comes
    from how they can be abused.

Data Imported:
    - Filename (for lookup)
    - Abuse functions (Download, Execute, AWL Bypass, etc.)
    - Expected paths (legitimate locations)
    - MITRE ATT&CK technique IDs
    - Detection guidance
    - Source URL for reference

Categories:
    - OSBinaries: Built-in Windows executables (cmd.exe, powershell.exe)
    - OSLibraries: DLLs with abuse potential
    - OSScripts: Built-in scripts (cscript, wscript)
    - OtherMSBinaries: Other Microsoft-signed tools

Abuse Functions:
    - Download: Download files from internet
    - Execute: Execute arbitrary code
    - AWL Bypass: Application Whitelist bypass
    - Credentials: Credential access
    - UAC Bypass: Bypass User Account Control
    - Encode/Decode: Obfuscation capabilities
    - ADS: Alternate Data Stream manipulation

Setup:
    git clone https://github.com/LOLBAS-Project/LOLBAS.git
    python scripts/import_all.py

Result:
    ~227 LOLBins imported with abuse functions and detection guidance
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def import_lolbas(db_path: Path, lolbas_dir: Path) -> dict:
    """
    Import LOLBAS data into context.db.

    Args:
        db_path: Path to context.db
        lolbas_dir: Path to cloned LOLBAS repository

    Returns:
        Dict with import statistics
    """
    stats = {"lolbins_imported": 0, "errors": 0, "skipped": 0}

    yml_dir = lolbas_dir / "yml"
    if not yml_dir.exists():
        logger.error(f"LOLBAS yml directory not found: {yml_dir}")
        return stats

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Process each category
        categories = ["OSBinaries", "OSLibraries", "OSScripts", "OtherMSBinaries"]

        for category in categories:
            category_dir = yml_dir / category
            if not category_dir.exists():
                continue

            logger.info(f"Processing {category}...")

            for yml_file in category_dir.glob("*.yml"):
                try:
                    lolbin = _parse_lolbas_yml(yml_file, category)
                    if not lolbin:
                        stats["skipped"] += 1
                        continue

                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO lolbins (
                            filename_lower, name, description, functions,
                            expected_paths, mitre_techniques, detection, source_url
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            lolbin["filename_lower"],
                            lolbin["name"],
                            lolbin["description"],
                            json.dumps(lolbin["functions"]),
                            json.dumps(lolbin["expected_paths"]),
                            json.dumps(lolbin["mitre_techniques"]),
                            lolbin["detection"],
                            f"https://lolbas-project.github.io/lolbas/{category}/{yml_file.stem}/",
                        ),
                    )
                    stats["lolbins_imported"] += 1

                except Exception as e:
                    stats["errors"] += 1
                    if stats["errors"] <= 10:
                        logger.warning(f"Error processing {yml_file}: {e}")

        conn.commit()
        logger.info(f"Imported {stats['lolbins_imported']} LOLBins")

    finally:
        conn.close()

    return stats


def _parse_lolbas_yml(yml_path: Path, category: str) -> dict[str, Any] | None:
    """
    Parse a single LOLBAS YAML file.

    Args:
        yml_path: Path to YAML file
        category: Category (OSBinaries, etc.)

    Returns:
        Dict with parsed LOLBin data, or None if invalid
    """
    with open(yml_path, encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {yml_path}: {e}")
            return None

    if not data or not data.get("Name"):
        return None

    name = data["Name"]
    filename_lower = name.lower()

    # Extract unique functions/categories from commands
    functions = set()
    mitre_techniques = set()

    for cmd in data.get("Commands", []):
        if cmd.get("Category"):
            functions.add(cmd["Category"])
        if cmd.get("MitreID"):
            mitre_techniques.add(cmd["MitreID"])

    # Extract expected paths
    expected_paths = []
    for path_entry in data.get("Full_Path", []):
        if path_entry.get("Path"):
            expected_paths.append(path_entry["Path"].lower())

    # Extract detection info
    detection_items = []
    for det in data.get("Detection", []):
        if det.get("IOC"):
            detection_items.append(f"IOC: {det['IOC']}")

    # Handle aliases
    aliases = []
    for alias_entry in data.get("Aliases", []):
        if alias_entry.get("Alias"):
            aliases.append(alias_entry["Alias"].lower())

    return {
        "filename_lower": filename_lower,
        "name": name,
        "description": data.get("Description", ""),
        "functions": sorted(functions),
        "expected_paths": expected_paths,
        "mitre_techniques": sorted(mitre_techniques),
        "detection": "\n".join(detection_items) if detection_items else None,
        "aliases": aliases,
        "category": category,
    }


def get_lolbin_functions() -> list[str]:
    """
    Get list of all LOLBAS function categories.

    These are the ways LOLBins can be abused.
    """
    return [
        "Download",  # Download files from internet
        "Upload",  # Exfiltrate data
        "Execute",  # Execute arbitrary code
        "AWL Bypass",  # Application Whitelist bypass
        "ADS",  # Alternate Data Streams
        "Encode",  # Encode/obfuscate
        "Decode",  # Decode payloads
        "Copy",  # Copy files
        "Compile",  # Compile code
        "Credentials",  # Credential access
        "Reconnaissance",  # System enumeration
        "UAC Bypass",  # Bypass UAC
    ]
