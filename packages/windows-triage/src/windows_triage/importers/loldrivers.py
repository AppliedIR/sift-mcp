"""Importer for LOLDrivers (Living Off The Land Drivers) data."""

import logging
import sqlite3
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def import_loldrivers(
    db_path: Path, loldrivers_dir: Path, include_malicious: bool = False
) -> dict:
    """
    Import LOLDrivers data into context.db.

    By default, only imports "vulnerable driver" category - these are legitimate
    drivers that can be abused by attackers. Optionally include malicious drivers.

    Args:
        db_path: Path to context.db
        loldrivers_dir: Path to cloned LOLDrivers repository
        include_malicious: If True, also import malicious drivers

    Returns:
        Dict with import statistics
    """
    stats = {
        "vulnerable_imported": 0,
        "malicious_imported": 0,
        "samples_imported": 0,
        "errors": 0,
        "skipped": 0,
    }

    yaml_dir = loldrivers_dir / "yaml"
    if not yaml_dir.exists():
        logger.error(f"LOLDrivers yaml directory not found: {yaml_dir}")
        return stats

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        for yaml_file in yaml_dir.glob("*.yaml"):
            try:
                driver = _parse_loldriver_yaml(yaml_file)
                if not driver:
                    stats["skipped"] += 1
                    continue

                category = driver.get("category", "").lower()

                # Filter by category
                is_vulnerable = "vulnerable" in category
                is_malicious = "malicious" in category

                if not is_vulnerable and not (include_malicious and is_malicious):
                    stats["skipped"] += 1
                    continue

                # Import each sample (hash) as a separate row
                for sample in driver.get("samples", []):
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO vulnerable_drivers (
                            filename_lower, sha256, sha1, md5,
                            authentihash_sha256, authentihash_sha1, authentihash_md5,
                            vendor, product, cve, vulnerability_type, description
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            sample.get("filename_lower"),
                            sample.get("sha256"),
                            sample.get("sha1"),
                            sample.get("md5"),
                            sample.get("authentihash_sha256"),
                            sample.get("authentihash_sha1"),
                            sample.get("authentihash_md5"),
                            sample.get("company"),
                            sample.get("product"),
                            driver.get("cve"),
                            category,
                            driver.get("description"),
                        ),
                    )
                    stats["samples_imported"] += 1

                if is_vulnerable:
                    stats["vulnerable_imported"] += 1
                elif is_malicious:
                    stats["malicious_imported"] += 1

            except Exception as e:
                stats["errors"] += 1
                if stats["errors"] <= 10:
                    logger.warning(f"Error processing {yaml_file}: {e}")

        conn.commit()
        logger.info(
            f"Imported {stats['vulnerable_imported']} vulnerable drivers "
            f"({stats['samples_imported']} samples)"
        )

    finally:
        conn.close()

    return stats


def _parse_loldriver_yaml(yaml_path: Path) -> dict[str, Any] | None:
    """
    Parse a single LOLDrivers YAML file.

    Args:
        yaml_path: Path to YAML file

    Returns:
        Dict with parsed driver data, or None if invalid
    """
    with open(yaml_path, encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {yaml_path}: {e}")
            return None

    if not data:
        return None

    category = data.get("Category", "")
    description = ""

    # Extract description from Commands if present
    commands = data.get("Commands", {})
    if isinstance(commands, dict):
        description = commands.get("Description", "")

    # Extract CVE from resources or description
    cve = None
    resources = data.get("Resources", [])
    if resources:
        for resource in resources:
            if isinstance(resource, str) and "CVE-" in resource.upper():
                import re

                match = re.search(r"CVE-\d{4}-\d+", resource, re.IGNORECASE)
                if match:
                    cve = match.group(0).upper()
                    break

    # Parse samples
    samples = []
    for sample in data.get("KnownVulnerableSamples", []):
        if not sample:
            continue

        filename = sample.get("Filename") or sample.get("OriginalFilename") or ""

        # Extract Authentihash (authenticode hash) if present
        authentihash = sample.get("Authentihash", {}) or {}

        samples.append(
            {
                "filename_lower": filename.lower() if filename else None,
                "sha256": sample.get("SHA256", "").lower()
                if sample.get("SHA256")
                else None,
                "sha1": sample.get("SHA1", "").lower() if sample.get("SHA1") else None,
                "md5": sample.get("MD5", "").lower() if sample.get("MD5") else None,
                "authentihash_sha256": authentihash.get("SHA256", "").lower()
                if authentihash.get("SHA256")
                else None,
                "authentihash_sha1": authentihash.get("SHA1", "").lower()
                if authentihash.get("SHA1")
                else None,
                "authentihash_md5": authentihash.get("MD5", "").lower()
                if authentihash.get("MD5")
                else None,
                "company": sample.get("Company"),
                "product": sample.get("Product"),
            }
        )

    return {
        "id": data.get("Id"),
        "category": category,
        "description": description,
        "cve": cve,
        "samples": samples,
        "mitre_id": data.get("MitreID"),
        "tags": data.get("Tags", []),
    }
