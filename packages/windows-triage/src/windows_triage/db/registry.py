"""
known_good_registry.db Operations - Full Registry Baseline (Optional)

This module provides the database interface for known_good_registry.db,
an optional 12GB database containing full registry baselines from
VanillaWindowsRegistryHives.

Use Case:
    Validate arbitrary registry keys/values against clean Windows installations.
    This is separate from the extracted services/tasks/autoruns in known_good.db.

Schema:
    - baseline_registry: Full key/value pairs with os_versions JSON array
    - baseline_os: OS version metadata

Usage:
    from windows_triage.db import RegistryDB

    db = RegistryDB("/path/to/known_good_registry.db")

    # Check if a key exists in baseline
    result = db.lookup_key("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")

    # Check if a specific value exists
    result = db.lookup_value(
        key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name="SecurityHealth"
    )
"""

import json
import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Any

from .schemas import REGISTRY_FULL_SCHEMA


class RegistryDB:
    """Interface to known_good_registry.db for full registry baseline lookups."""

    # Valid registry hives
    VALID_HIVES = {"SYSTEM", "SOFTWARE", "NTUSER", "DEFAULT", "SAM", "SECURITY"}

    def __init__(
        self, db_path: str | Path, read_only: bool = True, cache_size: int = 10000
    ):
        """Initialize connection to known_good_registry.db.

        Args:
            db_path: Path to SQLite database file
            read_only: If True, open database in read-only mode (default for this optional DB)
            cache_size: Size of LRU cache for lookups (0 to disable)
        """
        self.db_path = Path(db_path)
        self.read_only = read_only
        self.cache_size = cache_size
        self._conn: sqlite3.Connection | None = None

        # Configure LRU cache sizes based on cache_size parameter
        if cache_size > 0:
            self._lookup_key_cached = lru_cache(maxsize=cache_size)(
                self._lookup_key_uncached
            )
            self._lookup_value_cached = lru_cache(maxsize=cache_size)(
                self._lookup_value_uncached
            )

    def connect(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            if self.read_only:
                # Open in read-only mode using URI
                uri = f"file:{self.db_path}?mode=ro"
                self._conn = sqlite3.connect(uri, uri=True)
            else:
                self._conn = sqlite3.connect(str(self.db_path))
                # Performance pragmas for read-write mode
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def init_schema(self):
        """Initialize database schema."""
        conn = self.connect()
        conn.executescript(REGISTRY_FULL_SCHEMA)
        conn.commit()

    def is_available(self) -> bool:
        """Check if the registry database exists and is accessible."""
        if not self.db_path.exists():
            return False
        try:
            conn = self.connect()
            # Check if baseline_registry table exists
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='baseline_registry'"
            )
            return cursor.fetchone() is not None
        except Exception:
            return False

    @staticmethod
    def normalize_key_path(key_path: str) -> str:
        """Normalize registry key path for consistent lookups.

        - Convert to lowercase
        - Normalize backslashes
        - Strip leading/trailing backslashes
        """
        if not key_path:
            return ""
        # Normalize path separators and case
        normalized = key_path.replace("/", "\\").lower().strip("\\")
        return normalized

    @staticmethod
    def extract_hive(key_path: str) -> str | None:
        """Extract hive name from key path if present.

        Examples:
            "HKLM\\SOFTWARE\\Microsoft" -> "SOFTWARE"
            "SOFTWARE\\Microsoft" -> "SOFTWARE"
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet" -> "SYSTEM"
        """
        if not key_path:
            return None

        normalized = key_path.upper().replace("/", "\\").strip("\\")

        # Handle full HKEY paths
        hkey_mapping = {
            "HKEY_LOCAL_MACHINE": None,  # Needs further parsing
            "HKLM": None,
            "HKEY_CURRENT_USER": "NTUSER",
            "HKCU": "NTUSER",
            "HKEY_USERS": None,
            "HKU": None,
        }

        parts = normalized.split("\\")
        first_part = parts[0]

        if first_part in hkey_mapping:
            if hkey_mapping[first_part]:
                return hkey_mapping[first_part]
            # For HKLM, the next part is the hive
            if len(parts) > 1 and parts[1] in RegistryDB.VALID_HIVES:
                return parts[1]
            return None

        # Direct hive name
        if first_part in RegistryDB.VALID_HIVES:
            return first_part

        return None

    def lookup_key(
        self, key_path: str, hive: str | None = None, os_version: str | None = None
    ) -> list[dict[str, Any]]:
        """Look up a registry key in the baseline.

        Args:
            key_path: Registry key path (e.g., "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
            hive: Optional hive filter (SYSTEM, SOFTWARE, NTUSER, DEFAULT)
            os_version: Optional OS version filter

        Returns:
            List of matching entries with os_versions and value info
        """
        key_normalized = self.normalize_key_path(key_path)
        if not key_normalized:
            return []

        # Try to extract hive from path if not provided
        if not hive:
            hive = self.extract_hive(key_path)

        # Use cache if available
        if self.cache_size > 0:
            results = self._lookup_key_cached(key_normalized, hive, os_version)
        else:
            results = self._lookup_key_uncached(key_normalized, hive, os_version)

        return list(results)

    def _lookup_key_uncached(
        self, key_normalized: str, hive: str | None, os_version: str | None
    ) -> tuple:
        """Uncached key lookup implementation."""
        conn = self.connect()

        # Build query based on filters (LIMIT prevents resource exhaustion)
        if hive:
            query = """
                SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions
                FROM baseline_registry
                WHERE key_path_lower = ? AND hive = ?
                ORDER BY value_name
                LIMIT 1000
            """
            cursor = conn.execute(query, (key_normalized, hive.upper()))
        else:
            query = """
                SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions
                FROM baseline_registry
                WHERE key_path_lower = ?
                ORDER BY hive, value_name
                LIMIT 1000
            """
            cursor = conn.execute(query, (key_normalized,))

        results = []
        for row in cursor:
            os_versions_list = (
                json.loads(row["os_versions"]) if row["os_versions"] else []
            )

            # Filter by OS version if specified
            if os_version and os_version not in os_versions_list:
                continue

            results.append(
                {
                    "hive": row["hive"],
                    "key_path": row["key_path_lower"],
                    "value_name": row["value_name"],
                    "value_type": row["value_type"],
                    "value_data": row["value_data"],
                    "os_versions": os_versions_list,
                }
            )

        return tuple(results)

    def lookup_value(
        self,
        key_path: str,
        value_name: str,
        hive: str | None = None,
        os_version: str | None = None,
    ) -> list[dict[str, Any]]:
        """Look up a specific registry value in the baseline.

        Args:
            key_path: Registry key path
            value_name: Value name to look up
            hive: Optional hive filter
            os_version: Optional OS version filter

        Returns:
            List of matching entries
        """
        key_normalized = self.normalize_key_path(key_path)
        if not key_normalized:
            return []

        if not hive:
            hive = self.extract_hive(key_path)

        # Use cache if available
        if self.cache_size > 0:
            results = self._lookup_value_cached(
                key_normalized, value_name, hive, os_version
            )
        else:
            results = self._lookup_value_uncached(
                key_normalized, value_name, hive, os_version
            )

        return list(results)

    def _lookup_value_uncached(
        self,
        key_normalized: str,
        value_name: str,
        hive: str | None,
        os_version: str | None,
    ) -> tuple:
        """Uncached value lookup implementation."""
        conn = self.connect()

        # Build query based on filters (LIMIT prevents resource exhaustion)
        if hive:
            query = """
                SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions
                FROM baseline_registry
                WHERE key_path_lower = ? AND value_name = ? AND hive = ?
                LIMIT 1000
            """
            cursor = conn.execute(query, (key_normalized, value_name, hive.upper()))
        else:
            query = """
                SELECT hive, key_path_lower, value_name, value_type, value_data, os_versions
                FROM baseline_registry
                WHERE key_path_lower = ? AND value_name = ?
                ORDER BY hive
                LIMIT 1000
            """
            cursor = conn.execute(query, (key_normalized, value_name))

        results = []
        for row in cursor:
            os_versions_list = (
                json.loads(row["os_versions"]) if row["os_versions"] else []
            )

            # Filter by OS version if specified
            if os_version and os_version not in os_versions_list:
                continue

            results.append(
                {
                    "hive": row["hive"],
                    "key_path": row["key_path_lower"],
                    "value_name": row["value_name"],
                    "value_type": row["value_type"],
                    "value_data": row["value_data"],
                    "os_versions": os_versions_list,
                }
            )

        return tuple(results)

    def key_exists(self, key_path: str, hive: str | None = None) -> bool:
        """Check if a key exists in any baseline."""
        return len(self.lookup_key(key_path, hive)) > 0

    def value_exists(
        self, key_path: str, value_name: str, hive: str | None = None
    ) -> bool:
        """Check if a specific value exists in any baseline."""
        return len(self.lookup_value(key_path, value_name, hive)) > 0

    def clear_cache(self) -> None:
        """Clear all LRU caches."""
        if self.cache_size > 0:
            self._lookup_key_cached.cache_clear()
            self._lookup_value_cached.cache_clear()

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        if self.cache_size == 0:
            return {"caching_enabled": False}

        key_info = self._lookup_key_cached.cache_info()
        value_info = self._lookup_value_cached.cache_info()

        return {
            "caching_enabled": True,
            "lookup_key": {
                "hits": key_info.hits,
                "misses": key_info.misses,
                "size": key_info.currsize,
                "maxsize": key_info.maxsize,
            },
            "lookup_value": {
                "hits": value_info.hits,
                "misses": value_info.misses,
                "size": value_info.currsize,
                "maxsize": value_info.maxsize,
            },
        }

    def get_stats(self) -> dict[str, Any]:
        """Get database statistics."""
        if not self.is_available():
            return {
                "available": False,
                "reason": "Database not found or not initialized",
            }

        conn = self.connect()

        stats = {"available": True}

        # Count registry entries
        cursor = conn.execute("SELECT COUNT(*) FROM baseline_registry")
        stats["registry_entries"] = cursor.fetchone()[0]

        # Count by hive
        cursor = conn.execute(
            "SELECT hive, COUNT(*) FROM baseline_registry GROUP BY hive ORDER BY hive"
        )
        stats["by_hive"] = {row[0]: row[1] for row in cursor}

        # Count OS versions
        cursor = conn.execute("SELECT COUNT(*) FROM baseline_os")
        stats["os_versions"] = cursor.fetchone()[0]

        return stats
