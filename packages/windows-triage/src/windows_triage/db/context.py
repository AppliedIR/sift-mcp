"""
context.db Operations - Risk Enrichment Data

This module provides the database interface for context.db, which contains
security context and risk enrichment data for forensic triage.

Unlike known_good.db (which tracks what's "known good"), context.db tracks
risk indicators that inform whether something has abuse potential or matches
known suspicious patterns.

Data Sources:
    - LOLBAS (github.com/LOLBAS-Project/LOLBAS): Living Off The Land Binaries
      227 legitimate Windows tools that can be abused for malicious purposes

    - LOLDrivers (github.com/magicsword-io/LOLDrivers): Vulnerable drivers
      1,983 samples with file hash + authentihash for driver detection

    - HijackLibs (github.com/wietze/HijackLibs): DLL hijacking vulnerabilities
      2,284 hijackable DLL entries (DLL + vulnerable executable pairs)

    - MemProcFS (github.com/ufrisk/MemProcFS) + SANS Hunt Evil: Process expectations
      38 process rules for parent-child validation

    - Manual curation: Suspicious filename patterns, named pipe patterns,
      protected process names, legitimate hosting domains

Database Schema (key tables):
    - lolbins: LOLBin definitions with abuse functions
    - vulnerable_drivers: Vulnerable driver hashes (file + authentihash)
    - hijackable_dlls: DLL hijacking scenarios
    - expected_processes: Valid parent-child process relationships
    - suspicious_filenames: Known tool patterns (mimikatz.exe, etc.)
    - suspicious_pipe_patterns: C2 named pipe patterns
    - protected_process_names: Critical Windows processes (svchost, lsass)
    - windows_named_pipes: Known legitimate Windows pipes

Key Design Decisions:
    1. No known-bad hash database: OpenCTI handles malware hash lookups.
       This database focuses on context that OpenCTI can't provide.

    2. Both regex and exact patterns: suspicious_filenames supports both
       exact matches and regex patterns for flexible detection.

Usage:
    from windows_triage.db import ContextDB

    db = ContextDB("/path/to/context.db")

    # Check if file is a LOLBin
    lolbin = db.check_lolbin("certutil.exe")

    # Check for vulnerable driver
    driver = db.check_vulnerable_driver(hash_value, "sha256")

    # Validate process relationship
    process = db.get_expected_process("svchost.exe")
"""

import sqlite3
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional, List, Dict, Any
import json
import re

from .schemas import CONTEXT_SCHEMA, CONTEXT_INITIAL_DATA

logger = logging.getLogger(__name__)
from ..analysis.hashes import get_hash_column


class ContextDB:
    """Interface to context.db for risk enrichment lookups."""

    def __init__(self, db_path: str | Path, read_only: bool = False, cache_size: int = 10000):
        """
        Initialize connection to context.db.

        Args:
            db_path: Path to SQLite database file
            read_only: If True, open database in read-only mode (recommended for production)
            cache_size: Size of LRU cache for lookups (0 to disable)
        """
        self.db_path = Path(db_path)
        self.read_only = read_only
        self.cache_size = cache_size
        self._conn: Optional[sqlite3.Connection] = None

        # Configure LRU cache sizes based on cache_size parameter
        if cache_size > 0:
            self._check_lolbin_cached = lru_cache(maxsize=cache_size)(self._check_lolbin_uncached)
            self._get_expected_process_cached = lru_cache(maxsize=cache_size)(self._get_expected_process_uncached)
            self._get_protected_process_names_cached = lru_cache(maxsize=1)(self._get_protected_process_names_uncached)

    def connect(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            if self.read_only:
                # Open in read-only mode using URI
                uri = f"file:{self.db_path}?mode=ro"
                self._conn = sqlite3.connect(uri, uri=True)
            else:
                self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def init_schema(self):
        """Initialize database schema with initial data."""
        conn = self.connect()
        conn.executescript(CONTEXT_SCHEMA)
        conn.executescript(CONTEXT_INITIAL_DATA)
        conn.commit()

    # ==================== LOLBin Operations ====================

    def check_lolbin(self, filename: str) -> Optional[dict]:
        """
        Check if a filename is a known LOLBin.

        Args:
            filename: Filename to check (e.g., 'certutil.exe')

        Returns:
            LOLBin info or None
        """
        filename_lower = filename.lower()
        if self.cache_size > 0:
            cached = self._check_lolbin_cached(filename_lower)
            return dict(cached) if cached else None
        # Uncached also returns tuple for consistency; convert to dict
        result = self._check_lolbin_uncached(filename_lower)
        return dict(result) if result else None

    def _check_lolbin_uncached(self, filename_lower: str) -> Optional[tuple]:
        """Uncached LOLBin lookup (returns tuple for cache compatibility)."""
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT * FROM lolbins WHERE filename_lower = ?
            """,
            (filename_lower,)
        )
        row = cursor.fetchone()
        if row:
            result = dict(row)
            # Parse JSON fields
            for field in ('functions', 'expected_paths', 'mitre_techniques'):
                if result.get(field):
                    try:
                        parsed = json.loads(result[field])
                        result[field] = tuple(parsed) if isinstance(parsed, list) else parsed
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON in lolbins.{field}: {result[field]!r} - {e}")
            # Return as tuple of items for cache hashability
            return tuple(sorted(result.items()))
        return None

    def add_lolbin(
        self,
        filename: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        functions: Optional[List[str]] = None,
        expected_paths: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        detection: Optional[str] = None,
        source_url: Optional[str] = None
    ):
        """Add a LOLBin entry."""
        conn = self.connect()
        conn.execute(
            """
            INSERT OR REPLACE INTO lolbins
                (filename_lower, name, description, functions, expected_paths,
                 mitre_techniques, detection, source_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename.lower(),
                name,
                description,
                json.dumps(functions) if functions else None,
                json.dumps(expected_paths) if expected_paths else None,
                json.dumps(mitre_techniques) if mitre_techniques else None,
                detection,
                source_url
            )
        )
        conn.commit()

    # ==================== Vulnerable Driver Operations ====================

    def check_vulnerable_driver(self, hash_value: str, algorithm: str, check_authentihash: bool = True) -> Optional[dict]:
        """
        Check if a hash matches a known vulnerable driver.

        Args:
            hash_value: Hash to check
            algorithm: Hash algorithm (md5, sha1, sha256)
            check_authentihash: Also check authentihash columns (default True)

        Returns:
            Driver info or None
        """
        column = get_hash_column(algorithm)
        conn = self.connect()

        # Check file hash first
        cursor = conn.execute(
            f"""
            SELECT * FROM vulnerable_drivers WHERE {column} = ?
            """,
            (hash_value.lower(),)
        )
        row = cursor.fetchone()
        if row:
            result = dict(row)
            result['match_type'] = 'file_hash'
            return result

        # Also check authentihash if requested
        if check_authentihash:
            auth_column = f"authentihash_{get_hash_column(algorithm)}"
            cursor = conn.execute(
                f"""
                SELECT * FROM vulnerable_drivers WHERE {auth_column} = ?
                """,
                (hash_value.lower(),)
            )
            row = cursor.fetchone()
            if row:
                result = dict(row)
                result['match_type'] = 'authentihash'
                return result

        return None

    def add_vulnerable_driver(
        self,
        filename: Optional[str] = None,
        sha256: Optional[str] = None,
        sha1: Optional[str] = None,
        md5: Optional[str] = None,
        authentihash_sha256: Optional[str] = None,
        authentihash_sha1: Optional[str] = None,
        authentihash_md5: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        cve: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        description: Optional[str] = None
    ):
        """Add a vulnerable driver entry."""
        conn = self.connect()
        conn.execute(
            """
            INSERT INTO vulnerable_drivers
                (filename_lower, sha256, sha1, md5,
                 authentihash_sha256, authentihash_sha1, authentihash_md5,
                 vendor, product, cve, vulnerability_type, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename.lower() if filename else None,
                sha256.lower() if sha256 else None,
                sha1.lower() if sha1 else None,
                md5.lower() if md5 else None,
                authentihash_sha256.lower() if authentihash_sha256 else None,
                authentihash_sha1.lower() if authentihash_sha1 else None,
                authentihash_md5.lower() if authentihash_md5 else None,
                vendor,
                product,
                cve,
                vulnerability_type,
                description
            )
        )
        conn.commit()

    # ==================== Expected Process Operations ====================

    def get_expected_process(self, process_name: str) -> Optional[dict]:
        """
        Get expected process info for parent-child validation.

        Three validation approaches supported:
        - never_spawns_children: If true, this process should NEVER be a parent.
          If seen spawning anything = critical (process injection). Used for
          lsass.exe, dwm.exe, audiodg.exe, fontdrvhost.exe, lsaiso.exe.
        - valid_parents (whitelist): For system processes, flag if parent NOT in list
        - suspicious_parents (blacklist): For shells, flag if parent IS in list

        Args:
            process_name: Process name (e.g., 'svchost.exe', 'cmd.exe', 'lsass.exe')

        Returns:
            Dict with fields: valid_parents, suspicious_parents, never_spawns_children,
            valid_paths, user_type, valid_users, min/max_instances, etc. Or None.

            For cmd.exe/powershell.exe/pwsh.exe, suspicious_parents contains
            80 entries across 12 categories (Office, browsers, DCOM, etc.).
        """
        process_name_lower = process_name.lower()
        if self.cache_size > 0:
            cached = self._get_expected_process_cached(process_name_lower)
        else:
            # Uncached also returns tuple for consistency
            cached = self._get_expected_process_uncached(process_name_lower)

        if cached:
            # Convert back to mutable dict with mutable lists
            result = dict(cached)
            for field in ('valid_parents', 'suspicious_parents', 'valid_paths', 'valid_users'):
                if field in result and isinstance(result[field], tuple):
                    result[field] = list(result[field])
            return result
        return None

    def _get_expected_process_uncached(self, process_name_lower: str) -> Optional[tuple]:
        """Uncached expected process lookup."""
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT * FROM expected_processes WHERE process_name_lower = ?
            """,
            (process_name_lower,)
        )
        row = cursor.fetchone()
        if row:
            result = dict(row)
            # Parse JSON fields and convert lists to tuples for hashability
            for field in ('valid_parents', 'suspicious_parents', 'valid_paths', 'valid_users', 'required_args'):
                if result.get(field):
                    try:
                        parsed = json.loads(result[field])
                        result[field] = tuple(parsed) if isinstance(parsed, list) else parsed
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON in expected_processes.{field}: {result[field]!r} - {e}")
            return tuple(sorted(result.items()))
        return None

    def add_expected_process(
        self,
        process_name: str,
        valid_parents: List[str],
        parent_exits: bool = False,
        valid_paths: Optional[List[str]] = None,
        user_type: Optional[str] = None,
        valid_users: Optional[List[str]] = None,
        min_instances: int = 1,
        max_instances: Optional[int] = None,
        per_session: bool = False,
        required_args: Optional[str] = None,
        source: Optional[str] = None
    ):
        """Add an expected process entry."""
        conn = self.connect()
        conn.execute(
            """
            INSERT OR REPLACE INTO expected_processes
                (process_name_lower, valid_parents, parent_exits, valid_paths,
                 user_type, valid_users, min_instances, max_instances,
                 per_session, required_args, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                process_name.lower(),
                json.dumps(valid_parents),
                1 if parent_exits else 0,
                json.dumps(valid_paths) if valid_paths else None,
                user_type,
                json.dumps(valid_users) if valid_users else None,
                min_instances,
                max_instances,
                1 if per_session else 0,
                required_args,
                source
            )
        )
        conn.commit()

    # ==================== Suspicious Filename Operations ====================

    def check_suspicious_filename(self, filename: str) -> Optional[dict]:
        """
        Check if a filename matches known suspicious patterns.

        Args:
            filename: Filename to check

        Returns:
            Match info or None
        """
        conn = self.connect()
        filename_lower = filename.lower()

        # First try exact match
        cursor = conn.execute(
            """
            SELECT * FROM suspicious_filenames
            WHERE is_regex = 0 AND filename_pattern = ?
            """,
            (filename_lower,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)

        # Then try regex patterns
        cursor = conn.execute(
            "SELECT * FROM suspicious_filenames WHERE is_regex = 1"
        )
        for row in cursor.fetchall():
            pattern = row['filename_pattern']
            try:
                if re.fullmatch(pattern, filename_lower, re.IGNORECASE):
                    return dict(row)
            except re.error as e:
                logger.warning(f"Invalid regex in suspicious_filenames: {pattern!r} - {e}")
                continue

        return None

    # ==================== Pipe Pattern Operations ====================

    def check_suspicious_pipe(self, pipe_name: str) -> Optional[dict]:
        """
        Check if a pipe name matches known suspicious patterns.

        Args:
            pipe_name: Named pipe name to check

        Returns:
            Match info or None
        """
        conn = self.connect()
        pipe_name_lower = pipe_name.lower()

        # First try exact match
        cursor = conn.execute(
            """
            SELECT * FROM suspicious_pipe_patterns
            WHERE is_regex = 0 AND pipe_pattern = ?
            """,
            (pipe_name_lower,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)

        # Then try pattern matches (using * as wildcard)
        cursor = conn.execute(
            "SELECT * FROM suspicious_pipe_patterns WHERE is_regex = 1"
        )
        for row in cursor.fetchall():
            pattern = row['pipe_pattern']
            # Convert simple wildcard to regex (escape literal chars, then replace wildcard)
            parts = pattern.split('*')
            regex_pattern = '.*'.join(re.escape(p) for p in parts)
            try:
                if re.fullmatch(regex_pattern, pipe_name_lower, re.IGNORECASE):
                    return dict(row)
            except re.error as e:
                logger.warning(f"Invalid regex in suspicious_pipe_patterns: {pattern!r} - {e}")
                continue

        return None

    def check_windows_pipe(self, pipe_name: str) -> Optional[dict]:
        """
        Check if a pipe name is a known Windows pipe.

        Args:
            pipe_name: Named pipe name to check

        Returns:
            Pipe info or None (None means not a known Windows pipe)
        """
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT * FROM windows_named_pipes WHERE pipe_name = ?
            """,
            (pipe_name.lower(),)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    # ==================== Protected Process Operations ====================

    def get_protected_process_names(self) -> List[str]:
        """Get list of protected process names."""
        if self.cache_size > 0:
            return list(self._get_protected_process_names_cached())
        return self._get_protected_process_names_uncached()

    def _get_protected_process_names_uncached(self) -> tuple:
        """Uncached protected process names lookup."""
        conn = self.connect()
        cursor = conn.execute(
            "SELECT process_name_lower FROM protected_process_names"
        )
        return tuple(row[0] for row in cursor.fetchall())

    def check_protected_process(self, process_name: str) -> Optional[dict]:
        """Check if a process name is protected."""
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT * FROM protected_process_names WHERE process_name_lower = ?
            """,
            (process_name.lower(),)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    # ==================== Hijackable DLL Operations ====================

    def check_hijackable_dll(self, dll_name: str) -> List[dict]:
        """
        Check if a DLL is hijackable.

        Args:
            dll_name: DLL filename to check

        Returns:
            List of hijack scenarios for this DLL
        """
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT * FROM hijackable_dlls WHERE dll_name_lower = ?
            """,
            (dll_name.lower(),)
        )
        return [dict(row) for row in cursor.fetchall()]

    # ==================== Statistics ====================

    def get_stats(self) -> dict:
        """Get database statistics."""
        conn = self.connect()

        stats = {
            'lolbins': 0,
            'hijackable_dlls': 0,
            'vulnerable_drivers': 0,
            'expected_processes': 0,
            'suspicious_filenames': 0,
            'suspicious_pipes': 0,
            'windows_pipes': 0,
            'protected_processes': 0,
        }

        tables = [
            ('lolbins', 'lolbins'),
            ('hijackable_dlls', 'hijackable_dlls'),
            ('vulnerable_drivers', 'vulnerable_drivers'),
            ('expected_processes', 'expected_processes'),
            ('suspicious_filenames', 'suspicious_filenames'),
            ('suspicious_pipe_patterns', 'suspicious_pipes'),
            ('windows_named_pipes', 'windows_pipes'),
            ('protected_process_names', 'protected_processes'),
        ]

        for table, key in tables:
            cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
            stats[key] = cursor.fetchone()[0]

        return stats

    # ==================== Cache Operations ====================

    def clear_cache(self) -> None:
        """Clear all LRU caches."""
        if self.cache_size > 0:
            self._check_lolbin_cached.cache_clear()
            self._get_expected_process_cached.cache_clear()
            self._get_protected_process_names_cached.cache_clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self.cache_size == 0:
            return {'caching_enabled': False}

        return {
            'caching_enabled': True,
            'cache_size': self.cache_size,
            'check_lolbin': self._check_lolbin_cached.cache_info()._asdict(),
            'get_expected_process': self._get_expected_process_cached.cache_info()._asdict(),
            'get_protected_process_names': self._get_protected_process_names_cached.cache_info()._asdict(),
        }
