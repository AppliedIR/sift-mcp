"""
known_good.db Operations - Ground Truth Baselines (v2 Hybrid Schema)

This module provides the database interface for known_good.db using the
hybrid schema with path deduplication and hash indexing.

Schema Design:
    - baseline_files: Deduplicated paths with os_versions JSON array
    - baseline_hashes: Separate hash index for efficient lookups
    - baseline_services/tasks/autoruns: Deduplicated with os_versions

Key Features:
    - Path deduplication: Each unique path stored once (~2.7M rows vs 24M)
    - OS version tracking: JSON arrays preserve which OS versions have each entry
    - Efficient hash lookup: Separate index table without row multiplication
    - Storage efficient: ~5.6GB database vs ~12GB with full normalization

Usage:
    from windows_triage.db import KnownGoodDB

    db = KnownGoodDB("/path/to/known_good.db")

    # Check if path exists in baseline
    result = db.lookup_by_path("C:\\Windows\\System32\\cmd.exe")
    # Returns: {"found": True, "os_versions": ["Win10_21H2_Pro", ...]}

    # Check if filename exists anywhere
    result = db.lookup_by_filename("svchost.exe")

    # Hash lookup with file context
    result = db.lookup_hash("abc123...")
    # Returns file path, os_versions, and hash type
"""

import sqlite3
import json
from functools import lru_cache
from pathlib import Path
from typing import Optional, List, Dict, Any

from .schemas import KNOWN_GOOD_SCHEMA
from ..analysis.paths import normalize_path, extract_filename, extract_directory
from ..analysis.hashes import detect_hash_algorithm


class KnownGoodDB:
    """Interface to known_good.db with hybrid schema."""

    def __init__(self, db_path: str | Path, read_only: bool = False, cache_size: int = 10000):
        """Initialize connection to known_good.db.

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
            self._lookup_by_path_cached = lru_cache(maxsize=cache_size)(self._lookup_by_path_uncached)
            self._lookup_by_filename_cached = lru_cache(maxsize=cache_size)(self._lookup_by_filename_uncached)
            self._filename_exists_cached = lru_cache(maxsize=cache_size)(self._filename_exists_uncached)
            self._path_exists_cached = lru_cache(maxsize=cache_size)(self._path_exists_uncached)

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
            self._conn.execute("PRAGMA foreign_keys = ON")
            # Performance optimizations
            if not self.read_only:
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
        return self._conn

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def init_schema(self):
        """Initialize database schema."""
        conn = self.connect()
        conn.executescript(KNOWN_GOOD_SCHEMA)
        conn.commit()

    # ==================== OS Version Operations ====================

    def add_os_version(
        self,
        short_name: str,
        os_family: str,
        os_edition: Optional[str] = None,
        os_release: Optional[str] = None,
        build_number: Optional[str] = None,
        architecture: str = "x64",
        source_csv: Optional[str] = None
    ) -> int:
        """
        Add or get an OS version entry.

        Returns:
            The ID of the entry (existing or new)
        """
        conn = self.connect()

        # Try to get existing
        cursor = conn.execute(
            "SELECT id FROM baseline_os WHERE short_name = ?",
            (short_name,)
        )
        row = cursor.fetchone()
        if row:
            return row[0]

        # Create new
        cursor = conn.execute(
            """
            INSERT INTO baseline_os
                (short_name, os_family, os_edition, os_release, build_number, architecture, source_csv)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (short_name, os_family, os_edition, os_release, build_number, architecture, source_csv)
        )
        conn.commit()
        return cursor.lastrowid

    def get_os_version_id(self, short_name: str) -> Optional[int]:
        """Get OS version ID by short name."""
        conn = self.connect()
        cursor = conn.execute(
            "SELECT id FROM baseline_os WHERE short_name = ?",
            (short_name,)
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def get_os_versions(self) -> List[dict]:
        """Get all OS versions in the database."""
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM baseline_os ORDER BY short_name")
        return [dict(row) for row in cursor.fetchall()]

    # ==================== File Baseline Operations (Deduplication) ====================

    def upsert_file(
        self,
        path: str,
        os_short_name: str,
        source_csv: Optional[str] = None
    ) -> int:
        """
        Add or update a file path with OS version tracking.

        If path exists: adds os_short_name to os_versions JSON array
        If path is new: creates entry with os_versions = [os_short_name]

        Returns:
            The file ID
        """
        path_normalized = normalize_path(path)
        directory = extract_directory(path)
        filename = extract_filename(path)

        conn = self.connect()

        # Check if path exists
        cursor = conn.execute(
            "SELECT id, os_versions FROM baseline_files WHERE path_normalized = ?",
            (path_normalized,)
        )
        row = cursor.fetchone()

        if row:
            # Update existing - add OS version if not present
            file_id = row[0]
            os_versions = json.loads(row[1])
            if os_short_name not in os_versions:
                os_versions.append(os_short_name)
                conn.execute(
                    "UPDATE baseline_files SET os_versions = ? WHERE id = ?",
                    (json.dumps(os_versions), file_id)
                )
            return file_id
        else:
            # Insert new
            cursor = conn.execute(
                """
                INSERT INTO baseline_files
                    (path_normalized, directory_normalized, filename_lower, os_versions, first_seen_source)
                VALUES (?, ?, ?, ?, ?)
                """,
                (path_normalized, directory, filename, json.dumps([os_short_name]), source_csv)
            )
            return cursor.lastrowid

    def upsert_files_batch(
        self,
        files: List[Dict[str, Any]],
        os_short_name: str,
        source_csv: Optional[str] = None,
        batch_size: int = 10000
    ) -> Dict[str, int]:
        """
        Batch upsert files with deduplication.

        Args:
            files: List of dicts with keys: path, md5, sha1, sha256, file_size
            os_short_name: OS version short name
            source_csv: Source CSV filename
            batch_size: Commit interval

        Returns:
            Stats dict with inserted, updated counts
        """
        conn = self.connect()
        os_id = self.get_os_version_id(os_short_name)

        stats = {'inserted': 0, 'updated': 0, 'hashes_added': 0}

        # Build lookup cache for existing paths
        cursor = conn.execute("SELECT path_normalized, id, os_versions FROM baseline_files")
        path_cache = {row[0]: (row[1], json.loads(row[2])) for row in cursor.fetchall()}

        files_to_insert = []
        files_to_update = []  # (file_id, new_os_versions_json)
        hashes_to_insert = []

        for f in files:
            path = f.get('path', '')
            if not path:
                continue

            path_normalized = normalize_path(path)
            directory = extract_directory(path)
            filename = extract_filename(path)

            if path_normalized in path_cache:
                # Existing path - check if OS version needs adding
                file_id, os_versions = path_cache[path_normalized]
                if os_short_name not in os_versions:
                    os_versions.append(os_short_name)
                    files_to_update.append((json.dumps(os_versions), file_id))
                    stats['updated'] += 1
            else:
                # New path
                files_to_insert.append((
                    path_normalized,
                    directory,
                    filename,
                    json.dumps([os_short_name]),
                    source_csv
                ))
                stats['inserted'] += 1

            # Collect hashes (will be linked after file insert)
            for hash_type in ['md5', 'sha1', 'sha256']:
                hash_val = f.get(hash_type)
                if hash_val:
                    hashes_to_insert.append({
                        'path_normalized': path_normalized,
                        'hash_value': hash_val.lower(),
                        'hash_type': hash_type,
                        'os_id': os_id,
                        'file_size': f.get('file_size')
                    })

        # Execute batch inserts
        if files_to_insert:
            conn.executemany(
                """
                INSERT OR IGNORE INTO baseline_files
                    (path_normalized, directory_normalized, filename_lower, os_versions, first_seen_source)
                VALUES (?, ?, ?, ?, ?)
                """,
                files_to_insert
            )

        # Execute batch updates
        if files_to_update:
            conn.executemany(
                "UPDATE baseline_files SET os_versions = ? WHERE id = ?",
                files_to_update
            )

        conn.commit()

        # Now insert hashes with file_id lookups
        if hashes_to_insert:
            # Rebuild path->id cache after inserts
            cursor = conn.execute("SELECT path_normalized, id FROM baseline_files")
            path_to_id = {row[0]: row[1] for row in cursor.fetchall()}

            hash_records = []
            for h in hashes_to_insert:
                file_id = path_to_id.get(h['path_normalized'])
                if file_id:
                    hash_records.append((
                        h['hash_value'],
                        h['hash_type'],
                        file_id,
                        h['os_id'],
                        h['file_size']
                    ))

            if hash_records:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO baseline_hashes
                        (hash_value, hash_type, file_id, os_id, file_size)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    hash_records
                )
                stats['hashes_added'] = len(hash_records)
                conn.commit()

        return stats

    # ==================== Lookup Operations ====================

    def lookup_by_path(self, path: str, os_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Look up a file path in the baseline.

        Args:
            path: Windows file path
            os_version: Optional OS version filter (e.g., "Windows 10")

        Returns:
            List of matching entries with file info and hashes
        """
        path_normalized = normalize_path(path)
        # Use cached version if caching is enabled
        if self.cache_size > 0:
            # Cache key includes os_version; returns tuple for hashability
            cached_result = self._lookup_by_path_cached(path_normalized, os_version)
        else:
            # Uncached also returns tuple for consistency
            cached_result = self._lookup_by_path_uncached(path_normalized, os_version)
        # Convert tuples back to mutable dicts
        return [dict(r) for r in cached_result]

    def _lookup_by_path_uncached(self, path_normalized: str, os_version: Optional[str] = None) -> tuple:
        """Uncached path lookup (returns tuple for cache compatibility)."""
        conn = self.connect()

        cursor = conn.execute(
            """
            SELECT bf.id, bf.path_normalized, bf.filename_lower, bf.os_versions,
                   bh.hash_value, bh.hash_type
            FROM baseline_files bf
            LEFT JOIN baseline_hashes bh ON bf.id = bh.file_id
            WHERE bf.path_normalized = ?
            """,
            (path_normalized,)
        )

        results = []
        seen_ids = set()
        for row in cursor.fetchall():
            file_id = row[0]
            os_versions = json.loads(row[3])

            # Apply OS version filter if specified
            if os_version:
                if not any(os_version.lower() in ov.lower() for ov in os_versions):
                    continue

            if file_id not in seen_ids:
                entry = {
                    'found': True,
                    'file_id': file_id,
                    'path_normalized': row[1],
                    'filename': row[2],
                    'os_versions': tuple(os_versions),  # tuple for hashability
                }
                # Add hash info if present
                if row[4]:
                    entry[row[5]] = row[4]  # e.g., entry['md5'] = 'abc...'
                results.append(entry)
                seen_ids.add(file_id)
            elif row[4]:
                # Add additional hash to existing entry
                for r in results:
                    if r['file_id'] == file_id:
                        r[row[5]] = row[4]
                        break

        # Convert to tuple of frozensets for caching
        return tuple(tuple(sorted(r.items())) for r in results)

    def lookup_by_filename(self, filename: str) -> List[Dict[str, Any]]:
        """
        Look up all paths with a given filename.

        Args:
            filename: Filename to search

        Returns:
            List of matching entries with paths and os_versions
        """
        filename_lower = filename.lower()
        if self.cache_size > 0:
            cached_result = self._lookup_by_filename_cached(filename_lower)
        else:
            # Uncached also returns tuple for consistency
            cached_result = self._lookup_by_filename_uncached(filename_lower)
        # Convert tuples back to mutable dicts
        return [dict(r) for r in cached_result]

    def _lookup_by_filename_uncached(self, filename_lower: str) -> tuple:
        """Uncached filename lookup."""
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT id, path_normalized, directory_normalized, os_versions
            FROM baseline_files
            WHERE filename_lower = ?
            """,
            (filename_lower,)
        )

        results = []
        for row in cursor.fetchall():
            results.append(tuple(sorted({
                'file_id': row[0],
                'path_normalized': row[1],
                'directory': row[2],
                'os_versions': tuple(json.loads(row[3]))
            }.items())))
        return tuple(results)

    def filename_exists(self, filename: str) -> bool:
        """Check if a filename exists anywhere in the baseline."""
        filename_lower = filename.lower()
        if self.cache_size > 0:
            return self._filename_exists_cached(filename_lower)
        return self._filename_exists_uncached(filename_lower)

    def _filename_exists_uncached(self, filename_lower: str) -> bool:
        """Uncached filename existence check."""
        conn = self.connect()
        cursor = conn.execute(
            "SELECT 1 FROM baseline_files WHERE filename_lower = ? LIMIT 1",
            (filename_lower,)
        )
        return cursor.fetchone() is not None

    def path_exists(self, path: str) -> bool:
        """Check if exact path exists in baseline."""
        path_normalized = normalize_path(path)
        if self.cache_size > 0:
            return self._path_exists_cached(path_normalized)
        return self._path_exists_uncached(path_normalized)

    def _path_exists_uncached(self, path_normalized: str) -> bool:
        """Uncached path existence check."""
        conn = self.connect()
        cursor = conn.execute(
            "SELECT 1 FROM baseline_files WHERE path_normalized = ? LIMIT 1",
            (path_normalized,)
        )
        return cursor.fetchone() is not None

    def clear_cache(self) -> None:
        """Clear all LRU caches."""
        if self.cache_size > 0:
            self._lookup_by_path_cached.cache_clear()
            self._lookup_by_filename_cached.cache_clear()
            self._filename_exists_cached.cache_clear()
            self._path_exists_cached.cache_clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self.cache_size == 0:
            return {'caching_enabled': False}

        return {
            'caching_enabled': True,
            'cache_size': self.cache_size,
            'lookup_by_path': self._lookup_by_path_cached.cache_info()._asdict(),
            'lookup_by_filename': self._lookup_by_filename_cached.cache_info()._asdict(),
            'filename_exists': self._filename_exists_cached.cache_info()._asdict(),
            'path_exists': self._path_exists_cached.cache_info()._asdict(),
        }

    def lookup_hash(self, hash_value: str) -> List[Dict[str, Any]]:
        """
        Look up a hash in the baseline.

        Args:
            hash_value: Hash to look up (any algorithm)

        Returns:
            List of matching files with path and os_versions
        """
        hash_lower = hash_value.lower()
        hash_type = detect_hash_algorithm(hash_value)

        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT
                h.hash_value,
                h.hash_type,
                h.file_size,
                f.path_normalized,
                f.filename_lower,
                f.os_versions,
                o.short_name as hash_os_version
            FROM baseline_hashes h
            JOIN baseline_files f ON h.file_id = f.id
            LEFT JOIN baseline_os o ON h.os_id = o.id
            WHERE h.hash_value = ?
            """,
            (hash_lower,)
        )

        results = []
        for row in cursor.fetchall():
            results.append({
                'hash_value': row[0],
                'hash_type': row[1],
                'file_size': row[2],
                'path_normalized': row[3],
                'filename': row[4],
                'file_os_versions': json.loads(row[5]),
                'hash_os_version': row[6]
            })
        return results

    def lookup_hashes_batch(self, hashes: List[str]) -> Dict[str, List[Dict]]:
        """
        Look up multiple hashes efficiently.

        Args:
            hashes: List of hashes to look up

        Returns:
            Dict mapping hash -> list of matches
        """
        conn = self.connect()
        results = {}

        # Normalize hashes
        hashes_lower = [h.lower() for h in hashes]

        # SQLite placeholder limit
        batch_size = 500

        for i in range(0, len(hashes_lower), batch_size):
            batch = hashes_lower[i:i + batch_size]
            placeholders = ','.join('?' * len(batch))

            cursor = conn.execute(
                f"""
                SELECT
                    h.hash_value,
                    h.hash_type,
                    f.path_normalized,
                    f.filename_lower,
                    f.os_versions
                FROM baseline_hashes h
                JOIN baseline_files f ON h.file_id = f.id
                WHERE h.hash_value IN ({placeholders})
                """,
                batch
            )

            for row in cursor.fetchall():
                h = row[0]
                if h not in results:
                    results[h] = []
                results[h].append({
                    'hash_type': row[1],
                    'path_normalized': row[2],
                    'filename': row[3],
                    'os_versions': json.loads(row[4])
                })

        return results

    # ==================== Service Operations ====================

    def upsert_service(
        self,
        service_name: str,
        os_short_name: str,
        display_name: Optional[str] = None,
        binary_path: Optional[str] = None,
        start_type: Optional[int] = None,
        service_type: Optional[int] = None,
        object_name: Optional[str] = None,
        description: Optional[str] = None
    ) -> int:
        """Add or update a service with OS version tracking."""
        service_name_lower = service_name.lower()
        conn = self.connect()

        cursor = conn.execute(
            "SELECT id, os_versions FROM baseline_services WHERE service_name_lower = ?",
            (service_name_lower,)
        )
        row = cursor.fetchone()

        if row:
            service_id = row[0]
            os_versions = json.loads(row[1])
            if os_short_name not in os_versions:
                os_versions.append(os_short_name)
                conn.execute(
                    "UPDATE baseline_services SET os_versions = ? WHERE id = ?",
                    (json.dumps(os_versions), service_id)
                )
                conn.commit()
            return service_id
        else:
            cursor = conn.execute(
                """
                INSERT INTO baseline_services
                    (service_name_lower, display_name, binary_path_pattern, start_type,
                     service_type, object_name, description, os_versions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (service_name_lower, display_name, binary_path, start_type,
                 service_type, object_name, description, json.dumps([os_short_name]))
            )
            conn.commit()
            return cursor.lastrowid

    def lookup_service(self, service_name: str, os_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Look up a service in the baseline.

        Args:
            service_name: Service name to look up
            os_version: Optional OS version filter

        Returns:
            List of matching service entries
        """
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT * FROM baseline_services WHERE service_name_lower = ?
            """,
            (service_name.lower(),)
        )

        results = []
        for row in cursor.fetchall():
            result = dict(row)
            os_versions = json.loads(result['os_versions'])

            # Apply OS version filter if specified
            if os_version:
                if not any(os_version.lower() in ov.lower() for ov in os_versions):
                    continue

            result['os_versions'] = os_versions
            results.append(result)

        return results

    # ==================== Task Operations ====================

    def upsert_task(
        self,
        task_path: str,
        os_short_name: str,
        task_name: Optional[str] = None,
        uri: Optional[str] = None,
        actions_summary: Optional[str] = None,
        triggers_summary: Optional[str] = None,
        author: Optional[str] = None
    ) -> int:
        """Add or update a scheduled task with OS version tracking."""
        task_path_lower = task_path.lower()
        conn = self.connect()

        cursor = conn.execute(
            "SELECT id, os_versions FROM baseline_tasks WHERE task_path_lower = ?",
            (task_path_lower,)
        )
        row = cursor.fetchone()

        if row:
            task_id = row[0]
            os_versions = json.loads(row[1])
            if os_short_name not in os_versions:
                os_versions.append(os_short_name)
                conn.execute(
                    "UPDATE baseline_tasks SET os_versions = ? WHERE id = ?",
                    (json.dumps(os_versions), task_id)
                )
                conn.commit()
            return task_id
        else:
            cursor = conn.execute(
                """
                INSERT INTO baseline_tasks
                    (task_path_lower, task_name, uri, actions_summary, triggers_summary, author, os_versions)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (task_path_lower, task_name, uri, actions_summary, triggers_summary, author,
                 json.dumps([os_short_name]))
            )
            conn.commit()
            return cursor.lastrowid

    def lookup_task(self, task_path: str, os_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Look up a scheduled task in the baseline.

        Args:
            task_path: Task path to look up
            os_version: Optional OS version filter

        Returns:
            List of matching task entries
        """
        conn = self.connect()
        cursor = conn.execute(
            "SELECT * FROM baseline_tasks WHERE task_path_lower = ?",
            (task_path.lower(),)
        )

        results = []
        for row in cursor.fetchall():
            result = dict(row)
            os_versions = json.loads(result['os_versions'])

            # Apply OS version filter if specified
            if os_version:
                if not any(os_version.lower() in ov.lower() for ov in os_versions):
                    continue

            result['os_versions'] = os_versions
            results.append(result)

        return results

    # ==================== Autorun Operations ====================

    def upsert_autorun(
        self,
        hive: str,
        key_path: str,
        os_short_name: str,
        value_name: Optional[str] = None,
        value_data_pattern: Optional[str] = None,
        autorun_type: Optional[str] = None
    ) -> int:
        """Add or update an autorun entry with OS version tracking."""
        key_path_lower = key_path.lower()
        conn = self.connect()

        cursor = conn.execute(
            """
            SELECT id, os_versions FROM baseline_autoruns
            WHERE hive = ? AND key_path_lower = ? AND (value_name = ? OR (value_name IS NULL AND ? IS NULL))
            """,
            (hive, key_path_lower, value_name, value_name)
        )
        row = cursor.fetchone()

        if row:
            autorun_id = row[0]
            os_versions = json.loads(row[1])
            if os_short_name not in os_versions:
                os_versions.append(os_short_name)
                conn.execute(
                    "UPDATE baseline_autoruns SET os_versions = ? WHERE id = ?",
                    (json.dumps(os_versions), autorun_id)
                )
                conn.commit()
            return autorun_id
        else:
            cursor = conn.execute(
                """
                INSERT INTO baseline_autoruns
                    (hive, key_path_lower, value_name, value_data_pattern, autorun_type, os_versions)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (hive, key_path_lower, value_name, value_data_pattern, autorun_type,
                 json.dumps([os_short_name]))
            )
            conn.commit()
            return cursor.lastrowid

    def lookup_autorun(self, key_path: str, value_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Look up autorun entries by key path."""
        conn = self.connect()

        if value_name is not None:
            cursor = conn.execute(
                """
                SELECT * FROM baseline_autoruns
                WHERE key_path_lower = ? AND value_name = ?
                """,
                (key_path.lower(), value_name)
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM baseline_autoruns WHERE key_path_lower = ?",
                (key_path.lower(),)
            )

        results = []
        for row in cursor.fetchall():
            result = dict(row)
            result['os_versions'] = json.loads(result['os_versions'])
            results.append(result)
        return results

    # ==================== Statistics ====================

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        conn = self.connect()

        stats = {
            'os_versions': 0,
            'files': 0,
            'hashes': 0,
            'services': 0,
            'tasks': 0,
            'autoruns': 0,
        }

        for table, key in [
            ('baseline_os', 'os_versions'),
            ('baseline_files', 'files'),
            ('baseline_hashes', 'hashes'),
            ('baseline_services', 'services'),
            ('baseline_tasks', 'tasks'),
            ('baseline_autoruns', 'autoruns'),
        ]:
            try:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                stats[key] = cursor.fetchone()[0]
            except sqlite3.OperationalError:
                stats[key] = 0

        return stats

    def update_source_stats(self, source_name: str, record_count: int):
        """Update source tracking statistics."""
        conn = self.connect()
        conn.execute(
            """
            UPDATE sources SET
                last_sync_time = datetime('now'),
                record_count = ?
            WHERE name = ?
            """,
            (record_count, source_name)
        )
        conn.commit()
