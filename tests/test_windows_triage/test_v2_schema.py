"""
Unit Tests for v2 Hybrid Schema

Tests:
- Schema initialization
- KnownGoodDB deduplication logic
- OS version tracking with JSON arrays
- Hash index operations
- Service/task/autorun upserts
"""

import json
import pytest
import sqlite3
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from windows_triage.db import KnownGoodDB, KNOWN_GOOD_SCHEMA, REGISTRY_FULL_SCHEMA


class TestSchemaInitialization:
    """Test schema creation."""

    def test_known_good_schema_creates_tables(self, tmp_path):
        """Verify all expected tables are created."""
        db_path = tmp_path / "test_known_good.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        conn = db.connect()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]

        expected_tables = [
            'baseline_autoruns',
            'baseline_files',
            'baseline_hashes',
            'baseline_os',
            'baseline_services',
            'baseline_tasks',
            'sources',
        ]
        for table in expected_tables:
            assert table in tables, f"Missing table: {table}"

        db.close()

    def test_known_good_schema_creates_indexes(self, tmp_path):
        """Verify indexes are created."""
        db_path = tmp_path / "test_known_good.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        conn = db.connect()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
        )
        indexes = [row[0] for row in cursor.fetchall()]

        # Check key indexes exist
        assert 'idx_files_path' in indexes
        assert 'idx_files_filename' in indexes
        assert 'idx_hashes_value' in indexes

        db.close()

    def test_registry_schema_creates_tables(self, tmp_path):
        """Verify registry schema tables."""
        db_path = tmp_path / "test_registry.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(REGISTRY_FULL_SCHEMA)
        conn.commit()

        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]

        assert 'baseline_registry' in tables
        assert 'baseline_os' in tables

        conn.close()


class TestOSVersionOperations:
    """Test OS version tracking."""

    def test_add_os_version(self, tmp_path):
        """Test adding OS versions."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        os_id = db.add_os_version(
            short_name="Win10_21H2_Pro",
            os_family="Windows 10",
            os_edition="Pro",
            os_release="21H2",
            build_number="19044.1234"
        )

        assert os_id is not None
        assert os_id > 0

        # Adding same OS should return existing ID
        os_id2 = db.add_os_version(
            short_name="Win10_21H2_Pro",
            os_family="Windows 10"
        )
        assert os_id2 == os_id

        db.close()

    def test_get_os_versions(self, tmp_path):
        """Test retrieving OS versions."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10_21H2_Pro", "Windows 10", "Pro", "21H2")
        db.add_os_version("Win11_22H2_Enterprise", "Windows 11", "Enterprise", "22H2")

        versions = db.get_os_versions()
        assert len(versions) == 2

        names = [v['short_name'] for v in versions]
        assert "Win10_21H2_Pro" in names
        assert "Win11_22H2_Enterprise" in names

        db.close()


class TestFileDeduplication:
    """Test file path deduplication with OS version tracking."""

    def test_upsert_file_new(self, tmp_path):
        """Test inserting a new file."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10_21H2_Pro", "Windows 10")

        file_id = db.upsert_file(
            path="C:\\Windows\\System32\\cmd.exe",
            os_short_name="Win10_21H2_Pro",
            source_csv="test.csv"
        )

        assert file_id > 0

        # Verify stored correctly (v2: returns list)
        results = db.lookup_by_path("C:\\Windows\\System32\\cmd.exe")
        assert len(results) > 0
        assert "Win10_21H2_Pro" in results[0]['os_versions']

        db.close()

    def test_upsert_file_adds_os_version(self, tmp_path):
        """Test that upserting same file with different OS adds to os_versions."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10_21H2_Pro", "Windows 10")
        db.add_os_version("Win11_22H2_Pro", "Windows 11")

        # First insert
        file_id1 = db.upsert_file(
            path="C:\\Windows\\System32\\notepad.exe",
            os_short_name="Win10_21H2_Pro"
        )

        # Second insert with different OS
        file_id2 = db.upsert_file(
            path="C:\\Windows\\System32\\notepad.exe",
            os_short_name="Win11_22H2_Pro"
        )

        # Should be same file ID (deduplicated)
        assert file_id1 == file_id2

        # Should have both OS versions (v2: returns list)
        results = db.lookup_by_path("C:\\Windows\\System32\\notepad.exe")
        assert len(results) > 0
        assert len(results[0]['os_versions']) == 2
        assert "Win10_21H2_Pro" in results[0]['os_versions']
        assert "Win11_22H2_Pro" in results[0]['os_versions']

        db.close()

    def test_upsert_file_same_os_no_duplicate(self, tmp_path):
        """Test that upserting same file+OS doesn't duplicate."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10_21H2_Pro", "Windows 10")

        db.upsert_file("C:\\test.exe", "Win10_21H2_Pro")
        db.upsert_file("C:\\test.exe", "Win10_21H2_Pro")  # Duplicate

        # v2: returns list
        results = db.lookup_by_path("C:\\test.exe")
        assert len(results) > 0
        # Should only have one OS version entry
        assert results[0]['os_versions'].count("Win10_21H2_Pro") == 1

        db.close()

    def test_path_normalization(self, tmp_path):
        """Test that paths are normalized correctly."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")

        # Insert with drive letter and mixed case
        db.upsert_file("C:\\Windows\\SYSTEM32\\CMD.EXE", "Win10")

        # Lookup with different casing should work (v2: returns list)
        results = db.lookup_by_path("c:\\windows\\system32\\cmd.exe")
        assert len(results) > 0

        db.close()


class TestBatchOperations:
    """Test batch file operations."""

    def test_upsert_files_batch(self, tmp_path):
        """Test batch insert with deduplication."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10_21H2_Pro", "Windows 10")

        files = [
            {'path': 'C:\\Windows\\System32\\cmd.exe', 'md5': 'abc123', 'sha256': 'def456' * 4},
            {'path': 'C:\\Windows\\System32\\notepad.exe', 'md5': 'xyz789'},
            {'path': 'C:\\Windows\\System32\\calc.exe'},
        ]

        stats = db.upsert_files_batch(files, "Win10_21H2_Pro", "test.csv")

        assert stats['inserted'] == 3
        assert stats['updated'] == 0

        # Verify files exist
        assert db.path_exists("C:\\Windows\\System32\\cmd.exe")
        assert db.path_exists("C:\\Windows\\System32\\notepad.exe")
        assert db.filename_exists("calc.exe")

        db.close()

    def test_batch_deduplication_across_os(self, tmp_path):
        """Test batch operations maintain deduplication across OS versions."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")
        db.add_os_version("Win11", "Windows 11")

        files = [
            {'path': 'C:\\Windows\\System32\\svchost.exe'},
            {'path': 'C:\\Windows\\System32\\lsass.exe'},
        ]

        # Insert for Win10
        stats1 = db.upsert_files_batch(files, "Win10")
        assert stats1['inserted'] == 2

        # Insert same files for Win11
        stats2 = db.upsert_files_batch(files, "Win11")
        assert stats2['inserted'] == 0  # No new paths
        assert stats2['updated'] == 2   # OS versions updated

        # Check both OS versions present (v2: returns list)
        results = db.lookup_by_path("C:\\Windows\\System32\\svchost.exe")
        assert len(results) > 0
        assert "Win10" in results[0]['os_versions']
        assert "Win11" in results[0]['os_versions']

        db.close()


class TestHashOperations:
    """Test hash index operations."""

    def test_hash_lookup(self, tmp_path):
        """Test looking up files by hash."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")

        files = [
            {'path': 'C:\\Windows\\System32\\cmd.exe', 'sha256': 'a' * 64},
        ]
        db.upsert_files_batch(files, "Win10")

        results = db.lookup_hash('a' * 64)
        assert len(results) == 1
        assert results[0]['filename'] == 'cmd.exe'

        db.close()

    def test_batch_hash_lookup(self, tmp_path):
        """Test batch hash lookup."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")

        files = [
            {'path': 'C:\\file1.exe', 'sha256': 'a' * 64},
            {'path': 'C:\\file2.exe', 'sha256': 'b' * 64},
            {'path': 'C:\\file3.exe', 'sha256': 'c' * 64},
        ]
        db.upsert_files_batch(files, "Win10")

        results = db.lookup_hashes_batch(['a' * 64, 'b' * 64, 'x' * 64])

        assert 'a' * 64 in results
        assert 'b' * 64 in results
        assert 'x' * 64 not in results  # Not in database

        db.close()


class TestServiceOperations:
    """Test service baseline operations."""

    def test_upsert_service(self, tmp_path):
        """Test service upsert with deduplication."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        svc_id1 = db.upsert_service(
            service_name="BITS",
            os_short_name="Win10",
            display_name="Background Intelligent Transfer Service",
            binary_path="%SystemRoot%\\System32\\svchost.exe",
            start_type=3
        )

        svc_id2 = db.upsert_service(
            service_name="BITS",
            os_short_name="Win11",
            display_name="Background Intelligent Transfer Service"
        )

        # Should be same service ID
        assert svc_id1 == svc_id2

        # Check os_versions (v2: returns list)
        results = db.lookup_service("BITS")
        assert len(results) > 0
        assert "Win10" in results[0]['os_versions']
        assert "Win11" in results[0]['os_versions']

        db.close()


class TestTaskOperations:
    """Test scheduled task operations."""

    def test_upsert_task(self, tmp_path):
        """Test task upsert with deduplication."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        task_id1 = db.upsert_task(
            task_path="\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
            os_short_name="Win10",
            task_name="Schedule Scan"
        )

        task_id2 = db.upsert_task(
            task_path="\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
            os_short_name="Win11"
        )

        assert task_id1 == task_id2

        # v2: returns list
        results = db.lookup_task("\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan")
        assert len(results) > 0
        assert "Win10" in results[0]['os_versions']
        assert "Win11" in results[0]['os_versions']

        db.close()


class TestAutorunOperations:
    """Test autorun operations."""

    def test_upsert_autorun(self, tmp_path):
        """Test autorun upsert with deduplication."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        ar_id1 = db.upsert_autorun(
            hive="HKLM",
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            os_short_name="Win10",
            value_name="SecurityHealth",
            value_data_pattern="%ProgramFiles%\\Windows Defender\\MSASCuiL.exe"
        )

        ar_id2 = db.upsert_autorun(
            hive="HKLM",
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            os_short_name="Win11",
            value_name="SecurityHealth"
        )

        assert ar_id1 == ar_id2

        results = db.lookup_autorun("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SecurityHealth")
        assert len(results) == 1
        assert "Win10" in results[0]['os_versions']
        assert "Win11" in results[0]['os_versions']

        db.close()


class TestLookupOperations:
    """Test various lookup operations."""

    def test_lookup_by_filename(self, tmp_path):
        """Test filename lookup returns all paths."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")

        files = [
            {'path': 'C:\\Windows\\System32\\svchost.exe'},
            {'path': 'C:\\Windows\\SysWOW64\\svchost.exe'},
        ]
        db.upsert_files_batch(files, "Win10")

        results = db.lookup_by_filename("svchost.exe")
        assert len(results) == 2

        paths = [r['path_normalized'] for r in results]
        assert '\\windows\\system32\\svchost.exe' in paths
        assert '\\windows\\syswow64\\svchost.exe' in paths

        db.close()

    def test_filename_exists(self, tmp_path):
        """Test filename existence check."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")
        db.upsert_file("C:\\Windows\\System32\\cmd.exe", "Win10")

        assert db.filename_exists("cmd.exe") is True
        assert db.filename_exists("CMD.EXE") is True  # Case insensitive
        assert db.filename_exists("notexist.exe") is False

        db.close()

    def test_path_exists(self, tmp_path):
        """Test path existence check."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")
        db.upsert_file("C:\\Windows\\System32\\cmd.exe", "Win10")

        assert db.path_exists("C:\\Windows\\System32\\cmd.exe") is True
        assert db.path_exists("c:\\windows\\system32\\cmd.exe") is True
        assert db.path_exists("C:\\Windows\\System32\\notexist.exe") is False

        db.close()


class TestStatistics:
    """Test database statistics."""

    def test_get_stats(self, tmp_path):
        """Test statistics retrieval."""
        db_path = tmp_path / "test.db"
        db = KnownGoodDB(db_path)
        db.init_schema()

        db.add_os_version("Win10", "Windows 10")
        db.add_os_version("Win11", "Windows 11")

        files = [{'path': f'C:\\file{i}.exe'} for i in range(10)]
        db.upsert_files_batch(files, "Win10")

        db.upsert_service("TestService", "Win10")
        db.upsert_task("\\TestTask", "Win10")
        db.upsert_autorun("HKLM", "SOFTWARE\\Run", "Win10", "Test")

        stats = db.get_stats()

        assert stats['os_versions'] == 2
        assert stats['files'] == 10
        assert stats['services'] == 1
        assert stats['tasks'] == 1
        assert stats['autoruns'] == 1

        db.close()
