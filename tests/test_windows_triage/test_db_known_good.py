"""Integration tests for known_good.db operations (v2 schema)."""

import pytest


class TestKnownGoodDB:
    """Tests for KnownGoodDB class (v2 schema with path deduplication)."""

    def test_lookup_by_path(self, known_good_db_instance):
        """Test looking up a file by its full path."""
        db = known_good_db_instance
        db.connect()
        results = db.lookup_by_path("\\windows\\system32\\cmd.exe")
        assert len(results) > 0  # Returns list of matches
        # v2 schema: lookup_by_path returns list of dicts with path_normalized, os_versions
        assert 'path_normalized' in results[0]
        assert 'os_versions' in results[0]
        db.close()

    def test_lookup_by_path_case_insensitive(self, known_good_db_instance):
        """Test that path lookup is case-insensitive."""
        db = known_good_db_instance
        db.connect()
        results = db.lookup_by_path("\\WINDOWS\\System32\\CMD.EXE")
        assert len(results) > 0
        db.close()

    def test_lookup_by_path_not_found(self, known_good_db_instance):
        """Test looking up a non-existent path."""
        db = known_good_db_instance
        db.connect()
        results = db.lookup_by_path("\\nonexistent\\path\\file.exe")
        assert len(results) == 0  # Empty list when not found
        db.close()

    def test_lookup_by_filename(self, known_good_db_instance):
        """Test looking up files by filename only (returns list of dicts)."""
        db = known_good_db_instance
        db.connect()
        results = db.lookup_by_filename("cmd.exe")
        assert len(results) > 0
        # v2 schema returns file_id, path_normalized, directory, os_versions
        assert 'path_normalized' in results[0]
        assert 'cmd.exe' in results[0]['path_normalized']
        db.close()

    def test_lookup_by_filename_case_insensitive(self, known_good_db_instance):
        """Test that filename lookup is case-insensitive."""
        db = known_good_db_instance
        db.connect()
        results = db.lookup_by_filename("CMD.EXE")
        assert len(results) > 0
        db.close()

    def test_lookup_by_filename_not_found(self, known_good_db_instance):
        """Test looking up a non-existent filename."""
        db = known_good_db_instance
        db.connect()
        results = db.lookup_by_filename("malware.exe")
        assert len(results) == 0
        db.close()

    def test_filename_exists(self, known_good_db_instance):
        """Test checking if a filename exists in baseline (returns bool)."""
        db = known_good_db_instance
        db.connect()
        assert db.filename_exists("cmd.exe") is True
        assert db.filename_exists("malware.exe") is False
        db.close()

    def test_path_exists(self, known_good_db_instance):
        """Test checking if a path exists in baseline (returns bool)."""
        db = known_good_db_instance
        db.connect()
        assert db.path_exists("\\windows\\system32\\cmd.exe") is True
        assert db.path_exists("\\nonexistent\\path.exe") is False
        db.close()

    def test_lookup_hash_md5(self, known_good_db_instance):
        """Test looking up by MD5 hash (auto-detected)."""
        db = known_good_db_instance
        db.connect()
        # Full MD5 hash from fixture: 'abc123' + '0' * 26
        results = db.lookup_hash("abc123" + "0" * 26)
        assert len(results) > 0
        assert results[0]['filename'] == 'cmd.exe'
        db.close()

    def test_lookup_hash_sha1(self, known_good_db_instance):
        """Test looking up by SHA1 hash (auto-detected)."""
        db = known_good_db_instance
        db.connect()
        # Full SHA1 hash from fixture: 'def456' + '0' * 34
        results = db.lookup_hash("def456" + "0" * 34)
        assert len(results) > 0
        db.close()

    def test_lookup_hash_not_found(self, known_good_db_instance):
        """Test looking up a non-existent hash."""
        db = known_good_db_instance
        db.connect()
        results = db.lookup_hash("deadbeef12345678901234567890123456789012")
        assert len(results) == 0
        db.close()

    def test_get_stats(self, known_good_db_instance):
        """Test getting database statistics."""
        db = known_good_db_instance
        db.connect()
        stats = db.get_stats()
        assert 'files' in stats
        assert stats['files'] > 0
        assert 'hashes' in stats  # v2 schema has separate hash table
        db.close()


class TestKnownGoodDBWithRealData:
    """Tests that require the real populated database (v2 schema)."""

    @pytest.fixture
    def real_db(self):
        """Use the real known_good.db if it exists."""
        import sqlite3
        from pathlib import Path
        from windows_triage.db.known_good import KnownGoodDB

        db_path = Path(__file__).parent.parent / "data" / "known_good.db"
        if not db_path.exists():
            pytest.skip("Real database not available")

        # Check if v2 schema (has baseline_hashes table)
        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='baseline_hashes'")
        has_hashes_table = cursor.fetchone() is not None
        conn.close()
        if not has_hashes_table:
            pytest.skip("Database schema outdated (v1 schema) - run init_databases.py")

        db = KnownGoodDB(db_path)
        db.connect()
        return db

    def test_svchost_in_baseline(self, real_db):
        """Test that svchost.exe is in the baseline."""
        # v2: filename_exists returns bool
        assert real_db.filename_exists("svchost.exe") is True

    def test_cmd_in_baseline(self, real_db):
        """Test that cmd.exe is in the baseline."""
        assert real_db.filename_exists("cmd.exe") is True

    def test_explorer_path(self, real_db):
        """Test that explorer.exe path is correct."""
        assert real_db.path_exists("\\windows\\explorer.exe") is True

    def test_notepad_in_system32(self, real_db):
        """Test notepad.exe in system32."""
        # v2: lookup_by_path returns list of matching entries
        results = real_db.lookup_by_path("\\windows\\system32\\notepad.exe")
        assert len(results) > 0
