"""Tests for RegistryDB class and registry baseline functionality.

Tests the optional known_good_registry.db operations for validating
registry keys/values against clean Windows installation baselines.

Fixtures are defined in conftest.py: temp_registry_db, registry_db_instance, empty_temp_registry_db
"""

import pytest
import sqlite3
import tempfile
from pathlib import Path

from windows_triage.db import RegistryDB
from windows_triage.db.schemas import REGISTRY_FULL_SCHEMA


# ============================================================================
# RegistryDB Initialization Tests
# ============================================================================

class TestRegistryDBInitialization:
    """Tests for RegistryDB class initialization."""

    def test_init_with_existing_db(self, temp_registry_db):
        """Test initialization with existing database file."""
        db = RegistryDB(temp_registry_db)
        assert db.db_path == temp_registry_db
        assert db.read_only is True  # Default
        assert db.cache_size == 10000  # Default
        db.close()

    def test_init_with_custom_cache_size(self, temp_registry_db):
        """Test initialization with custom cache size."""
        db = RegistryDB(temp_registry_db, cache_size=5000)
        assert db.cache_size == 5000
        db.close()

    def test_init_with_cache_disabled(self, temp_registry_db):
        """Test initialization with caching disabled."""
        db = RegistryDB(temp_registry_db, cache_size=0)
        assert db.cache_size == 0
        db.close()

    def test_init_with_read_write(self, temp_registry_db):
        """Test initialization in read-write mode."""
        db = RegistryDB(temp_registry_db, read_only=False)
        assert db.read_only is False
        db.close()

    def test_init_with_nonexistent_db(self):
        """Test initialization with nonexistent database file."""
        db = RegistryDB("/nonexistent/path/registry.db")
        # Should create the object, but is_available should return False
        assert db.is_available() is False
        db.close()

    def test_init_with_path_object(self, temp_registry_db):
        """Test initialization with Path object."""
        db = RegistryDB(Path(temp_registry_db))
        assert isinstance(db.db_path, Path)
        db.close()


# ============================================================================
# normalize_key_path Tests
# ============================================================================

class TestNormalizeKeyPath:
    """Tests for the normalize_key_path static method."""

    def test_lowercase_conversion(self):
        """Test that paths are converted to lowercase."""
        result = RegistryDB.normalize_key_path("SOFTWARE\\Microsoft\\Windows")
        assert result == "software\\microsoft\\windows"

    def test_forward_slash_conversion(self):
        """Test that forward slashes are converted to backslashes."""
        result = RegistryDB.normalize_key_path("software/microsoft/windows")
        assert result == "software\\microsoft\\windows"

    def test_strip_leading_backslash(self):
        """Test that leading backslashes are stripped."""
        result = RegistryDB.normalize_key_path("\\SOFTWARE\\Microsoft")
        assert result == "software\\microsoft"

    def test_strip_trailing_backslash(self):
        """Test that trailing backslashes are stripped."""
        result = RegistryDB.normalize_key_path("SOFTWARE\\Microsoft\\")
        assert result == "software\\microsoft"

    def test_strip_both_backslashes(self):
        """Test that both leading and trailing backslashes are stripped."""
        result = RegistryDB.normalize_key_path("\\SOFTWARE\\Microsoft\\")
        assert result == "software\\microsoft"

    def test_empty_string(self):
        """Test handling of empty string."""
        result = RegistryDB.normalize_key_path("")
        assert result == ""

    def test_none_handling(self):
        """Test handling of None (should be handled by caller, but test empty)."""
        result = RegistryDB.normalize_key_path("")
        assert result == ""

    def test_mixed_slashes(self):
        """Test handling of mixed forward and backslashes."""
        result = RegistryDB.normalize_key_path("software/microsoft\\windows/currentversion")
        assert result == "software\\microsoft\\windows\\currentversion"


# ============================================================================
# extract_hive Tests
# ============================================================================

class TestExtractHive:
    """Tests for the extract_hive static method."""

    def test_direct_hive_software(self):
        """Test extraction of SOFTWARE hive."""
        result = RegistryDB.extract_hive("SOFTWARE\\Microsoft\\Windows")
        assert result == "SOFTWARE"

    def test_direct_hive_system(self):
        """Test extraction of SYSTEM hive."""
        result = RegistryDB.extract_hive("SYSTEM\\CurrentControlSet")
        assert result == "SYSTEM"

    def test_direct_hive_ntuser(self):
        """Test extraction of NTUSER hive."""
        result = RegistryDB.extract_hive("NTUSER\\Software\\Microsoft")
        assert result == "NTUSER"

    def test_hklm_software(self):
        """Test extraction from HKEY_LOCAL_MACHINE\\SOFTWARE."""
        result = RegistryDB.extract_hive("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft")
        assert result == "SOFTWARE"

    def test_hklm_system(self):
        """Test extraction from HKLM\\SYSTEM."""
        result = RegistryDB.extract_hive("HKLM\\SYSTEM\\CurrentControlSet")
        assert result == "SYSTEM"

    def test_hkcu_maps_to_ntuser(self):
        """Test that HKEY_CURRENT_USER maps to NTUSER."""
        result = RegistryDB.extract_hive("HKEY_CURRENT_USER\\Software\\Microsoft")
        assert result == "NTUSER"

    def test_hkcu_short_maps_to_ntuser(self):
        """Test that HKCU maps to NTUSER."""
        result = RegistryDB.extract_hive("HKCU\\Software\\Microsoft")
        assert result == "NTUSER"

    def test_hku_returns_none(self):
        """Test that HKU (HKEY_USERS) returns None (requires SID)."""
        result = RegistryDB.extract_hive("HKU\\.DEFAULT\\Software")
        # HKU doesn't map to a specific hive without SID context
        assert result is None

    def test_empty_string(self):
        """Test handling of empty string."""
        result = RegistryDB.extract_hive("")
        assert result is None

    def test_invalid_hive(self):
        """Test handling of invalid/unknown hive."""
        result = RegistryDB.extract_hive("INVALID\\SomeKey")
        assert result is None

    def test_case_insensitive(self):
        """Test that extraction is case-insensitive."""
        result = RegistryDB.extract_hive("software\\microsoft")
        assert result == "SOFTWARE"

    def test_forward_slashes(self):
        """Test handling of forward slashes."""
        result = RegistryDB.extract_hive("SOFTWARE/Microsoft/Windows")
        assert result == "SOFTWARE"


# ============================================================================
# is_available Tests
# ============================================================================

class TestIsAvailable:
    """Tests for the is_available method."""

    def test_available_with_valid_db(self, registry_db_instance):
        """Test that is_available returns True for valid database."""
        assert registry_db_instance.is_available() is True

    def test_available_with_empty_db(self, empty_temp_registry_db):
        """Test that is_available returns True for empty but valid schema."""
        db = RegistryDB(empty_temp_registry_db, read_only=False)
        assert db.is_available() is True
        db.close()

    def test_not_available_with_missing_db(self):
        """Test that is_available returns False for missing database."""
        db = RegistryDB("/nonexistent/path/registry.db")
        assert db.is_available() is False

    def test_not_available_with_invalid_db(self):
        """Test is_available with file that exists but is not a valid DB."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False, mode='w') as f:
            f.write("not a valid sqlite database")
            db_path = Path(f.name)

        db = RegistryDB(db_path, read_only=False)
        # Should return False because the table doesn't exist
        assert db.is_available() is False
        db.close()
        db_path.unlink()


# ============================================================================
# lookup_key Tests
# ============================================================================

class TestLookupKey:
    """Tests for the lookup_key method."""

    def test_lookup_existing_key(self, registry_db_instance):
        """Test looking up a key that exists."""
        results = registry_db_instance.lookup_key(
            "microsoft\\windows\\currentversion\\run"
        )
        assert len(results) > 0
        # Should have SecurityHealth from our test data
        value_names = [r['value_name'] for r in results]
        assert 'SecurityHealth' in value_names

    def test_lookup_nonexistent_key(self, registry_db_instance):
        """Test looking up a key that doesn't exist."""
        results = registry_db_instance.lookup_key(
            "nonexistent\\key\\path"
        )
        assert len(results) == 0

    def test_lookup_with_hive_filter(self, registry_db_instance):
        """Test looking up with explicit hive filter."""
        results = registry_db_instance.lookup_key(
            "microsoft\\windows\\currentversion\\run",
            hive="SOFTWARE"
        )
        assert len(results) > 0
        for r in results:
            assert r['hive'] == 'SOFTWARE'

    def test_lookup_with_wrong_hive_filter(self, registry_db_instance):
        """Test that wrong hive filter returns no results."""
        results = registry_db_instance.lookup_key(
            "microsoft\\windows\\currentversion\\run",
            hive="SYSTEM"  # The Run key is in SOFTWARE, not SYSTEM
        )
        assert len(results) == 0

    def test_lookup_with_os_version_filter(self, registry_db_instance):
        """Test looking up with OS version filter."""
        results = registry_db_instance.lookup_key(
            "microsoft\\windows\\currentversion\\run",
            os_version="W11_22H2"
        )
        assert len(results) > 0
        # All results should be from W11_22H2
        for r in results:
            assert 'W11_22H2' in r['os_versions']

    def test_lookup_excludes_wrong_os_version(self, registry_db_instance):
        """Test that OS version filter excludes other versions."""
        # VMware User Process is only in W10_21H2
        results = registry_db_instance.lookup_key(
            "microsoft\\windows\\currentversion\\run",
            os_version="W11_22H2"
        )
        value_names = [r['value_name'] for r in results]
        assert 'VMware User Process' not in value_names

    def test_lookup_auto_extracts_hive(self, registry_db_instance):
        """Test that hive is auto-extracted from path.

        Note: The current implementation extracts the hive but does NOT strip it
        from the key path. This means paths should be provided WITHOUT the hive
        prefix, or the hive should be explicitly specified.
        """
        # When hive is NOT in the path, it works
        results = registry_db_instance.lookup_key(
            "microsoft\\windows\\currentversion\\run"
        )
        assert len(results) > 0

        # When path includes the hive prefix, it auto-extracts the hive filter
        # but searches for the full normalized path (which won't match stored data
        # since stored data has key_path without hive prefix)
        results_with_hive_prefix = registry_db_instance.lookup_key(
            "SOFTWARE\\microsoft\\windows\\currentversion\\run"
        )
        # This returns empty because key_path_lower in DB is "microsoft\\windows\\..."
        # not "software\\microsoft\\windows\\..."
        # The hive is stored separately in the 'hive' column
        assert len(results_with_hive_prefix) == 0

    def test_lookup_empty_path(self, registry_db_instance):
        """Test looking up empty path."""
        results = registry_db_instance.lookup_key("")
        assert len(results) == 0

    def test_lookup_returns_list(self, registry_db_instance):
        """Test that lookup_key always returns a list."""
        results = registry_db_instance.lookup_key("some\\key")
        assert isinstance(results, list)


# ============================================================================
# lookup_value Tests
# ============================================================================

class TestLookupValue:
    """Tests for the lookup_value method."""

    def test_lookup_existing_value(self, registry_db_instance):
        """Test looking up a value that exists."""
        results = registry_db_instance.lookup_value(
            "microsoft\\windows\\currentversion\\run",
            "SecurityHealth"
        )
        assert len(results) == 1
        assert results[0]['value_name'] == 'SecurityHealth'
        assert results[0]['value_type'] == 'REG_SZ'

    def test_lookup_nonexistent_value(self, registry_db_instance):
        """Test looking up a value that doesn't exist."""
        results = registry_db_instance.lookup_value(
            "microsoft\\windows\\currentversion\\run",
            "NonexistentValue"
        )
        assert len(results) == 0

    def test_lookup_value_with_hive_filter(self, registry_db_instance):
        """Test looking up value with explicit hive filter."""
        results = registry_db_instance.lookup_value(
            "microsoft\\windows\\currentversion\\run",
            "SecurityHealth",
            hive="SOFTWARE"
        )
        assert len(results) == 1

    def test_lookup_value_with_wrong_hive_filter(self, registry_db_instance):
        """Test that wrong hive filter returns no results."""
        results = registry_db_instance.lookup_value(
            "microsoft\\windows\\currentversion\\run",
            "SecurityHealth",
            hive="SYSTEM"
        )
        assert len(results) == 0

    def test_lookup_value_with_os_version_filter(self, registry_db_instance):
        """Test looking up value with OS version filter."""
        results = registry_db_instance.lookup_value(
            "microsoft\\windows\\currentversion\\run",
            "SecurityHealth",
            os_version="W11_22H2"
        )
        assert len(results) == 1

    def test_lookup_value_os_specific(self, registry_db_instance):
        """Test looking up OS-specific value."""
        # VMware User Process is only in W10_21H2
        results = registry_db_instance.lookup_value(
            "microsoft\\windows\\currentversion\\run",
            "VMware User Process",
            os_version="W10_21H2"
        )
        assert len(results) == 1

        # Should not be found for W11_22H2
        results = registry_db_instance.lookup_value(
            "microsoft\\windows\\currentversion\\run",
            "VMware User Process",
            os_version="W11_22H2"
        )
        assert len(results) == 0

    def test_lookup_value_empty_key(self, registry_db_instance):
        """Test looking up with empty key path."""
        results = registry_db_instance.lookup_value("", "SomeValue")
        assert len(results) == 0


# ============================================================================
# key_exists and value_exists Tests
# ============================================================================

class TestExistsMethods:
    """Tests for key_exists and value_exists convenience methods."""

    def test_key_exists_true(self, registry_db_instance):
        """Test key_exists returns True for existing key."""
        assert registry_db_instance.key_exists(
            "microsoft\\windows\\currentversion\\run"
        ) is True

    def test_key_exists_false(self, registry_db_instance):
        """Test key_exists returns False for nonexistent key."""
        assert registry_db_instance.key_exists(
            "nonexistent\\key\\path"
        ) is False

    def test_value_exists_true(self, registry_db_instance):
        """Test value_exists returns True for existing value."""
        assert registry_db_instance.value_exists(
            "microsoft\\windows\\currentversion\\run",
            "SecurityHealth"
        ) is True

    def test_value_exists_false(self, registry_db_instance):
        """Test value_exists returns False for nonexistent value."""
        assert registry_db_instance.value_exists(
            "microsoft\\windows\\currentversion\\run",
            "NonexistentValue"
        ) is False


# ============================================================================
# get_stats Tests
# ============================================================================

class TestGetStats:
    """Tests for the get_stats method."""

    def test_get_stats_available(self, registry_db_instance):
        """Test get_stats with available database."""
        stats = registry_db_instance.get_stats()
        assert stats['available'] is True
        assert 'registry_entries' in stats
        assert stats['registry_entries'] > 0
        assert 'by_hive' in stats
        assert 'SOFTWARE' in stats['by_hive']
        assert 'os_versions' in stats

    def test_get_stats_unavailable(self):
        """Test get_stats with unavailable database."""
        db = RegistryDB("/nonexistent/path/registry.db")
        stats = db.get_stats()
        assert stats['available'] is False
        assert 'reason' in stats

    def test_get_stats_empty_db(self, empty_temp_registry_db):
        """Test get_stats with empty database."""
        db = RegistryDB(empty_temp_registry_db, read_only=False)
        stats = db.get_stats()
        assert stats['available'] is True
        assert stats['registry_entries'] == 0
        db.close()


# ============================================================================
# Cache Tests
# ============================================================================

class TestCaching:
    """Tests for the caching functionality."""

    def test_cache_stats_enabled(self, temp_registry_db):
        """Test cache statistics when caching is enabled."""
        db = RegistryDB(temp_registry_db, cache_size=100)

        # Perform lookups to populate cache
        db.lookup_key("microsoft\\windows\\currentversion\\run")
        db.lookup_key("microsoft\\windows\\currentversion\\run")  # Cache hit

        cache_stats = db.get_cache_stats()
        assert cache_stats['caching_enabled'] is True
        assert 'lookup_key' in cache_stats
        assert cache_stats['lookup_key']['hits'] >= 1
        db.close()

    def test_cache_stats_disabled(self, temp_registry_db):
        """Test cache statistics when caching is disabled."""
        db = RegistryDB(temp_registry_db, cache_size=0)

        cache_stats = db.get_cache_stats()
        assert cache_stats['caching_enabled'] is False
        db.close()

    def test_clear_cache(self, temp_registry_db):
        """Test clearing the cache."""
        db = RegistryDB(temp_registry_db, cache_size=100)

        # Perform lookups to populate cache
        db.lookup_key("microsoft\\windows\\currentversion\\run")

        cache_stats_before = db.get_cache_stats()
        assert cache_stats_before['lookup_key']['size'] > 0

        db.clear_cache()

        cache_stats_after = db.get_cache_stats()
        assert cache_stats_after['lookup_key']['size'] == 0
        db.close()


# ============================================================================
# Connection and Resource Management Tests
# ============================================================================

class TestConnectionManagement:
    """Tests for database connection management."""

    def test_connect_creates_connection(self, temp_registry_db):
        """Test that connect creates a connection."""
        db = RegistryDB(temp_registry_db, read_only=False)
        conn = db.connect()
        assert conn is not None
        db.close()

    def test_close_closes_connection(self, temp_registry_db):
        """Test that close properly closes connection."""
        db = RegistryDB(temp_registry_db, read_only=False)
        db.connect()
        db.close()
        assert db._conn is None

    def test_multiple_connects_same_connection(self, temp_registry_db):
        """Test that multiple connects return the same connection."""
        db = RegistryDB(temp_registry_db, read_only=False)
        conn1 = db.connect()
        conn2 = db.connect()
        assert conn1 is conn2
        db.close()

    def test_init_schema(self, temp_registry_db):
        """Test schema initialization."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            new_db_path = Path(f.name)

        db = RegistryDB(new_db_path, read_only=False)
        db.init_schema()

        # Should be available after schema init
        assert db.is_available() is True
        db.close()
        new_db_path.unlink()


# ============================================================================
# Integration with Real Database (if available)
# ============================================================================

class TestWithRealDatabase:
    """Tests using the actual known_good_registry.db if available.

    These tests validate the real imported database. If the DB exists but
    is empty, data-dependent tests skip with a diagnostic message rather
    than failing with an opaque '0 > 0' assertion.
    """

    @pytest.fixture
    def real_registry_db(self):
        """Load the real registry database if it exists."""
        db_path = Path(__file__).parent.parent / "data" / "known_good_registry.db"
        if not db_path.exists():
            pytest.skip("known_good_registry.db not available")

        db = RegistryDB(db_path)
        yield db
        db.close()

    def test_real_db_available(self, real_registry_db):
        """Test that real database is available and has correct schema."""
        assert real_registry_db.is_available() is True

    def test_real_db_populated(self, real_registry_db):
        """Test that the registry import actually produced data.

        This is the primary health check for the import pipeline.
        Failure here means import_registry_full.py ran but found no data,
        likely because RegistryHivesJSON.zip files weren't read.
        """
        db_path = Path(real_registry_db.db_path)
        stats = real_registry_db.get_stats()
        size_mb = db_path.stat().st_size / (1024 * 1024)

        assert stats['registry_entries'] > 0, (
            f"known_good_registry.db exists ({size_mb:.1f} MB) but contains "
            f"0 registry entries and {stats.get('os_versions', 0)} OS versions. "
            f"The registry import likely found no JSON files — check that "
            f"import_registry_full.py can read RegistryHivesJSON.zip archives."
        )
        assert stats['os_versions'] > 0, (
            f"known_good_registry.db has {stats['registry_entries']} entries "
            f"but 0 OS versions — import may be partially broken."
        )

    def test_real_db_has_data(self, real_registry_db):
        """Test that real database contains data (skips if empty)."""
        stats = real_registry_db.get_stats()
        if stats['registry_entries'] == 0:
            pytest.skip(
                "known_good_registry.db exists but is empty — "
                "registry import did not run or found no data"
            )
        assert stats['available'] is True
        assert stats['registry_entries'] > 0
        assert stats['os_versions'] > 0

    def test_real_db_common_key_lookup(self, real_registry_db):
        """Test looking up a common registry key (skips if empty)."""
        stats = real_registry_db.get_stats()
        if stats['registry_entries'] == 0:
            pytest.skip(
                "known_good_registry.db exists but is empty — "
                "registry import did not run or found no data"
            )
        # This key should exist in any Windows installation
        results = real_registry_db.lookup_key(
            "microsoft\\windows\\currentversion"
        )
        assert len(results) > 0

    def test_real_db_run_key_lookup(self, real_registry_db):
        """Test looking up the Run key (common persistence location)."""
        results = real_registry_db.lookup_key(
            "software\\microsoft\\windows\\currentversion\\run",
            hive="SOFTWARE"
        )
        # Run key entries vary by OS, but the key path should be queryable
        # The result might be empty or have entries depending on the baseline
        assert isinstance(results, list)
