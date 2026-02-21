"""Integration tests for context.db operations."""

import pytest


class TestContextDBLOLBins:
    """Tests for LOLBin operations."""

    def test_check_lolbin(self, context_db_instance):
        """Test checking a LOLBin by name."""
        db = context_db_instance
        result = db.check_lolbin("certutil.exe")
        assert result is not None
        assert result['name'] == 'Certutil.exe'
        assert 'Download' in result['functions']

    def test_check_lolbin_case_insensitive(self, context_db_instance):
        """Test that LOLBin lookup is case-insensitive."""
        db = context_db_instance
        result = db.check_lolbin("CERTUTIL.EXE")
        assert result is not None

    def test_check_lolbin_not_found(self, context_db_instance):
        """Test checking a non-existent LOLBin."""
        db = context_db_instance
        result = db.check_lolbin("notepad.exe")
        assert result is None

    def test_is_lolbin_check(self, context_db_instance):
        """Test checking if a file is a LOLBin."""
        db = context_db_instance
        assert db.check_lolbin("certutil.exe") is not None
        assert db.check_lolbin("mshta.exe") is not None
        assert db.check_lolbin("notepad.exe") is None


class TestContextDBDrivers:
    """Tests for vulnerable driver operations."""

    def test_check_vulnerable_driver(self, context_db_instance):
        """Test checking a vulnerable driver hash."""
        db = context_db_instance
        result = db.check_vulnerable_driver("aabbccdd1234567890abcdef1234567890abcdef1234567890abcdef12345678", "sha256")
        assert result is not None
        assert result['product'] == 'VulnDriver.sys'
        assert result['cve'] == 'CVE-2021-1234'

    def test_check_vulnerable_driver_not_found(self, context_db_instance):
        """Test checking a non-vulnerable driver hash."""
        db = context_db_instance
        result = db.check_vulnerable_driver("0000000000000000000000000000000000000000000000000000000000000000", "sha256")
        assert result is None


class TestContextDBHijackableDLLs:
    """Tests for hijackable DLL operations."""

    def test_check_hijackable_dll(self, context_db_instance):
        """Test checking a hijackable DLL."""
        db = context_db_instance
        result = db.check_hijackable_dll("version.dll")
        assert result is not None
        assert len(result) > 0
        assert any(r['vulnerable_exe'] == 'notepad.exe' for r in result)

    def test_check_hijackable_dll_case_insensitive(self, context_db_instance):
        """Test that DLL lookup is case-insensitive."""
        db = context_db_instance
        result = db.check_hijackable_dll("VERSION.DLL")
        assert result is not None

    def test_check_hijackable_dll_not_found(self, context_db_instance):
        """Test checking a non-hijackable DLL."""
        db = context_db_instance
        result = db.check_hijackable_dll("kernel32.dll")
        assert result is None or len(result) == 0


class TestContextDBProcessExpectations:
    """Tests for process expectation operations."""

    def test_get_expected_process(self, context_db_instance):
        """Test getting expected process info."""
        db = context_db_instance
        result = db.get_expected_process("svchost.exe")
        assert result is not None
        assert 'services.exe' in result['valid_parents']
        assert result['user_type'] == 'EITHER'

    def test_get_expected_process_case_insensitive(self, context_db_instance):
        """Test that process lookup is case-insensitive."""
        db = context_db_instance
        result = db.get_expected_process("SVCHOST.EXE")
        assert result is not None

    def test_get_expected_process_not_found(self, context_db_instance):
        """Test getting a non-expected process."""
        db = context_db_instance
        result = db.get_expected_process("custom_app.exe")
        assert result is None

    def test_lsass_parent(self, context_db_instance):
        """Test lsass.exe expected parent."""
        db = context_db_instance
        result = db.get_expected_process("lsass.exe")
        assert result is not None
        assert 'wininit.exe' in result['valid_parents']
        assert result['user_type'] == 'SYSTEM'

    def test_cmd_user_type(self, context_db_instance):
        """Test cmd.exe expected user type."""
        db = context_db_instance
        result = db.get_expected_process("cmd.exe")
        assert result is not None
        assert result['user_type'] == 'USER'  # Should be USER, SYSTEM is suspicious


class TestContextDBSuspiciousFilenames:
    """Tests for suspicious filename operations."""

    def test_check_suspicious_filename_exact(self, context_db_instance):
        """Test checking a known malicious filename."""
        db = context_db_instance
        result = db.check_suspicious_filename("mimikatz.exe")
        assert result is not None
        assert result['tool_name'] == 'Mimikatz'
        assert result['category'] == 'credential_theft'

    def test_check_suspicious_filename_regex(self, context_db_instance):
        """Test checking a filename against regex pattern."""
        db = context_db_instance
        result = db.check_suspicious_filename("psexec64.exe")
        assert result is not None
        assert result['tool_name'] == 'PsExec'

    def test_check_suspicious_filename_not_found(self, context_db_instance):
        """Test checking a normal filename."""
        db = context_db_instance
        result = db.check_suspicious_filename("notepad.exe")
        assert result is None


class TestContextDBProtectedNames:
    """Tests for protected process name operations."""

    def test_get_protected_process_names(self, context_db_instance):
        """Test getting protected process names."""
        db = context_db_instance
        names = db.get_protected_process_names()
        assert len(names) > 0
        assert 'svchost.exe' in names
        assert 'lsass.exe' in names
        assert 'csrss.exe' in names


class TestContextDBStats:
    """Tests for database statistics."""

    def test_get_stats(self, context_db_instance):
        """Test getting database statistics."""
        db = context_db_instance
        stats = db.get_stats()
        assert 'lolbins' in stats
        assert stats['lolbins'] > 0
        assert 'vulnerable_drivers' in stats
        assert 'hijackable_dlls' in stats
        assert 'expected_processes' in stats


class TestContextDBWithRealData:
    """Tests that require the real populated database."""

    @pytest.fixture
    def real_db(self):
        """Use the real context.db if it exists."""
        from pathlib import Path
        from windows_triage.db.context import ContextDB

        db_path = Path(__file__).parent.parent / "data" / "context.db"
        if not db_path.exists():
            pytest.skip("Real database not available")

        return ContextDB(db_path)

    def test_lolbin_count(self, real_db):
        """Test that we have expected LOLBin count."""
        stats = real_db.get_stats()
        assert stats['lolbins'] >= 200  # Should have 227+

    def test_certutil_lolbin(self, real_db):
        """Test certutil.exe LOLBin info."""
        result = real_db.check_lolbin("certutil.exe")
        assert result is not None
        assert 'Download' in result['functions']

    def test_process_expectations_count(self, real_db):
        """Test process expectations count."""
        stats = real_db.get_stats()
        assert stats['expected_processes'] >= 20

    def test_svchost_expectations(self, real_db):
        """Test svchost.exe expectations from real data."""
        result = real_db.get_expected_process("svchost.exe")
        assert result is not None
        assert 'services.exe' in result['valid_parents']

    def test_hijackable_dll_count(self, real_db):
        """Test hijackable DLL count."""
        stats = real_db.get_stats()
        assert stats['hijackable_dlls'] >= 500  # Should have 2000+
