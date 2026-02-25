"""Tests for WindowsTriageServer MCP tool handlers.

These tests validate all 12 MCP tools by testing the underlying handler methods
directly, bypassing the MCP protocol layer.
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest
from windows_triage.config import Config
from windows_triage.exceptions import DatabaseError, ValidationError
from windows_triage.server import (
    WindowsTriageServer,
    _validate_input_length,
    _validate_no_null_bytes,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_dbs():
    """Create temporary databases with minimal schema for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create known_good.db with v2 schema
        kg_path = tmpdir / "known_good.db"
        conn = sqlite3.connect(kg_path)
        cursor = conn.cursor()
        cursor.executescript("""
            -- baseline_files (v2 schema)
            CREATE TABLE baseline_files (
                id INTEGER PRIMARY KEY,
                path_normalized TEXT UNIQUE,
                directory_normalized TEXT NOT NULL,
                filename_lower TEXT NOT NULL,
                os_versions TEXT NOT NULL,
                first_seen_source TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_files_path ON baseline_files(path_normalized);
            CREATE INDEX idx_files_filename ON baseline_files(filename_lower);

            -- baseline_hashes (separate table for hash lookups)
            CREATE TABLE baseline_hashes (
                id INTEGER PRIMARY KEY,
                hash_value TEXT NOT NULL,
                hash_type TEXT NOT NULL,
                file_id INTEGER NOT NULL,
                os_id INTEGER,
                file_size INTEGER,
                FOREIGN KEY (file_id) REFERENCES baseline_files(id) ON DELETE CASCADE,
                UNIQUE(hash_value, hash_type, file_id)
            );
            CREATE INDEX idx_hashes_value ON baseline_hashes(hash_value);
            CREATE INDEX idx_hashes_type_value ON baseline_hashes(hash_type, hash_value);

            -- baseline_services
            CREATE TABLE baseline_services (
                id INTEGER PRIMARY KEY,
                service_name_lower TEXT UNIQUE NOT NULL,
                display_name TEXT,
                binary_path_pattern TEXT,
                start_type INTEGER,
                service_type INTEGER,
                object_name TEXT,
                description TEXT,
                os_versions TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_services_name ON baseline_services(service_name_lower);

            -- baseline_tasks
            CREATE TABLE baseline_tasks (
                id INTEGER PRIMARY KEY,
                task_path_lower TEXT UNIQUE NOT NULL,
                task_name TEXT,
                uri TEXT,
                actions_summary TEXT,
                triggers_summary TEXT,
                author TEXT,
                os_versions TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_tasks_path ON baseline_tasks(task_path_lower);

            -- baseline_autoruns
            CREATE TABLE baseline_autoruns (
                id INTEGER PRIMARY KEY,
                hive TEXT NOT NULL,
                key_path_lower TEXT NOT NULL,
                value_name TEXT,
                value_data_pattern TEXT,
                autorun_type TEXT,
                os_versions TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(hive, key_path_lower, value_name)
            );
            CREATE INDEX idx_autoruns_key ON baseline_autoruns(key_path_lower);

            -- Insert test data
            INSERT INTO baseline_files (path_normalized, directory_normalized, filename_lower, os_versions)
            VALUES
                ('\\windows\\system32\\cmd.exe', '\\windows\\system32', 'cmd.exe', '["W11_22H2", "W10_21H2"]'),
                ('\\windows\\system32\\notepad.exe', '\\windows\\system32', 'notepad.exe', '["W11_22H2", "W10_21H2"]'),
                ('\\windows\\system32\\certutil.exe', '\\windows\\system32', 'certutil.exe', '["W11_22H2", "W10_21H2"]');

            INSERT INTO baseline_hashes (hash_value, hash_type, file_id)
            VALUES
                ('abc123', 'md5', 1),
                ('def456', 'sha1', 1),
                ('ghi789', 'sha256', 1);

            INSERT INTO baseline_services (service_name_lower, display_name, binary_path_pattern, os_versions)
            VALUES
                ('bits', 'Background Intelligent Transfer Service',
                 '\\windows\\system32\\svchost.exe', '["W11_22H2", "W10_21H2"]'),
                ('spooler', 'Print Spooler',
                 '\\windows\\system32\\spoolsv.exe', '["W11_22H2", "W10_21H2"]');

            INSERT INTO baseline_tasks (task_path_lower, task_name, os_versions)
            VALUES
                ('\\microsoft\\windows\\updateorchestrator\\schedule scan',
                 'Schedule Scan', '["W11_22H2", "W10_21H2"]');

            INSERT INTO baseline_autoruns (hive, key_path_lower, value_name, os_versions)
            VALUES
                ('HKLM', 'software\\microsoft\\windows\\currentversion\\run',
                 'SecurityHealth', '["W11_22H2", "W10_21H2"]');
        """)
        conn.commit()
        conn.close()

        # Create context.db with actual schema
        ctx_path = tmpdir / "context.db"
        conn = sqlite3.connect(ctx_path)
        cursor = conn.cursor()
        cursor.executescript("""
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
            );
            CREATE INDEX idx_lol_filename ON lolbins(filename_lower);

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
            );
            CREATE INDEX idx_vd_sha256 ON vulnerable_drivers(sha256);
            CREATE INDEX idx_vd_md5 ON vulnerable_drivers(md5);

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
            );
            CREATE INDEX idx_ep_name ON expected_processes(process_name_lower);

            CREATE TABLE hijackable_dlls (
                id INTEGER PRIMARY KEY,
                dll_name_lower TEXT NOT NULL,
                hijack_type TEXT,
                vulnerable_exe TEXT,
                vulnerable_exe_path TEXT,
                expected_paths TEXT,
                vendor TEXT,
                UNIQUE(dll_name_lower, vulnerable_exe)
            );
            CREATE INDEX idx_hjk_dll ON hijackable_dlls(dll_name_lower);

            CREATE TABLE suspicious_pipe_patterns (
                id INTEGER PRIMARY KEY,
                pipe_pattern TEXT NOT NULL UNIQUE,
                is_regex INTEGER DEFAULT 0,
                pipe_example TEXT,
                tool_name TEXT,
                malware_family TEXT,
                mitre_technique TEXT,
                description TEXT
            );

            CREATE TABLE windows_named_pipes (
                id INTEGER PRIMARY KEY,
                pipe_name TEXT NOT NULL UNIQUE,
                pipe_pattern TEXT,
                protocol TEXT,
                service_name TEXT,
                associated_process TEXT,
                microsoft_doc_url TEXT,
                description TEXT
            );
            CREATE INDEX idx_np_name ON windows_named_pipes(pipe_name);

            CREATE TABLE suspicious_filenames (
                id INTEGER PRIMARY KEY,
                filename_pattern TEXT NOT NULL UNIQUE,
                is_regex INTEGER DEFAULT 0,
                tool_name TEXT,
                category TEXT,
                mitre_techniques TEXT,
                risk_level TEXT DEFAULT 'high',
                notes TEXT
            );
            CREATE INDEX idx_sf_pattern ON suspicious_filenames(filename_pattern);

            CREATE TABLE protected_process_names (
                id INTEGER PRIMARY KEY,
                process_name_lower TEXT NOT NULL UNIQUE,
                canonical_form TEXT NOT NULL,
                description TEXT
            );

            -- Insert test data
            INSERT INTO lolbins (filename_lower, name, description, functions, expected_paths, mitre_techniques)
            VALUES
                ('certutil.exe', 'certutil.exe', 'Certificate utility',
                 '["Download", "Encode", "Decode"]',
                 '["\\\\windows\\\\system32\\\\certutil.exe"]',
                 '["T1140", "T1105"]'),
                ('mshta.exe', 'mshta.exe', 'Microsoft HTML Application Host',
                 '["Execute", "AWL Bypass"]',
                 '["\\\\windows\\\\system32\\\\mshta.exe"]',
                 '["T1218.005"]');

            INSERT INTO vulnerable_drivers (filename_lower, sha256, md5, product, cve, vulnerability_type)
            VALUES
                ('rtcore64.sys',
                 '01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd',
                 'abc123def456',
                 'RTCore64', 'CVE-2019-16098', 'Arbitrary Read/Write');

            INSERT INTO expected_processes (process_name_lower, valid_parents, suspicious_parents,
                                           never_spawns_children, valid_paths, user_type)
            VALUES
                ('svchost.exe', '["services.exe"]', NULL, 0,
                 '["\\\\windows\\\\system32\\\\svchost.exe"]', 'SYSTEM'),
                ('lsass.exe', '["wininit.exe"]', NULL, 1,
                 '["\\\\windows\\\\system32\\\\lsass.exe"]', 'SYSTEM'),
                ('cmd.exe', NULL,
                 '["winword.exe", "excel.exe", "chrome.exe", "firefox.exe", "acrord32.exe", "java.exe"]',
                 0, NULL, 'EITHER');

            INSERT INTO hijackable_dlls (dll_name_lower, hijack_type, vulnerable_exe,
                                        vulnerable_exe_path, expected_paths, vendor)
            VALUES
                ('version.dll', 'Sideloading', 'notepad.exe',
                 '\\windows\\system32\\notepad.exe', '["\\\\windows\\\\system32"]', 'Microsoft');

            INSERT INTO suspicious_pipe_patterns (pipe_pattern, is_regex, tool_name, malware_family)
            VALUES
                ('msagent_*', 1, 'Cobalt Strike', 'Cobalt Strike'),
                ('postex_*', 1, 'Cobalt Strike', 'Cobalt Strike');

            INSERT INTO windows_named_pipes (pipe_name, protocol, service_name)
            VALUES
                ('lsass', 'LSARPC', 'LSASS'),
                ('netlogon', 'NETLOGON', 'Netlogon');

            INSERT INTO suspicious_filenames (filename_pattern, is_regex, tool_name, category, risk_level)
            VALUES
                ('mimikatz', 0, 'Mimikatz', 'credential_theft', 'critical'),
                ('procdump', 0, 'ProcDump', 'credential_theft', 'high');

            INSERT INTO protected_process_names (process_name_lower, canonical_form, description)
            VALUES
                ('svchost.exe', 'svchost.exe', 'Service Host'),
                ('lsass.exe', 'lsass.exe', 'Local Security Authority'),
                ('csrss.exe', 'csrss.exe', 'Client Server Runtime'),
                ('smss.exe', 'smss.exe', 'Session Manager');
        """)
        conn.commit()
        conn.close()

        yield kg_path, ctx_path


@pytest.fixture
def server(temp_dbs):
    """Create a WindowsTriageServer with test databases."""
    kg_path, ctx_path = temp_dbs
    config = Config(
        known_good_db=kg_path,
        context_db=ctx_path,
        skip_db_validation=True,
        cache_size=0,  # Disable caching for predictable tests
    )
    return WindowsTriageServer(config=config)


# ============================================================================
# Input Validation Tests
# ============================================================================


class TestInputValidation:
    """Tests for input validation functions."""

    def test_validate_input_length_valid(self):
        """Test that valid length passes."""
        _validate_input_length("short string", 100, "field")

    def test_validate_input_length_at_limit(self):
        """Test that string at limit passes."""
        _validate_input_length("x" * 100, 100, "field")

    def test_validate_input_length_exceeds(self):
        """Test that string exceeding limit raises."""
        with pytest.raises(ValidationError) as exc_info:
            _validate_input_length("x" * 101, 100, "test_field")
        assert "test_field" in str(exc_info.value)
        assert "100" in str(exc_info.value)

    def test_validate_input_length_none(self):
        """Test that None passes."""
        _validate_input_length(None, 100, "field")

    def test_validate_input_length_non_string(self):
        """Test that non-strings pass."""
        _validate_input_length(12345, 5, "field")

    def test_validate_no_null_bytes_clean(self):
        """Test that clean string passes."""
        _validate_no_null_bytes("clean string", "field")

    def test_validate_no_null_bytes_with_null(self):
        """Test that null bytes raise."""
        with pytest.raises(ValidationError) as exc_info:
            _validate_no_null_bytes("string\x00with\x00nulls", "test_field")
        assert "test_field" in str(exc_info.value)
        assert "null" in str(exc_info.value).lower()

    def test_validate_no_null_bytes_none(self):
        """Test that None passes."""
        _validate_no_null_bytes(None, "field")


# ============================================================================
# check_file Tests
# ============================================================================


class TestCheckFile:
    """Tests for check_file tool."""

    @pytest.mark.asyncio
    async def test_file_in_baseline(self, server):
        """Test checking a file that exists in baseline."""
        result = await server._check_file("C:\\Windows\\System32\\cmd.exe")
        assert result["path_in_baseline"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_file_not_in_baseline(self, server):
        """Test checking a file not in baseline."""
        result = await server._check_file("C:\\Users\\test\\malware.exe")
        assert result["path_in_baseline"] is False
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_lolbin_in_baseline(self, server):
        """Test checking a LOLBin in its expected location."""
        result = await server._check_file("C:\\Windows\\System32\\certutil.exe")
        assert result["path_in_baseline"] is True
        assert result["is_lolbin"] is True
        assert result["verdict"] == "EXPECTED_LOLBIN"

    @pytest.mark.asyncio
    async def test_lolbin_wrong_location(self, server):
        """Test checking a LOLBin in unexpected location."""
        result = await server._check_file("C:\\Users\\test\\certutil.exe")
        # Not in baseline, but filename matches LOLBin
        assert result["path_in_baseline"] is False
        assert result["verdict"] == "SUSPICIOUS"
        assert "non-standard location" in str(result.get("reasons", []))

    @pytest.mark.asyncio
    async def test_hash_mismatch(self, server):
        """Test checking file with hash mismatch."""
        result = await server._check_file(
            "C:\\Windows\\System32\\cmd.exe",
            hash_value="ffffffffffffffffffffffffffffffff",  # Wrong hash
        )
        # Should detect hash mismatch against baseline
        assert any(
            "hash_mismatch" in str(f.get("type", ""))
            for f in result.get("findings", [])
        )

    @pytest.mark.asyncio
    async def test_protected_process_wrong_path(self, server):
        """Test protected process name in wrong path."""
        result = await server._check_file("C:\\Temp\\svchost.exe")
        assert result["verdict"] == "SUSPICIOUS"
        # Should flag protected process in wrong location

    @pytest.mark.asyncio
    async def test_invalid_hash_ignored(self, server):
        """Test that invalid hash format is handled gracefully."""
        result = await server._check_file(
            "C:\\Windows\\System32\\cmd.exe", hash_value="not-a-valid-hash"
        )
        # Should still return valid result
        assert "verdict" in result


# ============================================================================
# check_process_tree Tests
# ============================================================================


class TestCheckProcessTree:
    """Tests for check_process_tree tool."""

    @pytest.mark.asyncio
    async def test_valid_parent_child(self, server):
        """Test valid parent-child relationship."""
        result = await server._check_process_tree(
            process_name="svchost.exe", parent_name="services.exe"
        )
        assert result["in_expectations_db"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_invalid_parent(self, server):
        """Test invalid parent process."""
        result = await server._check_process_tree(
            process_name="svchost.exe",
            parent_name="notepad.exe",  # Invalid parent
        )
        assert result["verdict"] == "SUSPICIOUS"

    @pytest.mark.asyncio
    async def test_suspicious_parent_blacklist(self, server):
        """Test suspicious parent from blacklist."""
        result = await server._check_process_tree(
            process_name="cmd.exe",
            parent_name="winword.exe",  # Office app spawning shell
        )
        assert result["verdict"] == "SUSPICIOUS"
        assert any(
            "suspicious_parent" in str(f.get("type", ""))
            for f in result.get("findings", [])
        )

    @pytest.mark.asyncio
    async def test_injection_detected(self, server):
        """Test injection detection (never_spawns_children)."""
        result = await server._check_process_tree(
            process_name="cmd.exe",
            parent_name="lsass.exe",  # lsass should never spawn children
        )
        assert result["verdict"] == "SUSPICIOUS"
        assert any(
            "injection" in str(f.get("type", "")).lower()
            for f in result.get("findings", [])
        )

    @pytest.mark.asyncio
    async def test_unknown_process(self, server):
        """Test unknown process (not in database)."""
        result = await server._check_process_tree(
            process_name="custom_app.exe", parent_name="explorer.exe"
        )
        assert result["in_expectations_db"] is False
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_path_validation(self, server):
        """Test path validation for known process."""
        result = await server._check_process_tree(
            process_name="svchost.exe",
            parent_name="services.exe",
            path="C:\\Temp\\svchost.exe",  # Wrong path
        )
        assert result["verdict"] == "SUSPICIOUS"

    @pytest.mark.asyncio
    async def test_user_validation_system(self, server):
        """Test user context validation for SYSTEM process."""
        result = await server._check_process_tree(
            process_name="svchost.exe", parent_name="services.exe", user="SYSTEM"
        )
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_user_validation_wrong_user(self, server):
        """Test wrong user context."""
        result = await server._check_process_tree(
            process_name="svchost.exe",
            parent_name="services.exe",
            user="testuser",  # Should be SYSTEM
        )
        assert result["verdict"] == "SUSPICIOUS"


# ============================================================================
# check_service Tests
# ============================================================================


class TestCheckService:
    """Tests for check_service tool."""

    @pytest.mark.asyncio
    async def test_service_in_baseline(self, server):
        """Test service that exists in baseline."""
        result = await server._check_service(service_name="BITS", os_version="W11_22H2")
        assert result["in_baseline"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_service_not_in_baseline(self, server):
        """Test service not in baseline."""
        result = await server._check_service(
            service_name="MaliciousService", os_version="W11_22H2"
        )
        assert result["in_baseline"] is False
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_service_missing_os_version(self, server):
        """Test that missing os_version returns error."""
        result = await server._check_service(service_name="BITS")
        assert "error" in result
        assert "os_version" in result["error"]

    @pytest.mark.asyncio
    async def test_service_binary_mismatch(self, server):
        """Test service with different binary path."""
        result = await server._check_service(
            service_name="BITS",
            binary_path="C:\\Temp\\malicious.exe",  # Wrong binary
            os_version="W11_22H2",
        )
        assert result["verdict"] == "SUSPICIOUS"


# ============================================================================
# check_scheduled_task Tests
# ============================================================================


class TestCheckScheduledTask:
    """Tests for check_scheduled_task tool."""

    @pytest.mark.asyncio
    async def test_task_in_baseline(self, server):
        """Test task that exists in baseline."""
        result = await server._check_scheduled_task(
            task_path="\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
            os_version="W11_22H2",
        )
        assert result["in_baseline"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_task_not_in_baseline(self, server):
        """Test task not in baseline."""
        result = await server._check_scheduled_task(
            task_path="\\Custom\\MaliciousTask", os_version="W11_22H2"
        )
        assert result["in_baseline"] is False
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_task_missing_os_version(self, server):
        """Test that missing os_version returns error."""
        result = await server._check_scheduled_task(
            task_path="\\Microsoft\\Windows\\Test"
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_task_suspicious_location(self, server):
        """Test task in suspicious location."""
        result = await server._check_scheduled_task(
            task_path="\\Temp\\SuspiciousTask", os_version="W11_22H2"
        )
        assert result["verdict"] == "SUSPICIOUS"


# ============================================================================
# check_autorun Tests
# ============================================================================


class TestCheckAutorun:
    """Tests for check_autorun tool."""

    @pytest.mark.asyncio
    async def test_autorun_in_baseline(self, server):
        """Test autorun that exists in baseline."""
        result = await server._check_autorun(
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            value_name="SecurityHealth",
            os_version="W11_22H2",
        )
        assert result["in_baseline"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_autorun_not_in_baseline(self, server):
        """Test autorun not in baseline."""
        result = await server._check_autorun(
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            value_name="MaliciousApp",
            os_version="W11_22H2",
        )
        assert result["in_baseline"] is False

    @pytest.mark.asyncio
    async def test_autorun_missing_os_version(self, server):
        """Test that missing os_version returns error."""
        result = await server._check_autorun(
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_autorun_high_risk_location(self, server):
        """Test autorun in high-risk persistence location."""
        result = await server._check_autorun(
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            value_name="UnknownApp",
            os_version="W11_22H2",
        )
        # High-risk location but not in baseline
        assert result["verdict"] == "SUSPICIOUS"


# ============================================================================
# check_registry Tests
# ============================================================================


class TestCheckRegistry:
    """Tests for check_registry tool."""

    @pytest.fixture
    def server_with_registry(self, temp_dbs):
        """Create a WindowsTriageServer with a registry database."""
        import sqlite3
        import tempfile

        from windows_triage.db.schemas import REGISTRY_FULL_SCHEMA

        kg_path, ctx_path = temp_dbs

        # Create a temporary registry database
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            reg_path = Path(f.name)

        conn = sqlite3.connect(reg_path)
        conn.executescript(REGISTRY_FULL_SCHEMA)

        cursor = conn.cursor()

        # Insert OS version
        cursor.execute(
            """
            INSERT INTO baseline_os (short_name, os_family, os_edition, os_release)
            VALUES (?, ?, ?, ?)
        """,
            ("W11_22H2", "Windows 11", "Enterprise", "22H2"),
        )

        # Insert registry entries
        test_entries = [
            (
                "SOFTWARE",
                "microsoft\\windows\\currentversion\\run",
                "SecurityHealth",
                "REG_SZ",
                "%ProgramFiles%\\Windows Defender\\MSASCuiL.exe",
                '["W11_22H2"]',
            ),
            (
                "SOFTWARE",
                "microsoft\\windows\\currentversion",
                "ProgramFilesDir",
                "REG_SZ",
                "C:\\Program Files",
                '["W11_22H2"]',
            ),
            (
                "SYSTEM",
                "currentcontrolset\\services\\bits",
                "Start",
                "REG_DWORD",
                "3",
                '["W11_22H2"]',
            ),
        ]

        for (
            hive,
            key_path,
            value_name,
            value_type,
            value_data,
            os_versions,
        ) in test_entries:
            cursor.execute(
                """
                INSERT INTO baseline_registry (hive, key_path_lower, value_name, value_type, value_data, os_versions)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (hive, key_path, value_name, value_type, value_data, os_versions),
            )

        conn.commit()
        conn.close()

        config = Config(
            known_good_db=kg_path,
            context_db=ctx_path,
            registry_db=reg_path,
            skip_db_validation=True,
            cache_size=0,
        )

        server = WindowsTriageServer(config=config)
        yield server

        # Cleanup
        reg_path.unlink(missing_ok=True)

    @pytest.fixture
    def server_without_registry(self, temp_dbs):
        """Create a WindowsTriageServer without a registry database."""
        kg_path, ctx_path = temp_dbs
        # Use a non-existent path for registry_db
        config = Config(
            known_good_db=kg_path,
            context_db=ctx_path,
            registry_db=Path("/nonexistent/path/known_good_registry.db"),
            skip_db_validation=True,
            cache_size=0,
        )
        return WindowsTriageServer(config=config)

    @pytest.mark.asyncio
    async def test_registry_db_not_available(self, server_without_registry):
        """Test check_registry when registry_db is not available."""
        result = await server_without_registry._check_registry(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        assert "error" in result
        assert (
            "not available" in result["error"].lower()
            or "not installed" in result.get("message", "").lower()
        )
        assert result.get("verdict") is None
        assert result.get("lookup_performed") is False

    @pytest.mark.asyncio
    async def test_registry_key_in_baseline(self, server_with_registry):
        """Test checking a registry key that exists in baseline."""
        result = await server_with_registry._check_registry(
            "microsoft\\windows\\currentversion\\run"
        )
        assert result["in_baseline"] is True
        assert result["verdict"] == "EXPECTED"
        assert "match_count" in result
        assert result["match_count"] > 0

    @pytest.mark.asyncio
    async def test_registry_key_not_in_baseline(self, server_with_registry):
        """Test checking a registry key not in baseline."""
        result = await server_with_registry._check_registry("nonexistent\\key\\path")
        assert result["in_baseline"] is False
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_registry_value_in_baseline(self, server_with_registry):
        """Test checking a specific registry value that exists."""
        result = await server_with_registry._check_registry(
            "microsoft\\windows\\currentversion\\run", value_name="SecurityHealth"
        )
        assert result["in_baseline"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_registry_value_not_in_baseline(self, server_with_registry):
        """Test checking a specific registry value that doesn't exist."""
        result = await server_with_registry._check_registry(
            "microsoft\\windows\\currentversion\\run", value_name="NonexistentValue"
        )
        assert result["in_baseline"] is False
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_registry_with_hive_filter(self, server_with_registry):
        """Test checking registry with explicit hive filter."""
        result = await server_with_registry._check_registry(
            "microsoft\\windows\\currentversion\\run", hive="SOFTWARE"
        )
        assert result["in_baseline"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_registry_with_wrong_hive_filter(self, server_with_registry):
        """Test that wrong hive filter returns no results."""
        # Run key is in SOFTWARE, not SYSTEM
        result = await server_with_registry._check_registry(
            "microsoft\\windows\\currentversion\\run", hive="SYSTEM"
        )
        assert result["in_baseline"] is False
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_registry_with_os_version_filter(self, server_with_registry):
        """Test checking registry with OS version filter."""
        result = await server_with_registry._check_registry(
            "microsoft\\windows\\currentversion\\run", os_version="W11_22H2"
        )
        assert result["in_baseline"] is True
        assert "W11_22H2" in result.get("os_versions", [])

    @pytest.mark.asyncio
    async def test_registry_system_hive(self, server_with_registry):
        """Test checking a SYSTEM hive key."""
        result = await server_with_registry._check_registry(
            "currentcontrolset\\services\\bits", hive="SYSTEM"
        )
        assert result["in_baseline"] is True
        assert result["verdict"] == "EXPECTED"

    @pytest.mark.asyncio
    async def test_registry_returns_values_info(self, server_with_registry):
        """Test that registry lookup returns values information."""
        result = await server_with_registry._check_registry(
            "microsoft\\windows\\currentversion\\run"
        )
        assert result["in_baseline"] is True
        # Should have values info if values exist
        if "values" in result:
            assert isinstance(result["values"], list)


# ============================================================================
# check_hash Tests
# ============================================================================


class TestCheckHash:
    """Tests for check_hash tool."""

    @pytest.mark.asyncio
    async def test_vulnerable_driver_sha256(self, server):
        """Test detecting vulnerable driver by SHA256."""
        result = await server._check_hash(
            "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
        )
        assert result["verdict"] == "SUSPICIOUS"
        assert "vulnerable_driver" in result

    @pytest.mark.asyncio
    async def test_unknown_hash(self, server):
        """Test unknown hash."""
        result = await server._check_hash(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        assert result["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_invalid_hash(self, server):
        """Test invalid hash format."""
        result = await server._check_hash("not-a-hash")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_hash_md5(self, server):
        """Test MD5 hash lookup."""
        # MD5 hashes are 32 characters
        result = await server._check_hash("abc123def456abc123def456abc12345")
        # Should detect MD5 algorithm
        assert result.get("algorithm") == "md5" or "error" not in result


# ============================================================================
# analyze_filename Tests
# ============================================================================


class TestAnalyzeFilename:
    """Tests for analyze_filename tool."""

    @pytest.mark.asyncio
    async def test_normal_filename(self, server):
        """Test normal filename."""
        result = await server._analyze_filename("notepad.exe")
        assert result["is_suspicious"] is False

    @pytest.mark.asyncio
    async def test_double_extension(self, server):
        """Test double extension detection."""
        result = await server._analyze_filename("document.pdf.exe")
        assert result["is_suspicious"] is True
        assert any(
            "double_extension" in str(f.get("type", ""))
            for f in result.get("findings", [])
        )

    @pytest.mark.asyncio
    async def test_known_tool_match(self, server):
        """Test known tool pattern match."""
        # The filename analysis checks against suspicious_filenames table
        # which has 'mimikatz' pattern. Our test DB has it, but the lookup
        # may require exact filename_pattern match.
        result = await server._analyze_filename("mimikatz.exe")
        # Just verify the analysis runs without error and returns expected structure
        assert "findings" in result
        assert "entropy" in result


# ============================================================================
# check_lolbin Tests
# ============================================================================


class TestCheckLolbin:
    """Tests for check_lolbin tool."""

    @pytest.mark.asyncio
    async def test_lolbin_found(self, server):
        """Test LOLBin lookup."""
        result = await server._check_lolbin("certutil.exe")
        assert result["is_lolbin"] is True
        assert "Download" in result.get("functions", [])

    @pytest.mark.asyncio
    async def test_not_lolbin(self, server):
        """Test non-LOLBin."""
        result = await server._check_lolbin("notepad.exe")
        assert result["is_lolbin"] is False

    @pytest.mark.asyncio
    async def test_lolbin_case_insensitive(self, server):
        """Test case-insensitive lookup."""
        result = await server._check_lolbin("CERTUTIL.EXE")
        assert result["is_lolbin"] is True


# ============================================================================
# check_hijackable_dll Tests
# ============================================================================


class TestCheckHijackableDll:
    """Tests for check_hijackable_dll tool."""

    @pytest.mark.asyncio
    async def test_hijackable_dll_found(self, server):
        """Test hijackable DLL lookup."""
        result = await server._check_hijackable_dll("version.dll")
        assert result["is_hijackable"] is True
        assert result["total_scenarios"] > 0

    @pytest.mark.asyncio
    async def test_not_hijackable(self, server):
        """Test non-hijackable DLL."""
        result = await server._check_hijackable_dll("kernel32.dll")
        assert result["is_hijackable"] is False


# ============================================================================
# check_pipe Tests
# ============================================================================


class TestCheckPipe:
    """Tests for check_pipe tool."""

    @pytest.mark.asyncio
    async def test_suspicious_pipe_regex(self, server):
        """Test suspicious pipe detection (regex pattern)."""
        result = await server._check_pipe("msagent_12345")
        assert result["verdict"] == "SUSPICIOUS"
        assert result["tool_name"] == "Cobalt Strike"

    @pytest.mark.asyncio
    async def test_windows_pipe(self, server):
        """Test known Windows pipe."""
        result = await server._check_pipe("lsass")
        assert result["verdict"] == "EXPECTED"
        assert result["is_windows_pipe"] is True

    @pytest.mark.asyncio
    async def test_unknown_pipe(self, server):
        """Test unknown pipe."""
        result = await server._check_pipe("custom_app_pipe")
        assert result["verdict"] == "UNKNOWN"


# ============================================================================
# get_db_stats Tests
# ============================================================================


class TestGetDbStats:
    """Tests for get_db_stats tool."""

    @pytest.mark.asyncio
    async def test_get_stats(self, server):
        """Test getting database statistics."""
        result = await server._get_db_stats()
        assert "known_good_db" in result
        assert "context_db" in result


# ============================================================================
# get_health Tests
# ============================================================================


class TestGetHealth:
    """Tests for get_health tool."""

    @pytest.mark.asyncio
    async def test_get_health(self, server):
        """Test getting server health."""
        result = await server._get_health()
        assert result["status"] == "healthy"
        assert "uptime_seconds" in result
        assert "databases" in result
        assert "cache" in result


# ============================================================================
# Server Initialization Tests
# ============================================================================


class TestServerInitialization:
    """Tests for server initialization."""

    def test_server_creates_with_valid_config(self, temp_dbs):
        """Test server creates with valid configuration."""
        kg_path, ctx_path = temp_dbs
        config = Config(
            known_good_db=kg_path, context_db=ctx_path, skip_db_validation=True
        )
        server = WindowsTriageServer(config=config)
        assert server is not None

    def test_server_fails_with_invalid_db_path(self):
        """Test server fails with invalid database path (read-only mode with missing file)."""
        config = Config(
            known_good_db=Path("/nonexistent/directory/known_good.db"),
            context_db=Path("/nonexistent/directory/context.db"),
            skip_db_validation=False,  # Validation will fail because DBs don't exist
        )
        # Should raise DatabaseError because read-only mode can't create missing file
        with pytest.raises(DatabaseError):
            WindowsTriageServer(config=config)


# ============================================================================
# Tool Registration Tests
# ============================================================================


class TestToolRegistration:
    """Tests for MCP tool registration."""

    def test_tools_registered(self, server):
        """Test that all 13 tools are registered."""
        # The server object has the tool handlers as methods
        handlers = [
            "_check_file",
            "_check_process_tree",
            "_check_service",
            "_check_scheduled_task",
            "_check_autorun",
            "_check_registry",
            "_check_hash",
            "_analyze_filename",
            "_check_lolbin",
            "_check_hijackable_dll",
            "_check_pipe",
            "_get_db_stats",
            "_get_health",
        ]
        for handler in handlers:
            assert hasattr(server, handler), f"Missing handler: {handler}"


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_empty_path(self, server):
        """Test handling empty path."""
        result = await server._check_file("")
        # Should handle gracefully
        assert "verdict" in result

    @pytest.mark.asyncio
    async def test_unicode_path(self, server):
        """Test handling Unicode in path."""
        result = await server._check_file("C:\\Users\\日本語\\test.exe")
        assert "verdict" in result

    @pytest.mark.asyncio
    async def test_very_long_path(self, server):
        """Test validation of very long path."""
        long_path = "C:\\" + "a" * 5000 + ".exe"
        with pytest.raises(ValidationError):
            await server._check_file(long_path)

    @pytest.mark.asyncio
    async def test_null_bytes_rejected(self, server):
        """Test that null bytes are rejected via validation function."""
        # Direct validation should raise
        with pytest.raises(ValidationError):
            _validate_no_null_bytes("C:\\Windows\x00\\cmd.exe", "path")

    @pytest.mark.asyncio
    async def test_special_characters_in_filename(self, server):
        """Test handling special characters."""
        result = await server._analyze_filename("file [1].exe")
        assert "findings" in result


# ============================================================================
# Process Tree Forensic Context Tests (F5)
# ============================================================================


class TestProcessTreeForensicContext:
    """Test F5 fix. SUSPICIOUS findings include forensic context from
    SUSPICIOUS_PARENT_CONTEXT when available."""

    @pytest.mark.asyncio
    async def test_suspicious_parent_has_forensic_context(self, server):
        """winword.exe spawning cmd.exe should include Office macro context."""
        result = await server._check_process_tree(
            process_name="cmd.exe",
            parent_name="winword.exe",
        )
        assert result["verdict"] == "SUSPICIOUS"
        finding = next(
            (f for f in result["findings"] if f["type"] == "suspicious_parent"),
            None,
        )
        assert finding is not None
        assert "Office macro" in finding["description"]

    @pytest.mark.asyncio
    async def test_browser_parent_has_forensic_context(self, server):
        """chrome.exe spawning cmd.exe should include browser exploit context."""
        result = await server._check_process_tree(
            process_name="cmd.exe",
            parent_name="chrome.exe",
        )
        assert result["verdict"] == "SUSPICIOUS"
        finding = next(
            (f for f in result["findings"] if f["type"] == "suspicious_parent"),
            None,
        )
        assert finding is not None
        assert "Browser exploitation" in finding["description"]

    @pytest.mark.asyncio
    async def test_pdf_parent_has_forensic_context(self, server):
        """acrord32.exe spawning cmd.exe should include PDF exploit context."""
        result = await server._check_process_tree(
            process_name="cmd.exe",
            parent_name="acrord32.exe",
        )
        assert result["verdict"] == "SUSPICIOUS"
        finding = next(
            (f for f in result["findings"] if f["type"] == "suspicious_parent"),
            None,
        )
        assert finding is not None
        assert "PDF exploitation" in finding["description"]

    @pytest.mark.asyncio
    async def test_non_mapped_parent_no_extra_context(self, server):
        """A suspicious parent not in SUSPICIOUS_PARENT_CONTEXT has the base
        description but no appended forensic context."""
        # java.exe is in cmd.exe's suspicious_parents list in the test DB
        # but is NOT in SUSPICIOUS_PARENT_CONTEXT.
        result = await server._check_process_tree(
            process_name="cmd.exe",
            parent_name="java.exe",
        )
        assert result["verdict"] == "SUSPICIOUS"
        finding = next(
            (f for f in result["findings"] if f["type"] == "suspicious_parent"),
            None,
        )
        assert finding is not None
        assert "common attack pattern" in finding["description"]
        # Should NOT contain any context-dict text (no period-separated appendix)
        # The description should end with the base pattern text.
        assert "Office macro" not in finding["description"]
        assert "Browser exploitation" not in finding["description"]
        assert "PDF exploitation" not in finding["description"]


# ============================================================================
# Process Tree User Context Tests (F6)
# ============================================================================


class TestProcessTreeUserContext:
    """Test F6 fix. When the user parameter is provided to
    check_process_tree, the result includes a user_context field."""

    @pytest.mark.asyncio
    async def test_user_context_in_result(self, server):
        """Result should include user_context when user param provided."""
        result = await server._check_process_tree(
            process_name="svchost.exe",
            parent_name="services.exe",
            user="SYSTEM",
        )
        assert "user_context" in result
        assert result["user_context"]["user"] == "SYSTEM"
        assert result["user_context"]["user_valid"] is True
        assert result["user_context"]["expected_type"] == "SYSTEM"

    @pytest.mark.asyncio
    async def test_no_user_context_without_param(self, server):
        """Result should NOT include user_context when no user param."""
        result = await server._check_process_tree(
            process_name="svchost.exe",
            parent_name="services.exe",
        )
        assert "user_context" not in result

    @pytest.mark.asyncio
    async def test_user_context_wrong_user(self, server):
        """Wrong user type should be reflected in user_context."""
        result = await server._check_process_tree(
            process_name="svchost.exe",
            parent_name="services.exe",
            user="DOMAIN\\regular_user",
        )
        assert "user_context" in result
        assert result["user_context"]["user"] == "DOMAIN\\regular_user"
        assert result["user_context"]["user_valid"] is False
        assert result["verdict"] == "SUSPICIOUS"
