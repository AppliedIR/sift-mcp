"""Tests for code review fixes: error response, structured logging, atexit cleanup."""

import json
import logging
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from windows_triage.config import Config
from windows_triage.oplog import _StructuredFormatter, setup_logging
from windows_triage.server import WindowsTriageServer

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
            CREATE TABLE baseline_services (
                id INTEGER PRIMARY KEY,
                service_name TEXT NOT NULL,
                display_name TEXT,
                binary_path TEXT,
                start_type TEXT,
                os_version TEXT NOT NULL,
                UNIQUE(service_name, os_version)
            );
            CREATE TABLE baseline_scheduled_tasks (
                id INTEGER PRIMARY KEY,
                task_path TEXT NOT NULL,
                os_version TEXT NOT NULL,
                UNIQUE(task_path, os_version)
            );
            CREATE TABLE baseline_autoruns (
                id INTEGER PRIMARY KEY,
                key_path TEXT NOT NULL,
                value_name TEXT NOT NULL,
                os_version TEXT NOT NULL,
                UNIQUE(key_path, value_name, os_version)
            );
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                migrated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO schema_version (version) VALUES (2);
        """)
        conn.commit()
        conn.close()

        # Create context.db
        ctx_path = tmpdir / "context.db"
        conn = sqlite3.connect(ctx_path)
        cursor = conn.cursor()
        cursor.executescript("""
            CREATE TABLE lolbins (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                paths TEXT,
                functions TEXT,
                detection TEXT
            );
            CREATE TABLE vulnerable_drivers (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                md5 TEXT, sha1 TEXT, sha256 TEXT,
                description TEXT
            );
            CREATE TABLE hijackable_dlls (
                id INTEGER PRIMARY KEY,
                dll_name TEXT NOT NULL,
                vulnerable_exe TEXT,
                dll_path TEXT
            );
            CREATE TABLE suspicious_pipes (
                id INTEGER PRIMARY KEY,
                pipe_name TEXT UNIQUE NOT NULL,
                category TEXT,
                tool TEXT,
                description TEXT
            );
            CREATE TABLE known_pipes (
                id INTEGER PRIMARY KEY,
                pipe_name TEXT UNIQUE NOT NULL,
                description TEXT
            );
            CREATE TABLE process_expectations (
                id INTEGER PRIMARY KEY,
                process_name TEXT NOT NULL,
                expected_parents TEXT,
                suspicious_parents TEXT,
                expected_paths TEXT,
                user_context TEXT,
                notes TEXT,
                never_spawns_children INTEGER DEFAULT 0,
                suspicious_parent_categories TEXT
            );
        """)
        conn.commit()
        conn.close()

        config = Config(
            data_dir=tmpdir,
            known_good_db=kg_path,
            context_db=ctx_path,
            registry_db=tmpdir / "nonexistent_registry.db",
            skip_db_validation=True,
        )
        yield config, kg_path, ctx_path


# ============================================================================
# _error_response tests
# ============================================================================


class TestErrorResponse:
    """Tests for standardized error response format."""

    def test_error_response_format(self, temp_dbs):
        """Error response returns consistent JSON structure."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        result = server._error_response("test_error", "Test message")
        assert len(result) == 1
        parsed = json.loads(result[0].text)
        assert parsed["error"] == "test_error"
        assert parsed["message"] == "Test message"

    def test_error_response_validation_error(self, temp_dbs):
        """Validation errors use validation_error code."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        result = server._error_response("validation_error", "bad input")
        parsed = json.loads(result[0].text)
        assert parsed["error"] == "validation_error"

    def test_error_response_database_error(self, temp_dbs):
        """Database errors use database_error code."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        result = server._error_response("database_error", "db failed")
        parsed = json.loads(result[0].text)
        assert parsed["error"] == "database_error"

    def test_error_response_internal_error(self, temp_dbs):
        """Internal errors use internal_error code."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        result = server._error_response("internal_error", "unexpected")
        parsed = json.loads(result[0].text)
        assert parsed["error"] == "internal_error"


# ============================================================================
# Structured logging tests
# ============================================================================


class TestStructuredLogging:
    """Tests for structured JSON logging."""

    def test_json_formatter_basic(self):
        """JSON formatter produces valid JSON."""
        formatter = _StructuredFormatter("test-service")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "test message"
        assert parsed["level"] == "INFO"
        assert parsed["service"] == "test-service"
        assert "ts" in parsed

    def test_json_formatter_warning_includes_location(self):
        """Warnings and above include file location."""
        formatter = _StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="/foo/bar.py",
            lineno=42,
            msg="warn",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "location" in parsed
        assert parsed["location"]["line"] == 42

    def test_json_formatter_info_no_location(self):
        """Info level does not include location."""
        formatter = _StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="info",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "location" not in parsed

    def test_json_formatter_exception(self):
        """Exception info is captured."""
        formatter = _StructuredFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="error",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["exception"]["type"] == "ValueError"
        assert "boom" in parsed["exception"]["message"]

    def test_setup_logging_text_format(self):
        """Text format uses standard formatter."""
        setup_logging(
            "windows-triage-mcp",
            level=logging.DEBUG,
            json_format=False,
            log_to_file=False,
        )
        logger = logging.getLogger("windows_triage_mcp")
        assert len(logger.handlers) == 1
        assert not isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_setup_logging_json_format(self):
        """JSON format uses StructuredFormatter."""
        setup_logging(
            "windows-triage-mcp",
            level=logging.DEBUG,
            json_format=True,
            log_to_file=False,
        )
        logger = logging.getLogger("windows_triage_mcp")
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_setup_logging_clears_existing_handlers(self):
        """Setup clears previous handlers."""
        setup_logging("windows-triage-mcp", json_format=False, log_to_file=False)
        setup_logging("windows-triage-mcp", json_format=True, log_to_file=False)
        logger = logging.getLogger("windows_triage_mcp")
        assert len(logger.handlers) == 1


# ============================================================================
# Database cleanup (atexit) tests
# ============================================================================


class TestDatabaseCleanup:
    """Tests for close_databases method."""

    def test_close_databases(self, temp_dbs):
        """close_databases closes all DB connections without error."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        # Should not raise
        server.close_databases()

    def test_close_databases_idempotent(self, temp_dbs):
        """Calling close_databases twice doesn't raise."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        server.close_databases()
        server.close_databases()

    def test_close_databases_handles_none_registry(self, temp_dbs):
        """close_databases handles None registry_db gracefully."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        assert server.registry_db is None
        server.close_databases()  # Should not raise

    def test_close_databases_handles_exception(self, temp_dbs):
        """close_databases silently handles exceptions from individual DBs."""
        config, _, _ = temp_dbs
        server = WindowsTriageServer(config=config)
        # Mock a DB that raises on close
        server.known_good_db = MagicMock()
        server.known_good_db.close.side_effect = RuntimeError("close failed")
        server.context_db = MagicMock()
        # Should not propagate the exception
        server.close_databases()
        server.known_good_db.close.assert_called_once()
        server.context_db.close.assert_called_once()


# ============================================================================
# Skip-validation warning test
# ============================================================================


class TestSkipValidationWarning:
    """Test that skip_db_validation logs a warning."""

    def test_skip_validation_logs_warning(self, temp_dbs):
        """Setting skip_db_validation emits a warning."""
        config, _, _ = temp_dbs
        assert config.skip_db_validation is True
        # Capture via handler on the specific logger (propagate may be off)
        ft_logger = logging.getLogger("windows_triage.server")
        records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r)
        handler.setLevel(logging.WARNING)
        ft_logger.addHandler(handler)
        try:
            server = WindowsTriageServer(config=config)
        finally:
            ft_logger.removeHandler(handler)
        assert any("WT_SKIP_DB_VALIDATION" in r.getMessage() for r in records)
