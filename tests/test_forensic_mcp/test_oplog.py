"""Tests for operational logging module."""

import json
import logging

from forensic_mcp.oplog import _StructuredFormatter, setup_logging


class TestStructuredFormatter:
    def test_basic_info_fields(self):
        formatter = _StructuredFormatter("test-service")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="hello world",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(formatter.format(record))
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "hello world"
        assert parsed["service"] == "test-service"
        assert "ts" in parsed
        assert "location" not in parsed

    def test_warning_includes_location(self):
        formatter = _StructuredFormatter("svc")
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="/foo/bar.py",
            lineno=42,
            msg="warn",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(formatter.format(record))
        assert parsed["location"]["file"] == "/foo/bar.py"
        assert parsed["location"]["line"] == 42

    def test_exception_info(self):
        formatter = _StructuredFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="error",
                args=(),
                exc_info=sys.exc_info(),
            )
        parsed = json.loads(formatter.format(record))
        assert parsed["exception"]["type"] == "ValueError"
        assert "boom" in parsed["exception"]["message"]


class TestSetupLogging:
    def test_stderr_handler_always_added(self):
        setup_logging("test-svc", log_to_file=False)
        logger = logging.getLogger("test_svc")
        assert len(logger.handlers) == 1
        assert logger.propagate is False

    def test_json_format_default(self):
        setup_logging("test-svc2", log_to_file=False)
        logger = logging.getLogger("test_svc2")
        assert isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_text_format(self):
        setup_logging("test-svc3", json_format=False, log_to_file=False)
        logger = logging.getLogger("test_svc3")
        assert not isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_file_handler_creates_log(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sift_common.oplog.Path.home", lambda: tmp_path)
        setup_logging("test-file-svc", log_to_file=True)
        log_file = tmp_path / ".aiir" / "logs" / "test-file-svc.jsonl"
        assert log_file.parent.exists()
        logger = logging.getLogger("test_file_svc")
        assert len(logger.handlers) == 2  # stderr + file

    def test_env_var_controls_format(self, monkeypatch):
        monkeypatch.setenv("AIIR_LOG_FORMAT", "text")
        setup_logging("test-env-fmt", log_to_file=False)
        logger = logging.getLogger("test_env_fmt")
        assert not isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_env_var_controls_file(self, monkeypatch):
        monkeypatch.setenv("AIIR_LOG_FILE", "false")
        setup_logging("test-env-file")
        logger = logging.getLogger("test_env_file")
        assert len(logger.handlers) == 1  # stderr only

    def test_clears_handlers_on_reconfig(self):
        setup_logging("test-clear", log_to_file=False)
        setup_logging("test-clear", log_to_file=False)
        logger = logging.getLogger("test_clear")
        assert len(logger.handlers) == 1
