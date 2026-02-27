"""Unit tests for sift_common.oplog — structured logging setup."""

import json
import logging

import pytest
from sift_common.oplog import _StructuredFormatter, setup_logging


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AIIR_LOG_FORMAT", raising=False)
    monkeypatch.delenv("AIIR_LOG_FILE", raising=False)


class TestStructuredFormatter:
    def test_json_output(self):
        formatter = _StructuredFormatter("test-svc")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="hello", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "hello"
        assert parsed["service"] == "test-svc"
        assert parsed["level"] == "INFO"
        assert "ts" in parsed

    def test_warning_includes_location(self):
        formatter = _StructuredFormatter("test-svc")
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="test.py",
            lineno=42, msg="warn", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "location" in parsed
        assert parsed["location"]["line"] == 42

    def test_info_no_location(self):
        formatter = _StructuredFormatter("test-svc")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="info", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "location" not in parsed

    def test_exception_info(self):
        formatter = _StructuredFormatter("test-svc")
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="test.py",
            lineno=1, msg="error", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["exception"]["type"] == "ValueError"
        assert parsed["exception"]["message"] == "test error"


class TestSetupLogging:
    def test_json_format_default(self):
        setup_logging("test-svc", log_to_file=False)
        logger = logging.getLogger("test_svc")
        assert len(logger.handlers) >= 1
        assert isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_text_format(self, monkeypatch):
        monkeypatch.setenv("AIIR_LOG_FORMAT", "text")
        setup_logging("test-svc2", log_to_file=False)
        logger = logging.getLogger("test_svc2")
        assert not isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_file_logging_disabled(self, monkeypatch):
        monkeypatch.setenv("AIIR_LOG_FILE", "false")
        setup_logging("test-svc3", log_to_file=False)
        logger = logging.getLogger("test_svc3")
        # Only stderr handler, no file handler
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 0

    def test_no_propagation(self):
        setup_logging("test-svc4", log_to_file=False)
        logger = logging.getLogger("test_svc4")
        assert logger.propagate is False
