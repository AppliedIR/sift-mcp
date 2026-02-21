"""Tests for structured logging module."""

from __future__ import annotations

import json
import logging
import pytest

from opencti_mcp.logging import (
    StructuredFormatter,
    RequestContextFilter,
    setup_logging,
    get_logger,
    set_request_id,
    clear_request_id,
)


class TestStructuredFormatter:
    """Tests for JSON log formatter."""

    def test_basic_log_format(self):
        """Basic log is formatted as JSON."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert data["level"] == "INFO"
        assert data["message"] == "Test message"
        assert data["logger"] == "test"
        assert data["service"] == "opencti-mcp"
        assert "timestamp" in data

    def test_error_includes_location(self):
        """Error logs include file location."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="/path/to/test.py",
            lineno=42,
            msg="Error message",
            args=(),
            exc_info=None,
        )
        record.funcName = "test_function"

        output = formatter.format(record)
        data = json.loads(output)

        assert "location" in data
        assert data["location"]["line"] == 42
        assert data["location"]["function"] == "test_function"

    def test_extra_fields_included(self):
        """Extra fields are included in output."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.custom_field = "custom_value"
        record.request_id = "abc123"

        output = formatter.format(record)
        data = json.loads(output)

        assert data["custom_field"] == "custom_value"
        assert data["request_id"] == "abc123"

    def test_custom_service_name(self):
        """Custom service name is used."""
        formatter = StructuredFormatter(service_name="my-service")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert data["service"] == "my-service"


class TestRequestContextFilter:
    """Tests for request context filter."""

    def test_set_request_id(self):
        """Request ID can be set."""
        filter = RequestContextFilter()
        request_id = filter.set_request_id("test-123")
        assert request_id == "test-123"

    def test_auto_generate_request_id(self):
        """Request ID is auto-generated if not provided."""
        filter = RequestContextFilter()
        request_id = filter.set_request_id()
        assert len(request_id) == 8  # Short UUID

    def test_filter_adds_context(self):
        """Filter adds context to log records."""
        filter = RequestContextFilter()
        filter.set_request_id("req-456")

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        filter.filter(record)
        assert record.request_id == "req-456"

    def test_clear_request_id(self):
        """Request ID can be cleared."""
        filter = RequestContextFilter()
        filter.set_request_id("test-123")
        filter.clear_request_id()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        filter.filter(record)
        assert not hasattr(record, 'request_id')


class TestLoggingSetup:
    """Tests for logging setup functions."""

    def test_get_logger_prefix(self):
        """get_logger adds package prefix."""
        logger = get_logger("client")
        assert logger.name == "opencti_mcp.client"

    def test_setup_logging_json(self):
        """JSON logging can be configured."""
        setup_logging(json_format=True)
        logger = logging.getLogger("opencti_mcp")
        assert len(logger.handlers) == 1

    def test_setup_logging_text(self):
        """Text logging can be configured."""
        setup_logging(json_format=False)
        logger = logging.getLogger("opencti_mcp")
        assert len(logger.handlers) == 1

    def test_global_request_id(self):
        """Global request ID functions work."""
        request_id = set_request_id("global-test")
        assert request_id == "global-test"
        clear_request_id()  # Clean up
