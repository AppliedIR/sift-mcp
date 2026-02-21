"""Tests for code review fixes: error response, structured logging, octal IP guard."""

import json
import logging
import pytest

from rag_mcp.server import RAGServer
from rag_mcp.oplog import _StructuredFormatter, setup_logging


# ============================================================================
# _error_response tests
# ============================================================================

class TestErrorResponse:
    """Tests for standardized error response format."""

    def test_error_response_format(self):
        """Error response returns consistent JSON structure."""
        result = RAGServer._error_response("test_error", "Test message")
        assert len(result) == 1
        parsed = json.loads(result[0].text)
        assert parsed["error"] == "test_error"
        assert parsed["message"] == "Test message"

    def test_error_response_validation(self):
        """Validation errors use validation_error code."""
        result = RAGServer._error_response("validation_error", "bad input")
        parsed = json.loads(result[0].text)
        assert parsed["error"] == "validation_error"

    def test_error_response_internal(self):
        """Internal errors use internal_error code."""
        result = RAGServer._error_response("internal_error", "unexpected")
        parsed = json.loads(result[0].text)
        assert parsed["error"] == "internal_error"
        assert "unexpected" in parsed["message"]


# ============================================================================
# Structured logging tests
# ============================================================================

class TestStructuredLogging:
    """Tests for structured JSON logging."""

    def test_json_formatter_basic(self):
        """JSON formatter produces valid JSON."""
        formatter = _StructuredFormatter("test-service")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "test message"
        assert parsed["level"] == "INFO"
        assert parsed["service"] == "test-service"
        assert "ts" in parsed

    def test_json_formatter_warning_includes_location(self):
        """Warnings include location info."""
        formatter = _StructuredFormatter()
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="/foo/bar.py",
            lineno=42, msg="warn", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "location" in parsed
        assert parsed["location"]["line"] == 42

    def test_json_formatter_info_no_location(self):
        """Info level omits location."""
        formatter = _StructuredFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="info", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "location" not in parsed

    def test_json_formatter_exception(self):
        """Exception info captured in JSON."""
        formatter = _StructuredFormatter()
        try:
            raise ValueError("boom")
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
        assert "boom" in parsed["exception"]["message"]

    def test_setup_logging_text(self):
        """Text format uses standard formatter."""
        setup_logging("forensic-rag-mcp", level=logging.DEBUG, json_format=False, log_to_file=False)
        logger = logging.getLogger("forensic_rag_mcp")
        assert len(logger.handlers) == 1
        assert not isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_setup_logging_json(self):
        """JSON format uses StructuredFormatter."""
        setup_logging("forensic-rag-mcp", level=logging.DEBUG, json_format=True, log_to_file=False)
        logger = logging.getLogger("forensic_rag_mcp")
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, _StructuredFormatter)

    def test_setup_logging_clears_handlers(self):
        """Setup clears previous handlers."""
        setup_logging("forensic-rag-mcp", json_format=False, log_to_file=False)
        setup_logging("forensic-rag-mcp", json_format=True, log_to_file=False)
        logger = logging.getLogger("forensic_rag_mcp")
        assert len(logger.handlers) == 1


# ============================================================================
# Octal IP SSRF guard tests
# ============================================================================

class TestOctalIpGuard:
    """Tests for octal IP notation detection in SSRF guard."""

    def test_octal_localhost_detected(self):
        """Octal 127.0.0.1 (0177.0.0.1) is detected as IP literal."""
        from rag_mcp.sources import _is_ip_literal
        assert _is_ip_literal("0177.0.0.1") is True

    def test_octal_10_network_detected(self):
        """Octal 10.x.x.x (012.x.x.x) is detected."""
        from rag_mcp.sources import _is_ip_literal
        assert _is_ip_literal("012.0.0.1") is True

    def test_standard_ipv4_detected(self):
        """Standard IPv4 still detected."""
        from rag_mcp.sources import _is_ip_literal
        assert _is_ip_literal("127.0.0.1") is True
        assert _is_ip_literal("192.168.1.1") is True

    def test_ipv6_detected(self):
        """IPv6 still detected."""
        from rag_mcp.sources import _is_ip_literal
        assert _is_ip_literal("::1") is True

    def test_hostnames_not_detected(self):
        """Normal hostnames are NOT IP literals."""
        from rag_mcp.sources import _is_ip_literal
        assert _is_ip_literal("github.com") is False
        assert _is_ip_literal("api.github.com") is False
        assert _is_ip_literal("raw.githubusercontent.com") is False

    def test_empty_and_none(self):
        """Empty string and None handled."""
        from rag_mcp.sources import _is_ip_literal
        assert _is_ip_literal("") is False
        assert _is_ip_literal(None) is False

    def test_octal_blocked_by_validate_url_host(self):
        """Octal IPs are blocked by the full URL validation chain."""
        from rag_mcp.sources import _validate_url_host
        with pytest.raises(ValueError, match="IP literal"):
            _validate_url_host("https://0177.0.0.1/evil")

    def test_octal_various_patterns(self):
        """Various octal patterns detected."""
        from rag_mcp.sources import _is_ip_literal
        assert _is_ip_literal("0100.0.0.1") is True  # 64.x.x.x
        assert _is_ip_literal("0300.0.0.1") is True  # 192.x.x.x
        assert _is_ip_literal("00.0.0.0") is True     # 0.0.0.0 in octal

    def test_non_octal_leading_zero(self):
        """Hostname starting with 0 but not octal IP format."""
        from rag_mcp.sources import _is_ip_literal
        # "0day.example.com" starts with 0 but has non-digit after
        assert _is_ip_literal("0day.example.com") is False
