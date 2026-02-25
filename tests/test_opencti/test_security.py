"""Security-focused tests for OpenCTI MCP.

These tests verify that security controls work correctly.
They should NEVER be skipped in CI/CD.
"""

from __future__ import annotations

import io
import logging
import pickle
from pathlib import Path
from unittest.mock import patch

import pytest
from opencti_mcp.config import Config, SecretStr
from opencti_mcp.errors import ConfigurationError
from opencti_mcp.validation import (
    MAX_IOC_LENGTH,
    MAX_QUERY_LENGTH,
    sanitize_for_log,
    validate_ioc,
    validate_length,
)

# =============================================================================
# Credential Safety Tests
# =============================================================================


class TestCredentialSafety:
    """Ensure credentials never leak."""

    def test_token_not_in_repr(self, mock_config: Config):
        """Config repr doesn't include token."""
        repr_str = repr(mock_config)
        assert "test-token" not in repr_str
        assert "12345" not in repr_str
        assert "***" in repr_str

    def test_token_not_in_str(self, mock_config: Config):
        """Config str doesn't include token."""
        str_val = str(mock_config)
        assert "test-token" not in str_val
        assert "12345" not in str_val

    def test_secret_str_repr(self):
        """SecretStr repr hides value."""
        secret = SecretStr("my-secret-token")
        assert "my-secret-token" not in repr(secret)
        assert "my-secret-token" not in str(secret)
        assert "***" in repr(secret)
        assert "***" in str(secret)

    def test_secret_str_get_value(self):
        """SecretStr can retrieve value explicitly."""
        secret = SecretStr("my-secret-token")
        assert secret.get_secret_value() == "my-secret-token"

    def test_config_not_picklable(self, mock_config: Config):
        """Config cannot be pickled (prevents credential serialization)."""
        with pytest.raises(TypeError, match="pickled"):
            pickle.dumps(mock_config)

    def test_config_reduce_blocked(self, mock_config: Config):
        """Config __reduce__ is blocked."""
        with pytest.raises(TypeError, match="pickled"):
            mock_config.__reduce__()

    def test_token_file_permissions_enforced(self, tmp_path: Path):
        """Token file with insecure permissions is rejected."""
        token_file = tmp_path / "token"
        token_file.write_text("secret-token")

        # Make file world-readable
        token_file.chmod(0o644)

        with patch.dict("os.environ", {"OPENCTI_TOKEN": ""}, clear=False):
            with patch("opencti_mcp.config.Path.home", return_value=tmp_path):
                token_dir = tmp_path / ".config" / "opencti-mcp"
                token_dir.mkdir(parents=True)
                insecure_token = token_dir / "token"
                insecure_token.write_text("secret-token")
                insecure_token.chmod(0o644)

                with pytest.raises(ConfigurationError, match="insecure permissions"):
                    Config.load()

    def test_token_not_logged(self, mock_config: Config, caplog):
        """Logging doesn't capture token."""
        logger = logging.getLogger("test")

        with caplog.at_level(logging.DEBUG):
            logger.info(f"Config: {mock_config}")
            logger.debug(f"Repr: {repr(mock_config)}")

        log_output = caplog.text
        assert "test-token" not in log_output
        assert "12345" not in log_output


# =============================================================================
# Input Validation Security Tests
# =============================================================================


class TestInputValidation:
    """Input validation security tests."""

    def test_length_checked_before_regex(self):
        """Length validation happens before pattern matching."""
        # Create a string that would be expensive for regex
        evil_input = "a" * (MAX_QUERY_LENGTH + 1000)

        # Should fail on length, not hang on regex
        with pytest.raises(Exception):
            validate_length(evil_input, MAX_QUERY_LENGTH, "query")

    @pytest.mark.parametrize(
        "length",
        [
            MAX_QUERY_LENGTH + 1,
            MAX_QUERY_LENGTH + 1000,
            MAX_QUERY_LENGTH * 2,
        ],
    )
    def test_max_query_length_enforced(self, length: int):
        """Query length limit is enforced."""
        from opencti_mcp.errors import ValidationError

        long_query = "a" * length
        with pytest.raises(ValidationError):
            validate_length(long_query, MAX_QUERY_LENGTH, "query")

    @pytest.mark.parametrize(
        "length",
        [
            MAX_IOC_LENGTH + 1,
            MAX_IOC_LENGTH + 1000,
        ],
    )
    def test_max_ioc_length_enforced(self, length: int):
        """IOC length limit is enforced."""
        from opencti_mcp.errors import ValidationError

        long_ioc = "a" * length
        with pytest.raises(ValidationError):
            validate_ioc(long_ioc)

    def test_null_bytes_rejected(self):
        """IOCs with null bytes are rejected."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError, match="null byte"):
            validate_ioc("192.168.1.1\x00evil")

    def test_empty_ioc_rejected(self):
        """Empty IOCs are rejected."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError, match="empty"):
            validate_ioc("")

    def test_whitespace_only_ioc_rejected(self):
        """Whitespace-only IOCs are rejected."""
        from opencti_mcp.errors import ValidationError

        with pytest.raises(ValidationError, match="empty"):
            validate_ioc("   ")

    def test_unicode_handling(self):
        """Unicode in IOCs is handled safely."""
        # Should not crash
        result = validate_ioc("example\u0430.com")  # Cyrillic 'a'
        assert result[0] is True  # Valid format


# =============================================================================
# Error Leakage Tests
# =============================================================================


class TestErrorLeakage:
    """Ensure internal details don't leak in errors."""

    def test_connection_error_safe_message(self):
        """ConnectionError has safe message."""
        from opencti_mcp.errors import ConnectionError

        error = ConnectionError("Failed to connect to http://secret-server:8080")
        assert "secret-server" not in error.safe_message
        assert "8080" not in error.safe_message

    def test_query_error_safe_message(self):
        """QueryError has safe message."""
        from opencti_mcp.errors import QueryError

        error = QueryError("GraphQL error: invalid token xyz123")
        assert "xyz123" not in error.safe_message
        assert "GraphQL" not in error.safe_message

    def test_no_stack_trace_exposure(self, mock_server):
        """Internal errors don't expose stack traces."""
        import asyncio

        from opencti_mcp.errors import QueryError

        # Force an error
        mock_server.client._client.indicator.list.side_effect = Exception(
            "internal error details"
        )

        async def test():
            result = await mock_server._dispatch_tool(
                "search_threat_intel", {"query": "test"}
            )
            return result

        with pytest.raises(QueryError):
            asyncio.run(test())


# =============================================================================
# Response Safety Tests
# =============================================================================


class TestResponseSafety:
    """Test response sanitization."""

    def test_response_size_limited(self):
        """Large responses are truncated."""
        from opencti_mcp.validation import (
            MAX_DESCRIPTION_LENGTH,
            MAX_RESPONSE_SIZE,
            truncate_response,
        )

        large_data = {
            "description": "x" * (MAX_RESPONSE_SIZE + 1000),
        }

        result = truncate_response(large_data)
        # Description should be truncated to MAX_DESCRIPTION_LENGTH + ellipsis
        assert len(result["description"]) <= MAX_DESCRIPTION_LENGTH + 3

    def test_description_truncated(self):
        """Long descriptions are truncated."""
        from opencti_mcp.validation import truncate_response

        data = {
            "description": "x" * 10000,
        }

        result = truncate_response(data)
        assert len(result["description"]) <= 503  # 500 + "..."

    def test_pattern_truncated(self):
        """Long patterns are truncated."""
        from opencti_mcp.validation import truncate_response

        data = {
            "pattern": "x" * 1000,
        }

        result = truncate_response(data)
        assert len(result["pattern"]) <= 203  # 200 + "..."


# =============================================================================
# Rate Limiting Tests
# =============================================================================


class TestRateLimiting:
    """Test rate limiting controls."""

    def test_query_rate_limit_enforced(self, mock_opencti_client):
        """Query rate limit is enforced."""
        from opencti_mcp.errors import RateLimitError

        # Exhaust the rate limit
        mock_opencti_client._query_limiter.max_calls = 2
        mock_opencti_client._query_limiter.calls.clear()

        # First two should work
        mock_opencti_client.search_indicators("test1")
        mock_opencti_client.search_indicators("test2")

        # Third should fail
        with pytest.raises(RateLimitError):
            mock_opencti_client.search_indicators("test3")

    def test_rate_limit_returns_wait_time(self, mock_opencti_client):
        """Rate limit error includes wait time."""
        from opencti_mcp.errors import RateLimitError

        mock_opencti_client._query_limiter.max_calls = 1
        mock_opencti_client._query_limiter.calls.clear()

        mock_opencti_client.search_indicators("test1")

        try:
            mock_opencti_client.search_indicators("test2")
            assert False, "Should have raised RateLimitError"
        except RateLimitError as e:
            assert e.wait_seconds >= 0
            assert e.limit_type == "query"


# =============================================================================
# Log Sanitization Tests
# =============================================================================


class TestLogSanitization:
    """Test log sanitization."""

    def test_sensitive_fields_redacted(self):
        """Sensitive fields are redacted in logs."""
        data = {
            "username": "admin",
            "token": "secret-token",
            "password": "secret-password",
            "api_key": "key-12345",
        }

        sanitized = sanitize_for_log(data)
        assert sanitized["username"] == "admin"
        assert "secret" not in sanitized["token"]
        assert "secret" not in sanitized["password"]
        assert "12345" not in sanitized["api_key"]
        assert "REDACTED" in sanitized["token"]

    def test_control_chars_escaped(self):
        """Control characters are escaped in logs."""
        data = "line1\nline2\rline3\x00null"

        sanitized = sanitize_for_log(data)
        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert "\x00" not in sanitized

    def test_long_values_truncated(self):
        """Long values are truncated in logs."""
        data = "x" * 1000

        sanitized = sanitize_for_log(data)
        assert len(sanitized) <= 520  # 500 + "[truncated]" margin


# =============================================================================
# Network Security Tests
# =============================================================================


class TestNetworkSecurity:
    """Test network security controls."""

    def test_only_http_https_allowed(self):
        """Only HTTP and HTTPS URLs are allowed."""
        with pytest.raises(ConfigurationError, match="Invalid URL scheme"):
            Config(
                opencti_url="ftp://localhost:8080",
                opencti_token=SecretStr("token"),
            )

    def test_file_url_rejected(self):
        """File URLs are rejected."""
        with pytest.raises(ConfigurationError, match="Invalid URL scheme"):
            Config(
                opencti_url="file:///etc/passwd",
                opencti_token=SecretStr("token"),
            )

    def test_http_warning_for_remote(self):
        """Warning logged for HTTP to non-local hosts."""

        # Set up a custom handler to capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setLevel(logging.WARNING)

        logger = logging.getLogger("opencti_mcp.config")
        original_handlers = logger.handlers.copy()
        logger.handlers = [handler]
        logger.setLevel(logging.WARNING)

        try:
            Config(
                opencti_url="http://remote-server.example.com:8080",
                opencti_token=SecretStr("token"),
            )

            log_output = log_capture.getvalue().lower()
            assert "plaintext" in log_output or "http" in log_output
        finally:
            logger.handlers = original_handlers

    def test_localhost_http_no_warning(self):
        """No warning for HTTP to localhost."""

        # Set up a custom handler to capture log output
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setLevel(logging.WARNING)

        logger = logging.getLogger("opencti_mcp.config")
        original_handlers = logger.handlers.copy()
        logger.handlers = [handler]
        logger.setLevel(logging.WARNING)

        try:
            Config(
                opencti_url="http://localhost:8080",
                opencti_token=SecretStr("token"),
            )

            log_output = log_capture.getvalue().lower()
            # Should not warn about plaintext for localhost
            assert "plaintext" not in log_output
        finally:
            logger.handlers = original_handlers


# =============================================================================
# Environment Variable Parsing Tests
# =============================================================================


class TestEnvVarParsing:
    """Test safe environment variable parsing (functionality correctness)."""

    def test_parse_int_env_valid(self):
        """Valid integer env vars are parsed correctly."""
        from opencti_mcp.config import _parse_int_env

        with patch.dict("os.environ", {"TEST_INT": "42"}):
            assert _parse_int_env("TEST_INT", 10) == 42

    def test_parse_int_env_default(self):
        """Missing env var uses default."""
        from opencti_mcp.config import _parse_int_env

        with patch.dict("os.environ", {}, clear=True):
            assert _parse_int_env("MISSING_VAR", 99) == 99

    def test_parse_int_env_invalid_uses_default(self):
        """Invalid integer env var uses default without crashing."""
        from opencti_mcp.config import _parse_int_env

        with patch.dict("os.environ", {"TEST_INT": "not-a-number"}):
            # Should not raise, should return default
            result = _parse_int_env("TEST_INT", 50)
            assert result == 50

    def test_parse_int_env_empty_uses_default(self):
        """Empty string env var uses default."""
        from opencti_mcp.config import _parse_int_env

        with patch.dict("os.environ", {"TEST_INT": ""}):
            result = _parse_int_env("TEST_INT", 30)
            assert result == 30

    def test_parse_float_env_valid(self):
        """Valid float env vars are parsed correctly."""
        from opencti_mcp.config import _parse_float_env

        with patch.dict("os.environ", {"TEST_FLOAT": "3.14"}):
            assert _parse_float_env("TEST_FLOAT", 1.0) == 3.14

    def test_parse_float_env_default(self):
        """Missing env var uses default."""
        from opencti_mcp.config import _parse_float_env

        with patch.dict("os.environ", {}, clear=True):
            assert _parse_float_env("MISSING_VAR", 2.5) == 2.5

    def test_parse_float_env_invalid_uses_default(self):
        """Invalid float env var uses default without crashing."""
        from opencti_mcp.config import _parse_float_env

        with patch.dict("os.environ", {"TEST_FLOAT": "abc"}):
            result = _parse_float_env("TEST_FLOAT", 1.5)
            assert result == 1.5

    def test_config_load_with_invalid_timeout(self):
        """Config.load handles invalid OPENCTI_TIMEOUT gracefully."""
        with patch.dict(
            "os.environ",
            {
                "OPENCTI_TOKEN": "test-token",
                "OPENCTI_TIMEOUT": "invalid",
            },
        ):
            config = Config.load()
            # Should use default of 60
            assert config.timeout_seconds == 60

    def test_config_load_with_invalid_max_retries(self):
        """Config.load handles invalid OPENCTI_MAX_RETRIES gracefully."""
        with patch.dict(
            "os.environ",
            {
                "OPENCTI_TOKEN": "test-token",
                "OPENCTI_MAX_RETRIES": "xyz",
            },
        ):
            config = Config.load()
            # Should use default of 3
            assert config.max_retries == 3
