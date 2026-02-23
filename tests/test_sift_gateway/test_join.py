"""Tests for sift_gateway.join — join code generation, validation, rate limiting."""

import time

import pytest

from sift_gateway.join import (
    generate_join_code,
    store_join_code,
    validate_join_code,
    mark_code_used,
    check_join_rate_limit,
    record_join_failure,
    _JOIN_CHARSET,
    _STATE_FILE,
)


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    """Use a temp state file for each test."""
    state_file = tmp_path / ".join_state.json"
    monkeypatch.setattr("sift_gateway.join._STATE_FILE", state_file)
    monkeypatch.setattr("sift_gateway.join._STATE_DIR", tmp_path)
    yield


class TestJoinCodeGeneration:
    def test_format(self):
        """Join code is XXXX-XXXX format."""
        code = generate_join_code()
        assert len(code) == 9  # 4 + dash + 4
        assert code[4] == "-"
        assert all(c in _JOIN_CHARSET for c in code.replace("-", ""))

    def test_no_ambiguous_chars(self):
        """Join codes exclude 0, O, 1, l, I."""
        ambiguous = set("0O1lI")
        for _ in range(50):
            code = generate_join_code()
            assert not ambiguous.intersection(code.replace("-", ""))

    def test_unique(self):
        """Generated codes are unique (statistical check)."""
        codes = {generate_join_code() for _ in range(100)}
        assert len(codes) == 100


class TestJoinCodeStorage:
    def test_bcrypt_storage(self, tmp_path):
        """Plaintext code is not stored; bcrypt hash is."""
        code = generate_join_code()
        store_join_code(code)
        # Read state file from the monkeypatched location and verify no plaintext
        import sift_gateway.join as join_mod
        state_text = join_mod._STATE_FILE.read_text()
        assert code not in state_text
        # But there should be a bcrypt hash (starts with $2b$)
        assert "$2b$" in state_text

    def test_validate_valid_code(self):
        """Valid, unexpired, unused code is accepted."""
        code = generate_join_code()
        store_join_code(code, expires_hours=1)
        result = validate_join_code(code)
        assert result is not None  # returns hash key

    def test_validate_wrong_code(self):
        """Wrong code is rejected."""
        code = generate_join_code()
        store_join_code(code)
        result = validate_join_code("ZZZZ-ZZZZ")
        assert result is None

    def test_validate_expired_code(self, monkeypatch):
        """Expired code is rejected."""
        code = generate_join_code()
        store_join_code(code, expires_hours=1)
        # Monkey-patch time to be in the future
        real_time = time.time
        monkeypatch.setattr("sift_gateway.join.time.time", lambda: real_time() + 7200)
        result = validate_join_code(code)
        assert result is None

    def test_single_use(self):
        """Used code is rejected on second attempt."""
        code = generate_join_code()
        store_join_code(code)
        # First use succeeds
        assert validate_join_code(code) is not None
        mark_code_used(code)
        # Second use fails
        assert validate_join_code(code) is None


class TestJoinRateLimit:
    def test_allows_initial_attempts(self):
        assert check_join_rate_limit("10.0.0.1") is True

    def test_blocks_after_failures(self):
        """3 failures trigger lockout."""
        ip = "10.0.0.2"
        for _ in range(3):
            record_join_failure(ip)
        assert check_join_rate_limit(ip) is False

    def test_allows_after_window(self, monkeypatch):
        """Rate limit resets after window expires."""
        ip = "10.0.0.3"
        for _ in range(3):
            record_join_failure(ip)
        assert check_join_rate_limit(ip) is False
        # Advance time past the 15-minute window
        real_time = time.time
        monkeypatch.setattr("sift_gateway.join.time.time", lambda: real_time() + 1000)
        assert check_join_rate_limit(ip) is True
