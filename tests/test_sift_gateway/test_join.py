"""Tests for sift_gateway.join — join code generation, validation, rate limiting."""

import json
import time

import pytest
import sift_gateway.join as join_mod
from sift_gateway.join import (
    _JOIN_CHARSET,
    check_join_rate_limit,
    generate_join_code,
    mark_code_used,
    record_join_failure,
    store_join_code,
    validate_join_code,
)


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    """Use a temp state file for each test."""
    state_file = tmp_path / ".join_state.json"
    monkeypatch.setattr("sift_gateway.join._STATE_FILE", state_file)
    monkeypatch.setattr("sift_gateway.join._STATE_DIR", tmp_path)
    # Reset in-memory rate limit state
    join_mod._join_failures.clear()
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

    def test_load_prunes_expired_and_used(self, tmp_path):
        """_load_state() prunes expired and used codes, keeps valid ones."""
        now = time.time()
        state = {
            "codes": {
                "hash_expired": {
                    "created": "2026-01-01T00:00:00+00:00",
                    "expires_ts": now - 3600,  # expired 1 hour ago
                    "used": False,
                },
                "hash_used": {
                    "created": "2026-01-01T00:00:00+00:00",
                    "expires_ts": now + 3600,  # still valid
                    "used": True,
                },
                "hash_valid": {
                    "created": "2026-01-01T00:00:00+00:00",
                    "expires_ts": now + 3600,  # still valid
                    "used": False,
                },
            },
            "failures": {},
        }
        join_mod._STATE_FILE.write_text(json.dumps(state))
        loaded = join_mod._load_state()
        assert "hash_expired" not in loaded["codes"]
        assert "hash_used" not in loaded["codes"]
        assert "hash_valid" in loaded["codes"]


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
        real_monotonic = time.monotonic
        monkeypatch.setattr(
            "sift_gateway.join.time.monotonic", lambda: real_monotonic() + 1000
        )
        assert check_join_rate_limit(ip) is True


class TestJoinGatewayCallOrder:
    """Verify mark_code_used is called before _add_api_key_to_config (TOCTOU fix)."""

    def test_mark_used_before_config_write(self, monkeypatch):
        """mark_code_used() must be called before _add_api_key_to_config()."""
        from unittest.mock import MagicMock, patch

        from sift_gateway.rest import rest_routes
        from starlette.applications import Starlette
        from starlette.testclient import TestClient

        call_order = []

        def mock_validate(code):
            return "fake_hash"

        def mock_mark_used(code):
            call_order.append("mark_code_used")

        def mock_add_api_key(gateway, token, examiner):
            call_order.append("_add_api_key_to_config")

        def mock_generate_token():
            return "aiir_gw_test123"

        # Build minimal app
        app = Starlette(routes=rest_routes())
        mock_gw = MagicMock()
        mock_gw.backends = {"forensic-mcp": MagicMock()}
        mock_gw.config = {"gateway": {"host": "10.0.0.5", "port": 4508}}
        app.state.gateway = mock_gw

        client = TestClient(app, raise_server_exceptions=False)

        with (
            patch("sift_gateway.rest.validate_join_code", mock_validate),
            patch("sift_gateway.rest.mark_code_used", mock_mark_used),
            patch("sift_gateway.rest._add_api_key_to_config", mock_add_api_key),
            patch("sift_gateway.rest.generate_gateway_token", mock_generate_token),
            patch("sift_gateway.rest.check_join_rate_limit", return_value=True),
        ):
            resp = client.post(
                "/api/v1/setup/join",
                json={
                    "code": "ABCD-EFGH",
                    "machine_type": "examiner",
                    "hostname": "analyst-1",
                },
            )

        assert resp.status_code == 200
        assert call_order == ["mark_code_used", "_add_api_key_to_config"]
