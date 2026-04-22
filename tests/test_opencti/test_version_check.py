"""Tests for the pycti/OpenCTI major-version compatibility enforcement.

Regression guard for UAT 2026-04-22: pycti 7.x installed against a
6.x server emits `GRAPHQL_VALIDATION_FAILED: Unknown type "AIPrompt"`
on every IOC query. Enforcing at connect-time turns that silent
per-IOC failure into one clear VersionMismatchError with an
actionable pin instruction.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.errors import VersionMismatchError


@pytest.fixture
def client_with_mocked_config():
    """Build an OpenCTIClient with a fake Config. connect() will be
    patched in the individual tests to control which pycti/server
    versions are reported."""
    cfg = MagicMock()
    cfg.opencti_url = "http://test:8080"
    cfg.opencti_token = MagicMock()
    cfg.opencti_token.get_secret_value = lambda: "test-token"
    cfg.ssl_verify = False
    client = OpenCTIClient(config=cfg)
    return client


def _mock_pycti_module(version: str):
    """Returns a MagicMock that resembles the pycti module with the
    given __version__. Used as a patch target for
    `import pycti` inside _enforce_version_compat."""
    mod = MagicMock()
    mod.__version__ = version
    return mod


def test_version_mismatch_at_init_raises(client_with_mocked_config, monkeypatch):
    """pycti 7.x against a 6.x server → VersionMismatchError with
    actionable pin instruction mentioning both majors."""
    client = client_with_mocked_config

    # Build a fake inner pycti client that returns server version 6.9.10.
    fake_inner = MagicMock()
    fake_inner.query.return_value = {"data": {"about": {"version": "6.9.10"}}}

    # Patch `import pycti` inside _enforce_version_compat to report 7.x.
    fake_pycti = _mock_pycti_module("7.260318.0")

    with patch.dict("sys.modules", {"pycti": fake_pycti}):
        with pytest.raises(VersionMismatchError) as exc_info:
            client._enforce_version_compat(fake_inner)

    msg = str(exc_info.value)
    assert "7.x" in msg or "7.260318.0" in msg
    assert "6.9.10" in msg or "6.x" in msg
    assert "README" in msg or "compatibility" in msg.lower()


def test_matching_majors_pass_cleanly(client_with_mocked_config):
    """pycti 6.x and server 6.x → no raise."""
    client = client_with_mocked_config
    fake_inner = MagicMock()
    fake_inner.query.return_value = {"data": {"about": {"version": "6.9.10"}}}
    fake_pycti = _mock_pycti_module("6.9.20")

    with patch.dict("sys.modules", {"pycti": fake_pycti}):
        # Should return None without raising.
        result = client._enforce_version_compat(fake_inner)
    assert result is None


def test_server_unreachable_does_not_fail_closed(client_with_mocked_config):
    """If the server about.version query raises (transient outage),
    skip the check rather than blocking init. Downstream queries
    surface the outage separately; version check is not the right
    place to fail-closed on a network issue."""
    client = client_with_mocked_config
    fake_inner = MagicMock()
    fake_inner.query.side_effect = OSError("connection refused")
    fake_pycti = _mock_pycti_module("7.260318.0")

    with patch.dict("sys.modules", {"pycti": fake_pycti}):
        # Should NOT raise — transient outage tolerated.
        result = client._enforce_version_compat(fake_inner)
    assert result is None
