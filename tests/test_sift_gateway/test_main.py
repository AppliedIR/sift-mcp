"""Tests for gateway __main__ (TLS configuration)."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sift_gateway.__main__ import main


class TestTLSConfig:
    def test_tls_missing_cert_exits(self, tmp_path):
        """Missing TLS certificate file causes sys.exit(1)."""
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(
            "gateway:\n"
            "  tls:\n"
            "    certfile: /nonexistent/cert.pem\n"
            "    keyfile: /nonexistent/key.pem\n"
            "backends: {}\n"
        )
        with patch("sys.argv", ["sift-gateway", "--config", str(config_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_tls_missing_key_exits(self, tmp_path):
        """Missing TLS key file causes sys.exit(1)."""
        cert = tmp_path / "cert.pem"
        cert.write_text("fake cert")
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(
            f"gateway:\n"
            f"  tls:\n"
            f"    certfile: {cert}\n"
            f"    keyfile: /nonexistent/key.pem\n"
            f"backends: {{}}\n"
        )
        with patch("sys.argv", ["sift-gateway", "--config", str(config_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_tls_default_host_0000(self, tmp_path):
        """With TLS enabled and no explicit host, default is 0.0.0.0."""
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("fake cert")
        key.write_text("fake key")
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(
            f"gateway:\n"
            f"  tls:\n"
            f"    certfile: {cert}\n"
            f"    keyfile: {key}\n"
            f"backends: {{}}\n"
        )
        with patch("sys.argv", ["sift-gateway", "--config", str(config_file)]):
            with patch("sift_gateway.__main__.uvicorn") as mock_uvicorn:
                with patch("sift_gateway.__main__.Gateway") as mock_gw_cls:
                    mock_gw = MagicMock()
                    mock_gw.create_app.return_value = MagicMock()
                    mock_gw_cls.return_value = mock_gw
                    main()
                    call_kwargs = mock_uvicorn.run.call_args
                    assert call_kwargs.kwargs.get("host", call_kwargs.args[1] if len(call_kwargs.args) > 1 else None) == "0.0.0.0" or call_kwargs[1]["host"] == "0.0.0.0"

    def test_no_tls_default_host_localhost(self, tmp_path):
        """Without TLS, default host is 127.0.0.1."""
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text("gateway: {}\nbackends: {}\n")
        with patch("sys.argv", ["sift-gateway", "--config", str(config_file)]):
            with patch("sift_gateway.__main__.uvicorn") as mock_uvicorn:
                with patch("sift_gateway.__main__.Gateway") as mock_gw_cls:
                    mock_gw = MagicMock()
                    mock_gw.create_app.return_value = MagicMock()
                    mock_gw_cls.return_value = mock_gw
                    main()
                    call_kwargs = mock_uvicorn.run.call_args
                    # host should be 127.0.0.1 (no TLS)
                    if call_kwargs.kwargs:
                        assert call_kwargs.kwargs["host"] == "127.0.0.1"
                    else:
                        assert call_kwargs[1]["host"] == "127.0.0.1"

    def test_tls_incomplete_config_exits(self, tmp_path):
        """TLS config with only certfile (no keyfile) causes exit."""
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(
            "gateway:\n"
            "  tls:\n"
            "    certfile: /some/cert.pem\n"
            "backends: {}\n"
        )
        with patch("sys.argv", ["sift-gateway", "--config", str(config_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
