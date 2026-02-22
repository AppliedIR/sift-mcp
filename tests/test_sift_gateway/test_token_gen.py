"""Tests for gateway token generation."""

from sift_gateway.token_gen import generate_gateway_token


class TestGenerateGatewayToken:
    def test_prefix(self):
        token = generate_gateway_token()
        assert token.startswith("aiir_gw_")

    def test_length(self):
        token = generate_gateway_token()
        assert len(token) == 32  # 8 prefix + 24 hex

    def test_uniqueness(self):
        tokens = {generate_gateway_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_hex_suffix(self):
        token = generate_gateway_token()
        suffix = token[8:]  # strip "aiir_gw_"
        int(suffix, 16)  # should not raise
