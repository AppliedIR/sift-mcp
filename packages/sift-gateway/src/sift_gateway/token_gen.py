"""Bearer token generation for the AIIR gateway."""

import secrets


def generate_gateway_token() -> str:
    """Generate a bearer token for gateway API authentication.

    Format: ``aiir_gw_`` prefix + 24 hex characters (96 bits entropy).
    Total length: 32 characters.
    """
    return f"aiir_gw_{secrets.token_hex(12)}"
