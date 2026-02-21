"""
Hash Detection and Validation Utilities

This module provides utilities for detecting, validating, and normalizing
cryptographic file hashes used in forensic analysis and threat intelligence.

Supported Hash Algorithms:
    - MD5 (32 hex characters) - Legacy, fast but collision-prone
    - SHA1 (40 hex characters) - Still common in malware databases
    - SHA256 (64 hex characters) - Preferred for modern use

Hash Format Handling:
    - Auto-detection by length (32/40/64 characters)
    - Case-insensitive (normalizes to lowercase)
    - Prefix support (md5:, sha1:, sha256:, sha-1:, sha-256:)

Usage:
    from windows_triage.analysis.hashes import (
        detect_hash_algorithm,
        validate_hash,
        normalize_hash
    )

    # Detect algorithm from hash length
    algo = detect_hash_algorithm("d41d8cd98f00b204e9800998ecf8427e")  # "md5"

    # Validate hash format
    is_valid = validate_hash("sha256:e3b0c44298fc...")  # True

    # Normalize for database lookup
    normalized = normalize_hash("SHA256:E3B0C44298FC...")  # "e3b0c44298fc..."
"""

import re
from typing import Optional


# Hash length to algorithm mapping
HASH_LENGTHS = {
    32: 'md5',
    40: 'sha1',
    64: 'sha256',
}

# Valid hex pattern
HEX_PATTERN = re.compile(r'^[a-fA-F0-9]+$')


def detect_hash_algorithm(hash_str: str) -> Optional[str]:
    """
    Detect hash algorithm from string length.

    Args:
        hash_str: Hash string (may include prefix like "md5:")

    Returns:
        Algorithm name: "md5", "sha1", or "sha256", or None if invalid
    """
    if hash_str is None:
        return None

    hash_str = hash_str.strip().lower()

    if not hash_str:
        return None

    # Remove common prefixes
    for prefix in ('md5:', 'sha1:', 'sha256:', 'sha-1:', 'sha-256:'):
        if hash_str.startswith(prefix):
            hash_str = hash_str[len(prefix):]
            break

    length = len(hash_str)

    return HASH_LENGTHS.get(length)


def validate_hash(hash_str: str) -> bool:
    """
    Validate that a string is a valid hexadecimal hash.

    Args:
        hash_str: Hash string to validate

    Returns:
        True if valid hex hash of known length
    """
    hash_str = hash_str.strip().lower()

    # Remove prefixes
    for prefix in ('md5:', 'sha1:', 'sha256:', 'sha-1:', 'sha-256:'):
        if hash_str.startswith(prefix):
            hash_str = hash_str[len(prefix):]
            break

    # Check length
    if len(hash_str) not in HASH_LENGTHS:
        return False

    # Check hex characters
    return bool(HEX_PATTERN.match(hash_str))


def normalize_hash(hash_str: str) -> str:
    """
    Normalize a hash string for database lookup.

    Args:
        hash_str: Hash string (may include prefix)

    Returns:
        Lowercase hash without prefix
    """
    hash_str = hash_str.strip().lower()

    # Remove prefixes
    for prefix in ('md5:', 'sha1:', 'sha256:', 'sha-1:', 'sha-256:'):
        if hash_str.startswith(prefix):
            hash_str = hash_str[len(prefix):]
            break

    return hash_str


def get_hash_column(algorithm: str) -> str:
    """
    Get the database column name for a hash algorithm.

    Args:
        algorithm: Hash algorithm name

    Returns:
        Column name (md5, sha1, or sha256)
    """
    algorithm = algorithm.lower().replace('-', '')
    if algorithm in ('md5', 'sha1', 'sha256'):
        return algorithm
    raise ValueError(f"Unknown hash algorithm: {algorithm}")


def parse_hash_with_algorithm(hash_str: str) -> tuple[Optional[str], Optional[str]]:
    """
    Parse a hash string and return (normalized_hash, algorithm).

    Args:
        hash_str: Hash string, optionally with prefix

    Returns:
        Tuple of (normalized_hash, algorithm), or (None, None) if invalid
    """
    if hash_str is None:
        return None, None

    normalized = normalize_hash(hash_str)
    algorithm = detect_hash_algorithm(normalized)

    if algorithm is None:
        return None, None

    return normalized, algorithm
