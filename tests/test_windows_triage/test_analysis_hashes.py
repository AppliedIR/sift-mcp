"""Tests for hash detection and validation utilities."""

import pytest
from windows_triage.analysis.hashes import (
    detect_hash_algorithm,
    get_hash_column,
    normalize_hash,
    parse_hash_with_algorithm,
    validate_hash,
)


class TestDetectHashAlgorithm:
    """Tests for detect_hash_algorithm function."""

    def test_md5_length(self):
        # MD5 = 32 characters
        assert detect_hash_algorithm("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1_length(self):
        # SHA1 = 40 characters
        assert (
            detect_hash_algorithm("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
        )

    def test_sha256_length(self):
        # SHA256 = 64 characters
        hash_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_hash_algorithm(hash_str) == "sha256"

    def test_with_md5_prefix(self):
        assert detect_hash_algorithm("md5:d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_with_sha1_prefix(self):
        assert (
            detect_hash_algorithm("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709")
            == "sha1"
        )

    def test_with_sha256_prefix(self):
        hash_str = (
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert detect_hash_algorithm(hash_str) == "sha256"

    def test_uppercase(self):
        assert detect_hash_algorithm("D41D8CD98F00B204E9800998ECF8427E") == "md5"

    def test_with_whitespace(self):
        assert detect_hash_algorithm("  d41d8cd98f00b204e9800998ecf8427e  ") == "md5"

    def test_invalid_length(self):
        # Now returns None instead of raising ValueError
        assert detect_hash_algorithm("abc123") is None

    def test_empty(self):
        # Now returns None instead of raising ValueError
        assert detect_hash_algorithm("") is None


class TestValidateHash:
    """Tests for validate_hash function."""

    def test_valid_md5(self):
        assert validate_hash("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_valid_sha1(self):
        assert validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True

    def test_valid_sha256(self):
        hash_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert validate_hash(hash_str) is True

    def test_invalid_characters(self):
        # Contains 'g' which is not hex
        assert validate_hash("g41d8cd98f00b204e9800998ecf8427e") is False

    def test_invalid_length(self):
        assert validate_hash("abc123") is False

    def test_with_prefix(self):
        assert validate_hash("md5:d41d8cd98f00b204e9800998ecf8427e") is True

    def test_empty(self):
        assert validate_hash("") is False

    def test_mixed_case(self):
        assert validate_hash("D41d8CD98f00B204E9800998ECf8427e") is True


class TestNormalizeHash:
    """Tests for normalize_hash function."""

    def test_lowercase(self):
        assert (
            normalize_hash("D41D8CD98F00B204E9800998ECF8427E")
            == "d41d8cd98f00b204e9800998ecf8427e"
        )

    def test_strip_whitespace(self):
        assert (
            normalize_hash("  d41d8cd98f00b204e9800998ecf8427e  ")
            == "d41d8cd98f00b204e9800998ecf8427e"
        )

    def test_remove_md5_prefix(self):
        assert (
            normalize_hash("md5:d41d8cd98f00b204e9800998ecf8427e")
            == "d41d8cd98f00b204e9800998ecf8427e"
        )

    def test_remove_sha1_prefix(self):
        assert (
            normalize_hash("sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709")
            == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )

    def test_remove_sha256_prefix(self):
        hash_str = (
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert normalize_hash(hash_str) == expected

    def test_remove_sha_dash_prefix(self):
        assert (
            normalize_hash("sha-1:da39a3ee5e6b4b0d3255bfef95601890afd80709")
            == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )


class TestGetHashColumn:
    """Tests for get_hash_column function."""

    def test_md5(self):
        assert get_hash_column("md5") == "md5"
        assert get_hash_column("MD5") == "md5"

    def test_sha1(self):
        assert get_hash_column("sha1") == "sha1"
        assert get_hash_column("SHA1") == "sha1"
        assert get_hash_column("sha-1") == "sha1"

    def test_sha256(self):
        assert get_hash_column("sha256") == "sha256"
        assert get_hash_column("SHA256") == "sha256"
        assert get_hash_column("sha-256") == "sha256"

    def test_invalid(self):
        with pytest.raises(ValueError, match="Unknown hash algorithm"):
            get_hash_column("sha512")


class TestParseHashWithAlgorithm:
    """Tests for parse_hash_with_algorithm function."""

    def test_md5(self):
        hash_str = "d41d8cd98f00b204e9800998ecf8427e"
        normalized, algorithm = parse_hash_with_algorithm(hash_str)
        assert normalized == hash_str
        assert algorithm == "md5"

    def test_sha256_with_prefix(self):
        hash_str = (
            "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        )
        normalized, algorithm = parse_hash_with_algorithm(hash_str)
        assert (
            normalized
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert algorithm == "sha256"

    def test_invalid_hash(self):
        # Now returns (None, None) instead of raising ValueError
        normalized, algorithm = parse_hash_with_algorithm("not-a-hash")
        assert normalized is None
        assert algorithm is None
