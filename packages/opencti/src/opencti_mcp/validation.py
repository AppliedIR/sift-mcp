"""Input validation utilities.

Security design:
1. Length checks FIRST (prevents ReDoS)
2. Simple patterns only (no complex regex)
3. Defense in depth (validate at multiple layers)
"""

from __future__ import annotations

import re
from typing import Any, Tuple

from .errors import ValidationError


# =============================================================================
# Security Constants - Resource Exhaustion Prevention
# =============================================================================

# ASCII-only character sets for security (prevents homoglyph/IDN attacks)
_ASCII_ALPHA = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
_ASCII_ALNUM = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
_ASCII_DIGITS = set('0123456789')

MAX_QUERY_LENGTH = 1000       # Search query
MAX_IOC_LENGTH = 2048         # IOC value (URLs can be long)
MAX_HASH_LENGTH = 128         # Hash with optional prefix
MAX_LIMIT = 100               # Max results per query
MAX_DAYS = 365                # Max days for temporal queries
MAX_RESPONSE_SIZE = 1_000_000  # 1MB response limit
MAX_DESCRIPTION_LENGTH = 500   # Truncate descriptions
MAX_PATTERN_LENGTH = 200       # Truncate patterns
MAX_OFFSET = 500              # Max pagination offset
MAX_LABEL_LENGTH = 63         # Max label length (DNS label limit)
MAX_DOMAIN_LENGTH = 253       # Max domain name length (DNS limit)
MAX_IPV6_LENGTH = 45          # Max IPv6 with embedded IPv4
HASH_LENGTHS = (32, 40, 64)   # MD5, SHA1, SHA256 lengths


# =============================================================================
# Length Validation
# =============================================================================

def validate_no_null_bytes(value: str, field: str) -> None:
    """Reject null bytes which can cause path truncation attacks.

    Security: Null bytes (\x00) in strings can cause security issues
    including path truncation and injection attacks.

    Args:
        value: Input value to check
        field: Field name for error message

    Raises:
        ValidationError: If input contains null bytes
    """
    if "\x00" in value:
        raise ValidationError(f"{field} contains invalid null byte")


def validate_length(value: str | None, max_length: int, field: str) -> None:
    """Validate input length and check for null bytes.

    Security: This MUST be called before any regex or parsing operations
    to prevent ReDoS attacks. Also rejects null bytes.

    Args:
        value: Input value to validate
        max_length: Maximum allowed length
        field: Field name for error message

    Raises:
        ValidationError: If input exceeds max_length or contains null bytes
    """
    if value is not None and isinstance(value, str):
        if len(value) > max_length:
            raise ValidationError(f"{field} exceeds maximum length of {max_length} characters")
        # Check for null bytes
        if "\x00" in value:
            raise ValidationError(f"{field} contains invalid null byte")


def validate_limit(value: int | None, max_value: int = MAX_LIMIT) -> int:
    """Validate and clamp limit parameter.

    Args:
        value: Requested limit
        max_value: Maximum allowed value

    Returns:
        Clamped limit value (1 to max_value)
    """
    if value is None:
        return 10  # Default
    if not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return 10
    return max(1, min(value, max_value))


def validate_days(value: int | None, max_value: int = MAX_DAYS) -> int:
    """Validate days parameter for temporal queries.

    Args:
        value: Requested days
        max_value: Maximum allowed value

    Returns:
        Clamped days value (1 to max_value)
    """
    if value is None:
        return 7  # Default
    if not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return 7
    return max(1, min(value, max_value))


def validate_offset(value: int | None, max_value: int = MAX_OFFSET) -> int:
    """Validate and clamp offset parameter for pagination.

    Args:
        value: Requested offset (can be None)
        max_value: Maximum allowed value (default: MAX_OFFSET)

    Returns:
        Clamped offset value (0 to max_value)
    """
    if value is None:
        return 0
    if not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return 0
    return max(0, min(value, max_value))


# =============================================================================
# IOC Validation
# =============================================================================

def validate_ioc(ioc: str) -> Tuple[bool, str]:
    """Validate IOC format and detect type.

    Security: Length check is performed FIRST before any pattern matching.

    Args:
        ioc: IOC value to validate

    Returns:
        Tuple of (is_valid, detected_type)

    Raises:
        ValidationError: If IOC exceeds length limit or is empty
    """
    # 1. Length check FIRST (security)
    validate_length(ioc, MAX_IOC_LENGTH, "IOC")

    # 2. Strip and normalize
    ioc = ioc.strip()
    if not ioc:
        raise ValidationError("IOC cannot be empty")

    # 3. Check for null bytes (security)
    if '\x00' in ioc:
        raise ValidationError("IOC contains invalid characters")

    # 4. Detect type using simple patterns (no complex regex)
    if _is_ipv4(ioc):
        return True, "ipv4"

    if _is_ipv6(ioc):
        return True, "ipv6"

    if _is_cidr(ioc):
        return True, "cidr"

    if _is_hash(ioc):
        hash_type = _detect_hash_type(ioc)
        return True, hash_type

    if ioc.startswith(('http://', 'https://', 'ftp://')):
        return True, "url"

    if _is_domain(ioc):
        return True, "domain"

    if _is_cve(ioc):
        return True, "cve"

    if _is_mitre_id(ioc):
        return True, "mitre"

    # Allow unknown types - let OpenCTI handle them
    return True, "unknown"


def _is_ipv4(value: str) -> bool:
    """Check if value is a valid IPv4 address.

    Uses simple parsing instead of regex to avoid ReDoS.
    """
    parts = value.split('.')
    if len(parts) != 4:
        return False

    for part in parts:
        if not part:
            return False
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
        # Reject leading zeros (e.g., "01.02.03.04")
        if len(part) > 1 and part[0] == '0':
            return False

    return True


def _is_ipv6(value: str) -> bool:
    """Check if value is a valid IPv6 address.

    Uses simple parsing instead of regex to avoid ReDoS.
    Supports full and compressed (::) notation.
    """
    # Length sanity check
    if len(value) > MAX_IPV6_LENGTH:
        return False

    # Must contain at least one colon
    if ':' not in value:
        return False

    # Handle :: compression
    if '::' in value:
        # Only one :: allowed
        if value.count('::') > 1:
            return False
        # Split on :: and validate both parts
        parts = value.split('::')
        if len(parts) != 2:
            return False
        left = parts[0].split(':') if parts[0] else []
        right = parts[1].split(':') if parts[1] else []
        # Total groups must be <= 8
        if len(left) + len(right) > 7:
            return False
        all_groups = left + right
    else:
        # Full notation - must have exactly 8 groups
        all_groups = value.split(':')
        if len(all_groups) != 8:
            return False

    # Validate each group
    hex_chars = set('0123456789abcdefABCDEF')
    for group in all_groups:
        if not group:
            continue  # Empty groups from :: are OK
        if len(group) > 4:
            return False
        if not all(c in hex_chars for c in group):
            return False

    return True


def _is_cidr(value: str) -> bool:
    """Check if value is a valid CIDR notation (IPv4 or IPv6).

    Uses simple parsing instead of regex to avoid ReDoS.
    """
    if '/' not in value:
        return False

    parts = value.rsplit('/', 1)
    if len(parts) != 2:
        return False

    network, prefix = parts

    # Validate prefix
    if not prefix.isdigit():
        return False
    prefix_num = int(prefix)

    # Check if IPv4 CIDR
    if _is_ipv4(network):
        return 0 <= prefix_num <= 32

    # Check if IPv6 CIDR
    if _is_ipv6(network):
        return 0 <= prefix_num <= 128

    return False


def _is_hash(value: str) -> bool:
    """Check if value looks like a hash (MD5/SHA1/SHA256)."""
    # Remove common prefixes
    normalized = _normalize_hash(value)

    # Check length (MD5=32, SHA1=40, SHA256=64)
    if len(normalized) not in HASH_LENGTHS:
        return False

    # Check hex characters
    return all(c in '0123456789abcdefABCDEF' for c in normalized)


def _detect_hash_type(value: str) -> str:
    """Detect hash algorithm from length."""
    normalized = _normalize_hash(value)
    length_to_type = {32: "md5", 40: "sha1", 64: "sha256"}
    return length_to_type.get(len(normalized), "hash")


def _normalize_hash(value: str) -> str:
    """Normalize hash by removing prefixes and whitespace."""
    value = value.strip().lower()

    # Remove common prefixes
    prefixes = ['md5:', 'sha1:', 'sha256:', 'sha-1:', 'sha-256:']
    for prefix in prefixes:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break

    return value.strip()


def _is_domain(value: str) -> bool:
    """Check if value looks like a domain name.

    Uses simple checks instead of complex regex to avoid ReDoS.

    Security: Uses ASCII-only validation to prevent IDN homoglyph attacks.
    Internationalized domain names (IDN) should be in Punycode format (xn--).
    """
    # Length check
    if len(value) > MAX_DOMAIN_LENGTH:
        return False

    # Must have at least one dot
    if '.' not in value:
        return False

    # Cannot start or end with dot
    if value.startswith('.') or value.endswith('.'):
        return False

    # Cannot have consecutive dots
    if '..' in value:
        return False

    # Check each label
    labels = value.split('.')
    for label in labels:
        if not label:
            return False
        if len(label) > MAX_LABEL_LENGTH:
            return False
        # Labels can only contain ASCII alphanumeric and hyphens
        # Security: Using explicit ASCII set prevents Unicode homoglyph attacks
        if not all(c in _ASCII_ALNUM or c == '-' for c in label):
            return False
        # Cannot start or end with hyphen
        if label.startswith('-') or label.endswith('-'):
            return False

    # TLD must be ASCII alphabetic (at least 2 chars)
    # Security: Using explicit ASCII set prevents homoglyph attacks
    tld = labels[-1]
    if len(tld) < 2 or not all(c in _ASCII_ALPHA for c in tld):
        return False

    return True


def _is_cve(value: str) -> bool:
    """Check if value is a CVE identifier."""
    upper = value.upper()
    if not upper.startswith('CVE-'):
        return False

    parts = upper[4:].split('-')
    if len(parts) != 2:
        return False

    year, num = parts
    if len(year) != 4 or not year.isdigit():
        return False
    if not num.isdigit() or len(num) < 4:
        return False

    return True


def _is_mitre_id(value: str) -> bool:
    """Check if value is a MITRE ATT&CK technique ID."""
    upper = value.upper()

    # Main technique: T1234
    if re.match(r'^T\d{4}$', upper):
        return True

    # Sub-technique: T1234.001
    if re.match(r'^T\d{4}\.\d{3}$', upper):
        return True

    return False


# =============================================================================
# UUID Validation (for entity IDs)
# =============================================================================

# UUID v4 pattern - used for OpenCTI entity IDs
_UUID_CHARS = set('0123456789abcdefABCDEF-')


def validate_uuid(value: str, field: str = "id") -> str:
    """Validate and normalize UUID format.

    Security: Prevents injection via malformed entity IDs.
    OpenCTI uses UUID v4 for all entity identifiers.

    Args:
        value: UUID string to validate
        field: Field name for error messages

    Returns:
        Normalized lowercase UUID

    Raises:
        ValidationError: If not a valid UUID format
    """
    if not value:
        raise ValidationError(f"{field} cannot be empty")

    # Length check first (UUIDs are exactly 36 chars with hyphens)
    if len(value) != 36:
        raise ValidationError(f"{field} must be a valid UUID (36 characters)")

    # Character check (only hex digits and hyphens)
    if not all(c in _UUID_CHARS for c in value):
        raise ValidationError(f"{field} contains invalid characters")

    # Structure check: 8-4-4-4-12
    parts = value.split('-')
    if len(parts) != 5:
        raise ValidationError(f"{field} must be a valid UUID format")

    expected_lengths = [8, 4, 4, 4, 12]
    for part, expected_len in zip(parts, expected_lengths):
        if len(part) != expected_len:
            raise ValidationError(f"{field} must be a valid UUID format")

    return value.lower()


def validate_uuid_list(values: list[str] | None, field: str = "ids",
                       max_items: int = 20) -> list[str]:
    """Validate a list of UUIDs.

    Args:
        values: List of UUID strings
        field: Field name for error messages
        max_items: Maximum allowed items

    Returns:
        List of normalized lowercase UUIDs

    Raises:
        ValidationError: If any UUID is invalid or list too long
    """
    if not values:
        return []

    if len(values) > max_items:
        raise ValidationError(f"{field} cannot contain more than {max_items} items")

    return [validate_uuid(v, f"{field}[{i}]") for i, v in enumerate(values)]


# =============================================================================
# Label Validation
# =============================================================================

# Allowed characters in labels (alphanumeric, common punctuation)
_LABEL_ALLOWED = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:. ')


def validate_label(value: str) -> str:
    """Validate a single label.

    Security: Prevents injection via malformed labels.

    Args:
        value: Label string

    Returns:
        Validated label (stripped)

    Raises:
        ValidationError: If label is invalid
    """
    if not value or not value.strip():
        raise ValidationError("Label cannot be empty")

    value = value.strip()

    if len(value) > 100:
        raise ValidationError("Label exceeds maximum length of 100 characters")

    # Check for null bytes
    if '\x00' in value:
        raise ValidationError("Label contains invalid characters")

    # Check allowed characters
    if not all(c in _LABEL_ALLOWED for c in value):
        raise ValidationError("Label contains invalid characters")

    return value


def validate_labels(values: list[str] | None, max_items: int = 10) -> list[str]:
    """Validate a list of labels.

    Args:
        values: List of label strings
        max_items: Maximum allowed items

    Returns:
        List of validated labels

    Raises:
        ValidationError: If any label is invalid
    """
    if not values:
        return []

    if len(values) > max_items:
        raise ValidationError(f"Cannot specify more than {max_items} labels")

    return [validate_label(v) for v in values]


# =============================================================================
# Observable Type Validation
# =============================================================================

# Valid STIX Cyber Observable (SCO) types
VALID_OBSERVABLE_TYPES = frozenset({
    'Artifact', 'Autonomous-System', 'Directory', 'Domain-Name',
    'Email-Addr', 'Email-Message', 'Email-Mime-Part-Type',
    'File', 'StixFile',  # StixFile is OpenCTI's name for File
    'IPv4-Addr', 'IPv6-Addr', 'Mac-Addr', 'Mutex', 'Network-Traffic',
    'Process', 'Software', 'Url', 'URL',  # Both cases for compatibility
    'User-Account', 'Windows-Registry-Key', 'Windows-Registry-Value-Type',
    'X509-Certificate', 'Cryptocurrency-Wallet', 'Hostname',
    'Text', 'User-Agent', 'Bank-Account', 'Phone-Number', 'Payment-Card',
    'Media-Content', 'Tracking-Number', 'Credential',
})


def validate_observable_types(
    values: list[str] | None,
    max_items: int = 10,
    extra_types: frozenset[str] | None = None
) -> list[str] | None:
    """Validate observable type list.

    Security: Restricts to known STIX SCO types to prevent injection.
    Supports custom types via extra_types for customized OpenCTI instances.

    Args:
        values: List of observable type strings
        max_items: Maximum allowed items
        extra_types: Additional allowed types (from config)

    Returns:
        Validated list or None if empty

    Raises:
        ValidationError: If too many items or unknown types
    """
    if not values:
        return None

    if not isinstance(values, list):
        raise ValidationError("observable_types must be a list")

    if len(values) > max_items:
        raise ValidationError(f"Cannot specify more than {max_items} observable types")

    # Merge base types with any custom types
    allowed_types = VALID_OBSERVABLE_TYPES
    if extra_types:
        allowed_types = VALID_OBSERVABLE_TYPES | extra_types

    validated = []
    for v in values:
        if not v or not isinstance(v, str):
            continue
        v = v.strip()
        # Check against known types (case-sensitive for STIX compliance)
        if v not in allowed_types:
            raise ValidationError(
                f"Unknown observable type: '{v}'. "
                f"Valid types include: IPv4-Addr, Domain-Name, StixFile, URL, etc."
            )
        validated.append(v)

    return validated if validated else None


# =============================================================================
# Note Type Validation
# =============================================================================

# Valid note types in OpenCTI
VALID_NOTE_TYPES = frozenset({
    'analysis', 'assessment', 'external', 'internal',
    'threat-report', 'hypothesis', 'observation', 'conclusion',
})


def validate_note_types(values: list[str] | None, max_items: int = 5) -> list[str] | None:
    """Validate note type list.

    Security: Restricts to known note types to prevent injection.

    Args:
        values: List of note type strings
        max_items: Maximum allowed items

    Returns:
        Validated list or None if empty

    Raises:
        ValidationError: If invalid type
    """
    if not values:
        return None

    if not isinstance(values, list):
        raise ValidationError("note_types must be a list")

    if len(values) > max_items:
        raise ValidationError(f"Cannot specify more than {max_items} note types")

    validated = []
    for v in values:
        if not v or not isinstance(v, str):
            continue
        v = v.strip().lower()
        if len(v) > 50:
            raise ValidationError(f"Note type '{v[:20]}...' is too long")
        # Check for invalid characters (ASCII alphanumeric and hyphen only)
        if not all(c in _ASCII_ALNUM or c == '-' for c in v):
            raise ValidationError(f"Note type '{v}' contains invalid characters")
        if v not in VALID_NOTE_TYPES:
            raise ValidationError(f"Unknown note type '{v}'. Valid: {', '.join(sorted(VALID_NOTE_TYPES))}")
        validated.append(v)

    return validated if validated else None


# =============================================================================
# Date Filter Validation
# =============================================================================

# ISO8601 date pattern: YYYY-MM-DD with optional time
_ISO_DATE_PATTERN = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})'  # Date: YYYY-MM-DD
    r'(T(\d{2}):(\d{2}):(\d{2})'  # Optional time: THH:MM:SS
    r'(\.\d+)?'  # Optional fractional seconds
    r'(Z|[+-]\d{2}:\d{2})?)?$'  # Optional timezone
)


def validate_date_filter(value: str | None, field: str = "date") -> str | None:
    """Validate ISO8601 date format for filter parameters.

    Security: Prevents malformed dates from being passed to OpenCTI.

    Args:
        value: Date string to validate
        field: Field name for error messages

    Returns:
        Validated date string or None

    Raises:
        ValidationError: If date format is invalid
    """
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")

    value = value.strip()
    if not value:
        return None

    # Length check first (security)
    if len(value) > 50:
        raise ValidationError(f"{field} is too long")

    # Check for null bytes
    if '\x00' in value:
        raise ValidationError(f"{field} contains invalid characters")

    # Validate format
    match = _ISO_DATE_PATTERN.match(value)
    if not match:
        raise ValidationError(
            f"{field} must be ISO8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)"
        )

    # Basic range validation for date components
    year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))

    if not (1970 <= year <= 2100):
        raise ValidationError(f"{field} year must be between 1970 and 2100")
    if not (1 <= month <= 12):
        raise ValidationError(f"{field} month must be between 1 and 12")
    if not (1 <= day <= 31):
        raise ValidationError(f"{field} day must be between 1 and 31")

    # Validate time components if present
    if match.group(4):  # Time component exists
        hour, minute, second = int(match.group(5)), int(match.group(6)), int(match.group(7))
        if not (0 <= hour <= 23):
            raise ValidationError(f"{field} hour must be between 0 and 23")
        if not (0 <= minute <= 59):
            raise ValidationError(f"{field} minute must be between 0 and 59")
        if not (0 <= second <= 59):
            raise ValidationError(f"{field} second must be between 0 and 59")

    return value


# =============================================================================
# Pattern Type Validation
# =============================================================================

# Valid indicator pattern types
VALID_PATTERN_TYPES = frozenset({
    'stix', 'pcre', 'sigma', 'snort', 'suricata', 'yara',
    'tanium-signal', 'spl', 'eql',
})


def validate_pattern_type(
    value: str | None,
    extra_types: frozenset[str] | None = None
) -> str:
    """Validate indicator pattern type.

    Supports custom types via extra_types for customized OpenCTI instances.

    Args:
        value: Pattern type string
        extra_types: Additional allowed types (from config)

    Returns:
        Validated pattern type (defaults to 'stix')

    Raises:
        ValidationError: If pattern type is invalid
    """
    if value is None:
        return "stix"

    if not isinstance(value, str):
        raise ValidationError("pattern_type must be a string")

    value = value.strip().lower()

    if not value:
        return "stix"

    # Merge base types with any custom types
    allowed_types = VALID_PATTERN_TYPES
    if extra_types:
        # Extra types are lowercased for comparison
        allowed_types = VALID_PATTERN_TYPES | frozenset(t.lower() for t in extra_types)

    if value not in allowed_types:
        raise ValidationError(
            f"Invalid pattern_type: '{value}'. "
            f"Valid types: {', '.join(sorted(allowed_types))}"
        )

    return value


# =============================================================================
# Relationship Type Validation
# =============================================================================

# Valid STIX relationship types
VALID_RELATIONSHIP_TYPES = frozenset({
    'indicates', 'uses', 'targets', 'attributed-to', 'related-to',
    'mitigates', 'derived-from', 'duplicate-of', 'variant-of',
    'impersonates', 'located-at', 'based-on', 'delivers', 'drops',
    'exploits', 'compromises', 'originates-from', 'investigates',
    'authored-by', 'beacons-to', 'exfiltrates-to', 'downloads',
    'communicates-with', 'consists-of', 'controls', 'has', 'hosts',
    'owns', 'part-of', 'resides-in', 'resolves-to', 'belongs-to',
    # OpenCTI custom types
    'participates-in', 'cooperates-with', 'employed-by', 'citizen-of',
    'national-of',
})


def validate_relationship_types(values: list[str] | None) -> list[str] | None:
    """Validate relationship type list.

    Security: Uses ASCII-only validation to prevent homoglyph attacks.

    Args:
        values: List of relationship type strings

    Returns:
        Validated list or None

    Raises:
        ValidationError: If any type is invalid
    """
    if not values:
        return None

    if len(values) > 20:
        raise ValidationError("Cannot specify more than 20 relationship types")

    validated = []
    for v in values:
        if not v or not isinstance(v, str):
            continue
        v = v.strip().lower()
        if len(v) > 50:
            raise ValidationError(f"Relationship type '{v[:20]}...' is too long")
        # Security: ASCII-only to prevent homoglyph attacks
        # Uses explicit ASCII alphanumeric set instead of c.isalnum()
        if not all(c in _ASCII_ALNUM or c == '-' for c in v):
            raise ValidationError(f"Relationship type '{v}' contains invalid characters")
        if v not in VALID_RELATIONSHIP_TYPES:
            raise ValidationError(f"Unknown relationship type '{v}'. Valid: {', '.join(sorted(VALID_RELATIONSHIP_TYPES))}")
        validated.append(v)

    return validated if validated else None


# =============================================================================
# STIX Pattern Validation
# =============================================================================

def validate_stix_pattern(pattern: str) -> None:
    """Basic validation of STIX pattern syntax.

    Security: Prevents obviously malformed patterns.
    This is NOT a full STIX parser - OpenCTI will do full validation.

    Args:
        pattern: STIX pattern string

    Raises:
        ValidationError: If pattern is obviously malformed
    """
    if not pattern or not pattern.strip():
        raise ValidationError("STIX pattern cannot be empty")

    pattern = pattern.strip()

    # Length check
    if len(pattern) > 2048:
        raise ValidationError("STIX pattern exceeds maximum length")

    # Must start with [ and end with ]
    if not pattern.startswith('[') or not pattern.endswith(']'):
        raise ValidationError("STIX pattern must be enclosed in brackets []")

    # Check for null bytes
    if '\x00' in pattern:
        raise ValidationError("STIX pattern contains invalid characters")

    # Check bracket balance (basic)
    open_count = pattern.count('[')
    close_count = pattern.count(']')
    if open_count != close_count:
        raise ValidationError("STIX pattern has unbalanced brackets")

    # Check for common pattern types
    valid_prefixes = (
        'ipv4-addr:', 'ipv6-addr:', 'domain-name:', 'url:', 'file:',
        'email-addr:', 'mac-addr:', 'windows-registry-key:', 'process:',
        'network-traffic:', 'artifact:', 'autonomous-system:', 'directory:',
        'mutex:', 'software:', 'user-account:', 'x509-certificate:',
    )

    # Pattern should contain at least one object type reference
    inner = pattern[1:-1].strip()
    has_valid_type = any(vp in inner.lower() for vp in valid_prefixes)

    if not has_valid_type and ':' not in inner:
        raise ValidationError("STIX pattern must reference an observable type")


# =============================================================================
# Hash Validation
# =============================================================================

def validate_hash(value: str) -> bool:
    """Validate file hash format.

    Args:
        value: Hash value to validate

    Returns:
        True if valid hash format
    """
    # Length check first
    validate_length(value, MAX_HASH_LENGTH, "hash")

    normalized = _normalize_hash(value)

    # Valid lengths: MD5=32, SHA1=40, SHA256=64
    if len(normalized) not in (32, 40, 64):
        return False

    # Must be hexadecimal
    return all(c in '0123456789abcdefABCDEF' for c in normalized)


def normalize_hash(value: str) -> str:
    """Normalize hash to lowercase without prefix."""
    return _normalize_hash(value)


# =============================================================================
# Response Truncation
# =============================================================================

def truncate_string(value: str | None, max_length: int) -> str | None:
    """Truncate string to max length with ellipsis."""
    if value is None:
        return None
    if len(value) <= max_length:
        return value
    return value[:max_length - 3] + "..."


def truncate_response(result: dict[str, Any], max_size: int = MAX_RESPONSE_SIZE) -> dict[str, Any]:
    """Truncate response if it exceeds size limit.

    Security: Prevents memory exhaustion from large OpenCTI responses.
    Always truncates long fields (description, pattern) regardless of total size.

    Adds truncation metadata to indicate what was truncated.
    """
    import json

    # Track what gets truncated
    truncated_fields: list[str] = []

    # Always truncate long fields for security
    result = _truncate_dict_fields(result, truncated_fields)

    serialized = json.dumps(result, default=str)

    if len(serialized) > max_size:
        # Add truncation notice if overall size was exceeded
        result['_truncated'] = True
        result['_original_size'] = len(serialized)

    # Add truncation indicators if any fields were truncated
    if truncated_fields:
        result['_truncated_fields'] = truncated_fields

    return result


def _truncate_dict_fields(data: dict[str, Any], truncated_fields: list[str] | None = None,
                          path: str = "") -> dict[str, Any]:
    """Recursively truncate large fields in a dict.

    Args:
        data: Dictionary to process
        truncated_fields: List to append truncated field paths to
        path: Current path for tracking (e.g., "results[0].description")
    """
    if truncated_fields is None:
        truncated_fields = []

    result = {}

    for key, value in data.items():
        field_path = f"{path}.{key}" if path else key

        if isinstance(value, str):
            if key == 'description':
                if len(value) > MAX_DESCRIPTION_LENGTH:
                    truncated_fields.append(field_path)
                result[key] = truncate_string(value, MAX_DESCRIPTION_LENGTH)
            elif key == 'pattern':
                if len(value) > MAX_PATTERN_LENGTH:
                    truncated_fields.append(field_path)
                result[key] = truncate_string(value, MAX_PATTERN_LENGTH)
            elif len(value) > 1000:
                truncated_fields.append(field_path)
                result[key] = truncate_string(value, 1000)
            else:
                result[key] = value
        elif isinstance(value, dict):
            result[key] = _truncate_dict_fields(value, truncated_fields, field_path)
        elif isinstance(value, list):
            # Limit list sizes
            if len(value) > MAX_LIMIT:
                truncated_fields.append(f"{field_path}[{MAX_LIMIT}+]")
            result[key] = [
                _truncate_dict_fields(v, truncated_fields, f"{field_path}[{i}]")
                if isinstance(v, dict) else v
                for i, v in enumerate(value[:MAX_LIMIT])
            ]
        else:
            result[key] = value

    return result


# =============================================================================
# Log Sanitization
# =============================================================================

SENSITIVE_FIELDS = {'token', 'password', 'secret', 'key', 'auth', 'credential', 'api_key'}


def sanitize_for_log(value: Any) -> Any:
    """Sanitize value for safe logging.

    Security: Prevents log injection and sensitive data exposure.
    """
    if isinstance(value, str):
        # Remove/escape control characters
        sanitized = value.encode('unicode_escape').decode('ascii')
        # Truncate long values
        if len(sanitized) > 500:
            sanitized = sanitized[:500] + "...[truncated]"
        return sanitized
    elif isinstance(value, dict):
        return _filter_sensitive(value)
    elif isinstance(value, list):
        return [sanitize_for_log(v) for v in value[:10]]
    else:
        return value


def _filter_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    """Filter sensitive fields from data before logging."""
    result = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(s in key_lower for s in SENSITIVE_FIELDS):
            result[key] = "***REDACTED***"
        elif isinstance(value, dict):
            result[key] = _filter_sensitive(value)
        elif isinstance(value, str):
            result[key] = sanitize_for_log(value)
        else:
            result[key] = value
    return result
