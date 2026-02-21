"""Analysis utilities for forensic triage."""

from .paths import (
    normalize_path,
    extract_filename,
    extract_directory,
    check_suspicious_path,
    parse_service_binary_path,
    is_system_path,
    SYSTEM_DIRECTORIES,
)

from .hashes import (
    detect_hash_algorithm,
    validate_hash,
    normalize_hash,
    get_hash_column,
    parse_hash_with_algorithm,
)

from .unicode import (
    detect_unicode_evasion,
    normalize_homoglyphs,
    normalize_leet,
    detect_leet_speak,
    detect_typosquatting,
    levenshtein_distance,
    strip_invisible_chars,
    get_canonical_form,
    check_process_name_spoofing,
    BIDI_OVERRIDES,
    ZERO_WIDTH_CHARS,
    HOMOGLYPHS,
    LEET_SUBSTITUTIONS,
)

from .filename import (
    calculate_entropy,
    analyze_filename,
    check_known_tool_filename,
    EXECUTABLE_EXTENSIONS,
)

from .verdicts import (
    Verdict,
    VerdictResult,
    calculate_hash_verdict,
    calculate_file_verdict,
    calculate_process_verdict,
    calculate_service_verdict,
)

__all__ = [
    # paths
    'normalize_path',
    'extract_filename',
    'extract_directory',
    'check_suspicious_path',
    'parse_service_binary_path',
    # hashes
    'detect_hash_algorithm',
    'validate_hash',
    'normalize_hash',
    'get_hash_column',
    'parse_hash_with_algorithm',
    # unicode
    'detect_unicode_evasion',
    'normalize_homoglyphs',
    'strip_invisible_chars',
    'get_canonical_form',
    'check_process_name_spoofing',
    'BIDI_OVERRIDES',
    'ZERO_WIDTH_CHARS',
    'HOMOGLYPHS',
    # filename
    'calculate_entropy',
    'analyze_filename',
    'check_known_tool_filename',
    'EXECUTABLE_EXTENSIONS',
    # verdicts
    'Verdict',
    'VerdictResult',
    'calculate_hash_verdict',
    'calculate_file_verdict',
    'calculate_process_verdict',
    'calculate_service_verdict',
]
