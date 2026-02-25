"""Analysis utilities for forensic triage."""

from .filename import (
    EXECUTABLE_EXTENSIONS,
    analyze_filename,
    calculate_entropy,
    check_known_tool_filename,
)
from .hashes import (
    detect_hash_algorithm,
    get_hash_column,
    normalize_hash,
    parse_hash_with_algorithm,
    validate_hash,
)
from .paths import (
    SYSTEM_DIRECTORIES,
    check_suspicious_path,
    extract_directory,
    extract_filename,
    is_system_path,
    normalize_path,
    parse_service_binary_path,
)
from .unicode import (
    BIDI_OVERRIDES,
    HOMOGLYPHS,
    LEET_SUBSTITUTIONS,
    ZERO_WIDTH_CHARS,
    check_process_name_spoofing,
    detect_leet_speak,
    detect_typosquatting,
    detect_unicode_evasion,
    get_canonical_form,
    levenshtein_distance,
    normalize_homoglyphs,
    normalize_leet,
    strip_invisible_chars,
)
from .verdicts import (
    Verdict,
    VerdictResult,
    calculate_file_verdict,
    calculate_hash_verdict,
    calculate_process_verdict,
    calculate_service_verdict,
)

__all__ = [
    # paths
    "SYSTEM_DIRECTORIES",
    "is_system_path",
    "normalize_path",
    "extract_filename",
    "extract_directory",
    "check_suspicious_path",
    "parse_service_binary_path",
    # hashes
    "detect_hash_algorithm",
    "validate_hash",
    "normalize_hash",
    "get_hash_column",
    "parse_hash_with_algorithm",
    # unicode
    "LEET_SUBSTITUTIONS",
    "detect_unicode_evasion",
    "detect_leet_speak",
    "detect_typosquatting",
    "levenshtein_distance",
    "normalize_leet",
    "normalize_homoglyphs",
    "strip_invisible_chars",
    "get_canonical_form",
    "check_process_name_spoofing",
    "BIDI_OVERRIDES",
    "ZERO_WIDTH_CHARS",
    "HOMOGLYPHS",
    # filename
    "calculate_entropy",
    "analyze_filename",
    "check_known_tool_filename",
    "EXECUTABLE_EXTENSIONS",
    # verdicts
    "Verdict",
    "VerdictResult",
    "calculate_hash_verdict",
    "calculate_file_verdict",
    "calculate_process_verdict",
    "calculate_service_verdict",
]
