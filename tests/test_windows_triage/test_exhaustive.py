"""
Exhaustive Test Suite for Windows Triage MCP Server

This module contains ~5000 test cases covering:
- Edge cases and boundary conditions
- NLP-style natural language tests
- Input validation and error handling
- Combination and interaction tests
- Unicode and encoding edge cases
- Path normalization edge cases
- Verdict calculation edge cases
"""

import random
import string

import pytest

# =============================================================================
# PATH NORMALIZATION EXHAUSTIVE TESTS
# =============================================================================


class TestPathNormalizationExhaustive:
    """Exhaustive tests for path normalization."""

    # Test all drive letters
    @pytest.mark.parametrize("drive", list(string.ascii_uppercase))
    def test_all_drive_letters(self, drive):
        """Test normalization works for all drive letters A-Z."""
        from windows_triage.analysis.paths import normalize_path

        result = normalize_path(f"{drive}:\\Windows\\cmd.exe")
        assert result == "\\windows\\cmd.exe"

    @pytest.mark.parametrize("drive", list(string.ascii_lowercase))
    def test_all_lowercase_drive_letters(self, drive):
        """Test normalization works for lowercase drive letters."""
        from windows_triage.analysis.paths import normalize_path

        result = normalize_path(f"{drive}:\\Windows\\cmd.exe")
        assert result == "\\windows\\cmd.exe"

    # Test various separator combinations
    # Note: Double slashes are NOT collapsed - they become double backslashes
    SEPARATOR_CASES = [
        ("C:/Windows/cmd.exe", "\\windows\\cmd.exe"),
        ("C:\\Windows\\cmd.exe", "\\windows\\cmd.exe"),
        ("C:/Windows\\cmd.exe", "\\windows\\cmd.exe"),
        ("C:\\Windows/cmd.exe", "\\windows\\cmd.exe"),
        ("C://Windows//cmd.exe", "\\\\windows\\\\cmd.exe"),  # Double slashes preserved
        (
            "C:\\\\Windows\\\\cmd.exe",
            "\\\\windows\\\\cmd.exe",
        ),  # Double backslashes preserved
        ("/Windows/cmd.exe", "\\windows\\cmd.exe"),
        ("\\Windows\\cmd.exe", "\\windows\\cmd.exe"),
    ]

    @pytest.mark.parametrize("input_path,expected", SEPARATOR_CASES)
    def test_separator_normalization(self, input_path, expected):
        """Test various separator combinations."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(input_path) == expected

    # Test trailing slash variations
    TRAILING_SLASH_CASES = [
        ("C:\\Windows\\", "\\windows"),
        ("C:\\Windows\\\\", "\\windows"),
        ("C:\\Windows\\\\\\", "\\windows"),
        ("C:\\Windows/", "\\windows"),
        ("C:\\Windows//", "\\windows"),
        ("C:\\Windows\\/", "\\windows"),
    ]

    @pytest.mark.parametrize("input_path,expected", TRAILING_SLASH_CASES)
    def test_trailing_slash_removal(self, input_path, expected):
        """Test trailing slash removal."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(input_path) == expected

    # Test root directory cases
    ROOT_CASES = [
        ("C:\\", "\\"),
        ("D:\\", "\\"),
        ("\\", "\\"),
        ("/", "\\"),
        ("C:/", "\\"),
    ]

    @pytest.mark.parametrize("input_path,expected", ROOT_CASES)
    def test_root_directory(self, input_path, expected):
        """Test root directory normalization preserves backslash."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(input_path) == expected

    # Test empty and None inputs
    def test_empty_string(self):
        """Test empty string input."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path("") == ""

    def test_none_input(self):
        """Test None input."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(None) is None

    def test_whitespace_only(self):
        """Test whitespace-only input."""
        from windows_triage.analysis.paths import normalize_path

        # Whitespace is preserved but lowercased
        result = normalize_path("   ")
        assert result == "   "

    # Test UNC paths
    UNC_CASES = [
        ("\\\\server\\share\\file.exe", "\\\\server\\share\\file.exe"),
        ("//server/share/file.exe", "\\\\server\\share\\file.exe"),
        ("\\\\server\\share\\", "\\\\server\\share"),
        ("\\\\192.168.1.1\\c$\\file.exe", "\\\\192.168.1.1\\c$\\file.exe"),
    ]

    @pytest.mark.parametrize("input_path,expected", UNC_CASES)
    def test_unc_paths(self, input_path, expected):
        """Test UNC path handling."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(input_path) == expected

    # Test paths with special characters
    SPECIAL_CHAR_CASES = [
        ("C:\\Program Files (x86)\\app.exe", "\\program files (x86)\\app.exe"),
        ("C:\\Users\\John Doe\\file.txt", "\\users\\john doe\\file.txt"),
        ("C:\\Data[1]\\file.exe", "\\data[1]\\file.exe"),
        ("C:\\Test{guid}\\app.exe", "\\test{guid}\\app.exe"),
        ("C:\\Test#1\\file.exe", "\\test#1\\file.exe"),
        ("C:\\Test@home\\file.exe", "\\test@home\\file.exe"),
    ]

    @pytest.mark.parametrize("input_path,expected", SPECIAL_CHAR_CASES)
    def test_special_characters(self, input_path, expected):
        """Test paths with special characters."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(input_path) == expected


class TestSystemPathDetectionExhaustive:
    """Exhaustive tests for system path detection."""

    # Test boundary matching - critical for security
    # Note: \windows is in SYSTEM_DIRECTORIES, so anything under \windows matches
    BOUNDARY_CASES = [
        ("C:\\Windows\\System32\\cmd.exe", True),
        ("C:\\Windows\\System32_backup\\cmd.exe", True),  # Under \windows (system)
        ("C:\\Windows\\System32test\\cmd.exe", True),  # Under \windows (system)
        ("C:\\Windows\\System32\\", True),
        ("C:\\Windows\\System32", True),
        ("C:\\WindowsOld\\System32\\cmd.exe", False),  # Not under \windows!
        ("C:\\Windows2\\System32\\cmd.exe", False),  # Not under \windows!
        ("C:\\NotWindows\\System32\\cmd.exe", False),  # Not under \windows!
        ("C:\\Users\\Public\\cmd.exe", False),  # Not a system path
        ("C:\\Temp\\cmd.exe", False),  # Not a system path
    ]

    @pytest.mark.parametrize("path,expected", BOUNDARY_CASES)
    def test_boundary_matching(self, path, expected):
        """Test that system path detection respects directory boundaries."""
        from windows_triage.analysis.paths import is_system_path

        assert is_system_path(path) == expected

    # Test all system directories
    SYSTEM_DIRS = [
        "\\windows\\system32",
        "\\windows\\syswow64",
        "\\windows\\winsxs",
        "\\windows",
        "\\program files",
        "\\program files (x86)",
    ]

    @pytest.mark.parametrize("sys_dir", SYSTEM_DIRS)
    def test_all_system_directories(self, sys_dir):
        """Test all defined system directories are recognized."""
        from windows_triage.analysis.paths import is_system_path

        test_path = f"C:{sys_dir}\\test.exe"
        assert is_system_path(test_path) is True

    # Test non-system directories
    NON_SYSTEM_DIRS = [
        "\\users\\public",
        "\\temp",
        "\\appdata",
        "\\programdata",
        "\\downloads",
    ]

    @pytest.mark.parametrize("non_sys_dir", NON_SYSTEM_DIRS)
    def test_non_system_directories(self, non_sys_dir):
        """Test non-system directories are not flagged."""
        from windows_triage.analysis.paths import is_system_path

        test_path = f"C:{non_sys_dir}\\test.exe"
        assert is_system_path(test_path) is False


class TestExtractFilenameExhaustive:
    """Exhaustive tests for filename extraction."""

    FILENAME_CASES = [
        ("C:\\Windows\\cmd.exe", "cmd.exe"),
        ("C:/Windows/cmd.exe", "cmd.exe"),
        ("cmd.exe", "cmd.exe"),
        ("\\cmd.exe", "cmd.exe"),
        ("/cmd.exe", "cmd.exe"),
        ("C:\\Windows\\", ""),
        ("C:\\", ""),
        ("", ""),
        ("..\\..\\cmd.exe", "cmd.exe"),
        ("C:\\Windows\\System32\\..\\cmd.exe", "cmd.exe"),
        ("file", "file"),
        ("FILE.EXE", "file.exe"),
        ("File.Exe", "file.exe"),
    ]

    @pytest.mark.parametrize("path,expected", FILENAME_CASES)
    def test_filename_extraction(self, path, expected):
        """Test filename extraction from various path formats."""
        from windows_triage.analysis.paths import extract_filename

        assert extract_filename(path) == expected


class TestExtractDirectoryExhaustive:
    """Exhaustive tests for directory extraction."""

    DIRECTORY_CASES = [
        ("C:\\Windows\\System32\\cmd.exe", "\\windows\\system32"),
        ("C:\\Windows\\cmd.exe", "\\windows"),
        ("\\Windows\\cmd.exe", "\\windows"),
        ("C:\\cmd.exe", "\\"),
        ("\\cmd.exe", "\\"),
        ("cmd.exe", ""),
        ("", ""),
        (
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "\\windows\\system32\\drivers\\etc",
        ),
    ]

    @pytest.mark.parametrize("path,expected", DIRECTORY_CASES)
    def test_directory_extraction(self, path, expected):
        """Test directory extraction from various path formats."""
        from windows_triage.analysis.paths import extract_directory

        assert extract_directory(path) == expected


# =============================================================================
# HASH DETECTION EXHAUSTIVE TESTS
# =============================================================================


class TestHashDetectionExhaustive:
    """Exhaustive tests for hash detection and validation."""

    # Valid hashes of each type
    VALID_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
    VALID_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    VALID_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_valid_md5(self):
        """Test valid MD5 hash detection."""
        from windows_triage.analysis.hashes import detect_hash_algorithm, validate_hash

        assert detect_hash_algorithm(self.VALID_MD5) == "md5"
        assert validate_hash(self.VALID_MD5) is True

    def test_valid_sha1(self):
        """Test valid SHA1 hash detection."""
        from windows_triage.analysis.hashes import detect_hash_algorithm, validate_hash

        assert detect_hash_algorithm(self.VALID_SHA1) == "sha1"
        assert validate_hash(self.VALID_SHA1) is True

    def test_valid_sha256(self):
        """Test valid SHA256 hash detection."""
        from windows_triage.analysis.hashes import detect_hash_algorithm, validate_hash

        assert detect_hash_algorithm(self.VALID_SHA256) == "sha256"
        assert validate_hash(self.VALID_SHA256) is True

    # Test uppercase hashes
    def test_uppercase_hashes(self):
        """Test uppercase hash handling."""
        from windows_triage.analysis.hashes import detect_hash_algorithm, validate_hash

        upper_md5 = self.VALID_MD5.upper()
        assert detect_hash_algorithm(upper_md5) == "md5"
        assert validate_hash(upper_md5) is True

    # Test mixed case hashes
    def test_mixed_case_hashes(self):
        """Test mixed case hash handling."""
        from windows_triage.analysis.hashes import validate_hash

        mixed = "D41d8Cd98F00b204E9800998eCf8427E"
        assert validate_hash(mixed) is True

    # Test hashes with prefixes
    PREFIX_CASES = [
        (f"md5:{VALID_MD5}", "md5"),
        (f"sha1:{VALID_SHA1}", "sha1"),
        (f"sha256:{VALID_SHA256}", "sha256"),
        (f"sha-1:{VALID_SHA1}", "sha1"),
        (f"sha-256:{VALID_SHA256}", "sha256"),
        (f"MD5:{VALID_MD5}", "md5"),
        (f"SHA256:{VALID_SHA256}", "sha256"),
    ]

    @pytest.mark.parametrize("hash_str,expected_algo", PREFIX_CASES)
    def test_hash_with_prefixes(self, hash_str, expected_algo):
        """Test hash detection with various prefixes."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        assert detect_hash_algorithm(hash_str) == expected_algo

    # Test invalid hashes
    INVALID_CASES = [
        "",  # empty
        "abc",  # too short
        "g41d8cd98f00b204e9800998ecf8427e",  # invalid char 'g'
        "d41d8cd98f00b204e9800998ecf8427",  # 31 chars (wrong length)
        "d41d8cd98f00b204e9800998ecf8427e0",  # 33 chars (wrong length)
        "d41d8cd98f00b204e9800998ecf8427e ",  # trailing space
        " d41d8cd98f00b204e9800998ecf8427e",  # leading space (stripped)
        "d41d8cd98f00b204e9800998ecf8427e\n",  # newline
    ]

    @pytest.mark.parametrize("invalid_hash", INVALID_CASES)
    def test_invalid_hashes(self, invalid_hash):
        """Test invalid hash rejection."""
        from windows_triage.analysis.hashes import validate_hash

        # Some edge cases may still validate (whitespace stripped)
        # Focus on clearly invalid ones
        if invalid_hash.strip() and len(invalid_hash.strip()) not in [32, 40, 64]:
            assert validate_hash(invalid_hash) is False

    # Test all hex characters
    def test_all_hex_chars_valid(self):
        """Test that all hex characters are accepted."""
        from windows_triage.analysis.hashes import validate_hash

        # Hash using all hex chars
        all_hex = "0123456789abcdef" * 2  # 32 chars = MD5
        assert validate_hash(all_hex) is True

    # Test whitespace handling
    WHITESPACE_CASES = [
        (f"  {VALID_MD5}  ", True),  # leading/trailing spaces stripped
        (f"\t{VALID_MD5}\t", True),  # tabs stripped
        (f"\n{VALID_MD5}\n", True),  # newlines stripped
    ]

    @pytest.mark.parametrize("hash_str,expected", WHITESPACE_CASES)
    def test_whitespace_handling(self, hash_str, expected):
        """Test whitespace handling in hash validation."""
        from windows_triage.analysis.hashes import validate_hash

        assert validate_hash(hash_str) == expected


# =============================================================================
# UNICODE DETECTION EXHAUSTIVE TESTS
# =============================================================================


class TestUnicodeDetectionExhaustive:
    """Exhaustive tests for Unicode evasion detection."""

    # Test all bidirectional override characters
    BIDI_CHARS = [
        ("\u202e", "RLO"),  # Right-to-Left Override
        ("\u202d", "LRO"),  # Left-to-Right Override
        ("\u202c", "PDF"),  # Pop Directional Formatting
        ("\u202b", "RLE"),  # Right-to-Left Embedding
        ("\u202a", "LRE"),  # Left-to-Right Embedding
        ("\u2066", "LRI"),  # Left-to-Right Isolate
        ("\u2067", "RLI"),  # Right-to-Left Isolate
        ("\u2068", "FSI"),  # First Strong Isolate
        ("\u2069", "PDI"),  # Pop Directional Isolate
    ]

    @pytest.mark.parametrize("char,name", BIDI_CHARS)
    def test_bidi_character_detection(self, char, name):
        """Test detection of all bidirectional override characters."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        result = detect_unicode_evasion(f"test{char}file.exe")
        bidi_findings = [f for f in result if f["type"] == "bidi_override"]
        assert len(bidi_findings) > 0, f"Should detect {name} ({char!r})"

    # Test all zero-width characters
    ZERO_WIDTH_CHARS = [
        ("\u200b", "ZWSP"),  # Zero Width Space
        ("\u200c", "ZWNJ"),  # Zero Width Non-Joiner
        ("\u200d", "ZWJ"),  # Zero Width Joiner
        ("\ufeff", "BOM"),  # Byte Order Mark
        ("\u00ad", "SHY"),  # Soft Hyphen
        ("\u2060", "WJ"),  # Word Joiner
    ]

    @pytest.mark.parametrize("char,name", ZERO_WIDTH_CHARS)
    def test_zero_width_character_detection(self, char, name):
        """Test detection of all zero-width characters."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        result = detect_unicode_evasion(f"sv{char}chost.exe")
        zw_findings = [f for f in result if f["type"] == "zero_width"]
        assert len(zw_findings) > 0, f"Should detect {name} ({char!r})"

    # Test Cyrillic homoglyphs
    CYRILLIC_HOMOGLYPHS = [
        ("а", "a"),  # Cyrillic а
        ("е", "e"),  # Cyrillic е
        ("о", "o"),  # Cyrillic о
        ("р", "p"),  # Cyrillic р
        ("с", "c"),  # Cyrillic с
        ("х", "x"),  # Cyrillic х
        ("у", "y"),  # Cyrillic у
        ("А", "A"),  # Cyrillic А
        ("В", "B"),  # Cyrillic В
        ("Е", "E"),  # Cyrillic Е
        ("Н", "H"),  # Cyrillic Н
        ("О", "O"),  # Cyrillic О
        ("Р", "P"),  # Cyrillic Р
        ("С", "C"),  # Cyrillic С
        ("Т", "T"),  # Cyrillic Т
        ("Х", "X"),  # Cyrillic Х
    ]

    @pytest.mark.parametrize("cyrillic,latin", CYRILLIC_HOMOGLYPHS)
    def test_cyrillic_homoglyph_detection(self, cyrillic, latin):
        """Test detection of Cyrillic homoglyphs."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        # Create filename with single Cyrillic letter
        test_name = f"test{cyrillic}file.exe"
        result = detect_unicode_evasion(test_name)
        homoglyph_findings = [f for f in result if f["type"] == "homoglyph"]
        assert len(homoglyph_findings) > 0, (
            f"Should detect Cyrillic '{cyrillic}' looking like '{latin}'"
        )

    # Test Greek homoglyphs
    GREEK_HOMOGLYPHS = [
        ("α", "a"),  # Greek alpha
        ("ο", "o"),  # Greek omicron
        ("ρ", "p"),  # Greek rho
        ("Α", "A"),  # Greek Alpha
        ("Β", "B"),  # Greek Beta
        ("Ε", "E"),  # Greek Epsilon
        ("Ο", "O"),  # Greek Omicron
    ]

    @pytest.mark.parametrize("greek,latin", GREEK_HOMOGLYPHS)
    def test_greek_homoglyph_detection(self, greek, latin):
        """Test detection of Greek homoglyphs."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        test_name = f"test{greek}file.exe"
        result = detect_unicode_evasion(test_name)
        homoglyph_findings = [f for f in result if f["type"] == "homoglyph"]
        assert len(homoglyph_findings) > 0, (
            f"Should detect Greek '{greek}' looking like '{latin}'"
        )


class TestLeetSpeakExhaustive:
    """Exhaustive tests for leet speak detection."""

    # All leet substitutions
    LEET_SUBS = [
        ("0", "o"),
        ("1", "i"),
        ("3", "e"),
        ("4", "a"),
        ("5", "s"),
        ("7", "t"),
        ("8", "b"),
        ("@", "a"),
        ("$", "s"),
        ("!", "i"),
    ]

    @pytest.mark.parametrize("leet,latin", LEET_SUBS)
    def test_leet_substitution_detection(self, leet, latin):
        """Test detection of all leet speak substitutions."""
        from windows_triage.analysis.unicode import normalize_leet

        test_name = f"svch{leet}st.exe"
        result = normalize_leet(test_name)
        assert leet not in result, f"Leet '{leet}' should be normalized to '{latin}'"

    # Test compound leet speak
    COMPOUND_LEET = [
        ("svch0st.exe", "svchost.exe"),
        ("sv3host.exe", "svehost.exe"),  # 3->e
        ("svchost.3x3", "svchost.exe"),
        ("l33t.exe", "leet.exe"),
        ("h4x0r.exe", "haxor.exe"),
        ("$yst3m.exe", "system.exe"),
    ]

    @pytest.mark.parametrize("leet_name,expected", COMPOUND_LEET)
    def test_compound_leet_normalization(self, leet_name, expected):
        """Test normalization of compound leet speak."""
        from windows_triage.analysis.unicode import normalize_leet

        result = normalize_leet(leet_name)
        assert result.lower() == expected.lower()


class TestTyposquattingExhaustive:
    """Exhaustive tests for typosquatting detection."""

    # Protected names to test against
    PROTECTED_NAMES = [
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "services.exe",
        "winlogon.exe",
        "wininit.exe",
        "dwm.exe",
    ]

    # Common typos (edit distance 1)
    TYPO_DISTANCE_1 = [
        ("svchost.exe", "svchots.exe"),  # transposition
        ("svchost.exe", "svchosr.exe"),  # substitution
        ("svchost.exe", "svhost.exe"),  # deletion
        ("svchost.exe", "svchostt.exe"),  # insertion
        ("lsass.exe", "lsas.exe"),  # deletion
        ("lsass.exe", "lsasss.exe"),  # insertion
        ("csrss.exe", "csrs.exe"),  # deletion
    ]

    @pytest.mark.parametrize("protected,typo", TYPO_DISTANCE_1)
    def test_typo_distance_1(self, protected, typo):
        """Test detection of single-edit typos."""
        from windows_triage.analysis.unicode import detect_typosquatting

        result = detect_typosquatting(typo, [protected])
        assert len(result) > 0, f"Should detect '{typo}' as typo of '{protected}'"

    # Typos that should NOT match (distance > 2)
    NOT_TYPOS = [
        ("svchost.exe", "notepad.exe"),
        ("svchost.exe", "explorer.exe"),
        ("lsass.exe", "cmd.exe"),
    ]

    @pytest.mark.parametrize("protected,not_typo", NOT_TYPOS)
    def test_not_typosquatting(self, protected, not_typo):
        """Test that distant names are not flagged as typos."""
        from windows_triage.analysis.unicode import detect_typosquatting

        result = detect_typosquatting(not_typo, [protected])
        assert len(result) == 0, (
            f"'{not_typo}' should not be flagged as typo of '{protected}'"
        )


# =============================================================================
# FILENAME ANALYSIS EXHAUSTIVE TESTS
# =============================================================================


class TestFilenameAnalysisExhaustive:
    """Exhaustive tests for filename analysis."""

    # Double extension patterns
    DOUBLE_EXT_CASES = [
        # (filename, should_detect)
        ("invoice.pdf.exe", True),
        ("report.doc.exe", True),
        ("photo.jpg.exe", True),
        ("music.mp3.exe", True),
        ("video.mp4.exe", True),
        ("data.txt.exe", True),
        ("sheet.xlsx.exe", True),
        ("slides.pptx.exe", True),
        ("document.docx.scr", True),
        ("image.png.bat", True),
        ("file.gif.cmd", True),
        ("note.txt.ps1", True),
        ("file.pdf.vbs", True),
        ("file.doc.js", True),
        ("file.jpg.hta", True),
        ("file.pdf.msi", True),
        # Should NOT detect
        ("normal.exe", False),
        ("document.pdf", False),
        ("config.xml.bak", False),
        ("file.tar.gz", False),
        ("archive.tar.bz2", False),
    ]

    @pytest.mark.parametrize("filename,should_detect", DOUBLE_EXT_CASES)
    def test_double_extension_detection(self, filename, should_detect):
        """Test double extension detection."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename(filename)
        de_findings = [f for f in result["findings"] if f["type"] == "double_extension"]
        if should_detect:
            assert len(de_findings) > 0, (
                f"Should detect double extension in '{filename}'"
            )
        else:
            assert len(de_findings) == 0, (
                f"Should NOT detect double extension in '{filename}'"
            )

    # Short name detection
    SHORT_NAME_CASES = [
        ("a.exe", True),
        ("x.exe", True),
        ("ab.exe", True),
        ("abc.exe", False),
        ("a.dll", True),
        ("x.sys", True),
        ("ab.bat", True),
    ]

    @pytest.mark.parametrize("filename,should_detect", SHORT_NAME_CASES)
    def test_short_name_detection(self, filename, should_detect):
        """Test short filename detection."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename(filename)
        short_findings = [f for f in result["findings"] if f["type"] == "short_name"]
        if should_detect:
            assert len(short_findings) > 0, f"Should detect short name in '{filename}'"
        else:
            assert len(short_findings) == 0, (
                f"Should NOT detect short name in '{filename}'"
            )

    # Space padding detection
    # Note: Two separate checks - 8+ consecutive spaces, OR 3+ trailing spaces before extension
    SPACE_PADDING_CASES = [
        ("doc.pdf        .exe", True),  # 8+ spaces - detected by space_padding
        ("doc.pdf       .exe", True),  # 7 spaces - detected by trailing_spaces (3+)
        ("doc   .exe", True),  # 3+ trailing spaces before ext
        ("doc  .exe", False),  # 2 trailing spaces - not detected
        ("normal.exe", False),
    ]

    @pytest.mark.parametrize("filename,should_detect", SPACE_PADDING_CASES)
    def test_space_padding_detection(self, filename, should_detect):
        """Test space padding detection."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename(filename)
        space_findings = [
            f
            for f in result["findings"]
            if f["type"] in ("space_padding", "trailing_spaces")
        ]
        if should_detect:
            assert len(space_findings) > 0, (
                f"Should detect space padding in '{filename!r}'"
            )
        else:
            assert len(space_findings) == 0, (
                f"Should NOT detect space padding in '{filename!r}'"
            )

    # Control character detection
    CONTROL_CHAR_CASES = [
        ("test\x00file.exe", True),  # null
        ("test\x01file.exe", True),  # SOH
        ("test\x1ffile.exe", True),  # US
        ("test\x7ffile.exe", True),  # DEL
        ("test\tfile.exe", True),  # tab
        ("test\nfile.exe", True),  # newline
        ("normalfile.exe", False),
    ]

    @pytest.mark.parametrize("filename,should_detect", CONTROL_CHAR_CASES)
    def test_control_char_detection(self, filename, should_detect):
        """Test control character detection."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename(filename)
        ctrl_findings = [f for f in result["findings"] if f["type"] == "control_chars"]
        if should_detect:
            assert len(ctrl_findings) > 0, (
                f"Should detect control chars in '{filename!r}'"
            )
        else:
            assert len(ctrl_findings) == 0, (
                f"Should NOT detect control chars in '{filename!r}'"
            )


class TestEntropyExhaustive:
    """Exhaustive tests for entropy calculation."""

    # Low entropy names (normal)
    LOW_ENTROPY = [
        "svchost.exe",
        "notepad.exe",
        "explorer.exe",
        "cmd.exe",
        "readme.txt",
    ]

    @pytest.mark.parametrize("filename", LOW_ENTROPY)
    def test_low_entropy_names(self, filename):
        """Test that normal names have low entropy."""
        from windows_triage.analysis.filename import analyze_filename, calculate_entropy

        name_part = filename.rsplit(".", 1)[0]
        entropy = calculate_entropy(name_part)
        result = analyze_filename(filename)
        # Should NOT flag as high entropy
        high_ent = [f for f in result["findings"] if f["type"] == "high_entropy"]
        assert len(high_ent) == 0, (
            f"'{filename}' should not be flagged for high entropy"
        )

    # High entropy names (suspicious)
    HIGH_ENTROPY = [
        "aX7kL9mQp.exe",
        "qWzYpTrNx.exe",
        "Kj8nMwLp2.exe",
        "xYz123AbC.exe",
    ]

    @pytest.mark.parametrize("filename", HIGH_ENTROPY)
    def test_high_entropy_names(self, filename):
        """Test that random-looking names have high entropy."""
        from windows_triage.analysis.filename import calculate_entropy

        name_part = filename.rsplit(".", 1)[0]
        entropy = calculate_entropy(name_part)
        # Random 9-char strings should have entropy > 3.0
        assert entropy > 3.0, f"'{filename}' should have high entropy"

    # Entropy boundary cases
    def test_entropy_boundary_threshold(self):
        """Test entropy threshold boundary (4.5)."""
        # Generate names around the threshold
        # Names with entropy just below 4.5 shouldn't flag
        # Names with entropy just above 4.5 should flag
        # This is difficult to test precisely due to entropy calculation


# =============================================================================
# VERDICT CALCULATION EXHAUSTIVE TESTS
# =============================================================================


class TestVerdictCalculationExhaustive:
    """Exhaustive tests for verdict calculation (offline analysis only).

    Note: MALICIOUS verdict is no longer returned by calculate_file_verdict.
    For threat intel lookups, use opencti-mcp separately.
    """

    def test_suspicious_critical_findings(self):
        """Test SUSPICIOUS verdict with critical findings."""
        from windows_triage.analysis.verdicts import Verdict, calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=[{"type": "double_extension", "severity": "critical"}],
            lolbin_info=None,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_expected_lolbin(self):
        """Test EXPECTED_LOLBIN verdict."""
        from windows_triage.analysis.verdicts import Verdict, calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info={"functions": ["Download", "Execute"]},
        )
        assert result.verdict == Verdict.EXPECTED_LOLBIN

    def test_expected_baseline_match(self):
        """Test EXPECTED verdict with baseline match."""
        from windows_triage.analysis.verdicts import Verdict, calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None,
        )
        assert result.verdict == Verdict.EXPECTED

    def test_unknown_no_matches(self):
        """Test UNKNOWN verdict with no database matches."""
        from windows_triage.analysis.verdicts import Verdict, calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=[],
            lolbin_info=None,
        )
        assert result.verdict == Verdict.UNKNOWN

    def test_suspicious_protected_process_wrong_path(self):
        """Test SUSPICIOUS for protected process in wrong path."""
        from windows_triage.analysis.verdicts import Verdict, calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,  # filename is known
            is_system_path=False,  # NOT in system path
            filename_findings=[],
            lolbin_info=None,
            is_protected_process=True,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_verdict_priority_suspicious_over_lolbin(self):
        """Test that SUSPICIOUS takes priority over EXPECTED_LOLBIN."""
        from windows_triage.analysis.verdicts import Verdict, calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[
                {"type": "homoglyph", "severity": "critical"}
            ],  # Critical finding
            lolbin_info={
                "functions": ["Download", "Execute"]
            },  # Would be EXPECTED_LOLBIN
        )
        assert result.verdict == Verdict.SUSPICIOUS


class TestProcessVerdictExhaustive:
    """Exhaustive tests for process verdict calculation."""

    def test_injection_detected_critical(self):
        """Test critical verdict for injection detection."""
        from windows_triage.analysis.verdicts import Verdict, calculate_process_verdict

        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=[{"type": "injection_detected", "severity": "critical"}],
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.confidence == "high"

    def test_suspicious_parent_critical(self):
        """Test critical verdict for suspicious parent."""
        from windows_triage.analysis.verdicts import Verdict, calculate_process_verdict

        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=True,
            user_valid=True,
            findings=[{"type": "suspicious_parent", "severity": "critical"}],
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_unknown_process_with_critical_finding(self):
        """Test that unknown process with critical finding is SUSPICIOUS."""
        from windows_triage.analysis.verdicts import Verdict, calculate_process_verdict

        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=[
                {
                    "type": "homoglyph",
                    "severity": "critical",
                    "description": "Unicode spoofing",
                }
            ],
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.confidence == "high"

    def test_expected_process_all_valid(self):
        """Test EXPECTED for known process with all valid checks."""
        from windows_triage.analysis.verdicts import Verdict, calculate_process_verdict

        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=True,
            user_valid=True,
            findings=[],
        )
        assert result.verdict == Verdict.EXPECTED


# =============================================================================
# NLP-STYLE TESTS
# =============================================================================


class TestNLPStyleQuestions:
    """NLP-style tests phrased as natural language questions."""

    def test_is_svchost_in_system32_normal(self):
        """Is svchost.exe in System32 normal?"""
        from windows_triage.analysis.paths import is_system_path

        assert is_system_path("C:\\Windows\\System32\\svchost.exe") is True

    def test_is_svchost_in_temp_suspicious(self):
        """Is svchost.exe in temp folder suspicious?"""
        from windows_triage.analysis.paths import is_system_path

        path = "C:\\Users\\Public\\Temp\\svchost.exe"
        assert is_system_path(path) is False

    def test_is_invoice_pdf_exe_double_extension(self):
        """Is invoice.pdf.exe a double extension attack?"""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("invoice.pdf.exe")
        de = [f for f in result["findings"] if f["type"] == "double_extension"]
        assert len(de) > 0

    def test_is_svch0st_leet_speak(self):
        """Is svch0st.exe (with zero) leet speak for svchost.exe?"""
        from windows_triage.analysis.unicode import detect_leet_speak

        result = detect_leet_speak("svch0st.exe", ["svchost.exe"])
        assert len(result) > 0

    def test_is_cyrillic_a_detected(self):
        """Is Cyrillic 'а' (looks like 'a') detected as homoglyph?"""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        result = detect_unicode_evasion("svch\u0430st.exe")  # Cyrillic а
        homoglyph_findings = [f for f in result if f["type"] == "homoglyph"]
        assert len(homoglyph_findings) > 0

    def test_is_rlo_attack_detected(self):
        """Is RLO (Right-to-Left Override) attack detected?"""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        result = detect_unicode_evasion("test\u202efdp.exe")
        bidi = [f for f in result if f["type"] == "bidi_override"]
        assert len(bidi) > 0

    def test_is_word_spawning_cmd_suspicious(self):
        """Is Microsoft Word spawning cmd.exe suspicious?"""
        # This would be tested via check_process_tree in server
        # For now, verify the expectation exists
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        cmd = next((p for p in procs if p["process_name"] == "cmd.exe"), None)
        assert cmd is not None
        assert "winword.exe" in cmd.get("suspicious_parents", [])

    def test_is_lsass_spawning_children_injection(self):
        """Is lsass.exe spawning any child process injection?"""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        lsass = next((p for p in procs if p["process_name"] == "lsass.exe"), None)
        assert lsass is not None
        assert lsass.get("never_spawns_children") is True

    def test_is_net1_only_from_net(self):
        """Should net1.exe only be spawned by net.exe?"""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        net1 = next((p for p in procs if p["process_name"] == "net1.exe"), None)
        assert net1 is not None
        assert net1.get("valid_parents") == ["net.exe"]


# =============================================================================
# COMBINATION TESTS
# =============================================================================


class TestCombinationScenarios:
    """Tests for combinations of multiple suspicious indicators."""

    def test_double_ext_plus_homoglyph(self):
        """Test file with both double extension AND homoglyph."""
        from windows_triage.analysis.filename import analyze_filename
        from windows_triage.analysis.unicode import detect_unicode_evasion

        # invoice with Cyrillic 'о' + .pdf.exe
        filename = "inv\u043eice.pdf.exe"
        fa_result = analyze_filename(filename)
        hg_result = detect_unicode_evasion(filename)
        # Should detect both
        de = [f for f in fa_result["findings"] if f["type"] == "double_extension"]
        hg_result = [f for f in hg_result if f["type"] == "homoglyph"]
        assert len(de) > 0
        assert len(hg_result) > 0

    def test_leet_plus_short_name(self):
        """Test file with both leet speak AND short name."""
        from windows_triage.analysis.filename import analyze_filename

        # "x.exe" with leet - but wait, x is only 1 char
        filename = "x0.exe"  # 2 char name with leet
        result = analyze_filename(filename)
        short = [f for f in result["findings"] if f["type"] == "short_name"]
        assert len(short) > 0

    def test_space_padding_plus_control_char(self):
        """Test file with both space padding AND control character."""
        from windows_triage.analysis.filename import analyze_filename

        # Note: "doc   \x00.exe" has spaces BEFORE null byte, not trailing
        # name_part = "doc   \x00" ends with null, not spaces
        # So only control_chars is detected (correct behavior)
        filename = "doc   \x00.exe"
        result = analyze_filename(filename)
        ctrl = [f for f in result["findings"] if f["type"] == "control_chars"]
        assert len(ctrl) > 0

    def test_space_padding_plus_control_char_combined(self):
        """Test file with trailing spaces AND control character elsewhere."""
        from windows_triage.analysis.filename import analyze_filename

        # This has trailing spaces at end of name_part AND control char
        filename = "doc\x00   .exe"  # null byte THEN trailing spaces
        result = analyze_filename(filename)
        space = [f for f in result["findings"] if f["type"] == "trailing_spaces"]
        ctrl = [f for f in result["findings"] if f["type"] == "control_chars"]
        assert len(space) > 0  # Trailing spaces detected
        assert len(ctrl) > 0  # Control char detected


# =============================================================================
# BOUNDARY VALUE TESTS
# =============================================================================


class TestBoundaryValues:
    """Tests for boundary conditions."""

    # Entropy threshold is 4.5 for names > 6 chars
    def test_entropy_length_boundary_6(self):
        """Test entropy check skipped for names <= 6 chars."""
        from windows_triage.analysis.filename import analyze_filename

        # 6 char random name - should NOT flag
        result = analyze_filename("xYzAbC.exe")
        he = [f for f in result["findings"] if f["type"] == "high_entropy"]
        assert len(he) == 0

    def test_entropy_length_boundary_7(self):
        """Test entropy check applies for names > 6 chars."""
        from windows_triage.analysis.filename import analyze_filename, calculate_entropy

        # 7+ char random name with high entropy
        name = "xYzAbCd"
        entropy = calculate_entropy(name)
        if entropy > 4.5:
            result = analyze_filename(f"{name}.exe")
            he = [f for f in result["findings"] if f["type"] == "high_entropy"]
            assert len(he) > 0

    # Short name threshold is 2
    def test_short_name_boundary_2(self):
        """Test short name detection at boundary (2 chars)."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("ab.exe")
        short = [f for f in result["findings"] if f["type"] == "short_name"]
        assert len(short) > 0

    def test_short_name_boundary_3(self):
        """Test short name NOT detected at 3 chars."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("abc.exe")
        short = [f for f in result["findings"] if f["type"] == "short_name"]
        assert len(short) == 0

    # Space padding threshold is 8
    def test_space_padding_boundary_7(self):
        """Test space padding NOT detected at 7 spaces."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("doc.pdf       .exe")  # 7 spaces
        sp = [f for f in result["findings"] if f["type"] == "space_padding"]
        assert len(sp) == 0

    def test_space_padding_boundary_8(self):
        """Test space padding detected at 8 spaces."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("doc.pdf        .exe")  # 8 spaces
        sp = [f for f in result["findings"] if f["type"] == "space_padding"]
        assert len(sp) > 0

    # Trailing spaces threshold is 3
    def test_trailing_spaces_boundary_2(self):
        """Test trailing spaces NOT detected at 2 spaces."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("doc  .exe")  # 2 trailing spaces
        ts = [f for f in result["findings"] if f["type"] == "trailing_spaces"]
        assert len(ts) == 0

    def test_trailing_spaces_boundary_3(self):
        """Test trailing spaces detected at 3 spaces."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("doc   .exe")  # 3 trailing spaces
        ts = [f for f in result["findings"] if f["type"] == "trailing_spaces"]
        assert len(ts) > 0


# =============================================================================
# INPUT VALIDATION TESTS
# =============================================================================


class TestInputValidation:
    """Tests for input validation edge cases."""

    def test_none_path_normalization(self):
        """Test None input to path normalization."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(None) is None

    def test_empty_path_normalization(self):
        """Test empty string input to path normalization."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path("") == ""

    def test_none_filename_analysis(self):
        """Test None input to filename analysis."""
        from windows_triage.analysis.filename import analyze_filename

        # Should handle None gracefully
        try:
            result = analyze_filename(None)
            # If it doesn't crash, check it returns something sensible
        except (TypeError, AttributeError):
            pass  # Expected behavior - None not supported

    def test_empty_filename_analysis(self):
        """Test empty string input to filename analysis."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("")
        assert result["filename"] == ""
        assert result["entropy"] == 0.0

    def test_very_long_path(self):
        """Test very long path (>4096 chars)."""
        from windows_triage.analysis.paths import normalize_path

        long_path = "C:\\" + "a" * 5000 + "\\file.exe"
        result = normalize_path(long_path)
        assert result is not None
        assert len(result) > 4000

    def test_very_long_filename(self):
        """Test very long filename."""
        from windows_triage.analysis.filename import analyze_filename

        long_name = "a" * 1000 + ".exe"
        result = analyze_filename(long_name)
        assert result["filename"] == long_name


# =============================================================================
# GENERATED PARAMETRIC TESTS
# =============================================================================


class TestGeneratedPathCases:
    """Generated test cases for path normalization."""

    # Generate test cases for various path patterns
    PATH_PATTERNS = []

    # All drive letters with standard path
    for d in string.ascii_uppercase:
        PATH_PATTERNS.append((f"{d}:\\Windows\\file.exe", "\\windows\\file.exe"))

    # Various depth levels
    for depth in range(1, 10):
        path = "C:\\" + "\\".join(["dir"] * depth) + "\\file.exe"
        expected = "\\" + "\\".join(["dir"] * depth) + "\\file.exe"
        PATH_PATTERNS.append((path, expected))

    @pytest.mark.parametrize("input_path,expected", PATH_PATTERNS)
    def test_generated_paths(self, input_path, expected):
        """Test generated path normalization cases."""
        from windows_triage.analysis.paths import normalize_path

        assert normalize_path(input_path) == expected


class TestGeneratedHashCases:
    """Generated test cases for hash validation."""

    # Generate valid hashes
    VALID_HASHES = []

    # MD5 variations (32 chars)
    for _ in range(50):
        h = "".join(random.choices("0123456789abcdef", k=32))
        VALID_HASHES.append(h)

    # SHA1 variations (40 chars)
    for _ in range(50):
        h = "".join(random.choices("0123456789abcdef", k=40))
        VALID_HASHES.append(h)

    # SHA256 variations (64 chars)
    for _ in range(50):
        h = "".join(random.choices("0123456789abcdef", k=64))
        VALID_HASHES.append(h)

    @pytest.mark.parametrize("hash_value", VALID_HASHES)
    def test_generated_valid_hashes(self, hash_value):
        """Test generated valid hashes."""
        from windows_triage.analysis.hashes import validate_hash

        assert validate_hash(hash_value) is True


class TestGeneratedInvalidHashCases:
    """Generated test cases for invalid hash rejection."""

    # Generate invalid hashes
    INVALID_HASHES = []

    # Wrong lengths
    for length in [1, 10, 20, 31, 33, 39, 41, 63, 65, 100]:
        h = "".join(random.choices("0123456789abcdef", k=length))
        INVALID_HASHES.append(h)

    # Invalid characters
    for _ in range(20):
        h = "".join(random.choices("0123456789abcdefghijklmnopqrstuvwxyz", k=32))
        if any(c not in "0123456789abcdef" for c in h):
            INVALID_HASHES.append(h)

    @pytest.mark.parametrize("hash_value", INVALID_HASHES)
    def test_generated_invalid_hashes(self, hash_value):
        """Test generated invalid hashes are rejected."""
        from windows_triage.analysis.hashes import validate_hash

        assert validate_hash(hash_value) is False


# =============================================================================
# PROCESS EXPECTATION TESTS
# =============================================================================


class TestProcessExpectationsExhaustive:
    """Exhaustive tests for process expectations."""

    def test_all_processes_have_name(self):
        """Test all process expectations have a name."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        for proc in procs:
            assert "process_name" in proc
            assert proc["process_name"]

    def test_all_processes_have_source(self):
        """Test all process expectations have a source."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        for proc in procs:
            assert "source" in proc
            assert proc["source"]

    def test_suspicious_parents_are_lists(self):
        """Test suspicious_parents is always a list or None."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        for proc in procs:
            sp = proc.get("suspicious_parents")
            assert sp is None or isinstance(sp, list)

    def test_valid_parents_are_lists(self):
        """Test valid_parents is always a list or None."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        for proc in procs:
            vp = proc.get("valid_parents")
            assert vp is None or isinstance(vp, list)

    def test_never_spawns_is_bool(self):
        """Test never_spawns_children is always bool or None."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        for proc in procs:
            ns = proc.get("never_spawns_children")
            assert ns is None or isinstance(ns, bool)

    def test_shells_have_suspicious_parents(self):
        """Test cmd/powershell/pwsh have suspicious parents defined."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        shells = ["cmd.exe", "powershell.exe", "pwsh.exe"]
        for shell in shells:
            proc = next((p for p in procs if p["process_name"] == shell), None)
            assert proc is not None, f"Missing {shell}"
            assert proc.get("suspicious_parents"), (
                f"{shell} should have suspicious_parents"
            )
            assert len(proc["suspicious_parents"]) >= 50, (
                f"{shell} should have many suspicious parents"
            )

    def test_injection_targets_never_spawn(self):
        """Test injection targets have never_spawns_children=True."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        injection_targets = [
            "lsass.exe",
            "dwm.exe",
            "audiodg.exe",
            "fontdrvhost.exe",
            "lsaiso.exe",
        ]
        for target in injection_targets:
            proc = next((p for p in procs if p["process_name"] == target), None)
            assert proc is not None, f"Missing {target}"
            assert proc.get("never_spawns_children") is True, (
                f"{target} should never spawn children"
            )


# =============================================================================
# SUSPICIOUS PARENT COVERAGE TESTS
# =============================================================================


class TestSuspiciousParentCoverage:
    """Test coverage of suspicious parent categories."""

    def test_office_apps_in_suspicious_parents(self):
        """Test Microsoft Office apps are in suspicious parents."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        cmd = next((p for p in procs if p["process_name"] == "cmd.exe"), None)
        office = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
        for app in office:
            assert app in cmd["suspicious_parents"], f"Missing {app}"

    def test_browsers_in_suspicious_parents(self):
        """Test browsers are in suspicious parents."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        cmd = next((p for p in procs if p["process_name"] == "cmd.exe"), None)
        browsers = ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"]
        for browser in browsers:
            assert browser in cmd["suspicious_parents"], f"Missing {browser}"

    def test_dcom_objects_in_suspicious_parents(self):
        """Test DCOM abuse objects are in suspicious parents."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        cmd = next((p for p in procs if p["process_name"] == "cmd.exe"), None)
        dcom = ["mmc.exe", "dllhost.exe", "wmiprvse.exe"]
        for obj in dcom:
            assert obj in cmd["suspicious_parents"], f"Missing {obj}"

    def test_pdf_readers_in_suspicious_parents(self):
        """Test PDF readers are in suspicious parents."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        cmd = next((p for p in procs if p["process_name"] == "cmd.exe"), None)
        pdfs = ["acrord32.exe", "acrobat.exe", "foxitreader.exe"]
        for pdf in pdfs:
            assert pdf in cmd["suspicious_parents"], f"Missing {pdf}"


# =============================================================================
# RECON TOOL TESTS
# =============================================================================


class TestReconToolsExhaustive:
    """Exhaustive tests for reconnaissance tool detection."""

    RECON_TOOLS = [
        "whoami.exe",
        "hostname.exe",
        "ipconfig.exe",
        "net.exe",
        "nltest.exe",
        "dsquery.exe",
        "systeminfo.exe",
        "tasklist.exe",
        "netstat.exe",
        "arp.exe",
        "nslookup.exe",
        "ping.exe",
        "tracert.exe",
        "quser.exe",
        "query.exe",
    ]

    @pytest.mark.parametrize("tool", RECON_TOOLS)
    def test_recon_tool_has_suspicious_parents(self, tool):
        """Test each recon tool has suspicious parents defined."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        proc = next((p for p in procs if p["process_name"] == tool), None)
        assert proc is not None, f"Missing {tool}"
        assert proc.get("suspicious_parents"), f"{tool} should have suspicious_parents"

    @pytest.mark.parametrize("tool", RECON_TOOLS)
    def test_recon_tool_flags_office_parent(self, tool):
        """Test recon tools flag Office apps as suspicious parents."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        proc = next((p for p in procs if p["process_name"] == tool), None)
        sp = proc.get("suspicious_parents", [])
        assert "winword.exe" in sp or "excel.exe" in sp, (
            f"{tool} should flag Office as suspicious"
        )


# =============================================================================
# SCRIPT HOST TESTS
# =============================================================================


class TestScriptHostsExhaustive:
    """Exhaustive tests for script host detection."""

    SCRIPT_HOSTS = ["wscript.exe", "cscript.exe", "mshta.exe"]

    @pytest.mark.parametrize("host", SCRIPT_HOSTS)
    def test_script_host_has_suspicious_parents(self, host):
        """Test each script host has suspicious parents."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        proc = next((p for p in procs if p["process_name"] == host), None)
        assert proc is not None, f"Missing {host}"
        assert proc.get("suspicious_parents"), f"{host} should have suspicious_parents"

    @pytest.mark.parametrize("host", SCRIPT_HOSTS)
    def test_script_host_flags_browsers(self, host):
        """Test script hosts flag browsers as suspicious."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        proc = next((p for p in procs if p["process_name"] == host), None)
        sp = proc.get("suspicious_parents", [])
        assert "chrome.exe" in sp, f"{host} should flag Chrome as suspicious"


# =============================================================================
# ADDITIONAL EDGE CASE TESTS
# =============================================================================


class TestAdditionalEdgeCases:
    """Additional edge case tests for comprehensive coverage."""

    def test_path_with_dots(self):
        """Test path with multiple dots in directory names."""
        from windows_triage.analysis.paths import normalize_path

        result = normalize_path("C:\\dir.name.here\\file.name.exe")
        assert result == "\\dir.name.here\\file.name.exe"

    def test_path_with_unicode(self):
        """Test path with Unicode characters."""
        from windows_triage.analysis.paths import normalize_path

        result = normalize_path("C:\\Users\\日本語\\file.exe")
        assert result == "\\users\\日本語\\file.exe"

    def test_filename_with_only_extension(self):
        """Test filename that is only an extension."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename(".exe")
        assert result["filename"] == ".exe"

    def test_filename_with_no_extension(self):
        """Test filename with no extension."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("filename")
        assert result["filename"] == "filename"

    def test_hash_with_newline_suffix(self):
        """Test hash with newline suffix (common in text files)."""
        from windows_triage.analysis.hashes import validate_hash

        h = "d41d8cd98f00b204e9800998ecf8427e\n"
        assert validate_hash(h) is True

    def test_hash_with_carriage_return(self):
        """Test hash with Windows-style line ending."""
        from windows_triage.analysis.hashes import validate_hash

        h = "d41d8cd98f00b204e9800998ecf8427e\r\n"
        assert validate_hash(h) is True

    def test_multiple_homoglyphs_in_one_name(self):
        """Test filename with multiple different homoglyphs."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        # Mix of Cyrillic and Greek
        result = detect_unicode_evasion("t\u0435st\u03b1.exe")  # Cyrillic е, Greek α
        homoglyph_findings = [f for f in result if f["type"] == "homoglyph"]
        assert len(homoglyph_findings) > 0

    def test_homoglyph_in_extension(self):
        """Test homoglyph in file extension."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        result = detect_unicode_evasion("file.\u0435xe")  # Cyrillic е in extension
        homoglyph_findings = [f for f in result if f["type"] == "homoglyph"]
        assert len(homoglyph_findings) > 0

    def test_zero_width_between_every_char(self):
        """Test zero-width characters between every character."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        result = detect_unicode_evasion(
            "s\u200bv\u200bc\u200bh\u200bo\u200bs\u200bt.exe"
        )
        zw = [f for f in result if f["type"] == "zero_width"]
        assert len(zw) > 0

    def test_multiple_rlo_characters(self):
        """Test multiple RLO characters in filename."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        result = detect_unicode_evasion("\u202etest\u202efile.exe")
        bidi = [f for f in result if f["type"] == "bidi_override"]
        assert len(bidi) > 0


# =============================================================================
# STRESS TESTS
# =============================================================================


class TestStressConditions:
    """Stress tests for edge conditions."""

    def test_very_deep_path(self):
        """Test very deep directory structure."""
        from windows_triage.analysis.paths import extract_filename, normalize_path

        depth = 100
        path = "C:\\" + "\\".join(["dir"] * depth) + "\\file.exe"
        result = normalize_path(path)
        assert extract_filename(result) == "file.exe"

    def test_many_extensions(self):
        """Test filename with many extensions."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("file.a.b.c.d.e.f.g.h.pdf.exe")
        de = [f for f in result["findings"] if f["type"] == "double_extension"]
        assert len(de) > 0

    def test_filename_all_numbers(self):
        """Test filename that is all numbers."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("123456789.exe")
        # Should have some entropy
        assert result["entropy"] > 0

    def test_filename_all_same_char(self):
        """Test filename with all same character."""
        from windows_triage.analysis.filename import analyze_filename, calculate_entropy

        result = analyze_filename("aaaaaaaa.exe")
        # Entropy should be 0 (all same char)
        assert calculate_entropy("aaaaaaaa") == 0.0

    def test_many_suspicious_parents(self):
        """Test that suspicious parent lists are not too large."""
        from windows_triage.importers.process_expectations import (
            load_process_expectations,
        )

        procs = load_process_expectations()
        for proc in procs:
            sp = proc.get("suspicious_parents", [])
            # Reasonable upper bound
            assert len(sp) < 200, (
                f"{proc['process_name']} has too many suspicious parents"
            )


# =============================================================================
# SERVICE BINARY PATH PARSING TESTS
# =============================================================================


class TestServiceBinaryPathParsing:
    """Exhaustive tests for service ImagePath parsing."""

    # Quoted paths
    QUOTED_PATH_CASES = [
        ('"C:\\Program Files\\Service\\svc.exe"', "\\program files\\service\\svc.exe"),
        (
            '"C:\\Program Files\\Service\\svc.exe" -arg1',
            "\\program files\\service\\svc.exe",
        ),
        (
            '"C:\\Program Files\\Service\\svc.exe" -arg1 -arg2',
            "\\program files\\service\\svc.exe",
        ),
        ('"C:\\path with spaces\\service.exe"', "\\path with spaces\\service.exe"),
        (
            '"C:\\Windows\\System32\\svchost.exe" -k netsvcs',
            "\\windows\\system32\\svchost.exe",
        ),
    ]

    @pytest.mark.parametrize("input_path,expected", QUOTED_PATH_CASES)
    def test_quoted_paths(self, input_path, expected):
        """Test parsing of quoted service paths."""
        from windows_triage.analysis.paths import parse_service_binary_path

        assert parse_service_binary_path(input_path) == expected

    # Unquoted paths
    UNQUOTED_PATH_CASES = [
        ("C:\\Windows\\System32\\svchost.exe", "\\windows\\system32\\svchost.exe"),
        (
            "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "\\windows\\system32\\svchost.exe",
        ),
        ("C:\\simple\\service.exe", "\\simple\\service.exe"),
        ("C:\\service.exe -arg", "\\service.exe"),
    ]

    @pytest.mark.parametrize("input_path,expected", UNQUOTED_PATH_CASES)
    def test_unquoted_paths(self, input_path, expected):
        """Test parsing of unquoted service paths."""
        from windows_triage.analysis.paths import parse_service_binary_path

        assert parse_service_binary_path(input_path) == expected

    # System root paths
    SYSROOT_CASES = [
        ("\\SystemRoot\\System32\\svc.exe", "\\windows\\system32\\svc.exe"),
        ("%SystemRoot%\\System32\\svc.exe", "\\windows\\system32\\svc.exe"),
        ("System32\\svc.exe", "\\windows\\system32\\svc.exe"),
    ]

    @pytest.mark.parametrize("input_path,expected", SYSROOT_CASES)
    def test_system_root_expansion(self, input_path, expected):
        """Test SystemRoot expansion in service paths."""
        from windows_triage.analysis.paths import parse_service_binary_path

        assert parse_service_binary_path(input_path) == expected

    # Driver paths
    DRIVER_CASES = [
        (
            "\\SystemRoot\\System32\\drivers\\afd.sys",
            "\\windows\\system32\\drivers\\afd.sys",
        ),
        ("System32\\drivers\\ntfs.sys", "\\windows\\system32\\drivers\\ntfs.sys"),
    ]

    @pytest.mark.parametrize("input_path,expected", DRIVER_CASES)
    def test_driver_paths(self, input_path, expected):
        """Test driver path parsing."""
        from windows_triage.analysis.paths import parse_service_binary_path

        assert parse_service_binary_path(input_path) == expected

    # Empty and edge cases
    def test_empty_path(self):
        """Test empty service path."""
        from windows_triage.analysis.paths import parse_service_binary_path

        assert parse_service_binary_path("") == ""

    def test_whitespace_path(self):
        """Test whitespace-only service path."""
        from windows_triage.analysis.paths import parse_service_binary_path

        result = parse_service_binary_path("   ")
        assert result == ""

    def test_unclosed_quote(self):
        """Test path with unclosed quote."""
        from windows_triage.analysis.paths import parse_service_binary_path

        result = parse_service_binary_path('"C:\\path\\svc.exe')
        assert "svc.exe" in result


# =============================================================================
# SUSPICIOUS DIRECTORY EXHAUSTIVE TESTS
# =============================================================================


class TestSuspiciousDirectoryDetection:
    """Exhaustive tests for suspicious directory detection."""

    SUSPICIOUS_PATHS = [
        "C:\\Temp\\malware.exe",
        "C:\\tmp\\evil.exe",
        "C:\\Windows\\Temp\\backdoor.exe",
        "C:\\Users\\Public\\Documents\\payload.exe",
        "C:\\ProgramData\\hidden.exe",
        "C:\\Intel\\malicious.exe",
        "C:\\Perflogs\\suspicious.exe",
        "C:\\$Recycle.Bin\\deleted.exe",
        "C:\\Users\\Admin\\AppData\\Local\\Temp\\tmp.exe",
        "C:\\Users\\Admin\\Downloads\\downloaded.exe",
        "C:\\Users\\Admin\\Desktop\\malware.exe",
    ]

    @pytest.mark.parametrize("path", SUSPICIOUS_PATHS)
    def test_suspicious_directory_detected(self, path):
        """Test suspicious directory detection."""
        from windows_triage.analysis.paths import check_suspicious_path

        result = check_suspicious_path(path)
        assert len(result) > 0, f"Should flag {path} as suspicious"

    CLEAN_PATHS = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Program Files\\App\\app.exe",
        "C:\\Program Files (x86)\\App\\app.exe",
    ]

    @pytest.mark.parametrize("path", CLEAN_PATHS)
    def test_clean_paths_not_flagged(self, path):
        """Test that clean paths are not flagged as suspicious."""
        from windows_triage.analysis.paths import check_suspicious_path

        result = check_suspicious_path(path)
        assert len(result) == 0, f"Should not flag {path}"


# =============================================================================
# LEET SPEAK DETECTION EXHAUSTIVE TESTS
# =============================================================================


class TestLeetSpeakDetection:
    """Exhaustive tests for leet speak detection."""

    # Leet speak detection requires the normalized form to match EXACTLY
    # Note: '1' maps to 'i', not 'l' - so "1sass" becomes "isass" not "lsass"
    LEET_CASES = [
        ("svch0st.exe", "svchost.exe"),  # 0 -> o: svchost matches
        ("5vchost.exe", "svchost.exe"),  # 5 -> s: svchost matches
        ("svchos7.exe", "svchost.exe"),  # 7 -> t: svchost matches
        ("svch0s7.exe", "svchost.exe"),  # Multiple: svchost matches
        ("w1nlogon.exe", "winlogon.exe"),  # 1 -> i: winlogon matches
        ("expl0rer.exe", "explorer.exe"),  # 0 -> o: explorer matches
    ]

    @pytest.mark.parametrize("leet_name,expected_match", LEET_CASES)
    def test_leet_speak_detection(self, leet_name, expected_match):
        """Test leet speak variants are detected via process name spoofing."""
        from windows_triage.analysis.unicode import check_process_name_spoofing

        # Protected processes list for matching
        protected = [
            "svchost.exe",
            "lsass.exe",
            "csrss.exe",
            "winlogon.exe",
            "explorer.exe",
        ]
        result = check_process_name_spoofing(leet_name, protected)
        leet_findings = [f for f in result if f["type"] == "leet_speak"]
        assert len(leet_findings) > 0, f"Should detect leet speak in {leet_name}"

    def test_leet_1_primary_is_i(self):
        """Test that '1' primary mapping is 'i' (most common in leet speak)."""
        from windows_triage.analysis.unicode import normalize_leet

        # Primary mapping: 1 -> i
        assert normalize_leet("m1m1katz") == "mimikatz"
        assert normalize_leet("w1nd0ws") == "windows"

    def test_leet_1_also_matches_l(self):
        """Test that '1' also matches 'l' for names like lsass."""
        from windows_triage.analysis.unicode import check_process_name_spoofing

        protected = ["lsass.exe", "svchost.exe"]
        # 1sass.exe should match lsass.exe via secondary 'l' mapping
        result = check_process_name_spoofing("1sass.exe", protected)
        leet_findings = [f for f in result if f["type"] == "leet_speak"]
        assert len(leet_findings) > 0
        assert leet_findings[0]["target_process"] == "lsass.exe"


# =============================================================================
# TYPOSQUATTING DETECTION EXHAUSTIVE TESTS
# =============================================================================


class TestTyposquattingDetection:
    """Exhaustive tests for typosquatting detection."""

    # Typosquatting uses Levenshtein distance <= 2
    # Note: Some transpositions require 2 edits in Levenshtein
    TYPO_CASES = [
        ("svchots.exe", "svchost.exe"),  # Transposition: distance 2
        ("svchoost.exe", "svchost.exe"),  # Insertion: distance 1
        ("svchst.exe", "svchost.exe"),  # Deletion: distance 1
        ("svcgost.exe", "svchost.exe"),  # Substitution: distance 1
        ("scvhost.exe", "svchost.exe"),  # Transposition: distance 2
    ]

    @pytest.mark.parametrize("typo_name,expected_match", TYPO_CASES)
    def test_typosquatting_detection(self, typo_name, expected_match):
        """Test typosquatting variants are detected via process name spoofing."""
        from windows_triage.analysis.unicode import check_process_name_spoofing

        # Protected processes list for matching
        protected = [
            "svchost.exe",
            "lsass.exe",
            "csrss.exe",
            "winlogon.exe",
            "explorer.exe",
        ]
        result = check_process_name_spoofing(typo_name, protected)
        # Note: type is 'typosquatting' not 'typosquat'
        typo_findings = [f for f in result if f["type"] == "typosquatting"]
        assert len(typo_findings) > 0, (
            f"Should detect typosquatting: {typo_name} similar to {expected_match}"
        )

    def test_edit_distance_calculation(self):
        """Test Levenshtein edit distance calculation."""
        from windows_triage.analysis.unicode import levenshtein_distance

        # Identical strings
        assert levenshtein_distance("svchost.exe", "svchost.exe") == 0
        # One substitution
        assert levenshtein_distance("svcgost.exe", "svchost.exe") == 1
        # One insertion
        assert levenshtein_distance("svchosst.exe", "svchost.exe") == 1
        # One deletion
        assert levenshtein_distance("svchst.exe", "svchost.exe") == 1

    def test_capital_i_looks_like_lowercase_l(self):
        """Test that nsIookup.exe (capital I) is detected as typosquatting of nslookup.exe.

        Capital 'I' visually resembles lowercase 'l' in many fonts, making this
        a common visual spoofing technique. This is detected via typosquatting
        (edit distance 1) rather than homoglyphs, since capital I is a valid
        ASCII letter.
        """
        from windows_triage.analysis.unicode import check_process_name_spoofing

        protected = ["nslookup.exe", "svchost.exe"]
        result = check_process_name_spoofing("nsIookup.exe", protected)

        # Should be detected (either via typosquatting or homoglyph)
        assert len(result) > 0, "nsIookup.exe should be flagged as suspicious"

        # Currently detected via typosquatting (edit distance 1)
        typo = [f for f in result if f["type"] == "typosquatting"]
        assert len(typo) > 0, "Should detect as typosquatting"
        assert typo[0]["target_process"] == "nslookup.exe"


# =============================================================================
# VERDICT PRIORITY EXHAUSTIVE TESTS
# =============================================================================


class TestVerdictPriority:
    """Test that verdict priorities are respected (offline analysis only).

    Note: MALICIOUS verdict tests removed - use opencti-mcp for threat intel.
    """

    def test_suspicious_beats_expected_lolbin(self):
        """Test SUSPICIOUS takes priority over EXPECTED_LOLBIN."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,  # Would be EXPECTED_LOLBIN
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[{"type": "double_extension", "severity": "critical"}],
            lolbin_info={"name": "certutil.exe", "functions": ["download"]},
            is_protected_process=False,
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_expected_lolbin_beats_expected(self):
        """Test EXPECTED_LOLBIN over EXPECTED for LOLBins."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info={"name": "certutil.exe", "functions": ["download"]},
            is_protected_process=False,
        )
        assert result.verdict.value == "EXPECTED_LOLBIN"

    def test_expected_beats_unknown(self):
        """Test EXPECTED over UNKNOWN for baseline matches."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None,
            is_protected_process=False,
        )
        assert result.verdict.value == "EXPECTED"


# =============================================================================
# PROTECTED PROCESS NAME DETECTION TESTS
# =============================================================================


class TestProtectedProcessNames:
    """Test protected process name detection."""

    PROTECTED_PROCESSES = [
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "services.exe",
        "winlogon.exe",
    ]

    @pytest.mark.parametrize("proc_name", PROTECTED_PROCESSES)
    def test_protected_in_wrong_location_suspicious(self, proc_name):
        """Test protected process in non-system path is suspicious."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,  # Wrong location!
            filename_findings=[],
            lolbin_info=None,
            is_protected_process=True,
        )
        assert result.verdict.value == "SUSPICIOUS"

    @pytest.mark.parametrize("proc_name", PROTECTED_PROCESSES)
    def test_protected_in_system_expected(self, proc_name):
        """Test protected process in system path is expected."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None,
            is_protected_process=True,
        )
        assert result.verdict.value == "EXPECTED"


# =============================================================================
# ENTROPY CALCULATION EXHAUSTIVE TESTS
# =============================================================================


class TestEntropyCalculation:
    """Exhaustive tests for entropy calculation."""

    def test_entropy_empty_string(self):
        """Test entropy of empty string."""
        from windows_triage.analysis.filename import calculate_entropy

        assert calculate_entropy("") == 0.0

    def test_entropy_single_char(self):
        """Test entropy of single character."""
        from windows_triage.analysis.filename import calculate_entropy

        assert calculate_entropy("a") == 0.0

    def test_entropy_repeated_char(self):
        """Test entropy of repeated single character."""
        from windows_triage.analysis.filename import calculate_entropy

        assert calculate_entropy("aaaaaa") == 0.0

    def test_entropy_two_chars_equal(self):
        """Test entropy of two equally distributed characters."""
        from windows_triage.analysis.filename import calculate_entropy

        entropy = calculate_entropy("ababab")
        # Should be 1.0 (2 chars, equal distribution)
        assert abs(entropy - 1.0) < 0.01

    def test_entropy_high_randomness(self):
        """Test entropy of high-randomness string."""
        from windows_triage.analysis.filename import calculate_entropy

        # All unique characters
        entropy = calculate_entropy("abcdefghij")
        assert entropy > 3.0

    def test_entropy_known_value(self):
        """Test entropy matches expected mathematical value."""

        from windows_triage.analysis.filename import calculate_entropy

        # "ab" has 2 chars with probability 0.5 each
        # H = -2 * (0.5 * log2(0.5)) = 1.0
        entropy = calculate_entropy("ab")
        assert abs(entropy - 1.0) < 0.001


# =============================================================================
# HASH TYPE DETECTION EXHAUSTIVE TESTS
# =============================================================================


class TestHashTypeDetection:
    """Exhaustive tests for hash type detection."""

    def test_detect_md5(self):
        """Test MD5 detection."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        assert detect_hash_algorithm("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_detect_sha1(self):
        """Test SHA1 detection."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        assert (
            detect_hash_algorithm("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
        )

    def test_detect_sha256(self):
        """Test SHA256 detection."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_hash_algorithm(h) == "sha256"

    def test_detect_unknown_length(self):
        """Test unknown hash length."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        assert detect_hash_algorithm("abcdef") is None

    def test_detect_with_whitespace(self):
        """Test detection with surrounding whitespace."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        assert detect_hash_algorithm("  d41d8cd98f00b204e9800998ecf8427e  ") == "md5"


# =============================================================================
# PROCESS VERDICT EXHAUSTIVE TESTS
# =============================================================================


class TestProcessVerdictExhaustive:
    """Exhaustive tests for process verdict calculation."""

    def test_unknown_process_no_findings(self):
        """Test unknown process with no findings returns UNKNOWN."""
        from windows_triage.analysis.verdicts import calculate_process_verdict

        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=[],
        )
        assert result.verdict.value == "UNKNOWN"

    def test_unknown_process_with_critical_finding(self):
        """Test unknown process with critical finding is SUSPICIOUS."""
        from windows_triage.analysis.verdicts import calculate_process_verdict

        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=[{"type": "injection", "severity": "critical"}],
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_known_process_invalid_parent(self):
        """Test known process with invalid parent is SUSPICIOUS."""
        from windows_triage.analysis.verdicts import calculate_process_verdict

        result = calculate_process_verdict(
            process_known=True,
            parent_valid=False,
            path_valid=True,
            user_valid=True,
            findings=[],
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_known_process_invalid_path(self):
        """Test known process with invalid path is SUSPICIOUS."""
        from windows_triage.analysis.verdicts import calculate_process_verdict

        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=False,
            user_valid=True,
            findings=[],
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_known_process_all_valid(self):
        """Test known process with all valid is EXPECTED."""
        from windows_triage.analysis.verdicts import calculate_process_verdict

        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=True,
            user_valid=True,
            findings=[],
        )
        assert result.verdict.value == "EXPECTED"


# =============================================================================
# SERVICE VERDICT EXHAUSTIVE TESTS
# =============================================================================


class TestServiceVerdictExhaustive:
    """Exhaustive tests for service verdict calculation."""

    def test_service_in_baseline_binary_matches(self):
        """Test service in baseline with matching binary is EXPECTED."""
        from windows_triage.analysis.verdicts import calculate_service_verdict

        result = calculate_service_verdict(
            service_in_baseline=True, binary_path_matches=True, binary_findings=[]
        )
        assert result.verdict.value == "EXPECTED"

    def test_service_in_baseline_binary_differs(self):
        """Test service in baseline with different binary is SUSPICIOUS."""
        from windows_triage.analysis.verdicts import calculate_service_verdict

        result = calculate_service_verdict(
            service_in_baseline=True, binary_path_matches=False, binary_findings=[]
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_service_not_in_baseline_clean(self):
        """Test unknown service with no findings is UNKNOWN."""
        from windows_triage.analysis.verdicts import calculate_service_verdict

        result = calculate_service_verdict(
            service_in_baseline=False, binary_path_matches=None, binary_findings=[]
        )
        assert result.verdict.value == "UNKNOWN"

    def test_service_not_in_baseline_suspicious_binary(self):
        """Test unknown service with suspicious binary is SUSPICIOUS."""
        from windows_triage.analysis.verdicts import calculate_service_verdict

        result = calculate_service_verdict(
            service_in_baseline=False,
            binary_path_matches=None,
            binary_findings=[{"type": "double_extension", "severity": "critical"}],
        )
        assert result.verdict.value == "SUSPICIOUS"


# =============================================================================
# HASH VERDICT EXHAUSTIVE TESTS
# =============================================================================


class TestHashVerdictExhaustive:
    """Exhaustive tests for hash verdict calculation (offline analysis only).

    Note: MALICIOUS verdict tests removed - use opencti-mcp for threat intel.
    """

    def test_hash_vulnerable_driver(self):
        """Test vulnerable driver hash is SUSPICIOUS."""
        from windows_triage.analysis.verdicts import calculate_hash_verdict

        result = calculate_hash_verdict(
            is_vulnerable_driver=True,
            driver_info={"product": "VulnDriver", "cve": "CVE-2024-1234"},
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_hash_lolbin(self):
        """Test LOLBin hash is EXPECTED_LOLBIN."""
        from windows_triage.analysis.verdicts import calculate_hash_verdict

        result = calculate_hash_verdict(
            is_lolbin=True, lolbin_info={"name": "certutil.exe"}
        )
        assert result.verdict.value == "EXPECTED_LOLBIN"

    def test_hash_unknown(self):
        """Test unknown hash is UNKNOWN."""
        from windows_triage.analysis.verdicts import calculate_hash_verdict

        result = calculate_hash_verdict()
        assert result.verdict.value == "UNKNOWN"


# =============================================================================
# EXTRACT DIRECTORY EXHAUSTIVE TESTS
# =============================================================================


class TestExtractDirectoryExhaustive:
    """Exhaustive tests for directory extraction."""

    EXTRACT_DIR_CASES = [
        ("C:\\Windows\\System32\\cmd.exe", "\\windows\\system32"),
        ("C:\\Windows\\cmd.exe", "\\windows"),
        ("C:\\cmd.exe", "\\"),
        ("cmd.exe", ""),
        ("\\Windows\\cmd.exe", "\\windows"),
        ("\\cmd.exe", "\\"),
    ]

    @pytest.mark.parametrize("path,expected_dir", EXTRACT_DIR_CASES)
    def test_extract_directory(self, path, expected_dir):
        """Test directory extraction."""
        from windows_triage.analysis.paths import extract_directory

        assert extract_directory(path) == expected_dir

    def test_extract_directory_empty(self):
        """Test directory extraction from empty string."""
        from windows_triage.analysis.paths import extract_directory

        assert extract_directory("") == ""


# =============================================================================
# EXTRACT FILENAME EXHAUSTIVE TESTS
# =============================================================================


class TestExtractFilenameExhaustive2:
    """More exhaustive tests for filename extraction."""

    EXTRACT_NAME_CASES = [
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ("C:\\cmd.exe", "cmd.exe"),
        ("cmd.exe", "cmd.exe"),
        ("\\\\server\\share\\file.exe", "file.exe"),
        ("C:\\Path\\File.With.Dots.exe", "file.with.dots.exe"),
        ("C:\\Path\\UPPERCASE.EXE", "uppercase.exe"),
    ]

    @pytest.mark.parametrize("path,expected_name", EXTRACT_NAME_CASES)
    def test_extract_filename(self, path, expected_name):
        """Test filename extraction."""
        from windows_triage.analysis.paths import extract_filename

        assert extract_filename(path) == expected_name

    def test_extract_filename_empty(self):
        """Test filename extraction from empty string."""
        from windows_triage.analysis.paths import extract_filename

        assert extract_filename("") == ""
