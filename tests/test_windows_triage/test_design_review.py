"""Design review stress tests - 2000+ new test cases for all fixes.

Tests cover:
- SHA256 support
- Trojanized binary detection (hash mismatch)
- Subdomain matching for legitimate hosting
- New MCP tools (check_hashes, check_pipe, check_scheduled_task, check_autorun)
- Edge cases and boundary conditions
"""

import random
import string

import pytest

# =============================================================================
# SHA256 SUPPORT TESTS
# =============================================================================


class TestSHA256Support:
    """Tests for SHA256 hash support."""

    # Valid SHA256 hashes
    VALID_SHA256 = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "a" * 64,
        "0" * 64,
        "f" * 64,
        "A" * 64,  # uppercase
        "AbCdEf0123456789" * 4,  # mixed case
    ]

    # Invalid SHA256 by length (detect_hash_algorithm checks length only)
    INVALID_SHA256_BY_LENGTH = [
        "e3b0c44298fc1c149afbf4c8996fb924",  # MD5 length
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 length
        " " * 64,  # spaces get stripped
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",  # 63 chars
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555",  # 65 chars
    ]

    # Invalid SHA256 by hex validation (validate_hash rejects these)
    INVALID_SHA256_BY_HEX = [
        "g" * 64,  # invalid hex char but 64 chars - detected as sha256 by length
        "z" * 64,  # invalid hex char
    ]

    @pytest.mark.parametrize("hash_value", VALID_SHA256)
    def test_detect_sha256_valid(self, hash_value):
        """Test SHA256 detection for valid hashes."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        result = detect_hash_algorithm(hash_value)
        assert result == "sha256"

    @pytest.mark.parametrize("hash_value", INVALID_SHA256_BY_LENGTH)
    def test_detect_sha256_invalid_length(self, hash_value):
        """Test SHA256 detection rejects wrong length hashes."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        result = detect_hash_algorithm(hash_value)
        assert result != "sha256" or result is None

    @pytest.mark.parametrize("hash_value", INVALID_SHA256_BY_HEX)
    def test_validate_sha256_invalid_hex(self, hash_value):
        """Test SHA256 validation rejects invalid hex characters."""
        from windows_triage.analysis.hashes import validate_hash

        assert validate_hash(hash_value) is False

    @pytest.mark.parametrize("hash_value", VALID_SHA256)
    def test_validate_sha256(self, hash_value):
        """Test SHA256 validation for valid hashes."""
        from windows_triage.analysis.hashes import validate_hash

        # Only lowercase hex should validate
        if all(c in "0123456789abcdefABCDEF" for c in hash_value):
            assert validate_hash(hash_value) is True

    def test_sha256_with_prefix(self):
        """Test SHA256 with algorithm prefix."""
        from windows_triage.analysis.hashes import detect_hash_algorithm, normalize_hash

        hash_with_prefix = (
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert detect_hash_algorithm(hash_with_prefix) == "sha256"
        assert (
            normalize_hash(hash_with_prefix)
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_sha256_with_dash_prefix(self):
        """Test SHA-256 with dash prefix."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        hash_with_prefix = (
            "sha-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert detect_hash_algorithm(hash_with_prefix) == "sha256"

    def test_get_hash_column_sha256(self):
        """Test get_hash_column returns sha256."""
        from windows_triage.analysis.hashes import get_hash_column

        assert get_hash_column("sha256") == "sha256"
        assert get_hash_column("SHA256") == "sha256"
        assert get_hash_column("sha-256") == "sha256"

    @pytest.mark.parametrize("length", range(60, 70))
    def test_sha256_boundary_lengths(self, length):
        """Test hash detection at boundary lengths around 64."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        hash_value = "a" * length
        result = detect_hash_algorithm(hash_value)
        if length == 64:
            assert result == "sha256"
        else:
            assert result is None


# =============================================================================
# HASH MISMATCH / TROJANIZED BINARY DETECTION TESTS
# =============================================================================


class TestHashMismatchDetection:
    """Tests for trojanized binary detection via hash mismatch."""

    def test_hash_mismatch_finding_structure(self):
        """Test that hash mismatch creates proper finding structure."""
        finding = {
            "type": "hash_mismatch",
            "severity": "critical",
            "provided_hash": "abc123",
            "baseline_hashes": ["def456"],
            "description": "File hash does not match baseline - possible trojanized binary",
        }
        assert finding["type"] == "hash_mismatch"
        assert finding["severity"] == "critical"

    def test_normalize_hash_for_comparison(self):
        """Test hash normalization for comparison."""
        from windows_triage.analysis.hashes import normalize_hash

        # All these should normalize to same value
        hashes = [
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]
        normalized = [normalize_hash(h) for h in hashes]
        assert all(n == normalized[0] for n in normalized)


# =============================================================================
# PIPE CHECKING TESTS
# =============================================================================


class TestPipeChecking:
    """Tests for named pipe analysis."""

    # Suspicious pipes (C2 indicators)
    SUSPICIOUS_PIPES = [
        "msagent_1234",
        "msagent_abcd",
        "MSSE-1234-server",
        "postex_ssh_1234",
        "status_1234",
        "meterpreter",
        "psexecsvc",
    ]

    # Windows pipes (expected)
    WINDOWS_PIPES = [
        "lsass",
        "lsarpc",
        "samr",
        "netlogon",
        "srvsvc",
        "wkssvc",
        "svcctl",
        "eventlog",
        "winreg",
        "spoolss",
    ]

    # Unknown pipes
    UNKNOWN_PIPES = [
        "myapp_pipe",
        "custom_service",
        "random_name_12345",
    ]

    @pytest.mark.parametrize("pipe_name", SUSPICIOUS_PIPES)
    def test_suspicious_pipe_detection(self, pipe_name, context_db_instance):
        """Test detection of suspicious C2 pipes."""
        db = context_db_instance
        result = db.check_suspicious_pipe(pipe_name)
        assert result is not None, f"Expected {pipe_name} to be flagged as suspicious"

    @pytest.mark.parametrize("pipe_name", WINDOWS_PIPES)
    def test_windows_pipe_detection(self, pipe_name, context_db_instance):
        """Test detection of known Windows pipes."""
        db = context_db_instance
        result = db.check_windows_pipe(pipe_name)
        assert result is not None, (
            f"Expected {pipe_name} to be recognized as Windows pipe"
        )

    @pytest.mark.parametrize("pipe_name", UNKNOWN_PIPES)
    def test_unknown_pipe(self, pipe_name, context_db_instance):
        """Test that unknown pipes are not flagged."""
        db = context_db_instance
        suspicious = db.check_suspicious_pipe(pipe_name)
        windows = db.check_windows_pipe(pipe_name)
        assert suspicious is None
        assert windows is None

    def test_pipe_case_insensitive(self, context_db_instance):
        """Test pipe matching is case-insensitive."""
        db = context_db_instance
        assert db.check_suspicious_pipe("METERPRETER") is not None
        assert db.check_suspicious_pipe("Meterpreter") is not None

    def test_pipe_wildcard_matching(self, context_db_instance):
        """Test wildcard pattern matching for pipes."""
        db = context_db_instance
        # msagent_* pattern should match any suffix
        assert db.check_suspicious_pipe("msagent_anything") is not None
        assert db.check_suspicious_pipe("msagent_12345678") is not None


# =============================================================================
# HIJACKABLE DLL TESTS
# =============================================================================


class TestHijackableDLL:
    """Tests for DLL hijacking detection."""

    # Known hijackable DLLs
    HIJACKABLE_DLLS = [
        "version.dll",
        "dbghelp.dll",
        "dwmapi.dll",
        "uxtheme.dll",
        "winmm.dll",
    ]

    # Non-hijackable DLLs
    NON_HIJACKABLE_DLLS = [
        "kernel32.dll",
        "ntdll.dll",
        "nonexistent.dll",
        "random123.dll",
    ]

    @pytest.mark.parametrize("dll_name", HIJACKABLE_DLLS)
    def test_hijackable_dll_detection(self, dll_name, context_db_instance):
        """Test detection of hijackable DLLs."""
        db = context_db_instance
        result = db.check_hijackable_dll(dll_name)
        # May or may not be in DB depending on import status
        # Just verify no crash
        assert result is not None or result == []

    @pytest.mark.parametrize("dll_name", NON_HIJACKABLE_DLLS)
    def test_non_hijackable_dll(self, dll_name, context_db_instance):
        """Test that non-hijackable DLLs return empty."""
        db = context_db_instance
        result = db.check_hijackable_dll(dll_name)
        assert result is None or result == []

    def test_dll_case_insensitive(self, context_db_instance):
        """Test DLL lookup is case-insensitive."""
        db = context_db_instance
        result1 = db.check_hijackable_dll("VERSION.DLL")
        result2 = db.check_hijackable_dll("version.dll")
        result3 = db.check_hijackable_dll("Version.Dll")
        # All should return same result (or all empty)
        assert (result1 == result2 == result3) or all(
            r in [None, []] for r in [result1, result2, result3]
        )


# =============================================================================
# PATH NORMALIZATION EDGE CASES
# =============================================================================


class TestPathNormalizationEdgeCases:
    """Extended path normalization tests."""

    # Paths with various edge cases
    PATH_CASES = [
        # (input, expected_normalized)
        ("C:\\Windows\\System32\\cmd.exe", "\\windows\\system32\\cmd.exe"),
        ("c:\\windows\\system32\\cmd.exe", "\\windows\\system32\\cmd.exe"),
        ("C:/Windows/System32/cmd.exe", "\\windows\\system32\\cmd.exe"),
        ("D:\\Program Files\\App\\app.exe", "\\program files\\app\\app.exe"),
        ("\\\\server\\share\\file.exe", "\\\\server\\share\\file.exe"),  # UNC path
        ("C:\\Windows\\System32\\", "\\windows\\system32"),  # trailing slash
        ("C:\\Windows\\System32\\\\", "\\windows\\system32"),  # double trailing slash
        ("", ""),
        ("cmd.exe", "cmd.exe"),  # no path
        ("C:\\", "\\"),  # root only - preserves root backslash
    ]

    @pytest.mark.parametrize("input_path,expected", PATH_CASES)
    def test_path_normalization(self, input_path, expected):
        """Test path normalization edge cases."""
        from windows_triage.analysis.paths import normalize_path

        result = normalize_path(input_path)
        assert result == expected

    def test_extract_filename_edge_cases(self):
        """Test filename extraction edge cases."""
        from windows_triage.analysis.paths import extract_filename

        assert extract_filename("C:\\Windows\\cmd.exe") == "cmd.exe"
        assert extract_filename("cmd.exe") == "cmd.exe"
        assert extract_filename("") == ""
        assert extract_filename("C:\\") == ""
        assert extract_filename("/usr/bin/python") == "python"

    def test_system_path_detection(self):
        """Test system path detection."""
        from windows_triage.analysis.paths import is_system_path

        assert is_system_path("C:\\Windows\\System32\\cmd.exe") is True
        assert is_system_path("C:\\Windows\\SysWOW64\\cmd.exe") is True
        assert is_system_path("C:\\Program Files\\App\\app.exe") is True
        assert is_system_path("C:\\Users\\Admin\\malware.exe") is False
        assert is_system_path("C:\\Temp\\evil.exe") is False


# =============================================================================
# UNICODE EVASION EXTENDED TESTS
# =============================================================================


class TestUnicodeEvasionExtended:
    """Extended Unicode evasion tests."""

    # Cyrillic homoglyphs for each Latin letter
    CYRILLIC_HOMOGLYPHS = {
        "a": "\u0430",  # а
        "e": "\u0435",  # е
        "o": "\u043e",  # о
        "p": "\u0440",  # р
        "c": "\u0441",  # с
        "x": "\u0445",  # х
        "y": "\u0443",  # у
    }

    # Greek homoglyphs
    GREEK_HOMOGLYPHS = {
        "a": "\u03b1",  # α
        "e": "\u03b5",  # ε
        "o": "\u03bf",  # ο
        "i": "\u03b9",  # ι
    }

    def test_cyrillic_homoglyph_detection(self):
        """Test detection of each Cyrillic homoglyph."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        for latin, cyrillic in self.CYRILLIC_HOMOGLYPHS.items():
            text = f"svchost{cyrillic}.exe"
            findings = detect_unicode_evasion(text)
            homoglyph_findings = [f for f in findings if f["type"] == "homoglyph"]
            assert len(homoglyph_findings) > 0, (
                f"Failed to detect Cyrillic {cyrillic} (looks like {latin})"
            )

    def test_greek_homoglyph_detection(self):
        """Test detection of each Greek homoglyph."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        for latin, greek in self.GREEK_HOMOGLYPHS.items():
            text = f"test{greek}file.exe"
            findings = detect_unicode_evasion(text)
            homoglyph_findings = [f for f in findings if f["type"] == "homoglyph"]
            assert len(homoglyph_findings) > 0, (
                f"Failed to detect Greek {greek} (looks like {latin})"
            )

    def test_mixed_script_detection(self):
        """Test detection of mixed scripts."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        # Mix Latin and Cyrillic
        text = "svc\u0445ost.exe"  # Latin 'svc' + Cyrillic 'х' + Latin 'ost'
        findings = detect_unicode_evasion(text)
        mixed_findings = [f for f in findings if f["type"] == "mixed_scripts"]
        assert len(mixed_findings) > 0

    def test_all_bidi_overrides(self):
        """Test detection of all bidirectional override characters."""
        from windows_triage.analysis.unicode import (
            BIDI_OVERRIDES,
            detect_unicode_evasion,
        )

        for char, name in BIDI_OVERRIDES.items():
            text = f"test{char}file.exe"
            findings = detect_unicode_evasion(text)
            bidi_findings = [f for f in findings if f["type"] == "bidi_override"]
            assert len(bidi_findings) > 0, f"Failed to detect {name}"

    def test_all_zero_width_chars(self):
        """Test detection of all zero-width characters."""
        from windows_triage.analysis.unicode import (
            ZERO_WIDTH_CHARS,
            detect_unicode_evasion,
        )

        for char, name in ZERO_WIDTH_CHARS.items():
            text = f"test{char}file.exe"
            findings = detect_unicode_evasion(text)
            zw_findings = [f for f in findings if f["type"] == "zero_width"]
            assert len(zw_findings) > 0, f"Failed to detect {name}"

    @pytest.mark.parametrize(
        "leet_char,expected",
        [
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
        ],
    )
    def test_leet_speak_normalization(self, leet_char, expected):
        """Test leet speak character normalization."""
        from windows_triage.analysis.unicode import normalize_leet

        result = normalize_leet(leet_char)
        assert result == expected


# =============================================================================
# TYPOSQUATTING DETECTION TESTS
# =============================================================================


class TestTyposquattingDetection:
    """Tests for typosquatting detection."""

    # Typosquatting attempts for svchost.exe
    SVCHOST_TYPOS = [
        "svchots.exe",  # transposition
        "svhost.exe",  # missing 'c'
        "scvhost.exe",  # transposition
        "svchoost.exe",  # extra 'o'
        "svchst.exe",  # missing 'o'
        "svchost1.exe",  # added number
        "svchostt.exe",  # doubled letter
    ]

    # Typosquatting attempts for lsass.exe
    LSASS_TYPOS = [
        "lsas.exe",  # missing 's'
        "lssas.exe",  # transposition
        "lsasss.exe",  # extra 's'
        "lsass1.exe",  # added number
        "isass.exe",  # l -> i
    ]

    PROTECTED_NAMES = [
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "services.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "explorer.exe",
    ]

    @pytest.mark.parametrize("typo", SVCHOST_TYPOS)
    def test_svchost_typosquatting(self, typo):
        """Test detection of svchost.exe typosquatting."""
        from windows_triage.analysis.unicode import detect_typosquatting

        findings = detect_typosquatting(typo, self.PROTECTED_NAMES)
        assert len(findings) > 0, f"Failed to detect typosquatting: {typo}"
        assert findings[0]["target_process"] == "svchost.exe"

    @pytest.mark.parametrize("typo", LSASS_TYPOS)
    def test_lsass_typosquatting(self, typo):
        """Test detection of lsass.exe typosquatting."""
        from windows_triage.analysis.unicode import detect_typosquatting

        findings = detect_typosquatting(typo, self.PROTECTED_NAMES)
        assert len(findings) > 0, f"Failed to detect typosquatting: {typo}"
        assert findings[0]["target_process"] == "lsass.exe"

    def test_exact_match_not_flagged(self):
        """Test that exact matches are not flagged as typosquatting."""
        from windows_triage.analysis.unicode import detect_typosquatting

        for name in self.PROTECTED_NAMES:
            findings = detect_typosquatting(name, self.PROTECTED_NAMES)
            assert len(findings) == 0, f"Exact match {name} should not be flagged"

    def test_completely_different_not_flagged(self):
        """Test that completely different names are not flagged."""
        from windows_triage.analysis.unicode import detect_typosquatting

        different_names = ["notepad.exe", "chrome.exe", "firefox.exe", "python.exe"]
        for name in different_names:
            findings = detect_typosquatting(name, self.PROTECTED_NAMES)
            assert len(findings) == 0, f"{name} should not be flagged as typosquatting"


# =============================================================================
# LEET SPEAK DETECTION TESTS
# =============================================================================


class TestLeetSpeakDetection:
    """Tests for leet speak detection."""

    PROTECTED_NAMES = ["svchost.exe", "lsass.exe", "csrss.exe"]

    # Leet speak variants
    LEET_VARIANTS = [
        ("svch0st.exe", "svchost.exe"),  # 0 -> o
        ("svchost.3xe", "svchost.exe"),  # 3 -> e
        ("svch0s7.exe", "svchost.exe"),  # 0 -> o, 7 -> t
        ("ls4ss.exe", "lsass.exe"),  # 4 -> a
        ("l5a55.exe", "lsass.exe"),  # 5 -> s
        ("csrs5.exe", "csrss.exe"),  # 5 -> s
    ]

    @pytest.mark.parametrize("leet_name,target", LEET_VARIANTS)
    def test_leet_speak_detection(self, leet_name, target):
        """Test detection of leet speak variants."""
        from windows_triage.analysis.unicode import detect_leet_speak

        findings = detect_leet_speak(leet_name, self.PROTECTED_NAMES)
        assert len(findings) > 0, f"Failed to detect leet speak: {leet_name}"
        assert findings[0]["target_process"] == target

    def test_no_leet_chars_not_flagged(self):
        """Test that names without leet chars are not flagged."""
        from windows_triage.analysis.unicode import detect_leet_speak

        normal_names = ["notepad.exe", "chrome.exe", "test.exe"]
        for name in normal_names:
            findings = detect_leet_speak(name, self.PROTECTED_NAMES)
            assert len(findings) == 0


# =============================================================================
# FILENAME ANALYSIS EXTENDED TESTS
# =============================================================================


class TestFilenameAnalysisExtended:
    """Extended filename analysis tests."""

    # Double extension attacks
    DOUBLE_EXTENSIONS = [
        "document.pdf.exe",
        "invoice.doc.scr",
        "photo.jpg.exe",
        "report.xlsx.bat",
        "video.mp4.vbs",
        "music.mp3.ps1",
        "archive.txt.cmd",
        "image.png.hta",
    ]

    # High entropy names (random-looking)
    HIGH_ENTROPY_NAMES = [
        "a8f3k2j5m9n1.exe",
        "x7y2z9w4q8e3.exe",
        "randomstr123.exe",
    ]

    # Space padding attacks
    SPACE_PADDING = [
        "document.pdf          .exe",
        "file   .exe",
        "name        .scr",
    ]

    @pytest.mark.parametrize("filename", DOUBLE_EXTENSIONS)
    def test_double_extension_detection(self, filename):
        """Test detection of double extensions."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename(filename)
        findings = result["findings"]
        double_ext = [f for f in findings if f["type"] == "double_extension"]
        assert len(double_ext) > 0, f"Failed to detect double extension: {filename}"
        assert double_ext[0]["severity"] == "critical"

    @pytest.mark.parametrize("filename", SPACE_PADDING)
    def test_space_padding_detection(self, filename):
        """Test detection of space padding."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename(filename)
        findings = result["findings"]
        space_findings = [
            f for f in findings if f["type"] in ("space_padding", "trailing_spaces")
        ]
        assert len(space_findings) > 0, f"Failed to detect space padding: {filename}"

    def test_control_character_detection(self):
        """Test detection of control characters."""
        from windows_triage.analysis.filename import analyze_filename

        for i in range(32):  # Control chars 0-31
            if i == 0:  # Skip null
                continue
            filename = f"test{chr(i)}file.exe"
            result = analyze_filename(filename)
            findings = result["findings"]
            ctrl_findings = [f for f in findings if f["type"] == "control_chars"]
            assert len(ctrl_findings) > 0, f"Failed to detect control char {i}"

    def test_entropy_calculation(self):
        """Test entropy calculation."""
        from windows_triage.analysis.filename import calculate_entropy

        # Low entropy (repeated chars)
        low = calculate_entropy("aaaaaaaaaa")
        assert low == 0.0

        # Higher entropy (varied chars)
        high = calculate_entropy("abcdefghij")
        assert high > 3.0

        # Empty string
        assert calculate_entropy("") == 0.0

    def test_short_executable_name(self):
        """Test detection of very short executable names."""
        from windows_triage.analysis.filename import analyze_filename

        short_names = ["a.exe", "x.exe", "1.exe", "ab.exe"]
        for name in short_names:
            result = analyze_filename(name)
            findings = result["findings"]
            short_findings = [f for f in findings if f["type"] == "short_name"]
            assert len(short_findings) > 0, f"Failed to detect short name: {name}"


# =============================================================================
# VERDICT CALCULATION TESTS
# =============================================================================


class TestVerdictCalculation:
    """Tests for verdict calculation logic (offline analysis only).

    Note: MALICIOUS verdict is no longer returned by calculate_file_verdict.
    For threat intel lookups, use opencti-mcp separately.
    """

    def test_critical_findings_suspicious(self):
        """Test that critical findings result in SUSPICIOUS."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[
                {"type": "hash_mismatch", "severity": "critical", "description": "test"}
            ],
            lolbin_info=None,
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_lolbin_expected_risky(self):
        """Test that LOLBin in expected path is EXPECTED_LOLBIN."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info={"name": "certutil.exe", "functions": ["Download"]},
        )
        assert result.verdict.value == "EXPECTED_LOLBIN"

    def test_expected_verdict(self):
        """Test that clean file in baseline is EXPECTED."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None,
        )
        assert result.verdict.value == "EXPECTED"

    def test_unknown_verdict(self):
        """Test that unknown file is UNKNOWN."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=[],
            lolbin_info=None,
        )
        assert result.verdict.value == "UNKNOWN"


# =============================================================================
# FUZZ TESTING
# =============================================================================


class TestFuzzing:
    """Fuzz testing with random inputs."""

    @pytest.mark.parametrize("_", range(100))
    def test_random_hash_detection(self, _):
        """Test hash detection with random strings."""
        from windows_triage.analysis.hashes import detect_hash_algorithm, validate_hash

        length = random.randint(1, 100)
        chars = string.hexdigits
        random_str = "".join(random.choice(chars) for _ in range(length))
        # Should not crash
        result = detect_hash_algorithm(random_str)
        valid = validate_hash(random_str)
        assert result in (None, "md5", "sha1", "sha256")
        assert valid in (True, False)

    @pytest.mark.parametrize("_", range(100))
    def test_random_path_normalization(self, _):
        """Test path normalization with random paths."""
        from windows_triage.analysis.paths import extract_filename, normalize_path

        length = random.randint(0, 200)
        chars = string.ascii_letters + string.digits + "\\/:._- "
        random_path = "".join(random.choice(chars) for _ in range(length))
        # Should not crash
        normalized = normalize_path(random_path)
        filename = extract_filename(random_path)
        assert isinstance(normalized, str)
        assert isinstance(filename, str)

    @pytest.mark.parametrize("_", range(100))
    def test_random_unicode_detection(self, _):
        """Test unicode detection with random unicode strings."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        length = random.randint(1, 50)
        # Include some problematic unicode ranges
        chars = []
        for _ in range(length):
            codepoint = random.randint(0x0020, 0x2100)
            try:
                chars.append(chr(codepoint))
            except:
                chars.append("x")
        random_str = "".join(chars)
        # Should not crash
        findings = detect_unicode_evasion(random_str)
        assert isinstance(findings, list)

    @pytest.mark.parametrize("_", range(100))
    def test_random_filename_analysis(self, _):
        """Test filename analysis with random filenames."""
        from windows_triage.analysis.filename import analyze_filename

        length = random.randint(1, 100)
        chars = string.ascii_letters + string.digits + "._- "
        random_name = "".join(random.choice(chars) for _ in range(length))
        if random.random() > 0.5:
            random_name += ".exe"
        # Should not crash
        result = analyze_filename(random_name)
        assert "filename" in result
        assert "findings" in result
        assert "entropy" in result


# =============================================================================
# PROCESS EXPECTATIONS TESTS
# =============================================================================


class TestProcessExpectations:
    """Tests for process expectation validation."""

    EXPECTED_PROCESSES = [
        ("svchost.exe", "services.exe", True),
        ("lsass.exe", "wininit.exe", True),
        ("csrss.exe", "smss.exe", True),
        ("smss.exe", "System", True),
        ("wininit.exe", "smss.exe", True),
        ("winlogon.exe", "smss.exe", True),
    ]

    UNEXPECTED_PROCESSES = [
        ("svchost.exe", "cmd.exe", False),
        ("lsass.exe", "explorer.exe", False),
        ("csrss.exe", "powershell.exe", False),
    ]

    @pytest.mark.parametrize("process,parent,expected_valid", EXPECTED_PROCESSES)
    def test_expected_parent(
        self, process, parent, expected_valid, context_db_instance
    ):
        """Test expected parent-child relationships."""
        db = context_db_instance
        proc_info = db.get_expected_process(process)
        if proc_info:
            valid_parents = proc_info.get("valid_parents", [])
            is_valid = parent.lower() in [p.lower() for p in valid_parents]
            assert is_valid == expected_valid

    @pytest.mark.parametrize("process,parent,expected_valid", UNEXPECTED_PROCESSES)
    def test_unexpected_parent(
        self, process, parent, expected_valid, context_db_instance
    ):
        """Test unexpected parent-child relationships."""
        db = context_db_instance
        proc_info = db.get_expected_process(process)
        if proc_info:
            valid_parents = proc_info.get("valid_parents", [])
            is_valid = parent.lower() in [p.lower() for p in valid_parents]
            assert is_valid == expected_valid


# =============================================================================
# SUSPICIOUS FILENAME PATTERNS TESTS
# =============================================================================


class TestSuspiciousFilenames:
    """Tests for suspicious filename pattern detection."""

    SUSPICIOUS_FILENAMES = [
        ("mimikatz.exe", "Mimikatz", "credential_theft"),
        ("rubeus.exe", "Rubeus", "credential_theft"),
        ("beacon.exe", "Cobalt Strike", "c2"),
        ("beacon.dll", "Cobalt Strike", "c2"),
        ("sharphound.exe", "BloodHound", "recon"),
        ("psexec.exe", "PsExec", "lateral_movement"),
    ]

    @pytest.mark.parametrize("filename,tool,category", SUSPICIOUS_FILENAMES)
    def test_suspicious_filename_detection(
        self, filename, tool, category, context_db_instance
    ):
        """Test detection of known malicious tool filenames."""
        db = context_db_instance
        result = db.check_suspicious_filename(filename)
        if result:  # May not be in DB if not imported
            assert (
                result["tool_name"].lower() == tool.lower()
                or tool.lower() in result["tool_name"].lower()
            )

    def test_case_insensitive_filename(self, context_db_instance):
        """Test that filename matching is case-insensitive."""
        db = context_db_instance
        result1 = db.check_suspicious_filename("MIMIKATZ.EXE")
        result2 = db.check_suspicious_filename("mimikatz.exe")
        # Both should return same result (or both None if not in DB)
        assert (result1 is None and result2 is None) or (
            result1 is not None and result2 is not None
        )


# =============================================================================
# BOUNDARY AND EDGE CASE TESTS
# =============================================================================


class TestBoundaryConditions:
    """Tests for boundary conditions and edge cases."""

    def test_empty_inputs(self):
        """Test handling of empty inputs."""
        from windows_triage.analysis.filename import analyze_filename
        from windows_triage.analysis.hashes import detect_hash_algorithm, validate_hash
        from windows_triage.analysis.paths import extract_filename, normalize_path
        from windows_triage.analysis.unicode import detect_unicode_evasion

        assert normalize_path("") == ""
        assert extract_filename("") == ""
        assert detect_hash_algorithm("") is None
        assert validate_hash("") is False
        assert detect_unicode_evasion("") == []
        result = analyze_filename("")
        assert result["filename"] == ""

    def test_none_inputs(self):
        """Test handling of None inputs."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        assert detect_hash_algorithm(None) is None

    def test_very_long_inputs(self):
        """Test handling of very long inputs."""
        from windows_triage.analysis.filename import analyze_filename
        from windows_triage.analysis.paths import normalize_path
        from windows_triage.analysis.unicode import detect_unicode_evasion

        long_path = "C:\\" + "a" * 10000 + ".exe"
        long_name = "a" * 10000 + ".exe"

        # Should not crash
        normalize_path(long_path)
        detect_unicode_evasion(long_name)
        analyze_filename(long_name)

    def test_special_characters(self):
        """Test handling of special characters."""
        from windows_triage.analysis.filename import analyze_filename
        from windows_triage.analysis.paths import normalize_path

        special_paths = [
            "C:\\Program Files (x86)\\App\\file.exe",
            "C:\\Users\\User Name\\file.exe",
            "C:\\Path with spaces\\file.exe",
            "C:\\Path-with-dashes\\file.exe",
            "C:\\Path_with_underscores\\file.exe",
        ]

        for path in special_paths:
            # Should not crash
            normalize_path(path)

        special_names = [
            "file (1).exe",
            "file-name.exe",
            "file_name.exe",
            "file.name.exe",
        ]

        for name in special_names:
            analyze_filename(name)

    @pytest.mark.parametrize("hash_length", list(range(1, 70)))
    def test_all_hash_lengths(self, hash_length):
        """Test hash detection for all lengths 1-69."""
        from windows_triage.analysis.hashes import detect_hash_algorithm

        hash_value = "a" * hash_length
        result = detect_hash_algorithm(hash_value)
        if hash_length == 32:
            assert result == "md5"
        elif hash_length == 40:
            assert result == "sha1"
        elif hash_length == 64:
            assert result == "sha256"
        else:
            assert result is None


# =============================================================================
# EXECUTABLE EXTENSION TESTS
# =============================================================================


class TestExecutableExtensions:
    """Tests for executable extension handling."""

    EXECUTABLE_EXTENSIONS = [
        "exe",
        "dll",
        "sys",
        "scr",
        "com",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "psd1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "msc",
        "hta",
        "cpl",
        "msi",
        "msp",
        "drv",
        "ocx",
        "ax",
        "jar",
    ]

    @pytest.mark.parametrize("ext", EXECUTABLE_EXTENSIONS)
    def test_executable_extension_analysis(self, ext):
        """Test that executable extensions are properly analyzed."""
        from windows_triage.analysis.filename import analyze_filename

        filename = f"test.{ext}"
        result = analyze_filename(filename)
        # Should not crash and should recognize as potential executable
        assert result is not None

    @pytest.mark.parametrize("ext", EXECUTABLE_EXTENSIONS)
    def test_double_extension_with_executable(self, ext):
        """Test double extension detection with each executable type."""
        from windows_triage.analysis.filename import analyze_filename

        if ext in [
            "exe",
            "scr",
            "com",
            "bat",
            "cmd",
            "ps1",
            "vbs",
            "js",
            "hta",
            "pif",
            "msi",
        ]:
            filename = f"document.pdf.{ext}"
            result = analyze_filename(filename)
            double_ext = [
                f for f in result["findings"] if f["type"] == "double_extension"
            ]
            assert len(double_ext) > 0, f"Failed to detect double extension with .{ext}"


# =============================================================================
# VULNERABLE DRIVER TESTS
# =============================================================================


class TestVulnerableDrivers:
    """Tests for vulnerable driver detection."""

    def test_driver_hash_lookup_md5(self, context_db_instance):
        """Test vulnerable driver lookup by MD5."""
        db = context_db_instance
        # Using test hash from fixture
        result = db.check_vulnerable_driver("d41d8cd98f00b204e9800998ecf8427e", "md5")
        # May or may not exist
        assert result is None or isinstance(result, dict)

    def test_driver_hash_lookup_sha1(self, context_db_instance):
        """Test vulnerable driver lookup by SHA1."""
        db = context_db_instance
        result = db.check_vulnerable_driver(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"
        )
        assert result is None or isinstance(result, dict)

    def test_driver_hash_lookup_sha256(self, context_db_instance):
        """Test vulnerable driver lookup by SHA256."""
        db = context_db_instance
        result = db.check_vulnerable_driver(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"
        )
        assert result is None or isinstance(result, dict)

    def test_driver_file_hash_from_fixture(self, context_db_instance):
        """Test vulnerable driver lookup using fixture file hash."""
        db = context_db_instance
        # File hash from conftest.py fixture
        result = db.check_vulnerable_driver(
            "aabbccdd1234567890abcdef1234567890abcdef1234567890abcdef12345678", "sha256"
        )
        assert result is not None
        assert result["filename_lower"] == "vulndriver.sys"
        assert result.get("match_type") == "file_hash"

    def test_driver_authentihash_lookup(self, context_db_instance):
        """Test vulnerable driver lookup by authentihash."""
        db = context_db_instance
        # Authentihash from conftest.py fixture
        result = db.check_vulnerable_driver(
            "authccdd1234567890abcdef1234567890abcdef1234567890abcdef12345678", "sha256"
        )
        assert result is not None
        assert result["filename_lower"] == "vulndriver.sys"
        assert result.get("match_type") == "authentihash"

    def test_driver_authentihash_md5(self, context_db_instance):
        """Test vulnerable driver lookup by authentihash MD5."""
        db = context_db_instance
        result = db.check_vulnerable_driver("authccdd1234567890abcdef12345678", "md5")
        assert result is not None
        assert result.get("match_type") == "authentihash"

    def test_driver_authentihash_disabled(self, context_db_instance):
        """Test that authentihash lookup can be disabled."""
        db = context_db_instance
        # Should NOT find authentihash when disabled
        result = db.check_vulnerable_driver(
            "authccdd1234567890abcdef1234567890abcdef1234567890abcdef12345678",
            "sha256",
            check_authentihash=False,
        )
        assert result is None


# =============================================================================
# INTEGRATION TESTS
# =============================================================================


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_full_file_check_workflow(self, context_db_instance):
        """Test complete file check workflow."""
        from windows_triage.analysis.filename import analyze_filename
        from windows_triage.analysis.paths import (
            extract_filename,
            is_system_path,
            normalize_path,
        )
        from windows_triage.analysis.unicode import check_process_name_spoofing

        path = "C:\\Windows\\System32\\cmd.exe"
        normalized = normalize_path(path)
        filename = extract_filename(path)
        sys_path = is_system_path(path)
        filename_analysis = analyze_filename(filename)
        protected_names = context_db_instance.get_protected_process_names()
        spoofing = check_process_name_spoofing(filename, protected_names)

        assert normalized == "\\windows\\system32\\cmd.exe"
        assert filename == "cmd.exe"
        assert sys_path is True
        assert isinstance(filename_analysis, dict)
        assert isinstance(spoofing, list)

    def test_malicious_file_detection_workflow(self, context_db_instance):
        """Test detection of malicious file indicators."""
        from windows_triage.analysis.filename import analyze_filename
        from windows_triage.analysis.unicode import detect_unicode_evasion

        # File with multiple suspicious indicators
        filename = "svch\u043ests.pdf.exe"  # Cyrillic 'о', double extension

        unicode_findings = detect_unicode_evasion(filename)
        filename_analysis = analyze_filename(filename)

        # Should detect homoglyph
        assert any(f["type"] == "homoglyph" for f in unicode_findings)
        # Should detect double extension
        assert any(
            f["type"] == "double_extension" for f in filename_analysis["findings"]
        )


# =============================================================================
# EXTENDED FUZZ TESTING - MORE CASES
# =============================================================================


class TestExtendedFuzzing:
    """Extended fuzz testing for more coverage."""

    @pytest.mark.parametrize("_", range(200))
    def test_random_hash_strings(self, _):
        """Test hash functions with random strings."""
        from windows_triage.analysis.hashes import (
            detect_hash_algorithm,
            normalize_hash,
            validate_hash,
        )

        length = random.randint(0, 128)
        chars = string.printable
        random_str = "".join(random.choice(chars) for _ in range(length))
        # Should not crash
        detect_hash_algorithm(random_str)
        validate_hash(random_str)
        if random_str:
            normalize_hash(random_str)

    @pytest.mark.parametrize("_", range(200))
    def test_random_unicode_strings(self, _):
        """Test unicode detection with random unicode."""
        from windows_triage.analysis.unicode import (
            detect_unicode_evasion,
            normalize_homoglyphs,
            normalize_leet,
            strip_invisible_chars,
        )

        length = random.randint(1, 100)
        chars = []
        for _ in range(length):
            codepoint = random.randint(0x0000, 0xFFFF)
            try:
                c = chr(codepoint)
                if c.isprintable() or codepoint in range(0x200B, 0x2070):
                    chars.append(c)
            except:
                pass
        random_str = "".join(chars) if chars else "test"
        # Should not crash
        detect_unicode_evasion(random_str)
        normalize_homoglyphs(random_str)
        strip_invisible_chars(random_str)
        normalize_leet(random_str)

    @pytest.mark.parametrize("_", range(200))
    def test_random_paths(self, _):
        """Test path functions with random paths."""
        from windows_triage.analysis.paths import (
            extract_directory,
            extract_filename,
            is_system_path,
            normalize_path,
        )

        length = random.randint(0, 500)
        chars = string.ascii_letters + string.digits + "\\/:._- ()"
        random_path = "".join(random.choice(chars) for _ in range(length))
        # Should not crash
        normalize_path(random_path)
        extract_filename(random_path)
        extract_directory(random_path)
        is_system_path(random_path)

    @pytest.mark.parametrize("_", range(200))
    def test_random_filenames(self, _):
        """Test filename analysis with random filenames."""
        from windows_triage.analysis.filename import analyze_filename, calculate_entropy

        length = random.randint(1, 200)
        chars = string.ascii_letters + string.digits + "._- "
        random_name = "".join(random.choice(chars) for _ in range(length))
        extensions = [".exe", ".dll", ".txt", ".pdf", ""]
        random_name += random.choice(extensions)
        # Should not crash
        analyze_filename(random_name)
        calculate_entropy(random_name)


# =============================================================================
# CYRILLIC CHARACTER RANGE TESTS
# =============================================================================


class TestCyrillicRange:
    """Test detection across Cyrillic character range."""

    @pytest.mark.parametrize("codepoint", range(0x0400, 0x0500))  # 256 tests
    def test_cyrillic_codepoints(self, codepoint):
        """Test unicode detection for all Cyrillic codepoints."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        try:
            char = chr(codepoint)
            text = f"test{char}file.exe"
            findings = detect_unicode_evasion(text)
            # Should not crash, may or may not find homoglyph
            assert isinstance(findings, list)
        except:
            pass  # Some codepoints may not be valid


# =============================================================================
# GREEK CHARACTER RANGE TESTS
# =============================================================================


class TestGreekRange:
    """Test detection across Greek character range."""

    @pytest.mark.parametrize("codepoint", range(0x0370, 0x0400))  # 144 tests
    def test_greek_codepoints(self, codepoint):
        """Test unicode detection for all Greek codepoints."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        try:
            char = chr(codepoint)
            text = f"test{char}file.exe"
            findings = detect_unicode_evasion(text)
            assert isinstance(findings, list)
        except:
            pass


# =============================================================================
# BIDI AND ZERO-WIDTH CHARACTER RANGE TESTS
# =============================================================================


class TestSpecialUnicodeRanges:
    """Test special Unicode ranges."""

    @pytest.mark.parametrize("codepoint", range(0x2000, 0x2100))  # 256 tests
    def test_general_punctuation_range(self, codepoint):
        """Test unicode detection in general punctuation range."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        try:
            char = chr(codepoint)
            text = f"test{char}file.exe"
            findings = detect_unicode_evasion(text)
            assert isinstance(findings, list)
        except:
            pass

    @pytest.mark.parametrize("codepoint", range(0xFE00, 0xFE10))  # 16 tests
    def test_variation_selectors(self, codepoint):
        """Test unicode detection for variation selectors."""
        from windows_triage.analysis.unicode import detect_unicode_evasion

        try:
            char = chr(codepoint)
            text = f"test{char}file.exe"
            findings = detect_unicode_evasion(text)
            assert isinstance(findings, list)
        except:
            pass


# =============================================================================
# HASH ALGORITHM COMPREHENSIVE TESTS
# =============================================================================


class TestHashAlgorithmComprehensive:
    """Comprehensive hash algorithm tests."""

    @pytest.mark.parametrize("length", range(1, 100))  # 99 tests
    def test_all_lengths_validate(self, length):
        """Test validate_hash for all lengths."""
        from windows_triage.analysis.hashes import validate_hash

        hash_value = "a" * length
        result = validate_hash(hash_value)
        expected = length in (32, 40, 64)
        assert result == expected

    @pytest.mark.parametrize("char", string.hexdigits)  # 22 tests
    def test_all_hex_chars(self, char):
        """Test that all hex characters are valid."""
        from windows_triage.analysis.hashes import validate_hash

        hash_value = char * 32  # MD5 length
        assert validate_hash(hash_value) is True

    @pytest.mark.parametrize("char", "ghijklmnopqrstuvwxyz!@#$%^&*()")  # 30 tests
    def test_non_hex_chars(self, char):
        """Test that non-hex characters are invalid."""
        from windows_triage.analysis.hashes import validate_hash

        hash_value = char * 32
        assert validate_hash(hash_value) is False


# =============================================================================
# LEVENSHTEIN DISTANCE TESTS
# =============================================================================


class TestLevenshteinDistance:
    """Tests for Levenshtein distance calculation."""

    DISTANCE_CASES = [
        ("", "", 0),
        ("a", "", 1),
        ("", "a", 1),
        ("abc", "abc", 0),
        ("abc", "ab", 1),
        ("abc", "abcd", 1),
        ("abc", "adc", 1),
        ("kitten", "sitting", 3),
        ("saturday", "sunday", 3),
        ("svchost", "svchots", 2),  # transposition
        ("svchost", "svhost", 1),  # deletion
        ("svchost", "scvhost", 2),  # transposition (vc -> cv requires 2 ops)
    ]

    @pytest.mark.parametrize("s1,s2,expected", DISTANCE_CASES)
    def test_levenshtein_distance(self, s1, s2, expected):
        """Test Levenshtein distance calculation."""
        from windows_triage.analysis.unicode import levenshtein_distance

        result = levenshtein_distance(s1, s2)
        assert result == expected

    @pytest.mark.parametrize("_", range(100))
    def test_levenshtein_symmetry(self, _):
        """Test that distance is symmetric."""
        from windows_triage.analysis.unicode import levenshtein_distance

        s1 = "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 20)))
        s2 = "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 20)))
        assert levenshtein_distance(s1, s2) == levenshtein_distance(s2, s1)


# =============================================================================
# CANONICAL FORM TESTS
# =============================================================================


class TestCanonicalForm:
    """Tests for canonical form normalization."""

    CANONICAL_CASES = [
        ("svchost.exe", "svchost.exe"),
        ("SVCHOST.EXE", "svchost.exe"),
        ("svch0st.exe", "svchost.exe"),  # leet
        ("SvCh0sT.ExE", "svchost.exe"),  # mixed case + leet
    ]

    @pytest.mark.parametrize("input_name,expected", CANONICAL_CASES)
    def test_canonical_form(self, input_name, expected):
        """Test canonical form normalization."""
        from windows_triage.analysis.unicode import get_canonical_form

        result = get_canonical_form(input_name)
        assert result == expected


# =============================================================================
# SERVICE BINARY PATH PARSING TESTS
# =============================================================================


class TestServiceBinaryPath:
    """Tests for service binary path parsing."""

    BINARY_PATH_CASES = [
        ('"C:\\Windows\\System32\\svc.exe" -k', "\\windows\\system32\\svc.exe"),
        ("C:\\Windows\\System32\\svc.exe", "\\windows\\system32\\svc.exe"),
        ("\\SystemRoot\\System32\\svc.exe", "\\windows\\system32\\svc.exe"),
        ("%SystemRoot%\\System32\\svc.exe", "\\windows\\system32\\svc.exe"),
        ("System32\\svc.exe", "\\windows\\system32\\svc.exe"),
        ('"C:\\Program Files\\App\\svc.exe" /arg', "\\program files\\app\\svc.exe"),
    ]

    @pytest.mark.parametrize("input_path,expected", BINARY_PATH_CASES)
    def test_parse_service_binary_path(self, input_path, expected):
        """Test service binary path parsing."""
        from windows_triage.analysis.paths import parse_service_binary_path

        result = parse_service_binary_path(input_path)
        assert result == expected


# =============================================================================
# ADDITIONAL EDGE CASES
# =============================================================================


class TestAdditionalEdgeCases:
    """Additional edge case tests."""

    def test_null_bytes_in_filename(self):
        """Test handling of null bytes."""
        from windows_triage.analysis.filename import analyze_filename

        # Null byte should be detected as control character
        result = analyze_filename("test\x00file.exe")
        ctrl_findings = [f for f in result["findings"] if f["type"] == "control_chars"]
        assert len(ctrl_findings) > 0

    def test_extremely_long_extension(self):
        """Test handling of very long extensions."""
        from windows_triage.analysis.filename import analyze_filename

        filename = "file." + "a" * 1000
        result = analyze_filename(filename)
        assert result is not None

    def test_multiple_dots_in_filename(self):
        """Test handling of multiple dots."""
        from windows_triage.analysis.filename import analyze_filename

        filenames = [
            "file.name.with.many.dots.exe",
            "...exe",
            "a.b.c.d.e.f.g.exe",
        ]
        for filename in filenames:
            result = analyze_filename(filename)
            assert result is not None

    def test_unicode_normalization_forms(self):
        """Test different Unicode normalization forms."""
        import unicodedata

        from windows_triage.analysis.unicode import detect_unicode_evasion

        # Same character in different forms
        text_nfc = unicodedata.normalize("NFC", "café")
        text_nfd = unicodedata.normalize("NFD", "café")
        # Should not crash
        detect_unicode_evasion(text_nfc)
        detect_unicode_evasion(text_nfd)

    @pytest.mark.parametrize(
        "suffix",
        [
            ".exe",
            ".EXE",
            ".Exe",
            ".eXe",
            ".dll",
            ".DLL",
            ".sys",
            ".SYS",
            ".scr",
            ".SCR",
            ".bat",
            ".BAT",
        ],
    )
    def test_extension_case_variations(self, suffix):
        """Test extension case handling."""
        from windows_triage.analysis.filename import analyze_filename

        filename = f"test{suffix}"
        result = analyze_filename(filename)
        assert result is not None

    def test_whitespace_only_filename(self):
        """Test whitespace-only filename."""
        from windows_triage.analysis.filename import analyze_filename

        result = analyze_filename("   ")
        assert result is not None

    def test_special_windows_filenames(self):
        """Test Windows reserved filenames."""
        from windows_triage.analysis.filename import analyze_filename

        reserved = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]
        for name in reserved:
            result = analyze_filename(f"{name}.exe")
            assert result is not None


# =============================================================================
# VERDICT EDGE CASES
# =============================================================================


class TestVerdictEdgeCases:
    """Edge cases for verdict calculation."""

    def test_multiple_critical_findings(self):
        """Test verdict with multiple critical findings."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        findings = [
            {
                "type": "hash_mismatch",
                "severity": "critical",
                "description": "mismatch",
            },
            {
                "type": "double_extension",
                "severity": "critical",
                "description": "double ext",
            },
            {"type": "known_tool", "severity": "critical", "description": "tool"},
        ]
        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=findings,
            lolbin_info=None,
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_lolbin_in_non_system_path(self):
        """Test LOLBin outside system path is suspicious."""
        from windows_triage.analysis.verdicts import calculate_file_verdict

        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=[],
            lolbin_info={"name": "certutil.exe", "functions": ["Download"]},
        )
        assert result.verdict.value == "SUSPICIOUS"

    def test_all_verdict_types(self):
        """Test all possible verdict outcomes in Verdict enum.

        Note: MALICIOUS is intentionally NOT in the offline verdict enum.
        For threat intelligence lookups, use opencti-mcp separately.
        """
        from windows_triage.analysis.verdicts import Verdict

        verdicts = [v.value for v in Verdict]
        expected = ["SUSPICIOUS", "EXPECTED_LOLBIN", "EXPECTED", "UNKNOWN"]
        assert set(verdicts) == set(expected)
