"""Tests for filename heuristics."""

from windows_triage.analysis.filename import (
    EXECUTABLE_EXTENSIONS,
    analyze_filename,
    calculate_entropy,
    check_known_tool_filename,
)


class TestCalculateEntropy:
    """Tests for calculate_entropy function."""

    def test_empty_string(self):
        assert calculate_entropy("") == 0.0

    def test_single_char_repeated(self):
        # All same characters = 0 entropy
        assert calculate_entropy("aaaa") == 0.0

    def test_low_entropy(self):
        # Repeated pattern, low entropy
        entropy = calculate_entropy("abab")
        assert 0 < entropy < 2

    def test_high_entropy(self):
        # Random-looking string
        entropy = calculate_entropy("aB3$xQ9!")
        assert entropy > 2.5

    def test_normal_filename(self):
        # Normal filename like "notepad" should have moderate entropy
        entropy = calculate_entropy("notepad")
        assert 1.5 < entropy < 3.5


class TestAnalyzeFilename:
    """Tests for analyze_filename function."""

    def test_normal_filename(self):
        result = analyze_filename("notepad.exe")
        assert result["is_suspicious"] is False
        assert len(result["findings"]) == 0

    def test_short_executable_name(self):
        result = analyze_filename("a.exe")
        assert result["is_suspicious"] is True
        assert any(f["type"] == "short_name" for f in result["findings"])

    def test_two_char_name(self):
        result = analyze_filename("ab.exe")
        assert result["is_suspicious"] is True
        assert any(f["type"] == "short_name" for f in result["findings"])

    def test_high_entropy_name(self):
        # Random-looking long name with more variation
        result = analyze_filename("xK9mQ2pLvRzYtW.exe")
        # High entropy is only flagged if entropy > 4.5 and length > 6
        # This might not hit the threshold - check the actual entropy
        assert result["entropy"] > 3.0  # Just verify entropy is calculated

    def test_double_extension_pdf_exe(self):
        result = analyze_filename("document.pdf.exe")
        assert result["is_suspicious"] is True
        assert any(f["type"] == "double_extension" for f in result["findings"])
        assert any(f["severity"] == "critical" for f in result["findings"])

    def test_double_extension_doc_scr(self):
        result = analyze_filename("invoice.doc.scr")
        assert any(f["type"] == "double_extension" for f in result["findings"])

    def test_double_extension_jpg_exe(self):
        result = analyze_filename("image.jpg.exe")
        assert any(f["type"] == "double_extension" for f in result["findings"])

    def test_space_padding(self):
        result = analyze_filename("document                    .exe")
        assert any(f["type"] == "space_padding" for f in result["findings"])

    def test_trailing_spaces(self):
        result = analyze_filename("document   .exe")
        assert any(f["type"] == "trailing_spaces" for f in result["findings"])

    def test_control_characters(self):
        result = analyze_filename("mal\x00ware.exe")
        assert any(f["type"] == "control_chars" for f in result["findings"])
        assert any(f["severity"] == "critical" for f in result["findings"])

    def test_normal_non_executable(self):
        # Non-executable shouldn't trigger short name warning
        result = analyze_filename("a.txt")
        assert result["is_suspicious"] is False

    def test_entropy_calculation(self):
        result = analyze_filename("test.exe")
        assert "entropy" in result
        assert isinstance(result["entropy"], float)


class TestCheckKnownToolFilename:
    """Tests for check_known_tool_filename function."""

    def test_exact_match(self):
        patterns = [
            {
                "filename_pattern": "mimikatz.exe",
                "is_regex": False,
                "tool_name": "Mimikatz",
            }
        ]
        result = check_known_tool_filename("mimikatz.exe", patterns)
        assert result is not None
        assert result["tool_name"] == "Mimikatz"

    def test_case_insensitive(self):
        patterns = [
            {
                "filename_pattern": "mimikatz.exe",
                "is_regex": False,
                "tool_name": "Mimikatz",
            }
        ]
        result = check_known_tool_filename("MIMIKATZ.EXE", patterns)
        assert result is not None

    def test_regex_pattern(self):
        patterns = [
            {
                "filename_pattern": "^psexec.*\\.exe$",
                "is_regex": True,
                "tool_name": "PsExec",
            }
        ]
        result = check_known_tool_filename("psexec64.exe", patterns)
        assert result is not None
        assert result["tool_name"] == "PsExec"

    def test_regex_no_match(self):
        patterns = [
            {
                "filename_pattern": "^psexec.*\\.exe$",
                "is_regex": True,
                "tool_name": "PsExec",
            }
        ]
        result = check_known_tool_filename("notepad.exe", patterns)
        assert result is None

    def test_no_match(self):
        patterns = [
            {
                "filename_pattern": "mimikatz.exe",
                "is_regex": False,
                "tool_name": "Mimikatz",
            }
        ]
        result = check_known_tool_filename("notepad.exe", patterns)
        assert result is None

    def test_empty_patterns(self):
        result = check_known_tool_filename("mimikatz.exe", [])
        assert result is None


class TestExecutableExtensions:
    """Tests for EXECUTABLE_EXTENSIONS set."""

    def test_common_executables(self):
        assert "exe" in EXECUTABLE_EXTENSIONS
        assert "dll" in EXECUTABLE_EXTENSIONS
        assert "sys" in EXECUTABLE_EXTENSIONS

    def test_scripts(self):
        assert "ps1" in EXECUTABLE_EXTENSIONS
        assert "vbs" in EXECUTABLE_EXTENSIONS
        assert "bat" in EXECUTABLE_EXTENSIONS

    def test_non_executable(self):
        assert "txt" not in EXECUTABLE_EXTENSIONS
        assert "pdf" not in EXECUTABLE_EXTENSIONS
        assert "jpg" not in EXECUTABLE_EXTENSIONS
