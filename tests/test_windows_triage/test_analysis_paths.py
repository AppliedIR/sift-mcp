"""Tests for path normalization and analysis utilities."""

from windows_triage.analysis.paths import (
    check_suspicious_path,
    extract_directory,
    extract_filename,
    is_system_path,
    normalize_path,
    parse_service_binary_path,
)


class TestNormalizePath:
    """Tests for normalize_path function."""

    def test_lowercase(self):
        assert (
            normalize_path("C:\\Windows\\System32\\CMD.EXE")
            == "\\windows\\system32\\cmd.exe"
        )

    def test_remove_drive_letter(self):
        assert normalize_path("C:\\Windows\\file.txt") == "\\windows\\file.txt"
        assert normalize_path("D:\\Data\\file.txt") == "\\data\\file.txt"

    def test_normalize_separators(self):
        assert (
            normalize_path("C:/Windows/System32/cmd.exe")
            == "\\windows\\system32\\cmd.exe"
        )

    def test_remove_trailing_slashes(self):
        assert normalize_path("C:\\Windows\\System32\\") == "\\windows\\system32"

    def test_empty_path(self):
        assert normalize_path("") == ""
        assert normalize_path(None) is None

    def test_unc_path(self):
        # UNC paths don't have drive letter
        result = normalize_path("\\\\server\\share\\file.txt")
        assert result == "\\\\server\\share\\file.txt"

    def test_relative_path(self):
        assert normalize_path("file.txt") == "file.txt"


class TestExtractFilename:
    """Tests for extract_filename function."""

    def test_basic_path(self):
        assert extract_filename("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"

    def test_forward_slashes(self):
        assert extract_filename("C:/Windows/System32/notepad.exe") == "notepad.exe"

    def test_filename_only(self):
        assert extract_filename("file.txt") == "file.txt"

    def test_empty(self):
        assert extract_filename("") == ""

    def test_uppercase(self):
        assert extract_filename("C:\\Windows\\CMD.EXE") == "cmd.exe"


class TestExtractDirectory:
    """Tests for extract_directory function."""

    def test_basic_path(self):
        assert (
            extract_directory("C:\\Windows\\System32\\cmd.exe") == "\\windows\\system32"
        )

    def test_filename_only(self):
        assert extract_directory("file.txt") == ""

    def test_empty(self):
        assert extract_directory("") == ""


class TestIsSystemPath:
    """Tests for is_system_path function."""

    def test_system32(self):
        assert is_system_path("C:\\Windows\\System32\\cmd.exe") is True

    def test_syswow64(self):
        assert is_system_path("C:\\Windows\\SysWOW64\\cmd.exe") is True

    def test_windows_root(self):
        assert is_system_path("C:\\Windows\\explorer.exe") is True

    def test_program_files(self):
        assert is_system_path("C:\\Program Files\\App\\app.exe") is True

    def test_program_files_x86(self):
        assert is_system_path("C:\\Program Files (x86)\\App\\app.exe") is True

    def test_user_directory(self):
        assert is_system_path("C:\\Users\\Admin\\Desktop\\file.exe") is False

    def test_temp_directory(self):
        assert is_system_path("C:\\Temp\\malware.exe") is False


class TestCheckSuspiciousPath:
    """Tests for check_suspicious_path function."""

    def test_temp_directory(self):
        findings = check_suspicious_path("C:\\Temp\\file.exe")
        assert len(findings) == 1
        assert findings[0]["type"] == "suspicious_directory"
        assert "temp" in findings[0]["matched"]

    def test_appdata_local_temp(self):
        findings = check_suspicious_path(
            "C:\\Users\\Admin\\AppData\\Local\\Temp\\evil.exe"
        )
        assert len(findings) == 1
        assert "temp" in findings[0]["matched"]

    def test_users_public(self):
        findings = check_suspicious_path("C:\\Users\\Public\\Downloads\\file.exe")
        assert len(findings) == 1

    def test_recycler(self):
        findings = check_suspicious_path("C:\\$Recycle.Bin\\file.exe")
        assert len(findings) == 1

    def test_normal_path(self):
        findings = check_suspicious_path("C:\\Windows\\System32\\cmd.exe")
        assert len(findings) == 0

    def test_perflogs(self):
        findings = check_suspicious_path("C:\\PerfLogs\\malware.exe")
        assert len(findings) == 1


class TestParseServiceBinaryPath:
    """Tests for parse_service_binary_path function."""

    def test_quoted_path(self):
        result = parse_service_binary_path(
            '"C:\\Program Files\\Service\\svc.exe" -arg1'
        )
        assert result == "\\program files\\service\\svc.exe"

    def test_unquoted_path(self):
        result = parse_service_binary_path(
            "C:\\Windows\\System32\\svchost.exe -k netsvcs"
        )
        assert result == "\\windows\\system32\\svchost.exe"

    def test_systemroot_variable(self):
        result = parse_service_binary_path("%SystemRoot%\\System32\\svc.exe")
        assert result == "\\windows\\system32\\svc.exe"

    def test_systemroot_path(self):
        result = parse_service_binary_path(
            "\\SystemRoot\\System32\\drivers\\driver.sys"
        )
        assert result == "\\windows\\system32\\drivers\\driver.sys"

    def test_system32_relative(self):
        result = parse_service_binary_path("System32\\svc.exe")
        assert result == "\\windows\\system32\\svc.exe"

    def test_empty(self):
        result = parse_service_binary_path("")
        assert result == ""

    def test_driver_path(self):
        result = parse_service_binary_path("\\SystemRoot\\System32\\drivers\\tcpip.sys")
        assert result == "\\windows\\system32\\drivers\\tcpip.sys"


class TestNormalizePathEnvExpansion:
    """Regression pin for specs/windows-triage-env-var-normalize-2026-04-24.md.

    Pre-fix, registry values like %windir%\\system32\\cmd.exe missed
    baseline lookup and fell through to the masquerade-target check,
    producing false SUSPICIOUS verdicts on legitimate Windows 10/11
    autoruns (SecurityHealthSystray + friends). Post-fix, normalize_path
    expands the seven env-var placeholders BEFORE drive-strip /
    separator-flip so the paths resolve canonically.
    """

    def test_windir_expansion(self):
        assert (
            normalize_path(r"%windir%\system32\cmd.exe") == r"\windows\system32\cmd.exe"
        )

    def test_systemroot_expansion(self):
        assert (
            normalize_path(r"%SystemRoot%\System32\cmd.exe")
            == r"\windows\system32\cmd.exe"
        )

    def test_programfiles_expansion(self):
        assert (
            normalize_path(r"%ProgramFiles%\App\app.exe")
            == r"\program files\app\app.exe"
        )

    def test_programfiles_x86_expansion(self):
        assert (
            normalize_path(r"%ProgramFiles(x86)%\App\app.exe")
            == r"\program files (x86)\app\app.exe"
        )

    def test_programdata_expansion(self):
        assert (
            normalize_path(r"%ProgramData%\foo\bar.exe") == r"\programdata\foo\bar.exe"
        )

    def test_allusersprofile_expansion(self):
        """%AllUsersProfile% alias maps to ProgramData on Vista+."""
        assert normalize_path(r"%AllUsersProfile%\foo.exe") == r"\programdata\foo.exe"

    def test_systemdrive_expansion(self):
        """%SystemDrive% collapses to empty — the trailing path segment
        supplies the canonical prefix on its own.
        """
        assert (
            normalize_path(r"%SystemDrive%\windows\system32\cmd.exe")
            == r"\windows\system32\cmd.exe"
        )

    def test_legacy_systemroot_backslash(self):
        r"""\SystemRoot\ prefix from kernel-space paths still resolves."""
        assert (
            normalize_path(r"\SystemRoot\System32\cmd.exe")
            == r"\windows\system32\cmd.exe"
        )

    def test_case_insensitive_env_match(self):
        """Env-var matching is case-insensitive — registry values mix
        cases routinely (%WinDir%, %ProgramFILES%, etc.).
        """
        assert (
            normalize_path(r"%WINDIR%\System32\cmd.exe") == r"\windows\system32\cmd.exe"
        )
        assert (
            normalize_path(r"%ProgramFILES%\App\app.exe")
            == r"\program files\app\app.exe"
        )

    def test_drive_letter_still_stripped_after_no_env_match(self):
        """Concrete paths (no env var) still lose the drive letter —
        existing behavior is unchanged on the no-match branch.
        """
        assert (
            normalize_path(r"C:\Windows\System32\cmd.exe")
            == r"\windows\system32\cmd.exe"
        )

    def test_no_env_no_drive_unchanged(self):
        assert (
            normalize_path(r"\windows\system32\cmd.exe") == r"\windows\system32\cmd.exe"
        )

    def test_empty_preserved(self):
        assert normalize_path("") == ""

    def test_env_var_in_middle_not_expanded(self):
        """Only leading placeholders expand. Mid-path env vars stay
        literal — registry rarely stores them mid-path, and expanding
        inside args (e.g. `cmd /c echo %var%`) would be wrong.
        """
        result = normalize_path(r"\windows\system32\%windir%.txt")
        assert result == r"\windows\system32\%windir%.txt"
