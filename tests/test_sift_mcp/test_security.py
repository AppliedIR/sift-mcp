"""Tests for sift-mcp security utilities — path validation, Zeek script blocking."""

import pytest

from sift_mcp.security import validate_input_path, sanitize_extra_args


# --- T2: Path traversal blocking ---

class TestValidateInputPath:
    """validate_input_path must block access to sensitive system directories."""

    def test_blocks_etc_shadow(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/etc/shadow")

    def test_blocks_proc_cmdline(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/proc/1/cmdline")

    def test_blocks_sys_class(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/sys/class")

    def test_blocks_dev_sda(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/dev/sda")

    def test_blocks_usr(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/usr/bin/ls")

    def test_blocks_bin(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/bin/sh")

    def test_blocks_sbin(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/sbin/init")

    def test_blocks_etc_passwd(self):
        """Another /etc path to confirm all files under /etc are blocked."""
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/etc/passwd")

    def test_allows_tmp_evidence(self):
        """Paths in /tmp should pass validation."""
        result = validate_input_path("/tmp/evidence.img")
        assert result.endswith("evidence.img")

    def test_allows_cases_evidence(self):
        """Paths in /cases should pass validation."""
        result = validate_input_path("/cases/test/image.E01")
        assert result.endswith("image.E01")

    def test_allows_home_directory(self):
        """Paths in /home should pass validation."""
        result = validate_input_path("/home/user/evidence/disk.dd")
        assert result.endswith("disk.dd")


# --- T3: Zeek script blocking ---

class TestZeekScriptBlocking:
    """Extra args containing Zeek scripts must be rejected.

    The validation lives in run_zeek (network.py), but we test the
    patterns directly to avoid needing a real Zeek binary.
    """

    def _check_zeek_args(self, extra_args: list[str]) -> None:
        """Reproduce the Zeek-specific validation from network.py.

        This mirrors the exact checks in run_zeek after sanitize_extra_args.
        """
        sanitized = sanitize_extra_args(extra_args, "zeek")
        for arg in sanitized:
            if "/" in arg or "\\" in arg:
                raise ValueError(
                    "Zeek script arguments not allowed in extra_args: "
                    "use explicit parameters instead"
                )
            if arg.endswith(".zeek") or arg.endswith(".bro"):
                raise ValueError(
                    "Zeek script arguments not allowed in extra_args: "
                    "use explicit parameters instead"
                )

    def test_blocks_path_with_slash(self):
        """Args containing / are blocked (could be script paths)."""
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["/tmp/evil.zeek"])

    def test_blocks_zeek_extension(self):
        """Args ending in .zeek are blocked."""
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["script.zeek"])

    def test_blocks_bro_extension(self):
        """Args ending in .bro are blocked (legacy Zeek scripts)."""
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["old.bro"])

    def test_blocks_backslash_path(self):
        """Args containing backslash are blocked."""
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["C:\\scripts\\evil.zeek"])

    def test_allows_normal_flags(self):
        """Normal Zeek flags should pass validation."""
        # These should not raise
        self._check_zeek_args(["-C"])  # ignore checksums
        self._check_zeek_args(["--no-checksums"])
        self._check_zeek_args([])  # empty list


# --- Extra: sanitize_extra_args ---

class TestSanitizeExtraArgs:
    """Verify dangerous flag and shell metacharacter blocking."""

    def test_blocks_exec_flag(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["-e", "malicious"], "some_tool")

    def test_blocks_shell_metacharacter(self):
        with pytest.raises(ValueError, match="Blocked shell metacharacter"):
            sanitize_extra_args(["--flag; rm -rf /"], "some_tool")

    def test_blocks_command_substitution(self):
        with pytest.raises(ValueError, match="Blocked shell metacharacter"):
            sanitize_extra_args(["$(whoami)"], "some_tool")

    def test_allows_safe_flags(self):
        result = sanitize_extra_args(["-r", "--verbose", "-o", "output.txt"], "some_tool")
        assert result == ["-r", "--verbose", "-o", "output.txt"]

    def test_bulk_extractor_e_flag_allowed(self):
        """bulk_extractor is exempted for -e (scanner enable)."""
        result = sanitize_extra_args(["-e", "email"], "run_bulk_extractor")
        assert result == ["-e", "email"]
