"""Tests for sift-mcp security utilities — path validation, denylist, rm protection."""

import os

import pytest

from sift_mcp.security import (
    validate_input_path,
    sanitize_extra_args,
    is_denied,
    validate_rm_targets,
)


# --- Denylist ---

class TestDenylist:
    """is_denied() checks against the hard denylist."""

    def test_mkfs_denied(self):
        assert is_denied("mkfs") is True

    def test_mkfs_ext4_denied(self):
        assert is_denied("mkfs.ext4") is True

    def test_dd_denied(self):
        assert is_denied("dd") is True

    def test_shutdown_denied(self):
        assert is_denied("shutdown") is True

    def test_fdisk_denied(self):
        assert is_denied("fdisk") is True

    def test_mount_denied(self):
        assert is_denied("mount") is True

    def test_kill_denied(self):
        assert is_denied("kill") is True

    def test_rm_not_denied(self):
        assert is_denied("rm") is False

    def test_fls_not_denied(self):
        assert is_denied("fls") is False

    def test_strings_not_denied(self):
        assert is_denied("strings") is False

    def test_bash_not_denied(self):
        assert is_denied("bash") is False

    def test_case_insensitive(self):
        assert is_denied("MKFS") is True
        assert is_denied("DD") is True


# --- rm Protection ---

class TestRmProtection:
    """validate_rm_targets() blocks rm in protected directories."""

    def test_rm_blocks_cases_dir(self):
        with pytest.raises(ValueError, match="protected evidence directory"):
            validate_rm_targets(["-rf", "/cases"])

    def test_rm_blocks_cases_subdir(self):
        with pytest.raises(ValueError, match="protected evidence directory"):
            validate_rm_targets(["/cases/INC-001/file.txt"])

    def test_rm_blocks_evidence_dir(self):
        with pytest.raises(ValueError, match="protected evidence directory"):
            validate_rm_targets(["/evidence/disk.dd"])

    def test_rm_blocks_case_evidence(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "INC-2026-001"
        case_dir.mkdir()
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir()
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        with pytest.raises(ValueError, match="case evidence"):
            validate_rm_targets([str(evidence_dir / "file.img")])

    def test_rm_allows_tmp(self):
        # Should not raise
        validate_rm_targets(["/tmp/output.csv"])

    def test_rm_allows_regular_file(self):
        validate_rm_targets(["-f", "/opt/work/temp.txt"])

    def test_rm_blocks_root(self):
        with pytest.raises(ValueError, match="filesystem root"):
            validate_rm_targets(["-rf", "/"])

    def test_rm_ignores_flags(self):
        """Flags (starting with -) are not treated as paths."""
        validate_rm_targets(["-rf"])  # should not raise


# --- Path validation ---

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

    def test_blocks_etc_passwd(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/etc/passwd")

    def test_blocks_boot(self):
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("/boot/vmlinuz")

    def test_allows_home_directory(self):
        """Paths in /home are now allowed for forensic analysis."""
        result = validate_input_path("/home/user/evidence/disk.dd")
        assert result.endswith("disk.dd")

    def test_allows_tmp(self):
        """Paths in /tmp are now allowed."""
        result = validate_input_path("/tmp/evidence.img")
        assert result.endswith("evidence.img")

    def test_allows_var_log(self):
        """Paths in /var/log are now allowed for forensic analysis."""
        result = validate_input_path("/var/log/syslog")
        assert result.endswith("syslog")

    def test_allows_usr(self):
        """Paths in /usr are now allowed."""
        result = validate_input_path("/usr/bin/ls")
        assert result.endswith("ls")

    def test_allows_cases_evidence(self):
        """Paths in /cases should pass validation."""
        result = validate_input_path("/cases/test/image.E01")
        assert result.endswith("image.E01")

    def test_allows_opt_directory(self):
        """Paths in /opt should pass validation."""
        result = validate_input_path("/opt/tools/evidence/disk.dd")
        assert result.endswith("disk.dd")

    def test_symlink_to_blocked_dir(self, tmp_path):
        """Symlink pointing to a blocked directory should be blocked."""
        import os
        link = tmp_path / "sneaky_link"
        os.symlink("/etc/passwd", str(link))
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path(str(link))

    def test_flag_value_path_validation(self):
        """flag=value arguments should have the value portion validated as a path."""
        with pytest.raises(ValueError, match="blocked system directory"):
            validate_input_path("--input=/etc/shadow")

    def test_flag_value_safe_path(self):
        """flag=value with safe path should pass."""
        result = validate_input_path("--input=/cases/evidence.img")
        assert result.endswith("evidence.img")


# --- Zeek script blocking ---

class TestZeekScriptBlocking:
    """Extra args containing Zeek scripts must be rejected."""

    def _check_zeek_args(self, extra_args: list[str]) -> None:
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
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["/tmp/evil.zeek"])

    def test_blocks_zeek_extension(self):
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["script.zeek"])

    def test_blocks_bro_extension(self):
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["old.bro"])

    def test_blocks_backslash_path(self):
        with pytest.raises(ValueError, match="Zeek script arguments not allowed"):
            self._check_zeek_args(["C:\\scripts\\evil.zeek"])

    def test_allows_normal_flags(self):
        self._check_zeek_args(["-C"])
        self._check_zeek_args(["--no-checksums"])
        self._check_zeek_args([])


# --- sanitize_extra_args ---

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
        result = sanitize_extra_args(["-e", "email"], "run_bulk_extractor")
        assert result == ["-e", "email"]

    # --- Per-tool blocked flags ---

    def test_find_exec_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*find"):
            sanitize_extra_args(["/cases", "-name", "*.log", "-exec", "rm", "{}", "+"], "find")

    def test_find_execdir_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*find"):
            sanitize_extra_args(["/cases", "-execdir", "cat", "{}", ";"], "find")

    def test_find_delete_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*find"):
            sanitize_extra_args(["/cases", "-name", "*.tmp", "-delete"], "find")

    def test_find_name_allowed(self):
        result = sanitize_extra_args(["/cases", "-name", "*.evtx", "-type", "f"], "find")
        assert "-name" in result

    def test_sed_inplace_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*sed"):
            sanitize_extra_args(["-i", "s/foo/bar/", "/cases/file.txt"], "sed")

    def test_sed_inplace_long_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*sed"):
            sanitize_extra_args(["--in-place", "s/foo/bar/", "/cases/file.txt"], "sed")

    def test_sed_read_only_allowed(self):
        result = sanitize_extra_args(["s/foo/bar/", "/cases/file.txt"], "sed")
        assert "s/foo/bar/" in result

    def test_find_fls_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*find"):
            sanitize_extra_args(["/cases", "-fls", "/tmp/output"], "find")

    def test_find_fprint_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*find"):
            sanitize_extra_args(["/cases", "-fprint", "/tmp/output"], "find")

    def test_find_fprint0_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*find"):
            sanitize_extra_args(["/cases", "-fprint0", "/tmp/output"], "find")

    def test_find_fprintf_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag.*find"):
            sanitize_extra_args(["/cases", "-fprintf", "/tmp/output", "%p"], "find")


# --- Security policy YAML ---

class TestSecurityPolicyYAML:
    """Verify security policy loads from YAML and matches expected contents."""

    def test_security_policy_loads_from_yaml(self):
        from sift_mcp.catalog import load_security_policy, clear_catalog_cache
        clear_catalog_cache()
        policy = load_security_policy()

        assert isinstance(policy["dangerous_flags"], set)
        assert "-e" in policy["dangerous_flags"]
        assert "--exec" in policy["dangerous_flags"]

        assert isinstance(policy["denied_binaries"], frozenset)
        assert "mkfs" in policy["denied_binaries"]
        assert "dd" in policy["denied_binaries"]
        assert "kill" in policy["denied_binaries"]

        assert "run_bulk_extractor" in policy["tool_allowed_flags"]
        assert "-e" in policy["tool_allowed_flags"]["run_bulk_extractor"]

        assert "find" in policy["tool_blocked_flags"]
        assert "-exec" in policy["tool_blocked_flags"]["find"]
        assert "sed" in policy["tool_blocked_flags"]
        assert "-i" in policy["tool_blocked_flags"]["sed"]

        clear_catalog_cache()
