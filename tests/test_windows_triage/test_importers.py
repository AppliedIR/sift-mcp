"""Tests for data importers."""

import pytest
from windows_triage.importers.process_expectations import (
    get_process_tree,
    get_system_processes,
    get_user_processes,
    load_process_expectations,
)


@pytest.fixture
def process_expectations():
    """Load process expectations from YAML."""
    return load_process_expectations()


class TestProcessExpectations:
    """Tests for process expectations (from YAML - sourced from MemProcFS + SANS Hunt Evil)."""

    def test_process_expectations_not_empty(self, process_expectations):
        """Test that we have process expectations."""
        assert len(process_expectations) > 0

    def test_system_process_has_no_parent(self, process_expectations):
        """Test that System process has no parent."""
        system = next(
            (p for p in process_expectations if p["process_name"] == "system"), None
        )
        assert system is not None
        assert system["valid_parents"] == []

    def test_smss_parent_is_system(self, process_expectations):
        """Test that smss.exe parent is system."""
        smss = next(
            (p for p in process_expectations if p["process_name"] == "smss.exe"), None
        )
        assert smss is not None
        assert "system" in smss["valid_parents"]

    def test_svchost_parent_is_services(self, process_expectations):
        """Test that svchost.exe parent is services.exe."""
        svchost = next(
            (p for p in process_expectations if p["process_name"] == "svchost.exe"),
            None,
        )
        assert svchost is not None
        assert "services.exe" in svchost["valid_parents"]

    def test_lsass_parent_is_wininit(self, process_expectations):
        """Test that lsass.exe parent is wininit.exe."""
        lsass = next(
            (p for p in process_expectations if p["process_name"] == "lsass.exe"), None
        )
        assert lsass is not None
        assert "wininit.exe" in lsass["valid_parents"]

    def test_cmd_user_type(self, process_expectations):
        """Test that cmd.exe can run as EITHER user or SYSTEM.

        cmd.exe runs as USER when launched interactively, but also runs
        as SYSTEM when services or scheduled tasks execute batch scripts.
        """
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        assert cmd is not None
        assert cmd["user_type"] == "EITHER"

    def test_powershell_user_type(self, process_expectations):
        """Test that powershell.exe can run as EITHER user or SYSTEM.

        PowerShell runs as USER when launched interactively, but also runs
        as SYSTEM when services or scheduled tasks execute scripts.
        """
        ps = next(
            (p for p in process_expectations if p["process_name"] == "powershell.exe"),
            None,
        )
        assert ps is not None
        assert ps["user_type"] == "EITHER"

    def test_csrss_is_system_process(self, process_expectations):
        """Test that csrss.exe should run as SYSTEM."""
        csrss = next(
            (p for p in process_expectations if p["process_name"] == "csrss.exe"), None
        )
        assert csrss is not None
        assert csrss["user_type"] == "SYSTEM"

    def test_csrss_parent_exits(self, process_expectations):
        """Test that csrss.exe parent (smss) exits after spawning."""
        csrss = next(
            (p for p in process_expectations if p["process_name"] == "csrss.exe"), None
        )
        assert csrss is not None
        assert csrss["parent_exits"] is True

    def test_explorer_parent_exits(self, process_expectations):
        """Test that explorer.exe parent (userinit) exits after spawning."""
        explorer = next(
            (p for p in process_expectations if p["process_name"] == "explorer.exe"),
            None,
        )
        assert explorer is not None
        assert explorer["parent_exits"] is True


class TestProcessTreeHelpers:
    """Tests for process tree helper functions."""

    def test_get_process_tree(self):
        """Test getting the process tree."""
        tree = get_process_tree()
        assert "system" in tree
        assert "smss.exe" in tree["system"]
        assert "services.exe" in tree
        assert "svchost.exe" in tree["services.exe"]

    def test_get_system_processes(self):
        """Test getting SYSTEM processes."""
        system_procs = get_system_processes()
        assert "system" in system_procs
        assert "lsass.exe" in system_procs
        assert "services.exe" in system_procs
        assert "csrss.exe" in system_procs
        # User processes should not be in list
        assert "cmd.exe" not in system_procs
        assert "powershell.exe" not in system_procs

    def test_get_user_processes(self):
        """Test getting USER processes.

        Note: cmd.exe and powershell.exe are now EITHER (can run as SYSTEM
        in services/tasks), so they're not in the strict USER-only list.
        """
        user_procs = get_user_processes()
        assert "explorer.exe" in user_procs
        assert "userinit.exe" in user_procs
        # EITHER processes should not be in strict USER list
        assert "cmd.exe" not in user_procs
        assert "powershell.exe" not in user_procs
        # SYSTEM processes should not be in list
        assert "lsass.exe" not in user_procs
        assert "services.exe" not in user_procs


class TestSuspiciousParents:
    """Tests for suspicious_parents blacklist feature."""

    def test_cmd_has_suspicious_parents(self, process_expectations):
        """Test that cmd.exe has suspicious_parents defined."""
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        assert cmd is not None
        assert "suspicious_parents" in cmd
        assert len(cmd["suspicious_parents"]) == 80

    def test_powershell_has_suspicious_parents(self, process_expectations):
        """Test that powershell.exe has suspicious_parents defined."""
        ps = next(
            (p for p in process_expectations if p["process_name"] == "powershell.exe"),
            None,
        )
        assert ps is not None
        assert "suspicious_parents" in ps
        assert len(ps["suspicious_parents"]) == 80

    def test_pwsh_has_suspicious_parents(self, process_expectations):
        """Test that pwsh.exe has suspicious_parents defined."""
        pwsh = next(
            (p for p in process_expectations if p["process_name"] == "pwsh.exe"), None
        )
        assert pwsh is not None
        assert "suspicious_parents" in pwsh
        assert len(pwsh["suspicious_parents"]) == 80

    def test_all_shells_have_same_suspicious_parents(self, process_expectations):
        """Test that all shell processes have identical suspicious_parents."""
        shells = ["cmd.exe", "powershell.exe", "pwsh.exe"]
        parents_sets = []
        for shell in shells:
            proc = next(
                (p for p in process_expectations if p["process_name"] == shell), None
            )
            parents_sets.append(set(proc["suspicious_parents"]))
        # All should be identical
        assert parents_sets[0] == parents_sets[1] == parents_sets[2]

    def test_office_apps_in_suspicious_parents(self, process_expectations):
        """Test that Office apps are in suspicious_parents."""
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        sus = cmd["suspicious_parents"]
        office_apps = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
        for app in office_apps:
            assert app in sus, f"{app} should be in suspicious_parents"

    def test_browsers_in_suspicious_parents(self, process_expectations):
        """Test that browsers are in suspicious_parents."""
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        sus = cmd["suspicious_parents"]
        browsers = ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"]
        for browser in browsers:
            assert browser in sus, f"{browser} should be in suspicious_parents"

    def test_dcom_objects_in_suspicious_parents(self, process_expectations):
        """Test that DCOM abuse executables are in suspicious_parents."""
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        sus = cmd["suspicious_parents"]
        dcom = ["mmc.exe", "dllhost.exe", "wmiprvse.exe", "scrcons.exe"]
        for obj in dcom:
            assert obj in sus, f"{obj} should be in suspicious_parents"

    def test_injection_targets_in_suspicious_parents(self, process_expectations):
        """Test that injection targets are in suspicious_parents."""
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        sus = cmd["suspicious_parents"]
        injection = ["lsass.exe", "csrss.exe", "smss.exe", "spoolsv.exe"]
        for target in injection:
            assert target in sus, f"{target} should be in suspicious_parents"

    def test_explorer_not_in_suspicious_parents(self, process_expectations):
        """Test that explorer.exe is NOT in suspicious_parents (legitimate)."""
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        assert "explorer.exe" not in cmd["suspicious_parents"]

    def test_svchost_not_in_suspicious_parents(self, process_expectations):
        """Test that svchost.exe is NOT in suspicious_parents (scheduled tasks)."""
        cmd = next(
            (p for p in process_expectations if p["process_name"] == "cmd.exe"), None
        )
        # svchost spawns cmd for scheduled tasks - legitimate
        assert "svchost.exe" not in cmd["suspicious_parents"]

    def test_net1_whitelist_approach(self, process_expectations):
        """Test that net1.exe uses whitelist (valid_parents) not blacklist.

        net1.exe should ONLY be spawned by net.exe. Direct invocation
        bypasses detection that hooks net.exe.
        """
        net1 = next(
            (p for p in process_expectations if p["process_name"] == "net1.exe"), None
        )
        assert net1 is not None, "net1.exe should be in process expectations"
        assert net1.get("valid_parents") == ["net.exe"], (
            "net1.exe should have valid_parents = ['net.exe'] (whitelist)"
        )
        assert net1.get("suspicious_parents") is None, (
            "net1.exe should not use suspicious_parents (blacklist)"
        )


class TestExpectationValidity:
    """Tests to verify expectation data validity."""

    def test_all_have_process_name(self, process_expectations):
        """Test that all expectations have a process name."""
        for proc in process_expectations:
            assert "process_name" in proc
            assert proc["process_name"]

    def test_all_have_user_type(self, process_expectations):
        """Test that all expectations have a user type."""
        valid_types = {"SYSTEM", "USER", "EITHER"}
        for proc in process_expectations:
            assert proc.get("user_type") in valid_types

    def test_all_have_source(self, process_expectations):
        """Test that all expectations have a source."""
        for proc in process_expectations:
            assert "source" in proc
            assert proc["source"]

    def test_valid_parents_is_list_or_null(self, process_expectations):
        """Test that valid_parents is always a list or null."""
        for proc in process_expectations:
            parents = proc.get("valid_parents")
            # Should be list or None
            assert parents is None or isinstance(parents, list)

    def test_valid_paths_lowercase(self, process_expectations):
        """Test that valid_paths are lowercase."""
        for proc in process_expectations:
            paths = proc.get("valid_paths")
            if paths:
                for path in paths:
                    assert path == path.lower(), f"Path not lowercase: {path}"
