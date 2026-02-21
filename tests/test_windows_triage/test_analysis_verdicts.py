"""Tests for verdict calculation logic."""

import pytest
from windows_triage.analysis.verdicts import (
    Verdict,
    VerdictResult,
    calculate_file_verdict,
    calculate_process_verdict,
    calculate_service_verdict,
    calculate_hash_verdict,
)


class TestVerdict:
    """Tests for Verdict enum (offline analysis only - no MALICIOUS verdict)."""

    def test_values(self):
        """Test all verdict values - MALICIOUS intentionally not included."""
        assert Verdict.SUSPICIOUS.value == "SUSPICIOUS"
        assert Verdict.EXPECTED_LOLBIN.value == "EXPECTED_LOLBIN"
        assert Verdict.EXPECTED.value == "EXPECTED"
        assert Verdict.UNKNOWN.value == "UNKNOWN"
        # MALICIOUS is intentionally not in the offline verdict system
        assert not hasattr(Verdict, 'MALICIOUS')

    def test_str(self):
        assert str(Verdict.SUSPICIOUS) == "SUSPICIOUS"
        assert str(Verdict.UNKNOWN) == "UNKNOWN"


class TestVerdictResult:
    """Tests for VerdictResult dataclass."""

    def test_to_dict(self):
        result = VerdictResult(
            verdict=Verdict.EXPECTED,
            reasons=["Path matches baseline"],
            confidence="high"
        )
        d = result.to_dict()
        assert d['verdict'] == "EXPECTED"
        assert d['reasons'] == ["Path matches baseline"]
        assert d['confidence'] == "high"


class TestCalculateFileVerdict:
    """Tests for calculate_file_verdict function (offline analysis only)."""

    def test_critical_filename_finding(self):
        """Critical findings like double extension should be SUSPICIOUS."""
        findings = [{
            'type': 'double_extension',
            'severity': 'critical',
            'description': 'Double extension detected'
        }]
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=findings,
            lolbin_info=None
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_known_tool_pattern(self):
        """Known attack tools should be SUSPICIOUS."""
        findings = [{
            'type': 'known_tool',
            'severity': 'high',
            'tool_name': 'Mimikatz',
            'category': 'credential_theft'
        }]
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=findings,
            lolbin_info=None
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_path_in_baseline(self):
        """File path in baseline should be EXPECTED."""
        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None
        )
        assert result.verdict == Verdict.EXPECTED
        assert result.confidence == 'high'

    def test_path_in_baseline_lolbin(self):
        """File in baseline that's a LOLBin should be EXPECTED_LOLBIN."""
        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info={'name': 'certutil.exe', 'functions': ['Download', 'Execute']}
        )
        assert result.verdict == Verdict.EXPECTED_LOLBIN
        assert "LOLBin" in result.reasons[1]

    def test_filename_in_baseline_system_path(self):
        """Filename in baseline in system path should be EXPECTED with medium confidence."""
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None
        )
        assert result.verdict == Verdict.EXPECTED
        assert result.confidence == 'medium'

    def test_lolbin_wrong_location(self):
        """LOLBin in non-system path should be SUSPICIOUS."""
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,  # Not in system path
            filename_findings=[],
            lolbin_info={'name': 'certutil.exe', 'functions': ['Download']}
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert "non-standard location" in result.reasons[0]

    def test_unknown_file(self):
        """File not in any database should be UNKNOWN (neutral)."""
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=[],
            lolbin_info=None
        )
        assert result.verdict == Verdict.UNKNOWN
        assert "neutral" in result.reasons[0].lower()

    def test_protected_process_wrong_path(self):
        """Protected process name outside system path should be SUSPICIOUS."""
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,
            is_system_path=False,  # Wrong path!
            filename_findings=[],
            lolbin_info=None,
            is_protected_process=True
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_high_severity_findings(self):
        """High severity findings should be SUSPICIOUS."""
        findings = [{
            'type': 'high_entropy',
            'severity': 'high',
            'description': 'High entropy filename'
        }]
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=findings,
            lolbin_info=None
        )
        assert result.verdict == Verdict.SUSPICIOUS


class TestCalculateProcessVerdict:
    """Tests for calculate_process_verdict function."""

    def test_process_spoofing_critical(self):
        findings = [{
            'type': 'process_spoofing',
            'severity': 'critical',
            'description': 'Possible spoofing of svchost.exe'
        }]
        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=findings
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.confidence == 'high'

    def test_unknown_process_no_findings(self):
        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=[]
        )
        assert result.verdict == Verdict.UNKNOWN

    def test_known_process_valid_parent(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=True,
            user_valid=True,
            findings=[]
        )
        assert result.verdict == Verdict.EXPECTED
        assert result.confidence == 'high'

    def test_known_process_invalid_parent(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=False,
            path_valid=True,
            user_valid=True,
            findings=[]
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert "parent" in result.reasons[0].lower()

    def test_known_process_invalid_path(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=False,  # Wrong path
            user_valid=True,
            findings=[]
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert "path" in result.reasons[0].lower()

    def test_known_process_invalid_user(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=True,
            user_valid=False,  # Wrong user
            findings=[]
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert "user" in result.reasons[0].lower()

    def test_path_none_not_flagged(self):
        # path_valid=None means we didn't check it
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=[]
        )
        assert result.verdict == Verdict.EXPECTED


class TestCalculateServiceVerdict:
    """Tests for calculate_service_verdict function."""

    def test_service_in_baseline(self):
        result = calculate_service_verdict(
            service_in_baseline=True,
            binary_path_matches=True,
            binary_findings=[]
        )
        assert result.verdict == Verdict.EXPECTED

    def test_service_in_baseline_binary_differs(self):
        result = calculate_service_verdict(
            service_in_baseline=True,
            binary_path_matches=False,  # Binary path changed
            binary_findings=[]
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert "hijacked" in result.reasons[1].lower()

    def test_critical_binary_finding(self):
        findings = [{
            'type': 'double_extension',
            'severity': 'critical',
            'description': 'Double extension'
        }]
        result = calculate_service_verdict(
            service_in_baseline=True,
            binary_path_matches=True,
            binary_findings=findings
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_unknown_service(self):
        result = calculate_service_verdict(
            service_in_baseline=False,
            binary_path_matches=None,
            binary_findings=[]
        )
        assert result.verdict == Verdict.UNKNOWN
        assert "neutral" in result.reasons[0].lower()


class TestCalculateHashVerdict:
    """Tests for calculate_hash_verdict function (offline analysis only).

    Note: This function no longer accepts opencti_result. For threat intel,
    use opencti-mcp separately.
    """

    def test_vulnerable_driver(self):
        """Vulnerable driver should be SUSPICIOUS."""
        result = calculate_hash_verdict(
            is_vulnerable_driver=True,
            driver_info={'product': 'RTCore64.sys', 'cve': 'CVE-2019-16098'}
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert "CVE" in result.reasons[1]

    def test_lolbin_hash(self):
        """Known LOLBin hash should be EXPECTED_LOLBIN."""
        result = calculate_hash_verdict(
            is_lolbin=True,
            lolbin_info={'name': 'certutil.exe'}
        )
        assert result.verdict == Verdict.EXPECTED_LOLBIN

    def test_unknown_hash(self):
        """Hash not in local databases should be UNKNOWN."""
        result = calculate_hash_verdict()
        assert result.verdict == Verdict.UNKNOWN
        assert "opencti" in result.reasons[1].lower()

    def test_vulnerable_driver_with_details(self):
        """Vulnerable driver with full details."""
        result = calculate_hash_verdict(
            is_vulnerable_driver=True,
            driver_info={
                'product': 'Vulnerable Driver',
                'cve': 'CVE-2021-12345',
                'vulnerability_type': 'Arbitrary Read/Write'
            }
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.confidence == 'high'
        assert any('Vulnerability' in r for r in result.reasons)
