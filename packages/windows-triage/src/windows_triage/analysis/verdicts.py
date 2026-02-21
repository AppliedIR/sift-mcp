"""
Verdict Calculation Logic for Windows Triage

This module implements the verdict calculation system that determines the
final assessment for files, processes, services, and hashes based on
OFFLINE analysis against local baselines.

For threat intelligence (MALICIOUS verdict), use opencti-mcp separately.

Verdict Categories (in priority order):

    SUSPICIOUS - Anomalies or suspicious patterns detected
        - Hash mismatch on known path (trojanized binary)
        - Protected process name in wrong location (svchost.exe in C:\\Temp)
        - Unicode evasion (RLO attacks, homoglyphs)
        - Double extensions (invoice.pdf.exe)
        - Unexpected process parent (Word spawning cmd.exe)
        - Known tool patterns (mimikatz.exe)
        - LOLBin in non-standard location
        - Vulnerable driver detected

    EXPECTED_LOLBIN - Matches baseline AND is a LOLBin
        - LOLBin in expected location (certutil.exe in System32)
        - Legitimate Windows tool that can be abused for malicious purposes

    EXPECTED - Matches Windows baseline, no risk factors
        - Path and/or filename found in VanillaWindowsReference
        - No LOLBin, no suspicious patterns

    UNKNOWN - Not in any database (NEUTRAL, not suspicious)
        - Our baseline cannot cover all legitimate software
        - Third-party apps, enterprise tools, or newer Windows components
        - Only flag as suspicious if actual indicators present

Key Design Decisions:

    1. Verdict Priority: SUSPICIOUS > EXPECTED_LOLBIN > EXPECTED > UNKNOWN
       Higher-risk verdicts always take precedence to prevent false negatives.

    2. UNKNOWN is neutral: Being absent from our baseline is NOT suspicious.
       Many legitimate applications won't be in VanillaWindowsReference.

    3. Path + filename validation: A file can be EXPECTED even if only the
       filename matches baseline AND it's in a system directory.

    4. Protected process detection: Critical system processes (svchost.exe,
       lsass.exe, csrss.exe) in non-system paths are always SUSPICIOUS.

    5. No MALICIOUS verdict: This module is offline-only. For threat
       intelligence lookups, use opencti-mcp which can return MALICIOUS.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, List


class Verdict(Enum):
    """Triage verdict categories (offline analysis only).

    Note: MALICIOUS is intentionally not included. For threat intelligence
    lookups that can identify malware, use opencti-mcp separately.
    """
    SUSPICIOUS = "SUSPICIOUS"
    EXPECTED_LOLBIN = "EXPECTED_LOLBIN"
    EXPECTED = "EXPECTED"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value


@dataclass
class VerdictResult:
    """Result of verdict calculation with reasoning."""
    verdict: Verdict
    reasons: List[str]
    confidence: str  # "high", "medium", "low"

    def to_dict(self) -> dict:
        return {
            'verdict': str(self.verdict),
            'reasons': self.reasons,
            'confidence': self.confidence
        }


def calculate_file_verdict(
    path_in_baseline: bool,
    filename_in_baseline: bool,
    is_system_path: bool,
    filename_findings: List[dict],
    lolbin_info: Optional[dict],
    is_protected_process: bool = False
) -> VerdictResult:
    """
    Calculate verdict for a file/path check (offline analysis only).

    For threat intelligence lookups, use opencti-mcp separately.

    Args:
        path_in_baseline: True if exact path exists in baseline
        filename_in_baseline: True if filename exists in baseline (any path)
        is_system_path: True if path is in Windows system directories
        filename_findings: Findings from filename analysis (unicode, patterns, etc.)
        lolbin_info: LOLBin info if filename is a known LOLBin
        is_protected_process: True if filename matches a protected process name

    Returns:
        VerdictResult with verdict, reasons, and confidence
    """
    reasons = []

    # Priority 1: Critical filename issues (unicode evasion, double extension)
    critical_findings = [f for f in filename_findings if f.get('severity') == 'critical']
    if critical_findings:
        reasons.append("Critical filename issues detected")
        for finding in critical_findings[:2]:
            reasons.append(finding.get('description', finding.get('type')))
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    # Priority 3: Suspicious filename patterns (known tools)
    tool_findings = [f for f in filename_findings if f.get('type') == 'known_tool']
    if tool_findings:
        reasons.append(f"Known tool: {tool_findings[0].get('tool_name', 'unknown')}")
        reasons.append(f"Category: {tool_findings[0].get('category', 'unknown')}")
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    # Priority 4: Path or filename matches baseline
    if path_in_baseline:
        if lolbin_info:
            reasons.append("Path matches Windows baseline")
            reasons.append(f"LOLBin: can be abused for {', '.join(lolbin_info.get('functions', [])[:2])}")
            return VerdictResult(
                verdict=Verdict.EXPECTED_LOLBIN,
                reasons=reasons,
                confidence='high'
            )
        reasons.append("Path matches Windows baseline")
        return VerdictResult(
            verdict=Verdict.EXPECTED,
            reasons=reasons,
            confidence='high'
        )

    if filename_in_baseline and is_system_path:
        if lolbin_info:
            reasons.append("Filename matches Windows baseline")
            reasons.append("Located in system directory")
            reasons.append(f"LOLBin: can be abused for {', '.join(lolbin_info.get('functions', [])[:2])}")
            return VerdictResult(
                verdict=Verdict.EXPECTED_LOLBIN,
                reasons=reasons,
                confidence='medium'
            )
        reasons.append("Filename matches Windows baseline")
        reasons.append("Located in system directory")
        return VerdictResult(
            verdict=Verdict.EXPECTED,
            reasons=reasons,
            confidence='medium'
        )

    # Priority 5: Just a LOLBin name (not in expected location)
    if lolbin_info and not is_system_path:
        reasons.append(f"LOLBin ({lolbin_info.get('name', 'unknown')}) in non-standard location")
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='medium'
        )

    # Priority 5b: Protected system process name in non-system location
    # These are critical Windows processes that should ONLY run from System32
    if is_protected_process and not is_system_path:
        reasons.append("Protected system process name found outside system directory")
        reasons.append("Likely process masquerading attempt")
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    # Priority 6: High severity filename issues
    high_findings = [f for f in filename_findings if f.get('severity') == 'high']
    if high_findings:
        for finding in high_findings[:2]:
            reasons.append(finding.get('description', finding.get('type')))
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='medium'
        )

    # Default: Unknown (neutral - just not in our baseline)
    reasons.append("Not in baseline (neutral - may be legitimate third-party software)")
    return VerdictResult(
        verdict=Verdict.UNKNOWN,
        reasons=reasons,
        confidence='low'
    )


def calculate_process_verdict(
    process_known: bool,
    parent_valid: bool,
    path_valid: Optional[bool],
    user_valid: Optional[bool],
    findings: List[dict]
) -> VerdictResult:
    """
    Calculate verdict for a process tree check.

    Args:
        process_known: True if process is in expected_processes table
        parent_valid: True if parent is valid for this process
        path_valid: True if path is valid (None if not checked)
        user_valid: True if user context is valid (None if not checked)
        findings: List of anomaly findings

    Returns:
        VerdictResult
    """
    reasons = []

    # Check for critical findings first (e.g., process spoofing)
    critical_findings = [f for f in findings if f.get('severity') == 'critical']
    if critical_findings:
        for finding in critical_findings:
            reasons.append(finding.get('description', finding.get('type')))
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    if not process_known:
        # Not in our expectations database - check for other issues
        # (Critical findings already handled above and returned)
        # Check high severity findings
        high_findings = [f for f in findings if f.get('severity') == 'high']
        if high_findings:
            for finding in high_findings[:2]:
                reasons.append(finding.get('description', finding.get('type')))
            return VerdictResult(
                verdict=Verdict.SUSPICIOUS,
                reasons=reasons,
                confidence='medium'
            )
        reasons.append("Process not in expectations database (neutral)")
        return VerdictResult(
            verdict=Verdict.UNKNOWN,
            reasons=reasons,
            confidence='low'
        )

    # Process is known - check relationships
    if not parent_valid:
        reasons.append("Unexpected parent process")
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    if path_valid is False:  # Explicitly False, not None
        reasons.append("Unexpected executable path")
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    if user_valid is False:  # Explicitly False, not None
        reasons.append("Unexpected user context")
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='medium'
        )

    # All checks passed
    reasons.append("Process relationship matches expectations")
    return VerdictResult(
        verdict=Verdict.EXPECTED,
        reasons=reasons,
        confidence='high'
    )


def calculate_service_verdict(
    service_in_baseline: bool,
    binary_path_matches: Optional[bool],
    binary_findings: List[dict]
) -> VerdictResult:
    """
    Calculate verdict for a service check.

    Args:
        service_in_baseline: True if service name exists in baseline
        binary_path_matches: True if binary path matches baseline (None if not checked)
        binary_findings: Findings about the binary path/name

    Returns:
        VerdictResult
    """
    reasons = []

    # Check for suspicious binary
    critical_findings = [f for f in binary_findings if f.get('severity') == 'critical']
    if critical_findings:
        for finding in critical_findings[:2]:
            reasons.append(finding.get('description', finding.get('type')))
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    if service_in_baseline:
        if binary_path_matches is False:
            reasons.append("Service name in baseline but binary path differs")
            reasons.append("May indicate hijacked service")
            return VerdictResult(
                verdict=Verdict.SUSPICIOUS,
                reasons=reasons,
                confidence='medium'
            )
        reasons.append("Service matches Windows baseline")
        return VerdictResult(
            verdict=Verdict.EXPECTED,
            reasons=reasons,
            confidence='high'
        )

    # Unknown service
    high_findings = [f for f in binary_findings if f.get('severity') == 'high']
    if high_findings:
        for finding in high_findings[:2]:
            reasons.append(finding.get('description', finding.get('type')))
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='medium'
        )

    reasons.append("Service not in baseline (neutral - may be third-party or enterprise software)")
    return VerdictResult(
        verdict=Verdict.UNKNOWN,
        reasons=reasons,
        confidence='low'
    )


def calculate_hash_verdict(
    is_vulnerable_driver: bool = False,
    driver_info: Optional[dict] = None,
    is_lolbin: bool = False,
    lolbin_info: Optional[dict] = None,
) -> VerdictResult:
    """
    Calculate verdict for a hash-only lookup (offline analysis only).

    Checks against vulnerable driver database. For threat intelligence
    lookups, use opencti-mcp separately.

    Args:
        is_vulnerable_driver: True if hash matches vulnerable driver
        driver_info: Driver details from LOLDrivers database
        is_lolbin: True if hash matches a known LOLBin
        lolbin_info: LOLBin details

    Returns:
        VerdictResult
    """
    reasons = []

    # Vulnerable driver (BYOVD attack potential)
    if is_vulnerable_driver and driver_info:
        reasons.append(f"Vulnerable driver: {driver_info.get('product', 'unknown')}")
        if driver_info.get('cve'):
            reasons.append(f"CVE: {driver_info['cve']}")
        if driver_info.get('vulnerability_type'):
            reasons.append(f"Vulnerability: {driver_info['vulnerability_type']}")
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=reasons,
            confidence='high'
        )

    # Known LOLBin hash
    if is_lolbin and lolbin_info:
        reasons.append(f"LOLBin: {lolbin_info.get('name', 'unknown')}")
        return VerdictResult(
            verdict=Verdict.EXPECTED_LOLBIN,
            reasons=reasons,
            confidence='medium'
        )

    # Hash not in local databases
    reasons.append("Hash not found in local databases (neutral)")
    reasons.append("For threat intel, query opencti-mcp")
    return VerdictResult(
        verdict=Verdict.UNKNOWN,
        reasons=reasons,
        confidence='low'
    )
