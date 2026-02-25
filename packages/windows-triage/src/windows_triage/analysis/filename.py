"""
Filename Heuristics for Detecting Suspicious Files

This module analyzes filenames for suspicious characteristics commonly used
by malware to evade detection or trick users into executing malicious files.

Detection Capabilities:

    1. Double Extensions
       Files masquerading as documents: "report.pdf.exe", "invoice.docx.scr"
       Severity: Critical (common phishing/malware technique)

    2. Shannon Entropy Analysis
       High entropy suggests random/generated filenames.
       Malware often uses random names like "aX7kL9mQ.exe".
       Threshold: >4.5 entropy for names >6 characters

    3. Space Padding
       Excessive spaces used to hide true extension.
       Example: "document.pdf                              .exe"
       Severity: High

    4. Control Characters
       Invisible characters that break parsing or hide content.
       Severity: Critical

    5. Short Executable Names
       Very short names (1-2 chars) for executables are unusual.
       Example: "a.exe", "x.dll"
       Severity: Medium

Executable Extensions Monitored:
    exe, dll, sys, scr, com, bat, cmd, ps1, psm1, vbs, vbe,
    js, jse, wsf, wsh, msc, hta, cpl, msi, msp, drv, ocx, ax, jar

Note:
    Unicode evasion (homoglyphs, leet speak, typosquatting) is handled
    separately by the unicode.py module to avoid duplicate findings.

Usage:
    from windows_triage.analysis.filename import analyze_filename

    result = analyze_filename("report.pdf.exe")
    # Returns:
    # {
    #     'filename': 'report.pdf.exe',
    #     'entropy': 2.85,
    #     'findings': [{'type': 'double_extension', 'severity': 'critical', ...}],
    #     'is_suspicious': True
    # }
"""

import math
import re
from collections import Counter

# Note: Unicode/process spoofing detection is handled by check_process_name_spoofing()
# which is called separately in the server to avoid duplicate findings.


def calculate_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness (potentially generated names).

    Args:
        s: String to analyze

    Returns:
        Entropy value (0.0 to ~4.7 for typical alphanumeric)
    """
    if not s:
        return 0.0

    freq = Counter(s)
    length = len(s)

    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# Executable extensions that warrant extra scrutiny
EXECUTABLE_EXTENSIONS = {
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
}

# Double extension patterns that are highly suspicious
DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(doc|docx|pdf|jpg|jpeg|png|gif|txt|xls|xlsx|ppt|pptx|mp3|mp4|avi|mov)"
    r"\.(exe|scr|com|bat|cmd|ps1|vbs|js|hta|pif|msi)$",
    re.IGNORECASE,
)


def analyze_filename(filename: str) -> dict:
    """
    Analyze a filename for suspicious characteristics.

    Checks for:
    - Very short names for executables
    - High entropy (random-looking names)
    - Double extensions (document.pdf.exe)
    - Space padding to hide extensions
    - Control characters
    - Unicode evasion (RLO, homoglyphs)

    Args:
        filename: Filename to analyze

    Returns:
        Dict with:
        - filename: Original filename
        - entropy: Shannon entropy of name part
        - findings: List of suspicious characteristics
        - is_suspicious: Boolean indicating if any findings
    """
    findings: list[dict] = []

    # Split name and extension
    if "." in filename:
        # Handle multiple dots - last one is extension
        parts = filename.rsplit(".", 1)
        name_part = parts[0]
        extension = parts[1].lower()
    else:
        name_part = filename
        extension = None

    # Calculate entropy
    entropy = calculate_entropy(name_part)

    # Check for very short names (suspicious for executables)
    # Threshold: 2 chars or less - single/double letter executables are rare in legitimate software
    if extension in EXECUTABLE_EXTENSIONS:
        if len(name_part) <= 2:
            findings.append(
                {
                    "type": "short_name",
                    "severity": "medium",
                    "name_length": len(name_part),
                    "description": f'Very short filename for executable: "{filename}"',
                }
            )

        # Check for high entropy (random-looking names)
        # Thresholds: >4.5 bits entropy for names >6 chars
        # - 4.5 bits: typical for random alphanumeric strings (log2(36) ≈ 5.17 for max)
        # - 6 chars: minimum length to avoid false positives on short legitimate names
        if entropy > 4.5 and len(name_part) > 6:
            findings.append(
                {
                    "type": "high_entropy",
                    "severity": "medium",
                    "entropy": round(entropy, 2),
                    "description": f"High entropy ({entropy:.2f}) suggests random/generated name",
                }
            )

    # Check for double extensions
    if DOUBLE_EXTENSION_PATTERN.search(filename):
        findings.append(
            {
                "type": "double_extension",
                "severity": "critical",
                "description": "Double extension detected - common masquerading technique",
            }
        )

    # Check for excessive spaces (used to hide real extension)
    # Threshold: 8+ consecutive spaces - enough to push extension off visible area in file explorers
    if "        " in filename:
        findings.append(
            {
                "type": "space_padding",
                "severity": "high",
                "description": "Excessive spaces in filename - may hide true extension",
            }
        )

    # Check for trailing spaces before extension
    # Threshold: 3+ trailing spaces - deliberate padding vs incidental single space
    if name_part.endswith("   "):
        findings.append(
            {
                "type": "trailing_spaces",
                "severity": "high",
                "description": "Trailing spaces before extension - may hide content",
            }
        )

    # Check for control characters
    if re.search(r"[\x00-\x1F\x7F]", filename):
        findings.append(
            {
                "type": "control_chars",
                "severity": "critical",
                "description": "Control characters in filename",
            }
        )

    # Note: Unicode evasion (homoglyphs, leet speak, typosquatting) and
    # process name spoofing are handled separately by check_process_name_spoofing()
    # to avoid duplicate findings when both functions are called.

    return {
        "filename": filename,
        "entropy": round(entropy, 2),
        "findings": findings,
        "is_suspicious": len(findings) > 0,
    }


def check_known_tool_filename(filename: str, known_patterns: list[dict]) -> dict | None:
    """
    Check if a filename matches known malicious tool patterns.

    Args:
        filename: Filename to check
        known_patterns: List of patterns from suspicious_filenames table

    Returns:
        Matching pattern info or None
    """
    filename_lower = filename.lower()

    for pattern in known_patterns:
        if pattern.get("is_regex"):
            if re.match(pattern["filename_pattern"], filename_lower):
                return pattern
        else:
            if filename_lower == pattern["filename_pattern"].lower():
                return pattern

    return None
