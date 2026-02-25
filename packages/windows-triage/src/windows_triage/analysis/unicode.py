"""
Unicode Evasion Detection for Forensic Analysis

This module detects various Unicode-based attacks used to disguise malicious
files and evade detection. These techniques are commonly used in phishing,
malware distribution, and process masquerading attacks.

Attack Types Detected:

    1. Bidirectional Text Overrides (RLO Attacks)
       Characters that reverse text direction to hide true file extensions.
       Example: "report[RLO]fdp.exe" displays as "reportexe.pdf"
       - Right-to-Left Override (U+202E) - CRITICAL
       - Left-to-Right Override (U+202D)
       - Various embedding/isolate characters

    2. Zero-Width Characters
       Invisible characters that can hide content or break parsing.
       - Zero Width Space (U+200B)
       - Zero Width Non-Joiner (U+200C)
       - Zero Width Joiner (U+200D)
       - Byte Order Mark (U+FEFF)

    3. Homoglyph Attacks
       Non-Latin characters that visually resemble Latin letters.
       Example: "svсhost.exe" (with Cyrillic 'с') looks like "svchost.exe"
       - Cyrillic lookalikes (а=a, е=e, о=o, р=p, с=c, х=x)
       - Greek lookalikes (α=a, ε=e, ο=o)

    4. Mixed Script Detection
       Filenames containing characters from multiple Unicode scripts.
       Example: Latin letters mixed with Cyrillic characters.

    5. Leet Speak Detection
       Number substitutions to evade pattern matching.
       Example: "svch0st.exe" -> "svchost.exe" (0=o)

    6. Typosquatting Detection
       Minor misspellings of protected process names.
       Example: "svchots.exe", "svhost.exe", "scvhost.exe"
       Uses Levenshtein (edit) distance for similarity matching.

Severity Levels:
    - critical: RLO attacks (actively deceptive)
    - high: Homoglyphs, leet speak, zero-width characters
    - medium: Mixed scripts, typosquatting

Usage:
    from windows_triage.analysis.unicode import (
        detect_unicode_evasion,
        check_process_name_spoofing,
        get_canonical_form
    )

    # Detect Unicode attacks in a filename
    findings = detect_unicode_evasion("suspicious_file.exe")

    # Check for process name spoofing
    protected = ["svchost.exe", "lsass.exe", "csrss.exe"]
    spoofing = check_process_name_spoofing("svch0st.exe", protected)

    # Get normalized form for comparison
    canonical = get_canonical_form("svch0st.exe")  # Returns "svchost.exe"
"""

import unicodedata

# Bidirectional override characters used in RLO attacks
BIDI_OVERRIDES = {
    "\u202e": "Right-to-Left Override (RLO)",
    "\u202d": "Left-to-Right Override (LRO)",
    "\u202c": "Pop Directional Formatting",
    "\u202b": "Right-to-Left Embedding",
    "\u202a": "Left-to-Right Embedding",
    "\u2066": "Left-to-Right Isolate",
    "\u2067": "Right-to-Left Isolate",
    "\u2068": "First Strong Isolate",
    "\u2069": "Pop Directional Isolate",
}

# Zero-width characters that can hide content
ZERO_WIDTH_CHARS = {
    "\u200b": "Zero Width Space",
    "\u200c": "Zero Width Non-Joiner",
    "\u200d": "Zero Width Joiner",
    "\ufeff": "Byte Order Mark / Zero Width No-Break Space",
    "\u00ad": "Soft Hyphen",
    "\u2060": "Word Joiner",
}

# Common homoglyphs - non-Latin characters that look like Latin letters
# Format: char -> (looks_like, unicode_name)
HOMOGLYPHS = {
    # Cyrillic lowercase
    "\u0430": ("a", "CYRILLIC SMALL LETTER A"),
    "\u0435": ("e", "CYRILLIC SMALL LETTER IE"),
    "\u043e": ("o", "CYRILLIC SMALL LETTER O"),
    "\u0440": ("p", "CYRILLIC SMALL LETTER ER"),
    "\u0441": ("c", "CYRILLIC SMALL LETTER ES"),
    "\u0443": ("y", "CYRILLIC SMALL LETTER U"),
    "\u0445": ("x", "CYRILLIC SMALL LETTER HA"),
    "\u0456": ("i", "CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I"),
    "\u0458": ("j", "CYRILLIC SMALL LETTER JE"),
    "\u04bb": ("h", "CYRILLIC SMALL LETTER SHHA"),
    "\u0455": ("s", "CYRILLIC SMALL LETTER DZE"),
    "\u0501": ("d", "CYRILLIC SMALL LETTER KOMI DE"),
    # Cyrillic uppercase
    "\u0410": ("A", "CYRILLIC CAPITAL LETTER A"),
    "\u0412": ("B", "CYRILLIC CAPITAL LETTER VE"),
    "\u0415": ("E", "CYRILLIC CAPITAL LETTER IE"),
    "\u041d": ("H", "CYRILLIC CAPITAL LETTER EN"),
    "\u041e": ("O", "CYRILLIC CAPITAL LETTER O"),
    "\u0420": ("P", "CYRILLIC CAPITAL LETTER ER"),
    "\u0421": ("C", "CYRILLIC CAPITAL LETTER ES"),
    "\u0422": ("T", "CYRILLIC CAPITAL LETTER TE"),
    "\u0425": ("X", "CYRILLIC CAPITAL LETTER HA"),
    "\u041c": ("M", "CYRILLIC CAPITAL LETTER EM"),
    "\u041a": ("K", "CYRILLIC CAPITAL LETTER KA"),
    # Greek lowercase
    "\u03b1": ("a", "GREEK SMALL LETTER ALPHA"),
    "\u03b5": ("e", "GREEK SMALL LETTER EPSILON"),
    "\u03bf": ("o", "GREEK SMALL LETTER OMICRON"),
    "\u03c1": ("p", "GREEK SMALL LETTER RHO"),
    "\u03c5": ("u", "GREEK SMALL LETTER UPSILON"),
    "\u03b9": ("i", "GREEK SMALL LETTER IOTA"),
    "\u03bd": ("v", "GREEK SMALL LETTER NU"),
    # Greek uppercase
    "\u0391": ("A", "GREEK CAPITAL LETTER ALPHA"),
    "\u0392": ("B", "GREEK CAPITAL LETTER BETA"),
    "\u0395": ("E", "GREEK CAPITAL LETTER EPSILON"),
    "\u0397": ("H", "GREEK CAPITAL LETTER ETA"),
    "\u0399": ("I", "GREEK CAPITAL LETTER IOTA"),
    "\u039a": ("K", "GREEK CAPITAL LETTER KAPPA"),
    "\u039c": ("M", "GREEK CAPITAL LETTER MU"),
    "\u039d": ("N", "GREEK CAPITAL LETTER NU"),
    "\u039f": ("O", "GREEK CAPITAL LETTER OMICRON"),
    "\u03a1": ("P", "GREEK CAPITAL LETTER RHO"),
    "\u03a4": ("T", "GREEK CAPITAL LETTER TAU"),
    "\u03a7": ("X", "GREEK CAPITAL LETTER CHI"),
    "\u0396": ("Z", "GREEK CAPITAL LETTER ZETA"),
}


def detect_unicode_evasion(text: str) -> list[dict]:
    """
    Detect Unicode-based evasion techniques in filenames/process names.

    Args:
        text: Filename or process name to analyze

    Returns:
        List of findings, each with:
        - type: 'bidi_override', 'zero_width', 'homoglyph', or 'mixed_scripts'
        - severity: 'critical', 'high', or 'medium'
        - position: Character position (for single-char findings)
        - character: The problematic character
        - description: Human-readable description
    """
    findings = []

    # Check for bidirectional overrides (RLO attack)
    for i, char in enumerate(text):
        if char in BIDI_OVERRIDES:
            findings.append(
                {
                    "type": "bidi_override",
                    "severity": "critical",
                    "position": i,
                    "character": repr(char),
                    "unicode_name": BIDI_OVERRIDES[char],
                    "description": "Bidirectional text override detected - possible RLO attack",
                }
            )

    # Check for zero-width characters
    for i, char in enumerate(text):
        if char in ZERO_WIDTH_CHARS:
            findings.append(
                {
                    "type": "zero_width",
                    "severity": "high",
                    "position": i,
                    "character": repr(char),
                    "unicode_name": ZERO_WIDTH_CHARS[char],
                    "description": "Zero-width character detected - may hide true content",
                }
            )

    # Check for homoglyphs
    for i, char in enumerate(text):
        if char in HOMOGLYPHS:
            looks_like, unicode_name = HOMOGLYPHS[char]
            findings.append(
                {
                    "type": "homoglyph",
                    "severity": "high",
                    "position": i,
                    "character": char,
                    "looks_like": looks_like,
                    "unicode_name": unicode_name,
                    "description": f'Non-Latin character that looks like "{looks_like}"',
                }
            )

    # Check for mixed scripts (excluding common punctuation/numbers)
    scripts = set()
    for char in text:
        if char.isalpha():
            try:
                name = unicodedata.name(char, "")
                if name:
                    # Extract script from Unicode name (first word usually)
                    script = name.split()[0]
                    # Normalize script names
                    if script in (
                        "LATIN",
                        "CYRILLIC",
                        "GREEK",
                        "ARMENIAN",
                        "HEBREW",
                        "ARABIC",
                    ):
                        scripts.add(script)
            except ValueError:
                pass

    if len(scripts) > 1:
        findings.append(
            {
                "type": "mixed_scripts",
                "severity": "medium",
                "scripts": sorted(scripts),
                "description": f"Mixed Unicode scripts detected: {', '.join(sorted(scripts))}",
            }
        )

    return findings


def normalize_homoglyphs(text: str) -> str:
    """
    Convert homoglyphs to their Latin equivalents.

    Useful for comparing filenames that may be using lookalike characters.

    Args:
        text: Text potentially containing homoglyphs

    Returns:
        Text with homoglyphs replaced by Latin equivalents
    """
    result = []
    for char in text:
        if char in HOMOGLYPHS:
            result.append(HOMOGLYPHS[char][0])
        else:
            result.append(char)
    return "".join(result)


def strip_invisible_chars(text: str) -> str:
    """
    Remove zero-width and bidirectional override characters.

    Args:
        text: Text potentially containing invisible characters

    Returns:
        Text with invisible characters removed
    """
    invisible = set(ZERO_WIDTH_CHARS.keys()) | set(BIDI_OVERRIDES.keys())
    return "".join(c for c in text if c not in invisible)


# Common leet speak substitutions (number -> letter)
# Values are tuples of possible replacements (first is primary/most common)
LEET_SUBSTITUTIONS = {
    "0": ("o",),
    "1": (
        "i",
        "l",
    ),  # 'i' is more common (w1nd0ws, m1m1katz), but can be 'l' (1sass -> lsass)
    "3": ("e",),
    "4": ("a",),
    "5": ("s",),
    "7": ("t",),
    "8": ("b",),
    "@": ("a",),
    "$": ("s",),
    "!": ("i",),
}


def normalize_leet(text: str, use_primary: bool = True) -> str:
    """
    Convert leet speak numbers to their letter equivalents.

    Args:
        text: Text potentially containing leet speak
        use_primary: If True, use only the primary (first) substitution

    Returns:
        Text with leet substitutions normalized (using primary mapping)
    """
    result = []
    for char in text:
        if char in LEET_SUBSTITUTIONS:
            result.append(LEET_SUBSTITUTIONS[char][0])  # Use primary mapping
        else:
            result.append(char)
    return "".join(result)


def get_leet_variations(text: str) -> list[str]:
    """
    Generate all possible leet speak normalizations for ambiguous characters.

    For example, '1sass' could be 'lsass' or 'isass'.

    Args:
        text: Text potentially containing leet speak

    Returns:
        List of all possible normalized forms
    """
    from itertools import product

    # Find positions with ambiguous leet characters
    variations_at_pos = []
    for char in text:
        if char in LEET_SUBSTITUTIONS:
            variations_at_pos.append(LEET_SUBSTITUTIONS[char])
        else:
            variations_at_pos.append((char,))

    # Generate all combinations
    return ["".join(combo) for combo in product(*variations_at_pos)]


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein (edit) distance between two strings.

    Edit distance = minimum number of single-character edits
    (insertions, deletions, substitutions) to change one string into another.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_typosquatting(
    text: str, protected_names: list[str], max_distance: int = 2
) -> list[dict]:
    """
    Detect potential typosquatting/misspelling of protected process names.

    Uses edit distance to find names that are suspiciously similar to
    protected processes (e.g., svchots.exe, svhost.exe, scvhost.exe).

    Args:
        text: Filename to check
        protected_names: List of protected process names
        max_distance: Maximum edit distance to consider as typosquatting (default: 2)

    Returns:
        List of findings if typosquatting detected
    """
    findings = []
    text_lower = text.lower()

    # Don't flag exact matches
    if text_lower in [p.lower() for p in protected_names]:
        return findings

    for protected in protected_names:
        protected_lower = protected.lower()

        # Skip if lengths are too different (optimization)
        if abs(len(text_lower) - len(protected_lower)) > max_distance:
            continue

        distance = levenshtein_distance(text_lower, protected_lower)

        if 0 < distance <= max_distance:
            findings.append(
                {
                    "type": "typosquatting",
                    "severity": "high",
                    "target_process": protected,
                    "actual_name": text,
                    "edit_distance": distance,
                    "description": f"Possible typosquatting of {protected} (edit distance: {distance})",
                }
            )
            break  # Only report first match

    return findings


def detect_leet_speak(text: str, protected_names: list[str]) -> list[dict]:
    """
    Detect leet speak being used to impersonate protected names.

    Handles ambiguous leet characters like '1' which can be 'l' or 'i'.
    For example, '1sass.exe' matches 'lsass.exe' (1->l).

    Args:
        text: Filename to check
        protected_names: List of protected process names

    Returns:
        List of findings if leet speak impersonation detected
    """
    findings = []

    # Check if text contains any leet characters
    has_leet = any(c in LEET_SUBSTITUTIONS for c in text)
    if not has_leet:
        return findings

    # Get all possible normalizations (handles ambiguous chars like '1' -> 'l' or 'i')
    text_lower = text.lower()
    variations = get_leet_variations(text_lower)

    for protected in protected_names:
        protected_lower = protected.lower()
        for normalized in variations:
            if normalized == protected_lower and text_lower != protected_lower:
                findings.append(
                    {
                        "type": "leet_speak",
                        "severity": "high",
                        "target_process": protected,
                        "actual_name": text,
                        "normalized_form": normalized,
                        "description": f"Leet speak impersonation of {protected}",
                    }
                )
                return findings  # Return on first match

    return findings


def get_canonical_form(text: str) -> str:
    """
    Get the canonical (normalized) form of a filename.

    Applies:
    - Homoglyph normalization
    - Leet speak normalization
    - Invisible character removal
    - Lowercase

    Args:
        text: Filename to normalize

    Returns:
        Canonical lowercase form
    """
    text = strip_invisible_chars(text)
    text = normalize_homoglyphs(text)
    text = normalize_leet(text)
    return text.lower()


def check_process_name_spoofing(
    process_name: str, protected_names: list[str]
) -> list[dict]:
    """
    Check if a process name is attempting to spoof a protected process.

    Checks for:
    - Unicode homoglyphs (Cyrillic/Greek letters that look like Latin)
    - Leet speak (numbers that look like letters: 0=o, 1=i, 3=e, etc.)
    - Typosquatting (minor misspellings: svchots.exe, svhost.exe)
    - Zero-width characters
    - Bidirectional overrides

    Args:
        process_name: Process name to check
        protected_names: List of protected process names (e.g., ['svchost.exe', 'lsass.exe'])

    Returns:
        List of findings if spoofing detected
    """
    findings = []

    # First check for Unicode evasion
    evasion_findings = detect_unicode_evasion(process_name)
    if evasion_findings:
        findings.extend(evasion_findings)

    # Check for leet speak impersonation
    leet_findings = detect_leet_speak(process_name, protected_names)
    if leet_findings:
        findings.extend(leet_findings)

    # Get canonical form (normalizes homoglyphs + leet + invisible chars)
    canonical = get_canonical_form(process_name)

    # Check if canonical form matches a protected name (homoglyph spoofing)
    for protected in protected_names:
        protected_lower = protected.lower()
        if canonical == protected_lower and process_name.lower() != protected_lower:
            # Only add if not already caught by leet speak detection
            already_found = any(f.get("type") == "leet_speak" for f in findings)
            if not already_found:
                findings.append(
                    {
                        "type": "process_spoofing",
                        "severity": "critical",
                        "target_process": protected,
                        "actual_name": process_name,
                        "canonical_form": canonical,
                        "description": f"Possible spoofing of {protected} using lookalike characters",
                    }
                )
            break

    # Check for typosquatting (only if no other spoofing detected)
    if not findings:
        typo_findings = detect_typosquatting(process_name, protected_names)
        if typo_findings:
            findings.extend(typo_findings)

    return findings
