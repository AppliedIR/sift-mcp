"""Tests for Unicode evasion detection."""

from windows_triage.analysis.unicode import (
    check_process_name_spoofing,
    detect_leet_speak,
    detect_typosquatting,
    detect_unicode_evasion,
    get_canonical_form,
    levenshtein_distance,
    normalize_homoglyphs,
    normalize_leet,
    strip_invisible_chars,
)


class TestDetectUnicodeEvasion:
    """Tests for detect_unicode_evasion function."""

    def test_clean_filename(self):
        findings = detect_unicode_evasion("svchost.exe")
        assert len(findings) == 0

    def test_rlo_attack(self):
        # RLO character followed by text
        filename = "invoice\u202eexe.pdf"  # Displays as "invoicfdp.exe"
        findings = detect_unicode_evasion(filename)
        assert len(findings) >= 1
        assert any(f["type"] == "bidi_override" for f in findings)
        assert any(f["severity"] == "critical" for f in findings)

    def test_zero_width_space(self):
        filename = "svc\u200bhost.exe"  # Zero-width space
        findings = detect_unicode_evasion(filename)
        assert len(findings) >= 1
        assert any(f["type"] == "zero_width" for f in findings)

    def test_cyrillic_homoglyph(self):
        # Cyrillic 'а' instead of Latin 'a' - use lsass.exe which has 'a'
        filename = "lsass.exe".replace("a", "\u0430")  # Cyrillic a
        findings = detect_unicode_evasion(filename)
        assert any(f["type"] == "homoglyph" for f in findings)

    def test_greek_homoglyph(self):
        # Greek 'ο' instead of Latin 'o'
        filename = "svchost.exe".replace("o", "\u03bf")  # Greek omicron
        findings = detect_unicode_evasion(filename)
        assert any(f["type"] == "homoglyph" for f in findings)

    def test_mixed_scripts(self):
        # Mix of Latin and Cyrillic - use chr() to avoid escape issues
        filename = "svch" + chr(0x043E) + "st.exe"  # Cyrillic 'о'
        findings = detect_unicode_evasion(filename)
        assert any(f["type"] in ("homoglyph", "mixed_scripts") for f in findings)

    def test_multiple_issues(self):
        # Both RLO and homoglyph
        filename = "\u202esvchost\u0430.exe"
        findings = detect_unicode_evasion(filename)
        assert len(findings) >= 2


class TestNormalizeHomoglyphs:
    """Tests for normalize_homoglyphs function."""

    def test_cyrillic_a(self):
        assert normalize_homoglyphs("\u0430bc") == "abc"

    def test_cyrillic_o(self):
        assert normalize_homoglyphs("hell\u043e") == "hello"

    def test_greek_alpha(self):
        assert normalize_homoglyphs("\u03b1pple") == "apple"

    def test_mixed(self):
        # Cyrillic а, о and Greek ε
        text = "h\u0435ll\u043e"
        result = normalize_homoglyphs(text)
        assert result == "hello"

    def test_no_homoglyphs(self):
        assert normalize_homoglyphs("normal") == "normal"


class TestStripInvisibleChars:
    """Tests for strip_invisible_chars function."""

    def test_zero_width_space(self):
        assert strip_invisible_chars("hello\u200bworld") == "helloworld"

    def test_rlo(self):
        assert strip_invisible_chars("test\u202etext") == "testtext"

    def test_bom(self):
        assert strip_invisible_chars("\ufeffhello") == "hello"

    def test_multiple_invisibles(self):
        text = "\u200btest\u202e\u200ctext\ufeff"
        assert strip_invisible_chars(text) == "testtext"

    def test_normal_text(self):
        assert strip_invisible_chars("normal") == "normal"


class TestNormalizeLeet:
    """Tests for normalize_leet function."""

    def test_zero_to_o(self):
        assert normalize_leet("hell0") == "hello"

    def test_one_to_i(self):
        assert normalize_leet("m1m1katz") == "mimikatz"

    def test_three_to_e(self):
        assert normalize_leet("t3st") == "test"

    def test_four_to_a(self):
        assert normalize_leet("m4lw4re") == "malware"

    def test_five_to_s(self):
        assert normalize_leet("5vchost") == "svchost"

    def test_combined(self):
        assert normalize_leet("5vch0st") == "svchost"

    def test_at_sign(self):
        assert normalize_leet("m@lware") == "malware"

    def test_dollar_sign(self):
        assert normalize_leet("$vchost") == "svchost"


class TestLevenshteinDistance:
    """Tests for levenshtein_distance function."""

    def test_identical(self):
        assert levenshtein_distance("hello", "hello") == 0

    def test_one_substitution(self):
        assert levenshtein_distance("hello", "hallo") == 1

    def test_one_insertion(self):
        assert levenshtein_distance("hello", "helloo") == 1

    def test_one_deletion(self):
        assert levenshtein_distance("hello", "helo") == 1

    def test_empty(self):
        assert levenshtein_distance("", "hello") == 5
        assert levenshtein_distance("hello", "") == 5

    def test_typosquatting_example(self):
        assert levenshtein_distance("svchost.exe", "svchots.exe") == 2

    def test_symmetric(self):
        assert levenshtein_distance("abc", "xyz") == levenshtein_distance("xyz", "abc")


class TestDetectTyposquatting:
    """Tests for detect_typosquatting function."""

    def test_svchots(self):
        # svchots instead of svchost (transposition)
        findings = detect_typosquatting("svchots.exe", ["svchost.exe"])
        assert len(findings) == 1
        assert findings[0]["type"] == "typosquatting"
        assert findings[0]["target_process"] == "svchost.exe"

    def test_svhost(self):
        # svhost instead of svchost (missing c)
        findings = detect_typosquatting("svhost.exe", ["svchost.exe"])
        assert len(findings) == 1

    def test_lsas(self):
        # lsas instead of lsass (missing s)
        findings = detect_typosquatting("lsas.exe", ["lsass.exe"])
        assert len(findings) == 1

    def test_exact_match_not_flagged(self):
        # Exact match should not be flagged
        findings = detect_typosquatting("svchost.exe", ["svchost.exe"])
        assert len(findings) == 0

    def test_too_different(self):
        # Completely different name
        findings = detect_typosquatting("notepad.exe", ["svchost.exe"])
        assert len(findings) == 0

    def test_case_insensitive(self):
        findings = detect_typosquatting("SVCHOTS.EXE", ["svchost.exe"])
        assert len(findings) == 1


class TestDetectLeetSpeak:
    """Tests for detect_leet_speak function."""

    def test_svch0st(self):
        findings = detect_leet_speak("svch0st.exe", ["svchost.exe"])
        assert len(findings) == 1
        assert findings[0]["type"] == "leet_speak"
        assert findings[0]["target_process"] == "svchost.exe"

    def test_5vchost(self):
        findings = detect_leet_speak("5vchost.exe", ["svchost.exe"])
        assert len(findings) == 1

    def test_ls4ss(self):
        # Use '4' for 'a' since '1' maps to 'i' not 'l'
        findings = detect_leet_speak("ls4ss.exe", ["lsass.exe"])
        assert len(findings) == 1

    def test_no_leet(self):
        findings = detect_leet_speak("notepad.exe", ["svchost.exe"])
        assert len(findings) == 0

    def test_normal_name_not_flagged(self):
        # Normal name that happens to have numbers shouldn't be flagged
        findings = detect_leet_speak("file123.exe", ["svchost.exe"])
        assert len(findings) == 0


class TestGetCanonicalForm:
    """Tests for get_canonical_form function."""

    def test_normal(self):
        assert get_canonical_form("SvcHost.exe") == "svchost.exe"

    def test_with_homoglyphs(self):
        # Cyrillic a -> Latin a
        text = "svc\u0430host.exe"
        assert "a" in get_canonical_form(text)

    def test_with_leet(self):
        assert get_canonical_form("svch0st.exe") == "svchost.exe"

    def test_with_invisible(self):
        text = "svc\u200bhost.exe"
        assert get_canonical_form(text) == "svchost.exe"

    def test_combined(self):
        # Leet + homoglyph - use chr() to avoid escape issues
        text = "5vch" + chr(0x043E) + "st.exe"  # 5 and Cyrillic о
        result = get_canonical_form(text)
        assert result == "svchost.exe"


class TestCheckProcessNameSpoofing:
    """Tests for check_process_name_spoofing function."""

    def test_clean_name(self):
        findings = check_process_name_spoofing(
            "notepad.exe", ["svchost.exe", "lsass.exe"]
        )
        assert len(findings) == 0

    def test_homoglyph_attack(self):
        # Cyrillic о instead of Latin o - use chr() to avoid escape issues
        filename = "svch" + chr(0x043E) + "st.exe"
        findings = check_process_name_spoofing(filename, ["svchost.exe"])
        assert len(findings) >= 1
        assert any(f["severity"] in ("critical", "high") for f in findings)

    def test_leet_speak_attack(self):
        findings = check_process_name_spoofing("5vch0st.exe", ["svchost.exe"])
        assert len(findings) >= 1
        assert any(f["type"] == "leet_speak" for f in findings)

    def test_typosquatting(self):
        findings = check_process_name_spoofing("svchots.exe", ["svchost.exe"])
        assert len(findings) >= 1
        assert any(f["type"] == "typosquatting" for f in findings)

    def test_rlo_attack(self):
        filename = "svc\u202eexe.host"
        findings = check_process_name_spoofing(filename, ["svchost.exe"])
        assert any(f["type"] == "bidi_override" for f in findings)

    def test_exact_match_not_flagged(self):
        # Real svchost.exe should not be flagged
        findings = check_process_name_spoofing("svchost.exe", ["svchost.exe"])
        assert len(findings) == 0
