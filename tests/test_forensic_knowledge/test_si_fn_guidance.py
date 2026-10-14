"""The $STANDARD_INFORMATION / $FILE_NAME guidance, as the knowledge loader
serves it: $FN can carry a timestomped $SI after a rename or same-volume move,
SI<FN is common on an ordinary system volume, and SI<FN and uSecZeros are each
a lead for review, never proof on their own.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from forensic_knowledge import loader

REPO = Path(__file__).resolve().parents[2]
USN = (
    'The USN journal can help: a timestomp writes a "Basic info change" record at '
    "the real time of the change. Many ordinary operations write the same record, "
    "so a match supports a timestomp but does not prove one."
)
FN_CREATED = (
    "No documented user-mode API sets it, but NTFS rewrites it on ordinary "
    "operations: a rename or same-volume move copies the file's $SI values from "
    "before the operation into it, so a timestomped $SI can be carried into $FN. A "
    "difference between $SI and $FN can indicate timestomping; treat it as a lead "
    "for further comparison, not proof."
)
FN_MATCHES_SI = (
    "FN timestamps are set at file creation and updated only on rename/move. "
    "Legitimate divergence is normal. SI timestamps earlier than FN timestamps are "
    "common on an ordinary Windows system volume, especially in WinSxS, System32 "
    "and WindowsApps, and after robocopy copies or shell zip extraction; they can "
    "also indicate timestomping. Judge a hit by the file's location and its dates "
    "against the other evidence; treat it as a lead, not proof."
)
SI_LT_FN = (
    "SI<FN=True marks a file for review. It does not alone mean the file is "
    "suspicious. It often legitimately occurs in WinSxS, System32 and WindowsApps. "
    "It also occurs after a file is copied with robocopy or extracted from a zip "
    "archive in File Explorer. Renaming or moving a timestomped file within the "
    "same volume copies its timestomped $SI timestamps into $FN, so SI<FN becomes "
    "False. " + USN
)
USEC_ZEROS = (
    "uSecZeros=True marks a file for review. It does not alone mean the file is "
    "suspicious. It often legitimately occurs after a file is extracted from a zip "
    "archive or copied from FAT-formatted media. A timestomp that sets non-zero "
    "sub-second values leaves uSecZeros=False. " + USN
)
ZERO_SUB_SECOND = (
    "Zero sub-second component in $SI Created or Modified (MFTECmd uSecZeros). "
    "Timestomping tools can cause it. It often legitimately occurs after a file is "
    "extracted from a zip archive or copied from FAT-formatted media. Some "
    "installers may also cause it. Treat it as a lead for further comparison, not "
    "proof."
)


def _mft() -> dict:
    loader.clear_cache()
    return loader.get_artifact("mft")


def _pattern_notes(field: str) -> list[str]:
    return [
        p["note"]
        for p in _mft()["cross_artifact_correlation"]
        if field in (p.get("fields") or [])
    ]


def _served() -> dict[str, str]:
    mft = _mft()
    (fn_created,) = [
        t["common_misinterpretation"]
        for t in mft["timestamps"]
        if t["field"] == "$FILE_NAME Created"
    ]
    (fn_matches,) = [
        c["correction"]
        for c in mft["common_misinterpretations"]
        if c["claim"]
        == "$FILE_NAME timestamps always match $STANDARD_INFORMATION timestamps"
    ]
    (si_lt_fn,) = _pattern_notes("SI<FN")
    (usec,) = _pattern_notes("uSecZeros")
    (trigger,) = [
        t for t in loader.get_playbook("timestomping")["triggers"] if "uSecZeros" in t
    ]
    return {
        "fn_created": fn_created,
        "fn_matches_si": fn_matches,
        "si_lt_fn": si_lt_fn,
        "usec_zeros": usec,
        "zero_sub_second_trigger": trigger,
    }


@pytest.mark.parametrize(
    ("where", "text"),
    [
        ("fn_created", FN_CREATED),
        ("fn_matches_si", FN_MATCHES_SI),
        ("si_lt_fn", SI_LT_FN),
        ("usec_zeros", USEC_ZEROS),
        ("zero_sub_second_trigger", ZERO_SUB_SECOND),
    ],
    ids=lambda v: v if " " not in v else "",
)
def test_the_si_fn_guidance_is_served_as_approved(where, text):
    assert _served()[where] == text


def test_si_lt_fn_and_usec_zeros_are_separate_notes_each_about_its_own_flag():
    """One note per flag: a hit on either is judged on its own causes."""
    both = [
        p
        for p in _mft()["cross_artifact_correlation"]
        if {"SI<FN", "uSecZeros"} <= set(p.get("fields") or [])
    ]
    assert both == []
    (si_lt_fn,) = _pattern_notes("SI<FN")
    (usec,) = _pattern_notes("uSecZeros")
    assert "uSecZeros" not in si_lt_fn and "SI<FN" not in usec


def test_no_guidance_says_fn_times_are_tamper_proof_or_si_before_fn_is_suspicious():
    """The old lines, anywhere the AI reads them: the knowledge data and the
    skills rendered from it."""
    old = (
        "reliable for detecting timestomping",
        "strongly suggest timestomping",
        "in non-servicing paths is suspicious",
        "Zero millisecond component in $SI",
    )
    places = [REPO / "packages" / "forensic-knowledge" / "data", REPO / "skills"]
    said = [
        (str(path.relative_to(REPO)), phrase)
        for place in places
        for path in sorted(place.rglob("*"))
        if path.is_file() and path.suffix in {".yaml", ".yml", ".md"}
        for phrase in old
        if phrase in path.read_text(errors="replace")
    ]
    assert said == []
