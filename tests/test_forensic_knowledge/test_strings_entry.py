"""The strings entry is read on SIFT (GNU strings) and on Windows
(Sysinternals strings), whose flags differ: `-a` is "all sections" in one and
"ASCII only" in the other. It has no quick start (get_tool_help gives the
installed version's syntax), every line naming a flag or a default length says
it's GNU strings on SIFT, and no line names a Sysinternals flag (the wintools
catalog carries those)."""

import re

import pytest
from forensic_knowledge import loader

FLAG = re.compile(r"(?<![\w-])--?[A-Za-z][\w=-]*|minimum string length is \d")


@pytest.fixture
def entry():
    loader.clear_cache()
    yield loader.get_tool("strings")
    loader.clear_cache()


def _lines(e: dict) -> list[str]:
    return [
        e["platform_notes"],
        *e["investigation_sequence"],
        *e["advisories"],
        *e["caveats"],
    ]


def test_there_is_no_quick_start(entry):
    assert "quick_start" not in entry


def test_every_line_naming_a_flag_or_default_length_says_gnu_strings_on_sift(entry):
    named = [x for x in _lines(entry) if FLAG.search(x)]
    assert named  # the SIFT guidance is kept, qualified
    assert [x for x in named if not re.search(r"GNU|SIFT", x)] == []


def test_no_line_names_a_sysinternals_flag(entry):
    assert [x for x in _lines(entry) if "Sysinternals" in x and FLAG.search(x)] == []


def test_the_utf16le_pass_on_sift_stays(entry):
    assert any(
        "UTF-16LE" in x and "second pass" in x and "GNU" in x for x in _lines(entry)
    )
