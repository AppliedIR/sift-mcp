"""setup-sift.sh turns the examiner name into the same slug in every shell locale.

The slug came from tr, sed and `head -c 20` under the shell's own locale, so
one name gave a different identity under C, C.UTF-8 and en_US.UTF-8, the byte
cut could split a character and leave config.yaml unreadable, and a leading or
trailing dash was written but stripped again by vhir. A name with no Latin
letter or digit (山田太郎, -) became dashes or "examiner", shared by everyone
with such a name. These run the installer's own examiner block, with its own
prompt helpers, in a scratch HOME.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "setup-sift.sh").read_text()
_I = SCRIPT.index('header "Examiner Identity"')
BLOCK = SCRIPT[_I : SCRIPT.index("# Write VHIR_EXAMINER to shell profile", _I)]
HELPERS = "\n".join(re.findall(r"^(?:info|ok|warn|err)\(\).*$", SCRIPT, re.M))
PROMPTS = SCRIPT[SCRIPT.index("prompt() {") : SCRIPT.index("prompt_yn_strict() {")]
PRELUDE = (
    "set -euo pipefail\n"
    'BOLD=""; NC=""; RED=""; GREEN=""; YELLOW=""; BLUE=""\n'
    'header() { :; }\nwhoami() { echo "$WHO"; }\n'
    f"{HELPERS}\n{PROMPTS}\n"
)
REFUSAL = "the examiner name needs a Latin letter or digit, e.g. --examiner=yamada"
LOCALES = ["C", "C.UTF-8", "en_US.UTF-8"]


def _locale(loc: str) -> str:
    if loc != "C":
        r = subprocess.run(
            ["/bin/bash", "-c", "printf %s é | wc -m"],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": loc},
            capture_output=True,
            text=True,
        )
        if r.stdout.strip() != "1":
            pytest.skip(f"locale {loc} is not installed")
    return loc


def _run(
    home: Path,
    loc: str,
    name="",
    answers: str | None = "",
    yes=False,
    who="osuser",
    read_from="/dev/stdin",
    timeout=60,
):
    r = subprocess.run(
        ["/bin/bash", "-c", PRELUDE + f"AUTO_YES={str(yes).lower()}\n" + BLOCK],
        env={
            "HOME": str(home),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": _locale(loc),
            "EXAMINER_NAME": name,
            "WHO": who,
            "READ_FROM": read_from,
        },
        input=None if answers is None else answers.encode(),
        stdin=subprocess.DEVNULL if answers is None else None,
        capture_output=True,
        timeout=timeout,
    )
    return r.returncode, r.stdout.decode("utf-8", "backslashreplace")


def _identity(home: Path, monkeypatch) -> tuple[str, str]:
    identity = pytest.importorskip("vhir_cli.identity")
    for k in ("VHIR_EXAMINER", "VHIR_ANALYST", "USERNAME"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("USER", "osuser")
    monkeypatch.setenv("HOME", str(home))
    got = identity.get_examiner_identity()
    return got["examiner"], got["examiner_source"]


def _printed(out: str) -> str:
    return re.findall(r"^\[OK\] Examiner: (.*)$", out, re.M)[-1]


@pytest.mark.parametrize("typed", [False, True], ids=["flag", "prompt"])
@pytest.mark.parametrize(
    "name",
    [
        "Øyvind Ås",
        "Nguyễn Thị Minh Khai",
        "Lê Thị Hồng Gấm",
        "Nguyễn Thị Thanh Hà",
        "Ana Lucía Hernández Ruiz",
    ],
)
def test_one_slug_in_every_locale_and_vhir_records_it(
    tmp_path, monkeypatch, name, typed
):
    slugs = set()
    for loc in LOCALES:
        home = tmp_path / loc
        if typed:
            rc, out = _run(home, loc, answers=f"{name}\ny\n")
        else:
            rc, out = _run(home, loc, name=name)
        assert rc == 0, out
        cfg = home / ".vhir" / "config.yaml"
        written = re.fullmatch(r'examiner: "(.*)"\n', cfg.read_bytes().decode("utf-8"))
        assert written, cfg.read_bytes()
        assert _printed(out) == written[1]
        assert _identity(home, monkeypatch) == (written[1], "config")
        slugs.add(written[1])
    assert len(slugs) == 1, slugs


@pytest.mark.parametrize("loc", LOCALES)
@pytest.mark.parametrize("name,slug", [("alice", "alice"), ("Jane-Doe", "jane-doe")])
def test_a_latin_name_keeps_its_slug(tmp_path, monkeypatch, loc, name, slug):
    rc, out = _run(tmp_path, loc, name=name)
    assert rc == 0, out
    assert _printed(out) == slug
    assert _identity(tmp_path, monkeypatch) == (slug, "config")
    assert REFUSAL not in out


@pytest.mark.parametrize("loc", LOCALES)
@pytest.mark.parametrize("before", [None, "examiner: old-name\n"])
@pytest.mark.parametrize("name", ["山田太郎", "-"])
def test_a_name_with_no_latin_letter_or_digit_is_refused(tmp_path, loc, before, name):
    cfg = tmp_path / ".vhir" / "config.yaml"
    if before is not None:
        cfg.parent.mkdir(parents=True)
        cfg.write_text(before)
    rc, out = _run(tmp_path, loc, name=name)
    assert rc == 1, out
    assert out.count(REFUSAL) == 1, out
    if before is None:
        assert not cfg.exists()
    else:
        assert cfg.read_text() == before


@pytest.mark.parametrize("loc", LOCALES)
def test_the_prompt_asks_again_after_a_refused_name(tmp_path, monkeypatch, loc):
    rc, out = _run(tmp_path, loc, answers="山田太郎\nyamada\ny\n")
    assert rc == 0, out
    assert out.count(REFUSAL) == 1, out
    assert _printed(out) == "yamada"
    assert _identity(tmp_path, monkeypatch) == ("yamada", "config")


@pytest.mark.parametrize("loc", LOCALES)
def test_yes_with_an_os_user_that_has_no_latin_letter_exits(tmp_path, loc):
    rc, out = _run(tmp_path, loc, yes=True, who="山田")
    assert rc == 1, out
    assert out.count(REFUSAL) == 1, out
    assert not (tmp_path / ".vhir" / "config.yaml").exists()


@pytest.mark.parametrize("loc", LOCALES)
def test_yes_with_a_latin_os_user_keeps_it(tmp_path, monkeypatch, loc):
    rc, out = _run(tmp_path, loc, yes=True)
    assert rc == 0, out
    assert _printed(out) == "osuser"
    assert _identity(tmp_path, monkeypatch) == ("osuser", "config")


@pytest.mark.parametrize("read_from", ["/dev/stdin", "/nonexistent/tty"])
@pytest.mark.parametrize("loc", LOCALES)
def test_no_answer_with_an_os_user_that_has_no_latin_letter_exits(
    tmp_path, loc, read_from
):
    rc, out = _run(
        tmp_path, loc, answers=None, who="山田", read_from=read_from, timeout=10
    )
    assert rc == 1, out
    assert out.count(REFUSAL) == 1, out
    assert not (tmp_path / ".vhir" / "config.yaml").exists()


@pytest.mark.parametrize("loc", LOCALES)
def test_no_answer_with_a_latin_os_user_keeps_it(tmp_path, monkeypatch, loc):
    rc, out = _run(tmp_path, loc, answers=None, timeout=10)
    assert rc == 0, out
    assert _printed(out) == "osuser"
    assert _identity(tmp_path, monkeypatch) == ("osuser", "config")
