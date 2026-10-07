"""Case text inside a quoted HTML attribute stays inside it.

The portal pages escape case text with `escapeHtml`, which went through a
text node: `&`, `<` and `>` were escaped, but not `"`. Much of that output
lands inside double-quoted attributes (`title="…"`, `data-id="…"`,
`class="badge …"`), so an IOC value or id holding `" onmouseover="…` ended
the attribute and added a handler. `escapeHtml` now escapes quotes as well.
Run under node with a `document` stub that escapes as a browser does.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import case_dashboard.routes as D
import pytest

STATIC = Path(D.__file__).parent / "static"
PAGES = {"v2": STATIC / "v2" / "index.html", "v1": STATIC / "index.html"}
PAYLOAD = '" onmouseover="alert(1)'
# A browser's textContent -> innerHTML: & < > only, never quotes
_DOCUMENT = (
    "const document = {createElement: () => ({set textContent(s) {"
    "this.innerHTML = String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')"
    ".replace(/>/g, '&gt;');}})};\n"
)
# An attribute built around escapeHtml output, on one line or across two
_SINK = re.compile(r"""([\w-]+)="([^"<>']*)'\s*\+\s*escapeHtml\(""")

pytestmark = pytest.mark.skipif(
    not shutil.which("node"), reason="node is not installed"
)


def _js_function(page: str, name: str) -> str:
    start = page.index(f"function {name}(")
    return page[start : page.index("\n}\n", start) + 3]


def _node(script: str) -> str:
    return subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout


def _escaped(page_name: str) -> str:
    page = PAGES[page_name].read_text()
    return _node(
        _DOCUMENT
        + _js_function(page, "escapeHtml")
        + f"process.stdout.write(escapeHtml({json.dumps(PAYLOAD + chr(39))}));"
    )


@pytest.mark.parametrize("page", sorted(PAGES))
def test_escape_html_escapes_both_quotes(page):
    assert _escaped(page) == "&quot; onmouseover=&quot;alert(1)&#39;"


def _sinks():
    for name, path in sorted(PAGES.items()):
        text = path.read_text()
        for m in _SINK.finditer(text):
            n = text.count("\n", 0, m.start()) + 1
            yield pytest.param(
                name, m.group(1), m.group(2), id=f"{name}:{n}:{m.group(1)}"
            )


@pytest.mark.parametrize("page, attr, before", list(_sinks()))
def test_case_text_stays_inside_each_quoted_attribute(page, attr, before):
    """Each attribute the pages build around escapeHtml output, with the
    payload as the case text: one attribute, closed where the page closes it."""
    rendered = f'<x {attr}="{before}{_escaped(page)}">'
    assert re.fullmatch(r'<x [\w-]+="[^"]*">', rendered), rendered


def test_at_least_the_known_sinks_are_checked():
    found = list(_sinks())
    assert len([p for p in found if p.values[0] == "v2"]) >= 9


def test_an_ioc_value_renders_inert_in_the_ioc_table():
    page = PAGES["v2"].read_text()
    iocs = [
        {
            "value": PAYLOAD,
            "type": "domain",
            "category": "network",
            "confidence": 'low" onmouseover="alert(2)',
            "status": "DRAFT",
            "sightings": [{"host": PAYLOAD}],
            "source_findings": [],
        }
    ]
    script = (
        _DOCUMENT.replace(
            "const document = {",
            "const els = {}; const document = {getElementById: (id) => "
            "(els[id] = els[id] || {value: '', innerHTML: ''}), ",
        )
        + "function setBadge() {}\nfunction escapeJsString(s) { return String(s); }\n"
        + f"var iocsData = {json.dumps(iocs)};\n"
        + _js_function(page, "escapeHtml")
        + _js_function(page, "renderIocs")
        + "renderIocs(); process.stdout.write(els.iocsBody.innerHTML);"
    )
    out = _node(script)
    assert 'title="&quot; onmouseover=&quot;alert(1)"' in out
    tags = re.sub(r'="[^"]*"', '=""', out)  # quoted attribute values are inert
    assert "onmouseover" not in "".join(re.findall(r"<[^>]*>", tags)), out


def test_the_edit_field_s_value_is_one_of_the_sinks():
    """The inline editor's `value="' +` with escapeHtml on the next line."""
    ids = [p.id for p in _sinks()]
    assert any(i.startswith("v2:") and i.endswith(":value") for i in ids), ids


def _js_escaped(page_name: str, text: str) -> str:
    page = PAGES[page_name].read_text()
    return _node(
        _js_function(page, "escapeJsString")
        + f"process.stdout.write(escapeJsString({json.dumps(text)}));"
    )


@pytest.mark.parametrize("page", sorted(PAGES))
def test_escape_js_string_has_no_quote_and_reads_back(page):
    text = 'x" onmouseover="alert(1)\' </b> & \\'
    out = _js_escaped(page, text)
    assert not set('"<>&') & set(out.replace("\\'", "")), out
    # Inside the handler's single-quoted JS string, it reads back as the text
    assert _node(f"process.stdout.write(String('{out}'));") == text


def _handlers():
    for name, path in sorted(PAGES.items()):
        text = path.read_text()
        for m in re.finditer(r"""on\w+="[^"]*?'\s*\+\s*escapeJsString\(""", text):
            n = text.count("\n", 0, m.start()) + 1
            yield pytest.param(name, id=f"{name}:{n}")


@pytest.mark.parametrize(
    "page", [p.values[0] for p in _handlers()], ids=[p.id for p in _handlers()]
)
def test_case_text_stays_inside_each_double_quoted_handler(page):
    rendered = f"<x onclick=\"go('{_js_escaped(page, PAYLOAD)}')\">"
    assert re.fullmatch(r'<x onclick="[^"]*">', rendered), rendered
