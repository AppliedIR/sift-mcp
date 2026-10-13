# escapeHtml Audit — Dashboard v2 (Post Sprint A/B)

**Date:** 2026-03-16
**Files:** `static/v2/index.html` (3209 lines at this audit; 4300 with the Hosts tab), `static/index.html` (v1, since retired and deleted: `/dashboard` redirects to the portal)
**Result:** PASS — all innerHTML assignments use escapeHtml on user-controllable strings

## Counts (v2)

- innerHTML assignments: ~45
- escapeHtml() calls: ~110
- escapeJsString() calls in onclick: ~25
- insertAdjacentHTML calls: 0
- document.write calls: 0
- eval/Function calls: 0

## Test Vector

`<img onerror=alert(1)>` as finding title imported via `vhir merge`:
1. `renderFinding()` calls `renderEditableField('title', ...)`
2. `renderEditableField()` calls `renderFieldWithDelta()`
3. `renderFieldWithDelta()` wraps value in `escapeHtml(String(value))`
4. Output: `&lt;img onerror=alert(1)&gt;` — rendered as inert text

**Result: payload does NOT execute.**

## Hardening Applied (Sprint B review)

- `renderResultSummary()`: `exit_code` and `stdout_bytes` now wrapped in
  `escapeHtml(String(...))`. Previously unescaped (numeric, non-exploitable).
- `formatTime()`/`formatTimeShort()`: all innerHTML usages now wrapped in
  `escapeHtml()`. Fallback path returns raw input on parse failure.
- `confClass`/`confClassFor()`: class attribute values now escaped.
- `field` parameter in onclick: all instances now use `escapeJsString(field)`.
- `de.modifications` iteration: changed from `for..in` to `Object.keys()` to
  prevent prototype pollution.
- Error banner uses `textContent` (not innerHTML).
- `_snapshot` stripped before POST via `deltaForSave()` (in-memory only).

## Re-audit Required

After any changes that add new innerHTML rendering code.

## Hosts tab (2026-10-07)

The Hosts tab replaces "Impacted Hosts" and renders host names, evidence,
origins, flags, run ids, unit locators, reasons, history and pivots read from
the case's host logs and findings. Every sink:

| Function | Sinks | Escaping |
|---|---|---|
| `hostNamesHtml` | raw name, evidence, origins, flags | `escapeHtml` |
| `hostsHeaderHtml` | state names, host-list sha256 and examiner, names listed with no data, the host-list hint | `escapeHtml`; counts are numbers |
| `hostRunsHtml` | run id, unit locator, raw name, reason | `escapeHtml` |
| `hostProposedHtml` | suggested host name in an `<input value="">`, names, flags and conflicts | `escapeAttr` for the value (escapes `"`), `escapeHtml` for text |
| `hostPivotsHtml` | item kind, id, title, "ambiguous: also matches" names, the indexed-data query | `escapeHtml` |
| `hostRowsHtml` | canonical, former names, state, flags | `escapeHtml` |
| `hostDetailHtml` | canonical; history time, examiner, origin, action | `escapeHtml` |
| `hostCorrectionsHtml` | machine id, its name as shown (`data-seen`) and keys (attributes and labels); other machines' names (the merge picker's suggestions) | `escapeAttr` (attributes, option values), `escapeHtml` (text) |
| `hostOpsHtml` | every journal field shown (`host-ops.json` is case data others can write): operation id, kind, new name, reason, start time, examiner, records to relabel, records relabelled; the last request's state and reason | `escapeHtml(String(…))`; the id in `data-op` with `escapeAttr` |
| `renderHosts` error | the error message | `escapeHtml` |

- **Buttons** carry only an action name and a numeric index into the page's
  data (`data-host-act`, `data-i`), handled by one delegated click listener:
  no case text reaches an `onclick` string or a data attribute.
- **`escapeAttr`:** a browser's textContent → innerHTML escapes `&`, `<` and
  `>` but not quotes, so `escapeHtml` alone isn't safe inside a double-quoted
  attribute; `escapeAttr` adds `&quot;`.
- **Tests:** `tests/test_case_dashboard/test_hosts_tab.py::TestTheTabRendersCaseTextAsText`
  runs these functions under node with `<img src=x onerror=…>` and a quote
  breakout in every field, and checks that no tag or handler comes from case
  text.

**Known gap (pre-existing, outside the Hosts tab):** nine older sinks put
`escapeHtml(...)` inside a double-quoted attribute (`data-id`, `class`,
`title`, `data-audit-id`, `data-artifact-type`, `data-role`), for example the
IOC table's `title="…"` carrying an IOC value. A value with `"` can end the
attribute there. They should move to `escapeAttr`.
