# escapeHtml Audit — Dashboard v2 (Post Sprint A/B)

**Date:** 2026-03-16
**Files:** `static/v2/index.html` (3209 lines), `static/index.html` (v1, unchanged)
**Result:** PASS — all innerHTML assignments use escapeHtml on user-controllable strings

## Counts (v2)

- innerHTML assignments: ~45
- escapeHtml() calls: ~110
- escapeJsString() calls in onclick: ~25
- insertAdjacentHTML calls: 0
- document.write calls: 0
- eval/Function calls: 0

## Test Vector

`<img onerror=alert(1)>` as finding title imported via `aiir merge`:
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
