# escapeHtml Audit — Dashboard v1 (Sprint 0 Gate)

**Date:** 2026-03-16
**File:** `static/index.html` (2934 lines)
**Result:** PASS — all innerHTML assignments use escapeHtml on user-controllable strings

## Counts

- innerHTML assignments: 34
- escapeHtml() calls: 92
- insertAdjacentHTML calls: 0
- document.write calls: 0

## Test Vector

`<img onerror=alert(1)>` as finding title imported via `aiir merge`:
1. `renderFinding()` calls `renderEditableField('title', ...)`
2. `renderEditableField()` calls `renderFieldWithDelta()`
3. `renderFieldWithDelta()` wraps value in `escapeHtml(String(value))`
4. Output: `&lt;img onerror=alert(1)&gt;` — rendered as inert text

**Result: payload does NOT execute.**

## Hardening Opportunities (non-exploitable)

- `renderResultSummary()`: `summary.exit_code` and `summary.stdout_bytes`
  inserted without escapeHtml(). Always numeric from server-side audit JSONL.
  Non-exploitable but inconsistent with the escaping discipline elsewhere.

## Re-audit Required

After any Sprint A/B changes that add new innerHTML rendering code.
