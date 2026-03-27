# Examiner Portal

The Examiner Portal is a browser-based interface for reviewing AI-generated forensic findings. It runs on the SIFT gateway and requires no installation on the examiner's machine.

**Open the portal:** `vhir portal` or navigate to `http://<gateway>:4508/portal/`

## Tabs

The portal has 8 tabs:

| Tab | Purpose |
|-----|---------|
| **Overview** | Case summary: finding counts by status, timeline span, evidence count, case metadata |
| **Findings** | Review, edit, approve, and reject findings — the primary workflow |
| **Timeline** | Chronological view of incident events with visual ruler and filtering |
| **Hosts** | Findings grouped by host (from the `host` field on each finding) |
| **Accounts** | Findings grouped by affected account |
| **Evidence** | Registered evidence files with SHA-256 hashes and integrity verification |
| **IOCs** | Indicators of compromise auto-extracted from findings, with cascading status |
| **TODOs** | Investigation tasks with status tracking |

## Finding Review Workflow

### Detail Panel Layout

When you select a finding, the detail panel shows:

1. **Sticky bar** — always visible at the top:
   - Finding ID, type badge, status badge
   - Host and event timestamp (incident date)
   - Approve / Reject / Undo buttons
   - Editable title with pencil icon

2. **Evidence Artifacts** — the raw evidence: source file, extraction command, and content. This appears first so the examiner sees proof before the AI's narrative.

3. **Provenance warnings** — amber alerts if the evidence chain has issues (e.g., source evidence not registered, audit trail gaps). Only shown when problems exist.

4. **Observation** — factual description of what the evidence shows. Editable.

5. **Interpretation** — analytical meaning of the evidence. Editable.

6. **Confidence + Justification** — confidence level badge (clickable to edit) with inline justification text. Shown as one row: `[MEDIUM] — Two artifacts: Security 4624 + Prefetch.`

7. **Context** — collapsible section for examiner notes (data exposure, business impact, chain of custody).

8. **Meta bar** — compact single line with host, account, event type, event timestamp, timeline link, and staging info. Reference data, not decision data.

### Editing Fields

Click the pencil icon (✎) next to any field label to edit. Fields become a text area with Save/Cancel buttons. The confidence badge opens a dropdown selector (HIGH, MEDIUM, LOW, SPECULATIVE).

All edits are staged locally in the browser until committed. The original value is preserved — edits show the modification with a strikethrough original and the new value.

### Approving and Rejecting

- **Approve** (`a` key) — marks the finding for approval
- **Reject** (`r` key) — opens a dialog for rejection reason
- **Undo** (`s` key) — removes the staged review action

Staged actions are shown with colored badges: green for approved, red for rejected, orange for edited.

**Batch operations:** Select multiple findings in the sidebar, then use "Approve All" or "Reject All" in the batch toolbar.

### Committing Reviews

Press `Shift+C` or click the Commit button to finalize all staged reviews. The commit dialog:

1. Shows a summary of pending actions (approvals, rejections, edits)
2. Requires the examiner's password for HMAC signing
3. Uses challenge-response authentication — the password never leaves the browser
4. Signs each approval/rejection with a cryptographic proof

After commit, findings move to APPROVED or REJECTED status. This is irreversible without re-staging.

## Timeline

The timeline tab shows incident events in chronological order with:

- **Visual ruler** — a proportional time axis with event markers colored by type (auth, execution, lateral, network, file, persistence, registry)
- **Filtering** — by status (pending/approved/rejected), event type, date range, source, and text search
- **Compact rows** — expandable to show full event details
- **Include/Exclude** — timeline events can be included or excluded from reports (same approve/reject pattern as findings)

When the timeline spans more than one year, axis labels include the year (e.g., `Jan '23 | Aug '25`).

## Evidence Tab

Lists all registered evidence files with:

- File path and SHA-256 hash
- Registration timestamp
- Integrity verification status (click to verify hash matches current file)
- Cross-references to findings that cite each evidence file

## IOCs Tab

Indicators of compromise auto-extracted from findings:

- IP addresses, domains, hashes, file paths, registry keys, accounts
- Each IOC links back to the source findings
- IOC status cascades from finding status — when all source findings are approved, the IOC is auto-approved
- Manually reviewed IOCs are protected from auto-cascading

## Sidebar

The findings sidebar shows:

- **Search** — full-text search across finding titles, observations, and interpretations
- **Filter presets** — Pending (unreviewed), Approved, Rejected, All
- **Finding cards** — show ID, title, confidence badge, host, and review status
- **Progress bar** — shows review completion (e.g., "12 of 15 reviewed")

## Keyboard Shortcuts

Press `?` to show the full shortcut list:

| Key | Action |
|-----|--------|
| `j` / `↓` | Next finding |
| `k` / `↑` | Previous finding |
| `a` | Approve / Include |
| `r` | Reject / Exclude |
| `e` | Edit interpretation |
| `s` | Undo review |
| `/` | Focus search |
| `Esc` | Close / cancel |
| `Shift+C` | Commit reviews |
| `Enter` / `Space` | Expand/collapse timeline row |
| `1`-`8` | Switch to tab |
| `?` | Show shortcuts |

## Security

- The portal serves over the gateway's HTTP endpoint (port 4508)
- Static assets (images, icons) are served without authentication
- All API endpoints require a Bearer token (from `gateway.yaml`)
- The commit workflow uses PBKDF2 key derivation + HMAC challenge-response — the examiner's password is never transmitted
- Content Security Policy restricts scripts to inline only (no external script loading)
- X-Frame-Options: DENY prevents clickjacking

## Opening the Portal

From the SIFT workstation:

```bash
vhir portal
```

From a remote machine (after `vhir join`):

```
http://<sift-ip>:4508/portal/
```

The legacy v1 dashboard is available at `/dashboard/` but is deprecated in favor of the portal.
