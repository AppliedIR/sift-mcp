---
name: case
description: Manage forensic investigation cases
arguments:
  - name: action
    required: false
    description: "Action: init, open, status, list, or close (omit for quick status)"
  - name: name
    required: false
    description: Case name (for init/open)
---

# Case Management Skill

Manage forensic investigation cases.

**Action:** $action
**Case name:** $name

## State File

Active case is tracked in `.claude/active_case`. Format:
```
<case-name>
evidence: <evidence_path>
extracted: <extracted_path>
reports: <reports_path>
```

This file is read by the prompt hook to inject paths into every Claude prompt.

---

## Actions

### (no action) - Quick status check

**When user types just `/case` with no arguments:**

1. Read `.claude/active_case`
2. If file exists and valid:
   - Display case status (same format as `open`)
3. If file missing or invalid:
   - List available cases (same as `list`)
   - Suggest: "Use `/case init <name>` to create or `/case open <name>` to load"

**Use case:** User starts new session, types `/case` to see where they are.

---

### `init [name]` - Create new case

1. If no name provided, ask for one
2. **Validate name:** alphanumeric, hyphens, underscores only. No spaces. Must not already exist.
   - Valid: `incident-2024-001`, `ransomware_acme`, `case42`
   - Invalid: `my case` (space), `case@home` (special char)
   - Regex: `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`
3. Propose default structure:
   ```
   Creating case: <name>

   Default paths:
     Evidence:   cases/<name>/evidence/
     Extracted:  cases/<name>/extracted/
     Reports:    cases/<name>/reports/

   Accept defaults? [Y] or customize paths? [C]
   ```
4. If customize, ask for each path individually
5. Ask for brief description (one line)
6. Create directory structure:
   ```
   cases/<name>/
   ├── CASE.yaml
   ├── evidence/
   ├── extracted/
   ├── audit/               # JSONL audit logs (auto-created by hooks)
   └── reports/
       ├── ACTIONS.md
       ├── FINDINGS.md
       └── TIMELINE.md
   ```
7. Copy templates from `cases/.templates/` to reports folder
8. Write CASE.yaml:
   ```yaml
   name: <name>
   description: <description>
   created: <today>
   status: active

   paths:
     evidence: cases/<name>/evidence/
     extracted: cases/<name>/extracted/
     reports: cases/<name>/reports/
   ```
9. **Write state file** `.claude/active_case`:
   ```
   <name>
   evidence: cases/<name>/evidence/
   extracted: cases/<name>/extracted/
   reports: cases/<name>/reports/
   ```
10. Display confirmation with paths

---

### `open <name>` - Load existing case

1. Validate case exists: `cases/<name>/CASE.yaml`
2. Read CASE.yaml for paths
3. **Write state file** `.claude/active_case`:
   ```
   <name>
   evidence: <evidence_path from CASE.yaml>
   extracted: <extracted_path from CASE.yaml>
   reports: <reports_path from CASE.yaml>
   ```
4. Display case context:
   ```
   ═══════════════════════════════════════════════════
   ACTIVE CASE: <name>
   ═══════════════════════════════════════════════════
   Description: <description>
   Status: <status>
   Created: <date>

   PATHS:
     Evidence:   <evidence_path>
     Extracted:  <extracted_path>
     Reports:    <reports_path>

   READ evidence from Evidence path.
   WRITE tool output to Extracted path.
   UPDATE ACTIONS.md, FINDINGS.md, TIMELINE.md in Reports path.
   ═══════════════════════════════════════════════════
   ```

---

### `status` - Show current context

1. **Read state file** `.claude/active_case`
2. If file missing → "No active case. Use `/case list` to see available cases."
3. If file exists:
   - Parse case name (first line) and paths
   - Verify `cases/<name>/CASE.yaml` still exists
   - If CASE.yaml missing → "Case folder no longer exists", **delete state file**, show list
   - If exists → Read CASE.yaml, display same format as `open`

---

### `list` - List all cases

1. **Read state file** `.claude/active_case` (if exists) to get active case name
2. Scan `cases/*/CASE.yaml` (exclude `.templates`)
3. Display table with active case marked:
   ```
   | Case                | Status | Created    | Description              |
   |---------------------|--------|------------|--------------------------|
   | * incident-2024-001 | active | 2024-02-05 | Suspected ransomware...  |
   | old-case            | closed | 2024-01-15 | Previous investigation   |
   ```
   (asterisk marks active case)
4. If no cases found, suggest `/case init`

---

### `close [name]` - Close a case

1. **Read state file** `.claude/active_case`
2. If no name provided:
   - If state file exists, use that case name
   - Otherwise → "No active case. Specify case name: `/case close <name>`"
3. Read `cases/<name>/CASE.yaml`
4. Update CASE.yaml: `status: closed`, add `closed_date: <today>`
5. Write updated CASE.yaml
6. **Delete state file** `.claude/active_case`
7. Confirm closure

---

## Important Notes

- **State file location:** `.claude/active_case`
- **State file purpose:** Persists active case across context compaction and sessions
- **Hook integration:** Prompt hook reads state file, injects paths every prompt
- All case data lives in `cases/` directory
- Templates are in `cases/.templates/`
- CASE.yaml stores metadata and paths (source of truth)
- State file is a cache of CASE.yaml paths for quick hook access
- Evidence folder is for source evidence (read from here)
- Extracted folder is for tool output (write here)
- Reports folder is for documentation (ACTIONS.md, FINDINGS.md, TIMELINE.md)
