---
name: welcome
description: Post-install verification and onboarding for AIIR lite
---

# /welcome — Post-Install Verification and Onboarding

**IMPORTANT:** All MCP checks in this skill MUST use MCP tool calls,
not Bash subprocess. If an MCP tool is unavailable, report it as a
failure — do not try to work around it with subprocess, filesystem
reads, or any other method. The ONLY acceptable action for an
unavailable MCP tool is to report the failure message specified below.
Do NOT attempt to infer status by other means.

Run these steps in order. Report results as you go. Stop and warn on
any failure.

---

## Step 1: Verify MCP Health

**forensic-rag:**
- Use the `forensic-rag` MCP tool `get_stats` (do NOT use subprocess
  or Bash — use the MCP tool directly)
- Report: document count, source count, index status
- If the MCP tool is not available or errors, report: "forensic-rag
  MCP not responding. The RAG index may not be built. Run:
  `RAG_INDEX_DIR=~/.aiir/rag-index python -m rag_mcp.build`"

**windows-triage:**
- Use the `windows-triage` MCP tool `get_health` (do NOT use
  subprocess or Bash — use the MCP tool directly)
- Report: database status, record counts per database
- If the MCP tool is not available or errors, report: "windows-triage
  MCP not responding. Check that triage databases exist at
  ~/.aiir/triage-db/"

Report status:
```
MCP Health:
  forensic-rag:     OK (X records, Y sources)
  windows-triage:   OK (databases loaded)
```

---

## Step 2: Verify Audit Hook

1. Run a trivial Bash command: `echo audit-hook-test`
2. Check if an audit entry was created. Look for
   `audit/claude-code.jsonl` in the active case directory
   (check `AIIR_CASE_DIR` env var, then `~/.aiir/active_case`)
3. If the file exists and has a recent entry: report OK
4. If missing: warn "Audit hook not working. Check that
   `hooks/forensic-audit.sh` exists and `AIIR_CASE_DIR` is set in
   your MCP configuration."

Note: If no case is active, the audit hook silently skips. This is
normal before `/case init`. Report this as informational, not a failure.

---

## Step 3: Check Config Conflicts

Read `~/.claude.json` (if it exists). Check for `mcpServers` entries
that duplicate the project `.mcp.json` servers (forensic-rag,
windows-triage).

- If conflicts found: warn "Duplicate MCP entries in ~/.claude.json
  may cause double-loading. Consider removing them."
- If no conflicts or file doesn't exist: report OK

---

## Step 4: Explain /case

Explain how case management works in lite mode:

**The `/case` skill manages your investigations:**

- `/case init <name>` — Create a new investigation with template files
- `/case open <name>` — Load an existing case
- `/case status` — Show current active case
- `/case list` — List all cases
- `/case close` — Close the active case

**Case directory structure:**
```
cases/<name>/
  CASE.yaml           # Metadata (name, description, status)
  evidence/           # Source evidence (read from here)
  extracted/          # Tool output (write here)
  audit/              # JSONL audit logs (auto-created)
  reports/
    ACTIONS.md        # Timestamped action log
    FINDINGS.md       # Evidence-backed findings
    TIMELINE.md       # Chronological events
```

The state file at `.claude/active_case` tracks which case is active
across sessions.

---

## Step 5: Explain Audit Trail

Explain what gets logged and where:

**What gets logged:**
- Every Bash command you run (via the PostToolUse hook)
- Every forensic-rag search query and result
- Every windows-triage validation query

**Where logs live:**
```
cases/<name>/audit/
  claude-code.jsonl           # All Bash commands
  forensic-rag-mcp.jsonl      # RAG search queries
  windows-triage-mcp.jsonl    # Baseline validations
```

**JSONL format:** Each line is a JSON object with timestamp, command,
evidence_id, output hash, and session ID. The audit trail is automatic
and tamper-evident (SHA-256 hashes of command + output).

---

## Step 6: Example Commands

Show these starting points:

**Start an investigation:**
```
/case init incident-001
```

**Search forensic knowledge:**
- "What artifacts indicate credential dumping?"
- "Search for lateral movement techniques in Windows environments"

**Analyze evidence:**
- "Analyze this EVTX file for suspicious activity"
- "Parse the $MFT and look for recently created executables"

**Validate Windows artifacts:**
- "Check if svchost.exe spawned by cmd.exe is normal"
- "Is this file hash associated with known malware?"

---

## Step 7: Optional Add-ons

Check which optional MCPs are configured and list what's available:

**Not installed (add with quickstart-lite.sh flags):**
- OpenCTI: `./quickstart-lite.sh --opencti` — Live threat intelligence
- REMnux: `./quickstart-lite.sh --remnux=HOST:PORT` — Automated malware analysis
- MS Learn: `./quickstart-lite.sh --mslearn` — Microsoft documentation search
- Zeltser: `./quickstart-lite.sh --zeltser` — IR writing guidelines

If any optional MCPs are already configured, report them as active.

---

## Step 8: Bash Permission Preference

Present this to the user:

> Lite mode runs forensic tools through Bash. You have two options:
>
> 1. **Approve each command** — Claude asks permission before every
>    Bash command. More oversight, more friction during investigations.
> 2. **Auto-allow Bash** — Commands run without prompting. The audit
>    hook still logs every command regardless of this setting.
>
> Which do you prefer?

If the user chooses option 2:
- Add `"Bash(*)"` to the `permissions.allow` array in the project's
  `.claude/settings.json`

If the user chooses option 1:
- No changes needed (this is the default)
- Tell the user: "You can change this later by adding `Bash(*)` to
  permissions.allow in `.claude/settings.json`."

---

## Summary

After all steps, produce a summary:

```
AIIR Lite — Installation Verified
==================================
forensic-rag:     [OK/WARN] (X records)
windows-triage:   [OK/WARN] (databases)
Audit hook:       [OK/WARN/NO CASE]
Config conflicts:  [OK/WARN]
```

If the user chose option 2 (auto-allow Bash) in Step 8, end with:
"Settings updated. Restart Claude Code to apply, then run
`/case init <name>` to begin."

Otherwise end with:
"Ready for forensic work. Run `/case init <name>` to begin."
