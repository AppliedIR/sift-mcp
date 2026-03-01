---
name: welcome
description: Post-install verification and onboarding for full AIIR
---

# /welcome — Post-Install Verification and Onboarding

Follow these phases in order. Report results as you go. Stop on failure.

---

## Phase 1: Your Arsenal

### Step 1: Backend Inventory

Run `aiir setup test` via Bash. If `aiir` is not in PATH (common on
fresh installs before shell restart), use `~/.aiir/venv/bin/aiir`
instead. Do NOT warn about PATH — the installer already told the user
to restart their shell.

It hits the gateway `/health` endpoint and returns per-backend status
with tool counts. Report the results.

If the gateway is not responding, stop immediately:
"Gateway not reachable. Check: `aiir service status`"

### Step 2: Forensic Capabilities

Call `list_available_tools` on sift-mcp. Do NOT display the raw tool list.
Summarize as a single line with count and categories:

```
Forensic tools:   N available (memory, filesystem, registry, timeline, network, imaging)
```

Only mention tools that are MISSING from expected categories. Do not
list individual tools unless they are absent. Do NOT show install
commands for missing tools — missing tools are a SIFT distribution
issue, not an AIIR problem.

Zimmerman tools that only run on Windows (PECmd, SrumECmd) are not
expected on Linux. Do not flag them as missing. If the examiner needs
prefetch or SRUM parsing, mention WinTools MCP as the solution.

### Step 3: Knowledge and Baselines

Call `get_stats` on forensic-rag and `get_health` on windows-triage:
```
Knowledge base:   N records across M sources
Triage baselines: known_good.db (X entries), context.db (Y entries)
```

### Step 4: Report Profiles

Call `list_profiles` on report-mcp. List profiles with descriptions
as returned by the tool.

---

## Phase 2: How to Work

### Step 5: The Interaction Model

Explain:
```
AIIR is conversation driven. Ask Claude to do anything:
- "Create a case called incident-001"
- "Register this evidence file"
- "Run volatility on this memory dump"
- "What artifacts indicate credential dumping?"
- "Generate an executive report"

Claude handles almost everything through MCP tools. No need to
memorize lots of commands or tool names.

The only CLI-only operations:
  aiir approve            Approve findings (HMAC-signed with your PIN)
  aiir reject             Reject findings with reason
  aiir exec               Run forensic command with TTY confirmation
  aiir config --setup-pin Set your approval PIN
  aiir config --reset-pin Change your approval PIN

These require YOUR terminal confirmation. By design, Claude cannot
approve its own findings or manage your PIN.
```

Do NOT add PATH warnings, export suggestions, or notes about `aiir`
not being in PATH. The installer already handles PATH messaging.

### Step 6: The Finding Workflow

Explain the approval workflow:
```
How findings work:
1. Claude discovers evidence and presents it to you
2. You discuss and refine the interpretation
3. Claude calls record_finding() — staged as DRAFT
4. Open the case dashboard to review: http://localhost:4508/dashboard/
5. Approve, edit, or reject findings from the dashboard
6. Finalize: aiir approve --review (requires your PIN)
   - Applies your dashboard decisions
   - Creates HMAC-signed approval records
   - Status: DRAFT → APPROVED

The AI proposes, the human validates. No finding is final
until you sign it.
```

### Step 7: Getting Started

Explain case creation and the sandbox model:
```
To begin your first investigation:

1. Create a case — ask Claude: "Create a case called incident-001"
2. Exit this session (/exit or Ctrl+C)
3. cd into the case directory: cd cases/incident-001
4. Start Claude Code again: claude
   Tip: claude --continue resumes your most recent session.
        claude --resume lets you pick from past sessions.

*** IMPORTANT: Always start Claude Code from within the case    ***
*** directory. The sandbox restricts all commands to this        ***
*** directory tree. Launching from elsewhere bypasses case       ***
*** isolation and forensic controls.                            ***

5. You do not need to run /welcome again.

Place evidence in the evidence/ subdirectory before starting.
```

---

## Phase 3: Infrastructure Confirmation

### Step 8: Sandbox Test

Run via Bash:
```bash
bwrap --unshare-user -- true
```
- Exit code 0: sandbox functional
- If fails: this is common on fresh installs (AppArmor may need a
  reboot). Do NOT display a warning. Do NOT create a separate section
  about sandbox fixes. Do NOT suggest AppArmor commands or action
  items. Just note "Sandbox: needs reboot" in the summary block.
  The installer already informed the user.

### Step 9: Controls Summary

Read settings.json (both `~/.claude/settings.json` and project
`.claude/settings.json`). Verify:
- **Deny rules** present (report actual count found)
- **Pre-bash guard** hook present
- **Audit hook** present
- **Prompt hook** present

If no case is active, note that the audit hook activates once a
case is created. This is informational, not a failure.

### Step 10: Config Conflicts

Read `~/.claude.json` (if it exists). Check for `mcpServers` entries
that duplicate gateway backends. If found, warn about double-loading.

### Step 11: REMnux Integration

Check if remnux-mcp is configured in the gateway backends.
- If configured: call `get_health`, report status
- If not: explain that REMnux (200+ malware analysis tools) can be
  added during `aiir setup client` by providing host and port.

---

## Phase 4: Summary

### Step 12: Status Block

Produce:
```
AIIR Full — Installation Verified
===================================
Gateway:          OK (X tools, Y backends)
  forensic-mcp:   OK    case-mcp:       OK
  sift-mcp:       OK    report-mcp:     OK
  forensic-rag:   OK (N records)
  windows-triage: OK (databases loaded)
  opencti-mcp:    [OK/NOT CONFIGURED]

Forensic tools:   N available (memory, filesystem, registry, ...)
Knowledge base:   N records across M sources

Controls:
  Sandbox:        [OK/needs reboot]
  Deny rules:     OK (N)
  Audit hook:     OK
  Pre-bash guard: OK

To start: ask Claude to create a case, then exit, cd into the
case directory, and restart Claude Code.
```

The summary block above is the COMPLETE output for Phase 4. Do NOT
add Action Items, PATH instructions, sandbox fix commands, or any
other sections after the summary.
