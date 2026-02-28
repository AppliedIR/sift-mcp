---
name: welcome
description: Post-install verification and onboarding for full AIIR
---

# /welcome — Post-Install Verification and Onboarding

Follow these phases in order. Report results as you go. Stop on failure.

---

## Phase 1: Your Arsenal

### Step 1: Backend Inventory

Run `aiir setup test` via Bash. It hits the gateway `/health` endpoint
and returns per-backend status with tool counts. Report the results.

If the gateway is not responding, stop immediately:
"Gateway not reachable. Check: `aiir service status`"

### Step 2: Forensic Capabilities

Call `list_available_tools` on sift-mcp. Group by category:
- **Memory:** vol, strings, bulk_extractor...
- **Filesystem:** fls, mmls, icat, MFTECmd...
- **Registry:** RECmd, regripper...
- **Event logs:** EvtxECmd, evtxexport...
- **Timeline:** log2timeline.py, psort.py, mactime...
- **Network:** tshark, tcpdump, ngrep...
- **Imaging:** dc3dd, ewfacquire, ewfinfo...

Highlight missing expected tools and suggest alternatives.

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
AIIR is conversation-driven. Ask Claude to do anything:
- "Create a case called incident-001"
- "Register this evidence file"
- "Run volatility on this memory dump"
- "What artifacts indicate credential dumping?"
- "Generate an executive report"

Claude handles everything through MCP tools. You never need to
memorize commands or tool names.

The only CLI-only operations:
  aiir approve            Approve findings (HMAC-signed with your PIN)
  aiir reject             Reject findings with reason
  aiir exec               Run forensic command with TTY confirmation
  aiir config --setup-pin Set your approval PIN
  aiir config --reset-pin Change your approval PIN

These require YOUR terminal confirmation. By design, Claude cannot
approve its own findings or manage your PIN.
```

### Step 6: The Finding Workflow

Explain the HMAC approval chain:
```
How findings work:
1. Claude discovers evidence and presents it to you
2. You discuss and refine the interpretation
3. Claude calls record_finding() — staged as DRAFT
4. You review: aiir review --findings
5. You approve: aiir approve <id>
   - Requires your PIN (set via aiir config --setup-pin)
   - Creates HMAC-signed approval record
   - Status: DRAFT → APPROVED
6. aiir review --verify confirms cryptographic integrity

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

Starting from the case directory means the sandbox restricts all
Bash commands to this directory tree. Evidence from other cases
cannot be accessed or modified — each investigation is isolated.

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
- If fails: check AppArmor (`aa-status 2>/dev/null | grep bwrap`).
  Suggest the AIIR deployment guide for profile configuration.

### Step 9: Controls Summary

Read settings.json (both `~/.claude/settings.json` and project
`.claude/settings.json`). Verify:
- **21 deny rules** active
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
  Sandbox:        OK     Deny rules:    OK (21)
  Audit hook:     OK     Pre-bash guard: OK

To start: ask Claude to create a case, then exit, cd into the
case directory, and restart Claude Code.
```
