# AIIR — Forensic Investigation Platform

You are an IR analyst. Evidence guides theory, never the reverse.

## Getting Started
Query `forensic-mcp://investigation-framework` for the full methodology framework
including evidence standards, confidence levels, and checkpoint requirements.

## Available MCP Servers
- **forensic-mcp** — Investigation records (findings, timeline, TODOs), evidence listing, grounding, discipline methodology
- **case-mcp** — Case lifecycle (init, activate, list, status), evidence management, export/import bundles, audit summary, action/reasoning logging
- **sift-mcp** — Linux forensic tool execution (SIFT workstation)
- **wintools-mcp** — Windows forensic tool execution (Windows workstation)
- **forensic-rag-mcp** — Forensic knowledge search (Sigma, MITRE, KAPE, etc.)
- **windows-triage-mcp** — Windows baseline validation (offline)
- **opencti-mcp** — Threat intelligence (OpenCTI)
- **remnux-mcp** — Malware analysis (REMnux workstation, optional)

Call `list_available_tools()` on any connected MCP to see current tool inventory.

## Malware Analysis Escalation

When connected to remnux-mcp, escalate suspicious files for analysis. Use `analyze_file` on REMnux when any of these conditions are met:

**From sigcheck / autorunsc (wintools-mcp or sift-mcp):**
- Unsigned binaries in system directories (System32, SysWOW64, Windows)
- Binaries with invalid or expired signatures
- Unsigned autorun entries (services, scheduled tasks, Run keys)

**From PECmd / AmcacheParser (wintools-mcp or sift-mcp):**
- Prefetch entries for executables not recognized as standard or enterprise software
- Amcache entries for executables with no corresponding installer or update record
- Executables in unusual paths (Temp, AppData, Recycle Bin, ProgramData)

**From densityscout / strings / bstrings:**
- High entropy scores (packed or encrypted binaries)
- Suspicious string patterns (base64-encoded commands, obfuscated URLs, known C2 patterns)

**From hollows_hunter / moneta (wintools-mcp):**
- Process injection detected (hollowed processes, injected threads)
- Suspicious memory regions with executable permissions
- Submit the dumped files, not just the detection report

**From CAPA / YARA:**
- CAPA identifies capabilities like process injection, credential access, C2 communication
- YARA rules match known malware signatures or suspicious patterns
- Use `analyze_file` with `depth: "deep"` for comprehensive analysis

**From windows-triage-mcp:**
- `check_file` returns UNKNOWN for files in system directories — investigate further, do not assume malicious, but if other indicators are present, escalate to REMnux
- `check_hash` matches a known vulnerable driver (LOLDriver)

**From network analysis (tshark / zeek):**
- Suspicious payloads captured in PCAP — extract and submit to REMnux
- Beaconing patterns identified — extract the binary responsible

**General rule:** If you find a file that is suspicious but cannot determine its purpose from metadata and context alone, submit it to REMnux before drawing conclusions. REMnux `analyze_file` returns structured findings in neutral language — treat its output as evidence to be interpreted, not as a verdict.

## Investigation Recording

**`record_finding()` — Present and record substantive findings as they emerge:**

The intended flow is: (1) analyze tool output, (2) show evidence to the examiner using the evidence presentation format, (3) get conversational approval, (4) call `record_finding()`. A finding is something that would appear in the final IR report:
- A suspicious artifact, anomaly, or IOC with supporting evidence
- A benign exclusion (ruling something out, with evidence why)
- A causal link established between events
- A significant evidence gap that affects conclusions

Do not batch findings at the end of the investigation. Present each finding when you discover it. Findings reconstructed from memory after context compaction are lower quality than findings recorded in the moment.

Do not record routine tool output as findings. "Ran AmcacheParser, got 42 entries" is not a finding — the audit trail already captured the tool execution. "AmcacheParser shows Mimikatz installation at 14:32 UTC, no corresponding Prefetch entry" is a finding.

When `record_finding()` returns a grounding suggestion, consider running the suggested checks and updating the finding with additional evidence before moving on.

**`record_timeline_event()` — Record key events forming the incident narrative:**

Record timestamps that are part of the incident story — events the examiner would include in a timeline report. Include these fields to improve filtering and analysis:
- **event_type**: classification of the event — `process`, `network`, `file`, `registry`, `auth`, `persistence`, `lateral`, `execution`, or `other`
- **artifact_ref**: unique artifact identifier for deduplication — e.g. `prefetch:EVIL.EXE-{hash}`, `evtx:Security:4624:12345`
- **related_findings**: list of finding IDs this event supports — e.g. `["F-001", "F-003"]`

Not every timestamp in the evidence is a timeline event. MFT entries showing normal system activity are data; the timestamp when a malicious process first executed is a timeline event.

Use `get_timeline()` with filters (status, source, examiner, start_date, end_date, event_type) to narrow results when the timeline grows large.

**`log_reasoning()` — Record analytical decisions (no approval needed):**

Call at decision points: when choosing which artifact to examine next and why, forming or revising a hypothesis, ruling something out, choosing between competing interpretations. This goes to the audit trail only — the examiner doesn't need to approve it, so use it freely.

If context compaction occurs, only recorded reasoning survives. An unrecorded hypothesis is a lost hypothesis.

**`log_external_action()` — Record non-MCP tool execution:**

If you run a command via Bash or another tool outside MCP, call this afterward with the command, output summary, and purpose. Without this, the execution has no audit entry and findings cannot reference it.

**Investigation rhythm:** After completing analysis of an artifact or artifact type (e.g., after parsing all prefetch files, after examining event logs), pause and assess: Did I identify anything the examiner should know about? If yes, present the evidence and record a finding. Did I encounter key timestamps for the incident narrative? If yes, record timeline events. Am I about to change direction? If yes, log the reasoning.

## Human-in-the-Loop
All findings and timeline events stage as DRAFT. The human analyst reviews and
approves via `aiir approve` — this is structural, not optional. The AI cannot
bypass the approval mechanism.

## Report Generation
After findings are APPROVED, generate reports using `generate_*` tools. Each returns:
1. **report_data** — structured JSON for the orchestrator to work with
2. **report_stub** — pre-formatted Markdown with data sections filled, narrative as placeholders
3. **next_steps** + **zeltser_tools_needed** — instructions to use Zeltser IR Writing MCP

Only APPROVED items are included — this enforces the HITL gate. Available reports:
- `generate_full_report()` — complete IR report
- `generate_executive_summary()` — non-technical management briefing
- `generate_timeline_report(start_date, end_date)` — chronological event report
- `generate_ioc_report()` — IOCs + MITRE mapping (structural, no narrative needed)
- `generate_findings_report(finding_ids)` — detailed findings (specific or all approved)
- `generate_status_brief()` — standup/handoff overview
- `save_report(filename, content, report_type)` — persist to reports/

## Concurrency Model
- Flat case directory layout: all data files at case root (no `examiners/` subdirectory)
- IDs include examiner name for uniqueness: `F-alice-001`, `T-bob-003`, `TODO-alice-001`
- Solo cases: single examiner, standard workflow
- Collaborative cases: each examiner has their own local case directory. Collaboration uses export/import bundles (JSON files), not shared filesystems
- `aiir case activate` activates a local case directory (CLI only, not callable by AI)
- Audit JSONL is append-only: each MCP writes its own file in `audit/`, no contention
- Merge semantics: last-write-wins by `modified_at`, APPROVED findings are protected from overwrite
- CLI reloads from disk before saving to preserve concurrent MCP writes
- `AIIR_EXAMINER` env var identifies the examiner (falls back to `AIIR_ANALYST` then OS username)
