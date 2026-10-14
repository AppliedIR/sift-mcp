# Tool Reference

Tool selection and investigation workflows. **Tools first, text second.**

---

## Critical Rules

### 1. Query Before Conclusions
```
WRONG: User asks about IOC -> Write response -> Then query tools
RIGHT: User asks about IOC -> Query tools FIRST -> Write response based on results
```

### 2. Parallel Tool Calls
When multiple queries needed, call ALL in a single message:
```
WRONG: [Tool 1] -> wait -> [Tool 2] -> wait -> [Tool 3]
RIGHT: [Tool 1, Tool 2, Tool 3] -> wait once -> all results
```

### 3. Syntax From the Installed Tool
Before building a tool's command line, call get_tool_help (get_windows_tool_help on Windows) and use a recipe for the installed version, or the tool's own help. Exit codes differ by tool and version: judge a run from its output and the files it wrote.

---

## Backend Availability

Lite mode runs MCP servers directly (no gateway). Check what's
available by calling each MCP's health tool:

| Backend | Default | Optional | How to check |
|---------|---------|----------|--------------|
| forensic-rag | Yes | — | MCP tool `get_knowledge_stats` |
| windows-triage | Yes | — | MCP tool `get_health` |
| threatintel-mcp | No | `--opencti` flag | MCP tool `get_health` |
| remnux-mcp | No | User-provided | MCP tool `check_tools` |
| wintools-mcp | No | User-provided | MCP tool `check_windows_tools` |

If a backend is unavailable, skip its steps in workflows below and
note the gap. Do not fail the investigation — degrade gracefully.

---

## Decision Framework

```
User Question
     |
     v
+-----------------------------------------------------------+
| File to analyze (PE, PDF, Office, ELF, archive, script)?  |
+-----------------------------------------------------------+
     | YES                              | NO
     v                                  v
+--------------+              +-----------------------------------------------------------+
| remnux-mcp   |              | Contains IOC (IP, hash, domain, URL)?                     |
| analyze_file |              | Contains "malicious", "threat actor", "APT", "CVE"?       |
+--------------+              +-----------------------------------------------------------+
                                   | YES                              | NO
                                   v                                  v
                            +--------------+              +-----------------------------------+
                            | threatintel-mcp  |              | Contains "detect", "sigma",       |
                            | FIRST        |              | "event ID", "MITRE", "hunt"?      |
                            +--------------+              +-----------------------------------+
                                                               | YES           | NO
                                                               v               v
                                                        +-------------+  +---------------------------+
                                                        | forensic-   |  | File/process to validate? |
                                                        | rag FIRST   |  +---------------------------+
                                                        +-------------+       | YES          | NO
                                                                              v              v
                                                                       +--------------+ +----------+
                                                                       | windows-     | | Bash     |
                                                                       | triage       | | tools    |
                                                                       +--------------+ +----------+
```

---

## Tool Selection Matrix

| User Intent | Primary Tool | Fallback |
|-------------|--------------|----------|
| IOC Lookup (IP, hash, domain) | threatintel-mcp `lookup_ioc` | windows-triage `check_hash` |
| Threat Actor Intel | threatintel-mcp `search_threat_intel` | forensic-rag `search_knowledge` (mitre_attack) |
| Malware Info | threatintel-mcp `search_entity` (type=malware) | forensic-rag `search_knowledge` (sigma, mbc) |
| CVE Details | threatintel-mcp `search_entity` (type=vulnerability) | forensic-rag `search_knowledge` (cisa_kev) |
| Mitigations | threatintel-mcp `search_entity` (type=course_of_action) | forensic-rag `search_knowledge` (mitre_d3fend) |
| Detection Rules | forensic-rag `search_knowledge` (sigma, elastic, chainsaw) | — |
| MITRE Technique | forensic-rag `search_knowledge` (mitre_attack) | threatintel-mcp `search_entity` (type=attack_pattern) |
| Forensic Artifacts | forensic-rag `search_knowledge` (velociraptor, forensic_artifacts, kape) | — |
| File Validation | windows-triage `check_file` | — |
| Process Validation | windows-triage `check_process_tree` | — |
| LOLBin Check | windows-triage `check_lolbin` | forensic-rag `search_knowledge` (lolbas) |
| Vulnerable Drivers | windows-triage `check_hash` | forensic-rag `search_knowledge` (loldrivers) |
| Malware File Analysis | remnux-mcp `analyze_file` | forensic-rag `search_knowledge` (sigma, mbc) |
| Document Macro Analysis | remnux-mcp `analyze_file` | — |
| IOC Extraction from File | remnux-mcp `extract_iocs` | `bulk_extractor` |
| Specific REMnux Tool | remnux-mcp `run_tool` | — |
| Run Windows forensic tool | wintools-mcp `run_windows_command` | Bash (see FORENSIC_TOOLS.md) |
| Run forensic tool | Bash (see FORENSIC_TOOLS.md) | — |
| Tool recommendations | forensic-rag `search_knowledge` | FORENSIC_TOOLS.md |
| EVTX Analysis | `EvtxECmd` | — |
| Memory Analysis | `vol` (Volatility 3) | — |
| Disk Forensics | `fls`, `mmls`, `icat` | — |
| Registry Analysis | `regripper`, `RECmd` | — |
| Timeline Creation | `log2timeline.py`, `psort.py` | `mactime` |

---

## Trigger Keywords

### Bash (forensic tools)
- Tool names: fls, mmls, icat, vol, strings, yara, exiftool, grep, etc.
- "run", "execute", "analyze disk", "extract file", "parse"
- See FORENSIC_TOOLS.md for syntax and usage

### windows-triage
- ANY filename (e.g., "scvhost.exe", "svchost.exe")
- File paths, process names, parent-child relationships
- "is this part of a default Windows install, in its default place?" (not "is this legitimate?": a default file or service can still be misused)
- Windows system file questions

### threatintel-mcp
- IP addresses, hashes (32/40/64 hex chars), domains/URLs
- "is this malicious", "check this", "lookup", "threat intel"
- APT/threat actor names, malware names, CVE identifiers
- "recent threats", "attributed to", country names in threat context

### forensic-rag
- "how to detect", "detection rule", "sigma rule"
- "event ID", "Windows event", "Sysmon event"
- MITRE IDs (T1xxx, TA00xx)
- "forensic artifact", "evidence of", "collect"
- "LOLBAS", "LOLBin", "living off the land"

### remnux-mcp (if available)
- "analyze this file", "malware analysis", "run capa", "run yara"
- "oletools", "pdfparser", "what capabilities", "suspicious file/document"
- File extensions: .exe, .dll, .doc, .xls, .pdf, .elf, .js, .vbs, .ps1

### wintools-mcp (if available)
- Zimmerman tool names: AmcacheParser, EvtxECmd, MFTECmd, PECmd, RECmd, etc.
- "run on Windows", "parse on the Windows box", "execute on Windows"
- Hayabusa, autorunsc, sigcheck, and winpmem to decompress a memory image already in the case
- Windows artifacts that need native Windows tools to parse

---

## Combined Query Patterns

### File/Process Investigation
```
1. windows-triage check_file or check_process_tree   -+
2. threatintel-mcp lookup_ioc (if hash available)           +- PARALLEL
3. forensic-rag search_knowledge (sigma/lolbas context)         -+
```

### IOC Investigation
```
1. threatintel-mcp lookup_ioc                 -+
2. windows-triage check_hash               +- PARALLEL
3. forensic-rag search_knowledge (detection rules)  -+
```

### Threat Actor Research
```
1. threatintel-mcp search_threat_intel                    -+
2. threatintel-mcp search_entity (type=malware)            +- PARALLEL
3. forensic-rag search_knowledge (TTPs from mitre_attack, sigma)-+
```

---

## Investigation Workflows

### Workflow 1: IOC Investigation
1. `threatintel-mcp lookup_ioc(ioc="...")` - What each platform holds on it
2. If not found: `windows-triage check_hash` (for drivers)
3. `forensic-rag search_knowledge(query="IOC type detection", source_ids=["sigma"])`
4. Synthesize with evidence per FORENSIC_DISCIPLINE.md

### Workflow 2: Threat Actor Research
1. `threatintel-mcp search_threat_intel(query="...")`
2. `threatintel-mcp search_entity(type="malware", query="...")`
3. `forensic-rag search_knowledge(query="...", source_ids=["mitre_attack"])`
4. `forensic-rag search_knowledge(query="... detection", source_ids=["sigma"])`

### Workflow 3: Detection Engineering
1. `forensic-rag search_knowledge(query="X", source_ids=["sigma", "elastic", "chainsaw"])`
2. `forensic-rag search_knowledge(query="X", source_ids=["mitre_attack"])`
3. `forensic-rag search_knowledge(query="X", source_ids=["atomic"])` (validation)

### Workflow 4: Forensic Artifact Collection
1. `forensic-rag search_knowledge(query="artifact", source_ids=["velociraptor"])`
2. `forensic-rag search_knowledge(query="artifact", source_ids=["forensic_artifacts", "kape"])`
3. `forensic-rag search_knowledge(query="artifact", source_ids=["sigma"])`

### Workflow 5: Suspicious File Analysis (REMnux)
```
1. Stage: remnux-mcp upload_from_host(file_path="/path/to/suspect.exe")
2. PARALLEL:
   a. remnux-mcp analyze_file(file_path="samples/suspect.exe", depth="standard")
   b. remnux-mcp extract_iocs(file_path="samples/suspect.exe")
3. Check action_required[] — follow remediation steps (unpack, extract, re-analyze)
4. Check suggested_next_steps[] — execute or explain why skipping
5. PARALLEL per extracted IOC:
   a. threatintel-mcp lookup_ioc(ioc="<IP/domain/hash>")
   b. windows-triage check_hash(hash="<file hash>")
6. forensic-rag search_knowledge(query="<capabilities from capa>", source_ids=["sigma","mitre_attack"])
7. Synthesize with evidence chain per FORENSIC_DISCIPLINE.md
```
Use `depth="quick"` for batch triage, `depth="deep"` for known-malicious or evasive samples.

### Workflow 6: Document Macro Analysis (REMnux)
```
1. remnux-mcp upload_from_host(file_path="/path/to/document.xlsm")
2. remnux-mcp analyze_file(file_path="samples/document.xlsm") -> oletools auto-selected
3. If macros: remnux-mcp run_tool(tool="olevba") with its deobfuscation option (remnux-mcp `get_tool_help` for this version's syntax)
4. remnux-mcp extract_iocs -> embedded IOCs
5. Per IOC: threatintel-mcp lookup_ioc
6. forensic-rag search_knowledge -> macro sigma rules
```

### Workflow 7: Disk Image Analysis
Run via Bash: `mmls` (partitions), `fls` (list files, or write a bodyfile), `mactime` (a timeline from a bodyfile), `icat` (extract a file by inode).
Run the tool with its own help option for this version's syntax.

### Workflow 8: Windows Artifact Analysis
Run via Bash: `AmcacheParser` (Amcache), `MFTECmd` ($MFT), `EvtxECmd` (event logs), `PECmd` (Prefetch), `regripper` (registry hives).
Run the tool with its own help option for this version's syntax.

### Workflow 9: Supertimeline
Run via Bash: `log2timeline.py` (a Plaso storage file from the evidence), then `psort.py` (that file as CSV, optionally filtered by date).
Run the tool with its own help option for this version's syntax.

### Workflow 10: Network Traffic
Run via Bash: `tshark` (fields from a capture), `bulk_extractor` (artifacts from a capture).
Run the tool with its own help option for this version's syntax.
Then check IOCs with `threatintel-mcp lookup_ioc`

### Workflow 11: Memory Analysis
Run via Bash: `vol` (Volatility 3), with the plugins windows.info, windows.pstree, windows.cmdline, windows.netscan, windows.malfind and windows.svcscan.
Run the tool with its own help option for this version's syntax.

### Workflow 12: File/Process Validation
1. `windows-triage check_file(path="...", hash="...")`
2. `windows-triage check_process_tree(process="...", parent="...")`
3. `windows-triage check_lolbin(filename="...")`
4. `threatintel-mcp lookup_ioc(ioc="<hash>")`
5. `forensic-rag search_knowledge(query="filename", source_ids=["sigma", "lolbas"])`

---

## Score Interpretation

### RAG Scores
| Score | Quality | Action |
|-------|---------|--------|
| 0.85+ | Excellent | High confidence, cite directly |
| 0.75-0.84 | Good | Relevant, include in response |
| 0.65-0.74 | Fair | May be tangential, use judgment |
| < 0.65 | Weak | Likely not relevant, may omit |

### threatintel-mcp lookup_ioc
Each configured platform answers under `providers.<name>` with its own
records: MATCH, NO_MATCH, or UNAVAILABLE (it couldn't be asked, which is not
a not-found). A MATCH is the platform's record, not a verdict: read OpenCTI's
`revoked`, `valid_until` and `x_opencti_score`, and MISP's `to_ids`, the
event's `published` and `threat_level_id`, `decay_score` and
`warninglist_hits`, before treating an IOC as malicious.

### OpenCTI Confidence
| Confidence | Meaning |
|------------|---------|
| 80-100 | High confidence, verified intel |
| 50-79 | Medium confidence, corroborate |
| < 50 | Low confidence, note uncertainty |

### Windows-Triage Verdicts
| Verdict | Meaning |
|---------|---------|
| SUSPICIOUS | Anomaly detected (wrong path, Unicode, injection, vulnerable driver) |
| EXPECTED_LOLBIN | Baseline match + LOLBin capability |
| EXPECTED | A default Windows file, service, task or autorun, in its default place (says nothing about how it was used) |
| UNKNOWN | Not in database (neutral) |

**Note:** windows-triage is offline-only. For threat-intelligence records, use threatintel-mcp `lookup_ioc` (each platform's records, not a verdict).

### REMnux analyze_file Response (if available)

**Depth tiers** — choose based on context:

| Depth | When to use |
|-------|-------------|
| `quick` | Initial triage, many files to process, time-sensitive |
| `standard` | Default for most analysis |
| `deep` | Known-malicious samples, evasive malware, thorough investigation |

**AI-directed response fields** — act on these:

| Field | What it means | What to do |
|-------|---------------|------------|
| `action_required[]` | Prioritized advisories (highest first) | Follow the `remediation` steps before continuing |
| `suggested_next_steps[]` | Server-recommended follow-on actions | Execute these or explain why skipping |
| `analysis_guidance` | Contextual notes per file type | Apply when reasoning about results |
| `workflow_hint` | Directional nudge for investigation flow | Factor into next action |

**Advisory interpretation — do not overclaim:**
- **YARA matches** = *resemblance*, not confirmation. Say "matches signatures associated with X", never "identified as X".
- **capa packed file** (exit code 14) = capabilities hidden by packing. Unpack first, then re-analyze.
- **AutoIt wrapper** = inner payload needs extraction via 7z before analysis.
- **GetProcAddress/LoadLibrary** in capa = appears in most Windows programs. Not inherently suspicious.

---

## Error Handling

### MCP Failures
| Error | Action |
|-------|--------|
| Tool not found | Check MCP server is running, restart Claude Code |
| Connection refused | Restart Claude Code to reconnect MCP servers |
| Timeout | Retry with simpler query or smaller scope |
| Empty results | Try broader query, different source |
| Backend unavailable | Note gap, use fallback from matrix above |

### Low-Quality Results
| Symptom | Action |
|---------|--------|
| RAG scores < 0.65 | Rephrase query, try synonyms |
| RAG unrelated results | Use source_ids for exact filtering |
| OpenCTI no results | Note as "not in threat intel" |
| OpenCTI low confidence | Corroborate with other sources |

### Graceful Degradation
1. Note the failure in findings (via `record_action`)
2. Try fallback if available (see tool selection matrix)
3. Proceed with available data
4. Flag as gap for human review
