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

---

## Backend Availability

Not all backends are installed on every deployment. Check what's
available before planning a workflow:

| Backend | Quick tier | Recommended tier | How to check |
|---------|-----------|-----------------|--------------|
| forensic-mcp | Always | Always | `aiir service status` |
| sift-mcp | Always | Always | `aiir service status` |
| windows-triage | No | Yes | `aiir service status` |
| forensic-rag | No | Yes | `aiir service status` |
| opencti-mcp | No | If configured | `aiir service status` |
| remnux-mcp | No | User-provided | `aiir service status` |

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
                            | opencti-mcp  |              | Contains "detect", "sigma",       |
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
                                                                       | windows-     | | sift-mcp |
                                                                       | triage       | | tools    |
                                                                       +--------------+ +----------+
```

---

## Tool Selection Matrix

| User Intent | Primary Tool | Fallback |
|-------------|--------------|----------|
| IOC Lookup (IP, hash, domain) | opencti-mcp `lookup_ioc` | windows-triage `check_hash` |
| Threat Actor Intel | opencti-mcp `search_threat_intel` | forensic-rag `search` (mitre_attack) |
| Malware Info | opencti-mcp `search_entity` (type=malware) | forensic-rag `search` (sigma, mbc) |
| CVE Details | opencti-mcp `search_entity` (type=vulnerability) | forensic-rag `search` (cisa_kev) |
| Mitigations | opencti-mcp `search_entity` (type=course_of_action) | forensic-rag `search` (mitre_d3fend) |
| Detection Rules | forensic-rag `search` (sigma, elastic, chainsaw) | — |
| MITRE Technique | forensic-rag `search` (mitre_attack) | opencti-mcp `search_attack_pattern` |
| Forensic Artifacts | forensic-rag `search` (velociraptor, forensic_artifacts, kape) | — |
| File Validation | windows-triage `check_file` | — |
| Process Validation | windows-triage `check_process_tree` | — |
| LOLBin Check | windows-triage `check_lolbin` | forensic-rag `search` (lolbas) |
| Vulnerable Drivers | windows-triage `check_hash` | forensic-rag `search` (loldrivers) |
| Malware File Analysis | remnux-mcp `analyze_file` | forensic-rag `search` (sigma, mbc) |
| Document Macro Analysis | remnux-mcp `analyze_file` | — |
| IOC Extraction from File | remnux-mcp `extract_iocs` | `bulk_extractor` |
| Specific REMnux Tool | remnux-mcp `run_tool` | — |
| Run forensic tool | Bash (see FORENSIC_TOOLS.md) | — |
| Tool recommendations | sift-mcp `suggest_tools` | forensic-mcp `get_tool_guidance` |
| EVTX Analysis | `EvtxECmd` | — |
| Memory Analysis | `vol` (Volatility 3) | — |
| Disk Forensics | `fls`, `mmls`, `icat` | — |
| Registry Analysis | `regripper`, `RECmd` | — |
| Timeline Creation | `log2timeline.py`, `psort.py` | `mactime` |

---

## Trigger Keywords

### forensic-mcp
- "record", "finding", "timeline", "case", "todo", "evidence"
- "status", "audit", "action log"
- Investigation management and documentation

### sift-mcp
- Tool names: fls, mmls, icat, vol, strings, yara, exiftool, grep, etc.
- "run", "execute", "analyze disk", "extract file", "parse"
- "what tools", "suggest tools for", "how to use [tool]"

### windows-triage
- ANY filename (e.g., "scvhost.exe", "svchost.exe")
- File paths, process names, parent-child relationships
- "is this normal", "is this legitimate", "is this suspicious"
- Windows system file questions

### opencti-mcp
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

---

## Combined Query Patterns

### File/Process Investigation
```
1. windows-triage check_file or check_process_tree   -+
2. opencti-mcp lookup_hash (if hash available)         +- PARALLEL
3. forensic-rag search (sigma/lolbas context)         -+
```

### IOC Investigation
```
1. opencti-mcp lookup_ioc                 -+
2. windows-triage check_hash               +- PARALLEL
3. forensic-rag search (detection rules)  -+
```

### Threat Actor Research
```
1. opencti-mcp search_threat_intel                    -+
2. opencti-mcp search_entity (type=malware)            +- PARALLEL
3. forensic-rag search (TTPs from mitre_attack, sigma)-+
```

---

## Investigation Workflows

### Workflow 1: IOC Investigation
1. `opencti-mcp lookup_ioc(value="...")` - Check if known malicious
2. If not found: `windows-triage check_hash` (for drivers)
3. `forensic-rag search(query="IOC type detection", source_ids=["sigma"])`
4. Synthesize with evidence per FORENSIC_DISCIPLINE.md

### Workflow 2: Threat Actor Research
1. `opencti-mcp search_threat_intel(query="...")`
2. `opencti-mcp search_entity(entity_type="malware", query="...")`
3. `forensic-rag search(query="...", source_ids=["mitre_attack"])`
4. `forensic-rag search(query="... detection", source_ids=["sigma"])`

### Workflow 3: Detection Engineering
1. `forensic-rag search(query="X", source_ids=["sigma", "elastic", "chainsaw"])`
2. `forensic-rag search(query="X", source_ids=["mitre_attack"])`
3. `forensic-rag search(query="X", source_ids=["atomic"])` (validation)

### Workflow 4: Forensic Artifact Collection
1. `forensic-rag search(query="artifact", source_ids=["velociraptor"])`
2. `forensic-rag search(query="artifact", source_ids=["forensic_artifacts", "kape"])`
3. `forensic-rag search(query="artifact", source_ids=["sigma"])`

### Workflow 5: Suspicious File Analysis (REMnux)
```
1. Stage: remnux-mcp upload_from_host(file_path="/path/to/suspect.exe")
2. PARALLEL:
   a. remnux-mcp analyze_file(file_path="samples/suspect.exe", depth="standard")
   b. remnux-mcp extract_iocs(file_path="samples/suspect.exe")
3. Check action_required[] — follow remediation steps (unpack, extract, re-analyze)
4. Check suggested_next_steps[] — execute or explain why skipping
5. PARALLEL per extracted IOC:
   a. opencti-mcp lookup_ioc(ioc="<IP/domain/hash>")
   b. windows-triage check_hash(hash="<file hash>")
6. forensic-rag search(query="<capabilities from capa>", source_ids=["sigma","mitre_attack"])
7. Synthesize with evidence chain per FORENSIC_DISCIPLINE.md
```
Use `depth="quick"` for batch triage, `depth="deep"` for known-malicious or evasive samples.

### Workflow 6: Document Macro Analysis (REMnux)
```
1. remnux-mcp upload_from_host(file_path="/path/to/document.xlsm")
2. remnux-mcp analyze_file(file_path="samples/document.xlsm") -> oletools auto-selected
3. If macros: remnux-mcp run_tool(tool="olevba", args=["--deobf","samples/document.xlsm"])
4. remnux-mcp extract_iocs -> embedded IOCs
5. Per IOC: opencti-mcp lookup_ioc
6. forensic-rag search -> macro sigma rules
```

### Workflow 7: Disk Image Analysis
```bash
# Run via Bash:
mmls disk.dd                              # Partitions
fls -r -o OFFSET disk.dd                  # List files recursively
fls -r -m "/" -o OFFSET disk.dd > body    # Create bodyfile
mactime -b body -d > timeline.csv         # Timeline from bodyfile
icat -o OFFSET disk.dd INODE > file       # Extract specific file
```

### Workflow 8: Windows Artifact Analysis
```bash
# Run via Bash:
AmcacheParser -f Amcache.hve --csv /out/  # Amcache
MFTECmd -f '$MFT' --csv /out/             # MFT parsing
EvtxECmd -d /evtx/ --csv /out/            # EVTX parsing
PECmd -d /prefetch/ --csv /out/           # Prefetch
regripper -r SYSTEM -a                    # Registry
```

### Workflow 9: Supertimeline
```bash
# Run via Bash:
log2timeline.py timeline.plaso /evidence/
psort.py -o l2tcsv timeline.plaso -w timeline.csv
psort.py -o l2tcsv timeline.plaso "date > '2024-01-01'" -w filtered.csv
```

### Workflow 10: Network Traffic
```bash
# Run via Bash:
tshark -r capture.pcap -T fields ...      # Extract fields
bulk_extractor -o /out/ capture.pcap      # Extract artifacts
```
Then check IOCs with `opencti-mcp lookup_ioc`

### Workflow 11: Memory Analysis
```bash
# Run via Bash:
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.cmdline
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.malfind
vol -f memory.dmp windows.svcscan
```

### Workflow 12: File/Process Validation
1. `windows-triage check_file(path="...", hash="...")`
2. `windows-triage check_process_tree(process="...", parent="...")`
3. `windows-triage check_lolbin(filename="...")`
4. `opencti-mcp lookup_hash(hash="...")`
5. `forensic-rag search(query="filename", source_ids=["sigma", "lolbas"])`

---

## Score Interpretation

### RAG Scores
| Score | Quality | Action |
|-------|---------|--------|
| 0.85+ | Excellent | High confidence, cite directly |
| 0.75-0.84 | Good | Relevant, include in response |
| 0.65-0.74 | Fair | May be tangential, use judgment |
| < 0.65 | Weak | Likely not relevant, may omit |

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
| EXPECTED | In Windows baseline |
| UNKNOWN | Not in database (neutral) |

**Note:** windows-triage is offline-only. For MALICIOUS verdicts, use opencti-mcp.

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
| Tool not found | Check `aiir service status`, restart backend |
| Connection refused | `aiir service restart [backend]` |
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
