# Suspicious Execution Investigation

Investigate unknown or unexpected program execution from forensic artifacts

MITRE ATT&CK: T1204, T1059

## Triggers

- Prefetch file for unrecognized executable
- Amcache entry with no corresponding installer record
- Execution from unusual path (Temp, AppData, Recycle Bin, Downloads)
- Shimcache entry for unknown binary

## Phase 1: Identify

1. Parse Prefetch with PECmd (via wintools-mcp) — note run count, timestamps, and loaded files/directories
2. Check Amcache with AmcacheParser (via sift-mcp or wintools-mcp) for file presence records and SHA1 hashes
3. Check Shimcache with AppCompatCacheParser (via sift-mcp or wintools-mcp) for additional presence evidence

## Phase 2: Validate

1. Check executable against Windows baseline (windows-triage: check_file)
2. Check filename for anomalies such as typosquatting or masquerading (windows-triage: analyze_filename)
3. Check if the executable is a known Living-off-the-Land binary (windows-triage: check_lolbin)

## Phase 3: Threat Intel

1. Check executable hash against threat intelligence (opencti: lookup_hash)
2. Search for technique context and detection rules (forensic-rag: search)

## Phase 4: Analysis

1. If suspicious, submit to REMnux for static analysis (remnux: analyze_file)
2. Check parent process if Sysmon data available (windows-triage: check_process_tree)
3. Check capabilities with capa (via sift-mcp or wintools-mcp) for behavioral indicators

## Phase 5: Scope

1. Search for same executable on other systems if multi-system investigation
2. Check for lateral delivery mechanism — was the file copied via SMB, RDP, PsExec?

## Phase 6: Record

1. Record finding — be precise about evidence type: Prefetch proves execution, Amcache proves presence, Shimcache proves presence
2. Include all evidence IDs and note artifact interpretation boundaries

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1204 — User Execution
- MITRE ATT&CK T1059 — Command and Scripting Interpreter
