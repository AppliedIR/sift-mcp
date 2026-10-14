# Credential Access Investigation

Investigate indicators of credential theft, dumping, or Kerberos abuse

MITRE ATT&CK: T1003, T1558

## Triggers

- LSASS access detected in Sysmon Event ID 10
- Known credential tools in Prefetch (mimikatz, procdump, comsvcs.dll)
- Kerberoasting event patterns (Event ID 4769 with RC4 encryption)
- Suspicious process accessing credential stores

## Phase 1: Identify

1. Parse Sysmon logs for LSASS access events with Hayabusa (via sift-mcp or wintools-mcp)
2. Check Prefetch for known credential tool execution using PECmd (via wintools-mcp)
3. Check running processes with Volatility3 pslist and psscan (via sift-mcp) if memory image available

## Phase 2: Tool Identification

1. Check file hashes of suspected credential tools (opencti: lookup_ioc)
2. Verify files against Windows baseline (windows-triage: check_file)
3. Submit unknown executables for static analysis (remnux: analyze_file)

## Phase 3: Scope

1. Check for Kerberoasting events — Event ID 4769 with RC4 encryption type (0x17)
2. Check for pass-the-hash logon patterns — on targets, Event ID 4624 Type 3 with NTLM authentication; on a suspected source host, 4624 Type 9 (NewCredentials — also produced by legitimate runas /netonly)
3. Check for DCSync indicators — Event ID 4662 with replication rights GUIDs

## Phase 4: Impact

1. Identify all accounts potentially compromised based on tool access patterns
2. Check for subsequent logons using potentially stolen credentials
3. Determine credential scope — local accounts, domain accounts, service accounts

## Phase 5: Record

1. Record finding with all evidence IDs
2. HITL checkpoint — credential compromise affects investigation scope determination

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1003 — OS Credential Dumping
- MITRE ATT&CK T1558 — Steal or Forge Kerberos Tickets
