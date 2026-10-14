# Unusual Logon Investigation

Investigate unexpected authentication events indicating unauthorized access or credential misuse

MITRE ATT&CK: T1078, T1021

## Triggers

- Logon from unusual source IP or at unusual time
- Type 10 (RDP) logon from unexpected system
- Service account used interactively
- Failed logon attempts followed by success from same source
- Logon type inconsistent with account purpose

## Phase 1: Identify

1. Parse Security event logs with Hayabusa (via sift-mcp or wintools-mcp) filtering for logon events (4624, 4625, 4648)
2. Filter by target account, source address, and logon type to isolate suspicious entries
3. Record evidence IDs for all relevant log entries

## Phase 2: Baseline

1. Check the account's previous logon history on this system using EvtxECmd (via sift-mcp or wintools-mcp) filtered by account name
2. Determine normal logon patterns — usual times, source systems, logon types
3. If available, check same account on other systems to establish cross-system baseline

## Phase 3: Context

1. Check process execution around logon time using PECmd (via wintools-mcp) to identify what was run
2. Check file creation around logon time using MFTECmd (via sift-mcp or wintools-mcp)
3. Check for new services or tasks created using windows-triage (check_service, check_scheduled_task)

## Phase 4: Lateral Check

1. Determine if the same account accessed other systems during the investigation timeframe
2. Check RDP activity in event logs (Event ID 1149, 4624 Type 10) and RDP bitmap cache artifacts
3. Check network share access in Security logs (Event IDs 5140, 5145)

## Phase 5: Corroborate

1. Check source IP reputation and threat intelligence (opencti: lookup_ioc)
2. Search for related techniques and detection context (forensic-rag: search_knowledge)
3. Verify process execution trees around logon time (windows-triage: check_process_tree)

## Phase 6: Record

1. Record finding with all evidence IDs from each phase
2. HITL checkpoint — examiner determines whether logon is unauthorized access

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1021 — Remote Services
