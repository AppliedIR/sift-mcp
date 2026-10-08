# Remote Access Investigation

Investigate unexpected remote access including RDP, PsExec, WMI, and WinRM connections

MITRE ATT&CK: T1021, T1570

## Triggers

- RDP connection from unexpected source system
- PsExec service installation (Event ID 7045 with PSEXESVC)
- WMI remote execution events (Event IDs 5857-5861)
- WinRM connections from non-administrative workstations

## Phase 1: Identify Method

1. Check for PsExec service install — Event ID 7045 with service name PSEXESVC using Hayabusa (via sift-mcp or wintools-mcp)
2. Check for RDP logons — Event ID 4624 Type 10, Event ID 1149 in TerminalServices-RemoteConnectionManager
3. Check for WMI events — Event IDs 5857-5861 using EvtxECmd (via sift-mcp or wintools-mcp)
4. Check for WinRM connections in Windows Remote Management event logs

## Phase 2: Source Analysis

1. Identify the source system for each remote access event
2. Determine if the source system is a known compromised or suspicious host
3. Check source IP against threat intelligence (opencti: lookup_ioc)

## Phase 3: Execution Context

1. Check what was executed after remote access using PECmd (via wintools-mcp)
2. Verify process execution trees around remote access time (windows-triage: check_process_tree)
3. Check for tools transferred to the system using MFTECmd (via sift-mcp or wintools-mcp)

## Phase 4: Scope

1. Map all systems accessed via the same remote access method
2. Identify all accounts used for remote access across systems
3. Build the lateral movement chain — source to destination with timestamps

## Phase 5: Record

1. Record finding including method, source, destination, account, and subsequent activity
2. Include all evidence IDs from each analysis phase

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1021 — Remote Services
- MITRE ATT&CK T1570 — Lateral Tool Transfer
