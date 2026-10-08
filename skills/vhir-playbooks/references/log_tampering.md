# Log Tampering Investigation

Investigate event log clearing, suspicious gaps, and anti-forensic activity targeting log integrity

MITRE ATT&CK: T1070.001, T1070

## Triggers

- Event ID 1102 detected (Security log cleared)
- Event ID 104 detected (System log cleared)
- Gaps in event log sequence numbers
- Missing expected log entries for known activity period

## Phase 1: Identify

1. Parse event logs with Hayabusa (via sift-mcp or wintools-mcp) for log clearing events — Event IDs 1102, 104
2. Check for time gaps in event sequence numbers across all log channels
3. Compare expected log volume against actual for the investigation timeframe

## Phase 2: Timeline

1. Establish exactly when logs were cleared using the clearing event timestamps
2. Determine what timeframe is now missing or incomplete
3. Check if clearing coincides with other suspicious activity

## Phase 3: Alternative Sources

1. Check USN Journal for file system activity during the gap using MFTECmd (via sift-mcp or wintools-mcp)
2. Check Sysmon logs which are stored in a separate event log channel
3. Check PowerShell transcripts and PSReadLine history for command activity
4. Check network logs and PCAP for activity during the gap period

## Phase 4: Attribution

1. Determine which account cleared the logs from Event ID 1102 subject fields
2. Check what that account did before and after clearing — logon events, process execution
3. Verify account against baseline (windows-triage: check_file)

## Phase 5: Record

1. Document the gap, alternative sources consulted, and evidence of anti-forensic activity
2. HITL checkpoint — evidence destruction may affect legal proceedings and investigation scope

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1070.001 — Clear Windows Event Logs
- MITRE ATT&CK T1070 — Indicator Removal
