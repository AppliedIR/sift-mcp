# Suspicious Autorun Investigation

Investigate unexpected persistence mechanisms including registry autoruns, services, and scheduled tasks

MITRE ATT&CK: T1547, T1053, T1543

## Triggers

- Unknown entry in Run/RunOnce registry keys
- New service installed (Event ID 7045)
- New or modified scheduled task
- WMI event subscription detected
- Suspicious BITS job persistence

## Phase 1: Identify

1. Parse registry for Run keys, services, and WMI subscriptions using RECmd (via sift-mcp or wintools-mcp)
2. Check scheduled tasks output using EvtxECmd (via sift-mcp or wintools-mcp) for task creation events
3. If a Windows image of the host is in the case, run autorunsc (via wintools-mcp) in offline mode against it to list its auto-start entries

## Phase 2: Validate

1. Check each persistence entry against baseline (windows-triage: check_autorun, check_service, check_scheduled_task)
2. Verify binary paths referenced by persistence entries (windows-triage: check_file)
3. Flag entries pointing to unusual paths (Temp, AppData, Recycle Bin, ProgramData)

## Phase 3: Analyze Binary

1. Check binary digital signatures using sigcheck (via wintools-mcp) on the binary's copy in the case. A path in a persistence entry names a file on the subject host. The same path on the wintools host is a different file.
2. Check binary entropy using densityscout (via wintools-mcp) on the binary's copy in the case, not on the same path on the wintools host
3. Check binary hash against threat intelligence (opencti: lookup_ioc)
4. Submit suspicious binaries for static analysis (remnux: analyze_file)

## Phase 4: Timeline

1. Determine when persistence was created — registry key timestamps, service install time, task creation time
2. Correlate persistence creation time with other activity using MFTECmd (via sift-mcp or wintools-mcp)
3. Check USN Journal for file operations around persistence creation time

## Phase 5: Record

1. Record finding including persistence mechanism type, binary details, and creation timeline
2. Include all evidence IDs from analysis phases

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1547 — Boot or Logon Autostart Execution
- MITRE ATT&CK T1053 — Scheduled Task/Job
- MITRE ATT&CK T1543 — Create or Modify System Process
