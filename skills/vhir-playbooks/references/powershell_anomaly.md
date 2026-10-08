# PowerShell Anomaly Investigation

Investigate suspicious PowerShell activity including encoded commands, download cradles, and obfuscated scripts

MITRE ATT&CK: T1059.001

## Triggers

- Encoded command parameter (-enc, -EncodedCommand) in process creation logs
- Download cradle patterns (IEX, Invoke-Expression, Net.WebClient, DownloadString)
- Script block logging alerts in PowerShell event logs
- Unusual script execution path or unsigned script

## Phase 1: Identify

1. Parse PowerShell event logs with EvtxECmd (via sift-mcp or wintools-mcp) — Event IDs 4103 (module logging), 4104 (script block logging)
2. Parse Security event logs for process creation with command line — Event ID 4688
3. Check PowerShell transcripts if enabled (check PSReadLine history and transcript paths)

## Phase 2: Decode

1. If encoded command detected (-enc), decode Base64 content to reveal actual command
2. Reassemble script block log entries if split across multiple Event ID 4104 entries
3. De-obfuscate command if string concatenation, character codes, or variable substitution used

## Phase 3: Analyze

1. Search for known techniques matching the command pattern (forensic-rag: search)
2. Check any download URLs found in the command (opencti: lookup_ioc)
3. Check the spawning process to understand execution context (windows-triage: check_process_tree)

## Phase 4: Impact

1. Identify what the PowerShell command executed — file drops, registry changes, network connections
2. Check for downloaded payloads in Prefetch, MFT, and Amcache
3. Check for subsequent PowerShell executions that may form a chain

## Phase 5: Record

1. Record finding including decoded command content, execution context, and impact assessment
2. Include all evidence IDs from each analysis phase

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1059.001 — PowerShell
- FireEye/Mandiant — Greater Visibility Through PowerShell Logging
