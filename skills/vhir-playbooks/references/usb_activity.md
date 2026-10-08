# USB Activity Investigation

Investigate USB device connections and removable media activity for data theft or malware delivery

MITRE ATT&CK: T1052.001, T1091

## Triggers

- New USB device appears in registry during investigation timeframe
- File operations to removable drive paths detected
- USB connection coincides with suspicious user activity
- Unknown USB device connected to sensitive system

## Phase 1: Identify Devices

1. Parse USB artifacts from registry using RECmd (via sift-mcp or wintools-mcp) — USBSTOR, MountPoints2, MountedDevices
2. Check SetupAPI logs for device installation events
3. Extract device serial numbers, vendor IDs, and product IDs

## Phase 2: Timeline

1. Correlate USB first and last connection times with investigation timeframe
2. Check event logs for USB-related events using EvtxECmd (via sift-mcp or wintools-mcp)
3. Determine connection duration and pattern (one-time vs repeated)

## Phase 3: File Operations

1. Check LNK files for removable drive paths using LECmd (via sift-mcp or wintools-mcp)
2. Check Jump Lists for recent file access on removable media using JLECmd (via sift-mcp or wintools-mcp)
3. Check MFT for file copy operations to or from removable drive letters

## Phase 4: Context

1. Determine if USB activity is routine for this user or anomalous
2. Check if same USB device was connected to other systems in the environment
3. Search for relevant threat context (forensic-rag: search)

## Phase 5: Record

1. Record finding including device serial, connection times, and files accessed
2. Include all evidence IDs from each analysis phase

## Sources

- SANS FOR500 — Windows Forensic Analysis
- MITRE ATT&CK T1052.001 — Exfiltration Over USB
- MITRE ATT&CK T1091 — Replication Through Removable Media
