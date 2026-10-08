# Data Staging Investigation

Investigate data collection and staging activity indicating preparation for exfiltration

MITRE ATT&CK: T1074, T1560

## Triggers

- Large archive file creation in temp or staging directory
- Archive tool (rar, 7z, zip) executed from unusual location
- Compression tool execution detected in Prefetch
- Unusual volume of file access in short timeframe

## Phase 1: Identify

1. Check Prefetch for archive tool execution using PECmd (via wintools-mcp) — look for 7z.exe, rar.exe, WinRAR.exe, compact.exe
2. Check MFT for large file creation in temp or staging paths using MFTECmd (via sift-mcp or wintools-mcp)
3. Check USN Journal for file rename and creation operations around staging time

## Phase 2: Content

1. Check Shellbags for folder access patterns using RECmd (via sift-mcp or wintools-mcp)
2. Check Jump Lists for recent file access using JLECmd (via sift-mcp or wintools-mcp)
3. Determine what data was accessed before the staging activity

## Phase 3: Exfiltration

1. Check network connections around staging time using tshark or zeek (via sift-mcp) if PCAP available
2. Check for cloud upload activity in browser history using Hindsight (via sift-mcp)
3. Check for large outbound data transfers in SRUM using SrumECmd (via sift-mcp or wintools-mcp)

## Phase 4: USB Check

1. Check USB device connections around staging time — MountPoints2 in registry via RECmd (via sift-mcp or wintools-mcp)
2. Check USBSTOR registry entries for device serial numbers and connection times

## Phase 5: Record

1. Record finding including timeline from data access through staging through potential exfiltration
2. Include all evidence IDs from each analysis phase

## Sources

- SANS FOR508 — Windows Enterprise Incident Response
- MITRE ATT&CK T1074 — Data Staged
- MITRE ATT&CK T1560 — Archive Collected Data
