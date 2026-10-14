# Timestomping Investigation

Investigate timestamp manipulation in NTFS file system metadata

MITRE ATT&CK: T1070.006

## Triggers

- $STANDARD_INFORMATION timestamps earlier than $FILE_NAME timestamps in MFT
- Zero sub-second component in $SI Created or Modified (MFTECmd uSecZeros). Timestomping tools can cause it. It often legitimately occurs after a file is extracted from a zip archive or copied from FAT-formatted media. Some installers may also cause it. Treat it as a lead for further comparison, not proof.
- Timestamps predating the file system creation date
- Timestamps inconsistent with other artifact evidence

## Phase 1: Identify

1. Parse MFT with MFTECmd (via sift-mcp or wintools-mcp) comparing $STANDARD_INFORMATION vs $FILE_NAME timestamps
2. Flag entries where $SI Created timestamp is earlier than $FN Created timestamp
3. Check for a zero millisecond component (MFTECmd uSecZeros); it can indicate a program set the time, including timestomping tools, and is a lead, not proof

## Phase 2: Verify

1. Check USN Journal for actual file creation and modification times
2. Check Prefetch for execution timing of the timestomped files if they are executables
3. Cross-reference with Amcache and Shimcache entries for the same files

## Phase 3: Scope

1. Search for other timestomped files using the same pattern — same target date, same nanosecond value
2. Check if a timestomping tool is present in Prefetch (timestomp.exe, NirCmd, known frameworks)
3. Determine scope of timestamp manipulation across the file system

## Phase 4: Context

1. Determine what the timestomped files are — executables, documents, scripts
2. Check files against Windows baseline (windows-triage: check_file)
3. Check file hashes against threat intelligence (opencti: lookup_hash)

## Phase 5: Record

1. Record finding including both $SI and $FN timestamps for affected files
2. Note the discrepancy as possible deliberate timestamp manipulation, with the artifacts from the other phases that support or contradict it
3. Include all evidence IDs from each analysis phase

## Sources

- SANS FOR500 — Windows Forensic Analysis
- MITRE ATT&CK T1070.006 — Timestomping
