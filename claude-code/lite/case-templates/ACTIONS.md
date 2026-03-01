# Actions Log

Case: [CASE_NAME]
Created: [DATE]

## Action Log

| Timestamp (UTC) | Action | Tool/Command | Result | Notes |
|-----------------|--------|--------------|--------|-------|
| | | | | |

## Format Guide

Log every investigative action immediately after execution:
- **Timestamp:** Full UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)
- **Action:** What was done (tool run, file examined, query made)
- **Tool/Command:** Exact command or tool invocation used
- **Result:** Outcome (found X, no results, error)
- **Notes:** Relevant observations

Example:
| 2024-02-05 14:32:15 | Ran process listing on memory dump | vol -f memory.raw windows.pstree | 47 processes found | Suspicious: svchost.exe under notepad.exe |
