---
name: vhir-ingest
description: 'How to start an investigation once the evidence is surveyed: which tools to run first, ingesting evidence into OpenSearch (triage packages, memory, delimited files) and querying it. Use after the evidence survey, before analysis, or when ingesting or querying indexed evidence.'
---

## Host list

At case start, or before the first ingest while the case has no host list, tell the examiner unprompted: a list of the machines in scope, uploaded before ingesting, confirms the hosts it names as the evidence arrives.
- They can give you any inventory (a PDF, spreadsheet, email, text or screenshot): read it and call `prepare_host_list` with one name per line (an optional FQDN after it), or the export's CSV or TSV text with its header row. Show them the entries and skipped rows; the draft waits in the Portal's Hosts tab to review, edit and Upload.
- Or they paste or upload a list in the Hosts tab themselves. Only the examiner's Upload applies a list: never say a list was uploaded or applied.
- In the Hosts tab, Confirm accepts a proposed machine. Start now lets a waiting run write with its hosts as proposed.

## Investigation Methodology

AFTER EVIDENCE SURVEY, BEFORE INVESTIGATION:
1. Run suggest_tools(artifact_type) for each evidence type found
2. Run idx_ingest_memory for any memory dumps (tier 2 recommended)
3. Upload suspicious binaries to REMnux via upload_from_host + analyze_file
4. All text-based evidence (CSV, TSV, log) can be ingested via
   idx_ingest_delimited regardless of encoding — UTF-16LE auto-detected
5. Use run_command with SIFT tools (vol, fls, icat, regripper, strings)
   for deep analysis beyond indexed data
6. Use wintools-mcp for offline evidence analysis on forensic workstation (autorunsc, sigcheck, PECmd)

After ingesting evidence, do NOT default to OpenSearch queries only.
Use this sequence:

1. **Scope** — idx_case_summary, idx_aggregate, idx_list_detections
2. **Triage** — idx_enrich_triage (baseline), idx_enrich_intel (threat intel)
3. **Query** — idx_search for specific hypotheses
4. **Deep analysis** — run_command with SIFT tools for artifacts that
   need examination beyond indexed data
5. **Cross-reference** — suggest_tools for each artifact type to discover
   tools you haven't considered
6. **Malware** — upload_from_host to REMnux for suspicious binaries
7. **Memory** — idx_ingest_memory for memory dumps (3 tiers of Volatility)

When you find a suspicious file, binary, or process:
- check_file on windows-triage for baseline validation
- upload_from_host + analyze_file on REMnux for behavioral analysis
- lookup_ioc on threatintel-mcp for threat intelligence

When you encounter an artifact type you haven't analyzed before:
- suggest_tools(artifact_type="...") on sift-mcp
- get_tool_guidance(tool_name="...") on forensic-mcp

### opensearch-mcp (Evidence Indexing + Querying)
Parse, index, and query forensic evidence at scale via OpenSearch. **Use these MCP tools for ingestion — do NOT use `vhir ingest` via Bash.**

- **Ingest:** `idx_ingest` (triage packages), `idx_ingest_memory` (memory dumps), `idx_ingest_json`, `idx_ingest_delimited`, `idx_ingest_accesslog`
- **`idx_ingest` artifact choice:** `include` adds tier-2 and tier-3 tools (such as `mft`, `usn`, `timeline`) to the tier-1 tools, which still run (registry, shimcache, amcache, shellbags and the rest); the other artifacts (prefetch, srum, plaso, transcripts, defender and the like) are limited to the ones named. `full: true` runs every tool tier; `include` still limits those other artifacts. `exclude` removes types in either case.
- **Kansa:** No one call takes Kansa's own layout (`Output_*/<Module>/<host>-<Module>.csv`): `idx_ingest` finds no raw artifacts, and `hostname="auto"` reads only the top folder's files. Never give `hostname="auto"` a module folder: it reads the module name as the host and files every host's rows under it. Copy each host's files into a folder of its own (`evidence/kansa-by-host/<host>/`), named exactly as the evidence names the host (the FQDN at the start of Kansa's file names, or its short name), log the copy (`log_external_action`) and register the copies, then call `idx_ingest_delimited(path="evidence/kansa-by-host", recursive=true, dry_run=false)` once: one run, one unit per host, one host confirm. Not file by file: each per-file run needs its own host confirm. Until the hosts are confirmed, the run also lists each module name as waiting; confirming the hosts releases them.
- **Query:** `idx_search`, `idx_count`, `idx_aggregate`, `idx_timeline`, `idx_field_values`, `idx_get_event`
- **Overview:** `idx_case_summary`, `idx_status`, `idx_ingest_status`
- **Enrich:** `idx_enrich_triage` (baseline), `idx_enrich_intel` (threat intel)
- **Detect:** `idx_list_detections` (Hayabusa detection alerts: count and query)
