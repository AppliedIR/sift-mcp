---
name: vhir-ingest
description: 'How to start an investigation once the evidence is surveyed: which tools to run first, ingesting evidence into OpenSearch (triage packages, memory, delimited files) and querying it. Use after the evidence survey, before analysis, or when ingesting or querying indexed evidence.'
---

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
- **Query:** `idx_search`, `idx_count`, `idx_aggregate`, `idx_timeline`, `idx_field_values`, `idx_get_event`
- **Overview:** `idx_case_summary`, `idx_status`, `idx_ingest_status`
- **Enrich:** `idx_enrich_triage` (baseline), `idx_enrich_intel` (threat intel)
- **Detect:** `idx_list_detections` (Hayabusa/Sigma alerts)
