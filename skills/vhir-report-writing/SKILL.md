---
name: vhir-report-writing
description: 'Writing the investigation report with report-mcp: the report profiles, case metadata, the writing guidance to follow and saving the report. Use once findings are approved and a report is wanted.'
metadata:
  source: 'AGENTS.md (Report Generation); claude-code/full/CLAUDE.md (MCP Backends: report-mcp)'
---

## Report Generation (report-mcp)

Use these tools after findings are APPROVED:

- `generate_report(profile)` — get case data + Zeltser guidance for a
  report type: full, executive, timeline, ioc, findings, status
- `set_case_metadata(field, value)` — set incident metadata (type,
  severity, dates, scope, team) in CASE.yaml
- `get_case_metadata()` — retrieve case metadata
- `save_report(filename, content)` — persist rendered report
- `list_reports()` — list saved reports
- `list_profiles()` — show available report types

Workflow: call generate_report → follow zeltser_guidance to call
Zeltser tools → write narrative sections → save_report.

### report-mcp (Report Generation)
Data-driven investigation reports with profile-based formatting.

- `generate_report` — generate report from case data (profiles: full, executive, timeline, ioc, findings, status)
- `set_case_metadata` — set report metadata (organization, classification, etc.)
- `get_case_metadata` — retrieve report metadata
- `list_profiles` — available report profiles with descriptions
- `save_report` — save generated report to file
- `list_reports` — list saved reports
