# AIIR Platform Architecture

**Status:** Definitive reference for what is built. Not aspirational.
**Last updated:** 2026-02-25

---

## Invariants

These are structural facts. If a diagram, README, or plan contradicts any of these, the diagram is wrong.

1. **All client-to-server connections use MCP Streamable HTTP.** No client connects via stdio. Stdio is internal only (gateway → backend MCPs).
2. **The gateway runs on the SIFT workstation.** It is not optional — even solo analysts use it (on localhost). It aggregates all SIFT-local MCPs behind one HTTP endpoint.
3. **wintools-mcp runs on a Windows machine.** It is independent of the gateway. The gateway does not manage, proxy, or coordinate with wintools-mcp in any way.
4. **Clients connect to two endpoints at most:** the gateway (for all SIFT tools) and wintools-mcp (for Windows tools). These are separate, unrelated connections.
5. **The case directory is local per examiner.** Each examiner has their own flat case directory on their SIFT machine. forensic-mcp and the aiir CLI both read and write it. Multi-examiner collaboration uses export/merge (not shared filesystem).
6. **Human approval is structural.** Findings stage as DRAFT. Only the aiir CLI (human, interactive, /dev/tty) can move them to APPROVED or REJECTED. The AI cannot approve its own work.
7. **AGENTS.md is the source of truth for forensic rules.** It is LLM-agnostic. Per-client config files (CLAUDE.md, .cursorrules) are copies/derivatives, not sources.
8. **forensic-knowledge is a shared data package.** It is a pip-installable YAML package. forensic-mcp, sift-mcp, and wintools-mcp all depend on it. It has no runtime state.

---

## Components

### Where things run

| Component | Runs on | Port | Protocol (to clients) | Protocol (internal) |
|-----------|---------|------|-----------------------|---------------------|
| sift-gateway | SIFT | 4508 | Streamable HTTP MCP | stdio to backends |
| forensic-mcp | SIFT | — | (via gateway) | stdio subprocess |
| case-mcp | SIFT | — | (via gateway) | stdio subprocess |
| report-mcp | SIFT | — | (via gateway) | stdio subprocess |
| sift-mcp | SIFT | — | (via gateway) | stdio subprocess |
| forensic-rag-mcp | SIFT | — | (via gateway) | stdio subprocess |
| windows-triage-mcp | SIFT | — | (via gateway) | stdio subprocess |
| opencti-mcp | SIFT | — | (via gateway) | stdio subprocess |
| wintools-mcp | Windows | 4624 | Streamable HTTP MCP | — |
| aiir CLI | SIFT | — | — (filesystem) | — |
| sift-common | SIFT | — | — (internal package) | — |
| forensic-knowledge | anywhere | — | — (pip package) | — |

### What each component does

| Component | Purpose |
|-----------|---------|
| **sift-gateway** | Aggregates SIFT-local MCPs. Starts each as a stdio subprocess. Exposes all their tools via `/mcp` (Streamable HTTP) and `/api/v1/tools` (REST). API key → examiner identity mapping for multi-user. |
| **forensic-mcp** | Findings, timeline, evidence, TODOs, discipline rules. The investigation state machine. 12 tools + 14 MCP resources (or 26 tools in tools mode for clients without resource support). |
| **case-mcp** | Case lifecycle and status. Init, activate, close, migrate, list cases, case info, evidence summary, timeline summary, findings summary, recent activity, disk usage, export, import. 13 tools. |
| **report-mcp** | Report generation with data-driven profiles (full, executive, timeline, ioc, findings, status). Aggregates approved findings, IOCs, MITRE mappings, and Zeltser IR Writing guidance. 6 tools. |
| **sift-mcp** | Authenticated, denylist-protected forensic tool execution on Linux/SIFT. Zimmerman suite, Volatility, Sleuth Kit, Hayabusa, etc. FK-enriched response envelopes. 6 core tools, 65+ catalog entries. |
| **forensic-rag-mcp** | Semantic search across Sigma rules, MITRE ATT&CK, Atomic Red Team, Splunk, KAPE, Velociraptor, LOLBAS, GTFOBins. |
| **windows-triage-mcp** | Offline Windows baseline validation. Checks files, processes, services, scheduled tasks, registry, DLLs, pipes against known-good databases. |
| **opencti-mcp** | Read-only threat intelligence from OpenCTI. IOC lookup, threat actor search, malware search, MITRE technique search. 10 tools. |
| **wintools-mcp** | Catalog-gated forensic tool execution on Windows. Zimmerman suite, Hayabusa. FK-enriched response envelopes. Denylist blocks dangerous binaries. 7 tools, 22 catalog entries. |
| **aiir CLI** | Human-only actions: approve/reject findings, review case status, manage evidence, generate reports, audit trail queries, case lifecycle (init/close/activate/migrate), execute forensic commands with audit trail, configure examiner identity. Not callable by AI. |
| **sift-common** | Shared internal package. Canonical AuditWriter, operational logging (oplog), CSV/JSON/text output parsers. Used by all SIFT MCPs. |
| **forensic-knowledge** | Shared YAML data package. Tool guidance, artifact knowledge, discipline rules, playbooks, collection checklists. No runtime state. |

---

## Deployment Topologies

### Solo analyst

One SIFT workstation. The LLM client and aiir CLI both run on SIFT.

```
┌─────────────────────── SIFT Workstation ───────────────────────┐
│                                                                │
│  LLM Client ──streamable-http──► sift-gateway :4508            │
│                                      │                         │
│                                    stdio                       │
│                                      │                         │
│                                  SIFT MCPs                     │
│                                      │                         │
│  aiir CLI ──filesystem──► Case Directory ◄── forensic-mcp ─────┘
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### SIFT + Windows

SIFT workstation + Windows forensic VM. The LLM client and aiir CLI run on SIFT. wintools-mcp runs on the Windows box and accesses the case directory over SMB. The LLM client makes two separate HTTP connections: one to the gateway (SIFT tools) and one to wintools-mcp (Windows tools).

```
┌─────────────────────── SIFT Workstation ───────────────────────┐
│                                                                │
│  LLM Client ──streamable-http──► sift-gateway :4508 ──► MCPs  │
│                                                                │
│  aiir CLI ──filesystem──► Case Directory                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘

┌───────────── Windows Forensic Workstation ─────────────────────┐
│                                                                │
│  wintools-mcp :4624                                            │
│       │                                                        │
│       └──SMB──► Case Directory (on SIFT)                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘

LLM Client ──streamable-http──► wintools-mcp :4624
```

### Multi-examiner

Multiple examiners work the same case. Each examiner runs their own full stack (LLM client, aiir CLI, sift-gateway, and all MCPs) on their own SIFT workstation with a local case directory. Collaboration is merge-based: examiners export findings/timeline as JSON and import each other's contributions using last-write-wins dedup.

```
┌─ Examiner 1 — SIFT Workstation ─┐
│ LLM Client + aiir CLI            │
│ sift-gateway :4508 ──► MCPs      │
│ Case Directory (local)            │
└───────────────────────────────────┘
        │
        │  export / merge (JSON files)
        │
┌─ Examiner 2 — SIFT Workstation ─┐
│ LLM Client + aiir CLI            │
│ sift-gateway :4508 ──► MCPs      │
│ Case Directory (local)            │
└───────────────────────────────────┘
```

Each examiner's findings and timeline entries include the examiner name in the ID (e.g., `F-alice-001`, `T-bob-003`). The `modified_at` field enables last-write-wins merge semantics.

---

## Case Directory Structure

Flat layout. No `examiners/` subdirectory. All data files at case root.

```
cases/INC-2026-0219/
├── CASE.yaml                    # Case metadata (name, status, examiner)
├── evidence/                    # Original evidence (read-only after registration)
├── extractions/                 # Extracted artifacts
├── reports/                     # Generated reports
├── findings.json                # F-alice-001, F-alice-002, ...
├── timeline.json                # T-alice-001, ...
├── todos.json                   # TODO-alice-001, ...
├── evidence.json                # Evidence registry
├── actions.jsonl                # Investigative actions (append-only)
├── evidence_access.jsonl        # Chain-of-custody log
├── approvals.jsonl              # Approval audit trail
└── audit/
    ├── forensic-mcp.jsonl
    ├── sift-mcp.jsonl
    ├── claude-code.jsonl       # PostToolUse hook captures (Claude Code only)
    └── ...
```

ID format includes examiner name: `F-{examiner}-{seq:03d}`, `T-{examiner}-{seq:03d}`, `TODO-{examiner}-{seq:03d}`. This makes IDs globally unique across examiners without namespace prefixing.

---

## Protocol Stack

```
LLM Client
    │
    │  MCP Streamable HTTP (POST /mcp, SSE responses)
    │
    ▼
sift-gateway :4508                     wintools-mcp :4624
    │                                      │
    │  stdio (subprocess)                  │  subprocess.run(shell=False)
    │                                      │
    ▼                                      ▼
forensic-mcp                          Windows forensic tools
case-mcp                              (Zimmerman, Hayabusa)
report-mcp
sift-mcp ──► SIFT forensic tools
forensic-rag-mcp
windows-triage-mcp
opencti-mcp
```

The gateway uses the low-level MCP `Server` class (not FastMCP) because tools are discovered dynamically from backends at runtime. wintools-mcp uses `FastMCP.streamable_http_app()` because it has statically-registered tools.

Authentication at both endpoints uses ASGI-level wrappers (not Starlette `BaseHTTPMiddleware`) to avoid buffering SSE streams.

---

## Examiner Identity

Resolution order (highest priority first):

1. `--examiner` CLI flag
2. `AIIR_EXAMINER` environment variable
3. `~/.aiir/config.yaml` examiner field
4. `AIIR_ANALYST` environment variable (deprecated)
5. OS username (fallback, warns if unconfigured)

The gateway maps API keys to examiner identities in `gateway.yaml`. The examiner name is injected into forensic-mcp tool calls for audit trail attribution.

---

## Client Configuration

`aiir setup client` generates Streamable HTTP configs. All entries use `"type": "streamable-http"`.

```bash
# Solo (gateway on localhost)
aiir setup client --sift=http://127.0.0.1:4508 --client=claude-code -y

# SIFT + Windows
aiir setup client --sift=http://SIFT_IP:4508 --windows=WIN_IP:4624

# Interactive wizard
aiir setup client
```

Generated `.mcp.json` example:
```json
{
  "mcpServers": {
    "aiir": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:4508/mcp"
    },
    "wintools-mcp": {
      "type": "streamable-http",
      "url": "http://192.168.1.20:4624/mcp"
    }
  }
}
```

---

## Repo Map

| Repo | GitHub | Purpose |
|------|--------|---------|
| [sift-mcp](https://github.com/AppliedIR/sift-mcp) | AppliedIR/sift-mcp | SIFT monorepo: 10 packages (forensic-mcp, case-mcp, report-mcp, sift-mcp, sift-gateway, forensic-knowledge, forensic-rag, windows-triage, opencti, sift-common), SIFT installer, platform docs |
| [wintools-mcp](https://github.com/AppliedIR/wintools-mcp) | AppliedIR/wintools-mcp | Windows tool execution MCP + Windows installer |
| [aiir](https://github.com/AppliedIR/aiir) | AppliedIR/aiir | CLI + this architecture doc |

Public repos under the AppliedIR GitHub org.
