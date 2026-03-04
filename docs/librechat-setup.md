# LibreChat Setup Guide for AIIR

Configure LibreChat as an AIIR forensic investigation client. LibreChat
connects to the AIIR gateway via MCP (streamable-http) and gets per-backend
forensic discipline instructions automatically.

**Minimum version:** v0.8.3+ recommended (streamable-http reconnection fix,
deferred tool loading). Currently v0.8.3-rc1 — use v0.8.3+ when available.

## Two-Mode Architecture

LibreChat operates in two modes with AIIR. Understanding this split is
essential for correct setup.

**Standard mode** uses the `modelSpecs` preset. The `promptPrefix` injects
forensic discipline as a system prompt every request. All tool definitions
load into every request context. Simpler but heavier (~51K tokens of tool
schemas per turn with 64 tools).

**Agents mode (recommended)** uses Agent Instructions configured in the UI.
Tool Search and deferred loading reduce per-turn context from ~51K to ~5K
tokens. The `promptPrefix` from modelSpecs is NOT used in Agents mode —
agents have a separate prompt pipeline.

In Agents mode, the LLM receives context from three tiers:
1. Shared run context (file context, RAG, Memory)
2. Agent Instructions (what you paste in the Agent Builder)
3. MCP instructions (per-backend methodology, delivered automatically)

Use Agents mode for investigations. Standard mode works as a quick fallback.

## Prerequisites

1. AIIR gateway running (`aiir service status` shows backends healthy)
2. Bearer token from `~/.aiir/gateway.yaml`
3. LibreChat v0.8.3+ with MCP support enabled

## Quick Start

Generate a starting config:

```
aiir setup client --client=librechat --sift-url=http://localhost:4508
```

This creates `librechat_mcp.yaml` with per-backend MCP entries, timeouts,
initTimeout, allowedDomains, and model settings. Merge it into your
`librechat.yaml`.

After merging, create an AIIR Investigation agent (see "Creating an AIIR
Agent" below). The generated config handles standard mode. Agents mode
requires manual setup in the UI.

## mcpServers Configuration

Use per-backend endpoints (not the aggregate `/mcp`). Each backend gets its
own MCP connection with isolated instructions and appropriate timeouts.

```
mcpServers:
  forensic-mcp:
    type: "streamable-http"
    url: "http://<gateway>:4508/mcp/forensic-mcp"
    headers:
      Authorization: "Bearer <token>"
    timeout: 60000
    initTimeout: 30000
    serverInstructions: true

  sift-mcp:
    type: "streamable-http"
    url: "http://<gateway>:4508/mcp/sift-mcp"
    headers:
      Authorization: "Bearer <token>"
    timeout: 300000          # 5 min — forensic tools can run long
    initTimeout: 30000
    serverInstructions: true

  case-mcp:
    type: "streamable-http"
    url: "http://<gateway>:4508/mcp/case-mcp"
    headers:
      Authorization: "Bearer <token>"
    timeout: 60000
    initTimeout: 15000
    serverInstructions: true

  report-mcp:
    type: "streamable-http"
    url: "http://<gateway>:4508/mcp/report-mcp"
    headers:
      Authorization: "Bearer <token>"
    timeout: 60000
    initTimeout: 15000
    serverInstructions: true

  forensic-rag-mcp:
    type: "streamable-http"
    url: "http://<gateway>:4508/mcp/forensic-rag-mcp"
    headers:
      Authorization: "Bearer <token>"
    timeout: 60000
    initTimeout: 30000
    serverInstructions: true

  windows-triage-mcp:
    type: "streamable-http"
    url: "http://<gateway>:4508/mcp/windows-triage-mcp"
    headers:
      Authorization: "Bearer <token>"
    timeout: 120000          # 2 min — baseline DB queries
    initTimeout: 30000
    serverInstructions: true

  opencti-mcp:
    type: "streamable-http"
    url: "http://<gateway>:4508/mcp/opencti-mcp"
    headers:
      Authorization: "Bearer <token>"
    timeout: 60000
    initTimeout: 15000
    serverInstructions: true
```

Set `serverInstructions: true` on all backends. Each backend delivers its own
forensic discipline instructions during the MCP handshake.

### Timeout and initTimeout

| Backend | timeout | initTimeout | Reason |
|---------|---------|-------------|--------|
| sift-mcp | 300000 (5 min) | 30000 | Forensic tool execution (vol.py, bulk_extractor) |
| windows-triage-mcp | 120000 (2 min) | 30000 | Baseline database queries |
| forensic-mcp | 60000 | 30000 | Lazy start + SQLite DB load |
| forensic-rag-mcp | 60000 | 30000 | Chromadb collection init |
| All others | 60000 | 15000 | Default |

`timeout` covers ongoing tool execution. `initTimeout` covers the initial
MCP handshake — backends that lazy-start and load databases need more than
the 10s default.

## allowedDomains

LibreChat's SSRF protection blocks private IPs by default. If the gateway
runs on localhost or a LAN IP (which it always does), MCP connections will
silently fail without this setting.

```
mcpSettings:
  allowedDomains:
    - "localhost"
    - "127.0.0.1"
    - "<gateway-ip>"
```

Replace `<gateway-ip>` with your gateway's hostname or IP.

## modelSpecs

The modelSpec provides forensic discipline for standard (non-agent) mode
via `promptPrefix`. In Agents mode, promptPrefix is NOT used — discipline
goes in Agent Instructions instead.

```
modelSpecs:
  list:
    - spec: aiir-investigation
      name: "AIIR Investigation"
      preset:
        endpoint: "anthropic"  # change if using azureOpenAI, bedrock, etc.
        maxContextTokens: 200000   # full Claude context window
        maxOutputTokens: 16384     # forensic analysis needs long output
        greeting: |
          AIIR Investigation workspace ready. Connected backends and forensic
          discipline are active. Start with your investigation objective or
          evidence to analyze. All findings stage as DRAFT for your review.
        promptPrefix: |
          You are an IR analyst orchestrating forensic investigations ...
          (see promptPrefix section below for full text)
        modelDisplayLabel: "Claude"
        promptCache: true
```

Do NOT set `enforce: true`. Enforce is a server-side submission validator
that rejects requests without a matching spec. When a user selects an agent
from the sidebar, the spec field is empty, causing a "No model spec selected"
error. Without enforce, both standard mode (via modelSpec) and agents mode
(via sidebar) work freely.

`promptCache: true` (default for Anthropic) caches the system prompt. After
the first turn, the ~1200 token promptPrefix costs 10% of normal input
pricing — effectively free.

### promptPrefix (for standard mode)

This is the full forensic discipline text. Paste it under `promptPrefix: |`
in the modelSpec above. In Agents mode, use the lean Agent Instructions
instead (see below).

```
You are an IR analyst orchestrating forensic investigations on an AIIR workstation. Evidence guides theory, never the reverse.

EVIDENCE PRESENTATION: Every finding must include: (1) Source — artifact file path. (2) Extraction — tool and command. (3) Content — actual log entry or record, never a summary. (4) Observation — factual. (5) Interpretation — analytical, clearly labeled. (6) Confidence — SPECULATIVE/LOW/MEDIUM/HIGH with justification. If you cannot show the evidence, you cannot make the claim.

HUMAN-IN-THE-LOOP: Stop and present evidence before: concluding root cause, attributing to a threat actor, ruling something OUT, pivoting investigation direction, declaring clean/contained, establishing timeline, acting on IOC findings. Show evidence → state proposed conclusion → ask for approval.

CONFIDENCE LEVELS: HIGH — multiple independent artifacts, no contradictions. MEDIUM — single artifact or circumstantial. LOW — inference or incomplete data. SPECULATIVE — no direct evidence, must be labeled.

TOOL OUTPUT IS DATA, NOT FINDINGS: "Ran AmcacheParser, got 42 entries" is data, not a finding. Interpret and evaluate before recording.

SAVE OUTPUT: Always pass save_output: true to run_command. This saves output to a file and returns a summary. Use the saved file path for focused analysis. Never let raw tool output render inline.

ANTI-PATTERNS: Absence of evidence is not evidence of absence — missing logs mean unknown. Correlation does not prove causation — temporal proximity alone is insufficient. Do not let theory drive evidence interpretation. Do not explain away contradictions.

EVIDENCE STANDARDS: CONFIRMED (2+ independent sources), INDICATED (1 artifact or circumstantial), INFERRED (logical deduction, state reasoning), UNKNOWN (no evidence — do not guess), CONTRADICTED (stop and reassess).

RECORDING: Surface findings incrementally as discovered. Use record_finding after presenting evidence and receiving approval. Use record_timeline_event for incident-narrative timestamps. Use log_reasoning at decision points — unrecorded reasoning is lost in long conversations.

All findings and timeline events stage as DRAFT. The examiner reviews and approves via the approval mechanism.
```

## Extended Thinking

For Claude models that support extended thinking, add these settings to a
separate modelSpec preset:

```
    - spec: aiir-investigation-thinking
      name: "AIIR Investigation (Thinking)"
      preset:
        endpoint: "anthropic"
        thinking: true
        thinkingBudget: "8000"
        maxContextTokens: 200000
        maxOutputTokens: 16384
        promptPrefix: |
          ... (same as above)
```

Extended thinking requires `temperature=1` (API constraint). Leave
temperature at its default when using extended thinking. To use a lower
temperature (e.g., 0.3), omit the thinking settings — these are mutually
exclusive.

## recursionLimit

```
endpoints:
  agents:
    recursionLimit: 75       # default for all agents
    maxRecursionLimit: 100   # hard cap — no agent can exceed this
```

The default of 25 is too low. Multi-step evidence chains routinely hit
25-50 tool calls in a single finding cycle. Individual agents can override
via "Max Agent Steps" in Advanced Settings, up to the `maxRecursionLimit`.

## --deferred-tools for forensic-mcp

The gateway starts forensic-mcp with `--deferred-tools` by default. This
exposes 14 discipline references (investigation framework, evidence
standards, playbooks, etc.) as MCP tools instead of MCP resources.

This matters because LibreChat supports MCP tools only — not resources.
Without `--deferred-tools`, the LLM cannot access methodology, validation
schemas, or playbooks.

Verify with `aiir service status` — forensic-mcp should show 26 tools
(12 base + 14 deferred).

## Creating an AIIR Agent (Step-by-Step)

This is the single most important setup step. Agents mode with deferred
loading is the biggest performance lever for LibreChat.

1. Open LibreChat, click the Agents panel, click Create Agent.

2. Set the fields:
   - **Name:** AIIR Investigation
   - **Model:** claude-sonnet-4-6 (or your preferred Claude model)
   - **Instructions:** paste the Agent Instructions text below
   - **Tool Search:** ON

3. Add MCP Servers: select all AIIR backends (forensic-mcp, sift-mcp,
   case-mcp, report-mcp, forensic-rag-mcp, windows-triage-mcp, opencti-mcp).

4. Configure deferred loading: for each backend's tools, click the clock
   icon to defer ALL tools EXCEPT these 6 (used almost every turn):
   - `run_command` (sift-mcp)
   - `record_finding` (forensic-mcp)
   - `get_findings` (forensic-mcp)
   - `record_timeline_event` (forensic-mcp)
   - `log_reasoning` (case-mcp)
   - `get_case_status` (forensic-mcp)

5. Advanced Settings:
   - Max context tokens: 200000
   - Max Agent Steps: 75

**Why this matters:** Without deferred loading, 64 tool definitions
(~800 tokens each = ~51K tokens) load into every request. With deferred
loading, only 6 core tools load (~5K tokens) and the rest are discovered
on demand via Tool Search. That recovers 23% of the context window.
With `promptCache`, all system content (~7K tokens) is cached at 90%
discount after turn 1.

## Agent Instructions

Paste the following into the Agent Instructions field when creating the
agent. This text is designed for Agents mode — it does NOT duplicate the
per-backend MCP instructions (tier 3) which are delivered automatically
via `serverInstructions`.

```
You are an incident response analyst on the AIIR forensic investigation platform.

INVESTIGATION WORKFLOW
Plan before acting. For any multi-step task, list your planned steps, then execute. The examiner monitors your progress and can redirect at any time.

CROSS-BACKEND ORCHESTRATION
Each MCP backend serves a distinct role. Use them together:
- sift-mcp: Execute forensic tools. Always pass save_output: true.
- forensic-mcp: Record findings, timeline events, and manage investigation state.
- case-mcp: Case lifecycle, evidence registration, and log_reasoning for decision points.
- windows-triage: Validate files, processes, services against Windows baselines before concluding anything is malicious. UNKNOWN means "not in database" — neutral, not suspicious.
- opencti: Enrich IOCs with threat context. Correlation supports but does not prove.
- forensic-rag: Search for artifact interpretation guides and investigation procedures.
- report-mcp: Generate reports from approved findings only.

HUMAN-IN-THE-LOOP CHECKPOINTS
STOP and present evidence to the examiner before:
- Concluding root cause or attributing to a threat actor
- Ruling something out or declaring an area clean
- Establishing or revising the incident timeline
- Expanding or pivoting investigation direction
Format: show the evidence, state your proposed conclusion, ask for approval.

RECORDING
Surface findings as you discover them — do not batch at the end.
- record_finding: after presenting evidence and getting approval
- record_timeline_event: for timestamps in the incident narrative
- log_reasoning: at decision points (choosing direction, forming hypotheses, ruling things out) — unrecorded reasoning is lost when context is truncated
- get_case_status: check investigation progress before and during work

CONTEXT MANAGEMENT
For investigations longer than 25-30 turns, start a new conversation for the next phase (e.g., Triage → Deep Analysis → Reporting). At the start of each phase, call get_findings and get_timeline to reload investigation state. Use Memory to persist key facts (hostname, OS version, initial IOCs, attacker TTPs) across conversations.
```

**Why not paste the full promptPrefix?** In Agents mode, tier 3 MCP
instructions deliver ~2150 tokens of per-backend methodology (evidence
presentation, confidence levels, anti-patterns, recording rules,
save_output, tool output handling). The full promptPrefix duplicates all
of this. The lean Agent Instructions above (~500 tokens) adds what tier 3
does NOT cover: cross-backend orchestration, HITL checkpoints, context
management, and recording workflow.

## Additional Agents

Create purpose-built agents with only their relevant backends. Each
sub-agent with fewer backends eliminates Tool Search overhead entirely.

| Agent | Backends | Core tools (keep loaded) |
|-------|----------|--------------------------|
| Investigation | All 7 | run_command, record_finding, get_findings, record_timeline_event, log_reasoning, get_case_status |
| Triage | sift-mcp, windows-triage-mcp | run_command, check_file, check_process_tree, analyze_filename |
| Reporting | case-mcp, report-mcp, forensic-mcp, forensic-rag-mcp | generate_report, save_report, get_findings, get_timeline |

### Triage Agent Instructions

```
You are performing artifact triage on a SIFT workstation. Use run_command
to execute forensic tools and windows-triage to validate artifacts against
baselines. Always pass save_output: true. UNKNOWN means "not in database"
— neutral, not suspicious. Present findings to the examiner before
concluding anything is malicious.
```

### Reporting Agent Instructions

```
You are generating an incident response report using the AIIR platform.
Only approved findings and timeline events appear in reports. Use
search_knowledge for IR writing best practices. Use generate_report to
draft, then save_report to persist. Set case metadata as information emerges.
```

## Context Management Strategy

This is the biggest operational gap vs Claude Code. LibreChat truncates old
messages without intelligent compression. The promptPrefix survives
truncation (it's a system prompt, not conversation history), but earlier
evidence and reasoning can be lost.

**Phase-based conversations:** Split investigations into phases (Triage,
Deep Analysis, Reporting). Start a new conversation for each phase.

**Context reload:** At the start of each phase, call `get_findings` and
`get_timeline` to reload investigation state from the case database.

**Conversation length:** Recommend 25-30 turns per conversation for complex
investigations before starting a new phase.

**Memory:** Key investigation facts (hostname, OS version, initial IOCs,
attacker TTPs) persist across conversations via LibreChat's Memory feature.
The LLM updates Memory automatically during conversations.

## Memory Configuration

Memory is user-managed at runtime. Admin cannot pre-seed content. The LLM
learns forensic patterns from Agent Instructions and MCP instructions over
time. Default keys (`user_preferences`, `conversation_context`,
`learned_facts`) work out of the box.

Optional configuration in `librechat.yaml`:

```
memory:
  messageWindowSize: 10  # default 5 may miss important context
```

Do NOT set `validKeys` to custom keys the LLM doesn't know — this breaks
default behavior.

## URL Bookmarks

Users can create browser bookmarks for different investigation modes:

- `?spec=aiir-investigation` — loads the modelSpec preset (standard mode)
- `?agent_id=<id>` — loads a specific agent directly
- `?prompt=Analyze+this+evidence&submit=true` — pre-fills and auto-submits

Find the agent ID in the URL when you have an agent selected.

## Limitations vs Claude Code

| Feature | Claude Code | LibreChat |
|---------|------------|-----------|
| CLAUDE.md (350 lines) | Loaded every turn | Use promptPrefix (standard) or Agent Instructions (agents) |
| MCP server instructions | Active | Active (`serverInstructions: true`) |
| Hooks (forensic rules, bash guard, audit) | Active | Not available |
| Deny rules (case data protection) | Active | N/A (MCP tools only, no Bash/file access) |
| Context compaction | Intelligent compression | Truncates older messages (use phase-based conversations) |
| TaskCreate progress tracking | Native | Not available |
| Deferred tool loading | N/A | Available (Agents mode, per-tool toggle) |
| Memory | Auto-memory in ~/.claude/ | Auto-injected every turn (user-managed) |

Deny rules are irrelevant for LibreChat. It's a chat client — the LLM has
no Bash tool, no file write capability. It can only call MCP tools, which
enforce their own server-side access controls.

## Troubleshooting

### MCP connections fail silently

Check `allowedDomains`. LibreChat blocks private IPs by default. Add your
gateway hostname to the allowedDomains list.

### Backends fail to connect (timeout during init)

Increase `initTimeout` for the affected backend. Lazy-start backends that
load SQLite databases or chromadb collections can take 15-30 seconds on
first connection. Default LibreChat initTimeout is 10s — too short.

### Missing backends in tool list

Run `aiir service status` to check which backends are running. Non-started
backends are excluded from generated configs. Start them with
`aiir service start` and re-run `aiir setup client --client=librechat`.

### Timeouts on forensic tools

sift-mcp should have `timeout: 300000` (5 min). Tools like volatility3,
bulk_extractor, and log2timeline can run several minutes on large evidence
files. If tools still timeout, increase further.

### Tool Search not finding tools

Verify the agent has Tool Search enabled. Check that deferred tools have
descriptive names — Tool Search matches by tool description. If a tool
can't be found, toggle its "Defer Loading" off to keep it always loaded.

### "Tool not found" errors

Verify forensic-mcp is running with `--deferred-tools`. Without it, the
14 discipline tools (get_investigation_framework, etc.) are registered as
MCP resources which LibreChat cannot see.

## Auto-Generation

```
aiir setup client --client=librechat --sift-url=http://localhost:4508
```

Generates `librechat_mcp.yaml` with:
- Per-backend MCP server entries with per-backend timeouts and initTimeout
- `allowedDomains` for the gateway hostname
- `modelSpecs` with the investigation promptPrefix, greeting, and model settings
- `endpoints.agents.recursionLimit: 75`

Users must create agents manually (UI only — no YAML config for agents).
The generated config handles standard mode. Follow the "Creating an AIIR
Agent" section above for agents mode setup.
