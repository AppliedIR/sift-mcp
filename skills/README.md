# Skills

Agent Skills shipped with Valhuntir, one directory each, with a `SKILL.md`
in the client-neutral Agent Skills format (no client-specific frontmatter).
`vhir setup client` and `vhir update` deploy them for the clients that read
skills.

## finding-skeptic: the agent it needs

The skill runs its skeptic as a separate agent. A client deploys one with:

- **Isolated context:** its own context window (a Claude Code subagent), or a
  separate thread (a Codex custom agent, which inherits the parent's sandbox
  and permissions).
- **Tools:** read and query tools on every backend, plus `run_command` on
  sift-mcp and the Windows tool runner on wintools-mcp. **Not**
  `record_finding`, `record_timeline_event`, or any ingest, case, evidence,
  backup or import tool; no direct shell tool; `run_command` remains.
  `run_command` is an unsandboxed shell with the examiner's sudo. The
  allowlist limits case-state tools, not execution.
- **Model:** the client's default (no pin).
- **Instructions:** the skeptic's part of `finding-skeptic/SKILL.md`.

The agent files are in `../agents/finding-skeptic/`:

- `claude.md` (Claude Code, `~/.claude/agents/finding-skeptic.md`): its
  `tools` line is the allowlist.
- `codex.toml` (Codex, `~/.codex/agents/finding-skeptic.toml`): it has no
  shell tool. Codex doesn't apply MCP settings per agent, so the Codex skeptic
  keeps every MCP tool the session has, `record_finding` included; only its
  instructions keep it from them.

A client without skills or subagents (an MCP-only chat client) doesn't run the
skeptic: its findings show "Not challenged" at approval, and the examiner's
review is their only challenge.
