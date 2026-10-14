#!/usr/bin/env bash
#
# Codex PreToolUse hook: Codex's finding-skeptic gets the tools Claude's
# skeptic is given (agents/finding-skeptic/claude.md `tools:`, its read and
# query MCP tools) and nothing that writes or hands work on. Codex applies no
# tool list from an agent file, but marks each call the skeptic makes with
# "agent_type": "finding-skeptic". For those calls it refuses (exit 2, the
# reason on stderr) any other MCP tool, apply_patch and the shell, and
# spawning or messaging another agent: an agent the skeptic started would be
# marked "default", so it can't be checked. Calls by any other agent pass.
#
CHECK=$(
    cat <<'PY'
import json, sys

ALLOWED = {  # Claude's skeptic's tools (agents/finding-skeptic/claude.md), by server
    "forensic-mcp": {
        "get_actions", "get_anti_patterns", "get_checkpoint_requirements", "get_collection_checklist",
        "get_confidence_definitions", "get_corroboration_suggestions", "get_evidence_standards",
        "get_evidence_template", "get_false_positive_context", "get_findings", "get_investigation_framework",
        "get_playbook", "get_rules", "get_timeline", "get_tool_guidance", "list_playbooks", "list_todos",
        "validate_finding",
    },
    "report-mcp": {
        "get_case_metadata", "list_profiles", "list_reports",
    },
    "sift-mcp": {
        "check_tools", "get_tool_help", "list_available_tools", "run_command", "suggest_tools",
    },
    "forensic-rag-mcp": {
        "get_knowledge_stats", "list_knowledge_sources", "search_knowledge",
    },
    "windows-triage-mcp": {
        "analyze_filename", "check_autorun", "check_file", "check_hash", "check_hijackable_dll", "check_lolbin",
        "check_pipe", "check_process_tree", "check_registry", "check_scheduled_task", "check_service",
        "get_db_stats", "get_health",
    },
    "opencti-mcp": {
        "get_entity", "get_health", "get_recent_indicators", "get_relationships", "lookup_ioc", "search_entity",
        "search_reports", "search_threat_intel",
    },
    "threatintel-mcp": {
        "get_entity", "get_health", "get_recent_indicators", "get_relationships", "lookup_ioc", "search_entity",
        "search_reports", "search_threat_intel",
    },
    "opensearch-mcp": {
        "idx_aggregate", "idx_case_summary", "idx_count", "idx_field_values", "idx_get_event",
        "idx_ingest_status", "idx_list_detections", "idx_search", "idx_shard_status", "idx_status",
        "idx_timeline",
    },
    "wintools-mcp": {
        "check_windows_tools", "get_share_info", "get_windows_tool_help", "list_kape_targets",
        "list_missing_windows_tools", "list_windows_tools", "run_windows_command", "scan_tools",
        "suggest_windows_tools",
    },
    "remnux-mcp": {
        "check_tools", "get_file_info", "get_tool_help", "list_files", "suggest_tools",
    },
}
WRITES = {"apply_patch", "Bash", "exec_command", "write_stdin", "shell", "local_shell"}
# A namespaced tool's name comes prefixed, e.g. collaborationspawn_agent
HANDS_ON = ("spawn_agent", "send_input", "resume_agent", "followup_task", "send_message", "assign_agent_task")


def refuse(why):
    print(f"BLOCKED: {why}", file=sys.stderr)
    sys.exit(2)


try:
    payload = json.load(sys.stdin)
    agent, tool = payload.get("agent_type"), str(payload["tool_name"])
except Exception:
    refuse("the skeptic's tool check couldn't read this call, so it was blocked to be safe")
if agent != "finding-skeptic":
    sys.exit(0)
if tool.startswith("mcp__"):
    server, _, name = tool[5:].partition("__")
    if name:  # mcp__<server>__<tool>, the server as Codex names it (a "-" made "_"): that pair
        ok = any(server.replace("-", "_") == s.replace("-", "_") and name in n for s, n in ALLOWED.items())
    else:  # another shape: the tool's name alone
        ok = any(tool.rsplit("__", 1)[-1] in n for n in ALLOWED.values())
    if not ok:
        refuse(f"the finding-skeptic reads and queries only; {tool} isn't one of its tools")
elif tool in WRITES or tool.endswith(HANDS_ON):
    refuse(f"the finding-skeptic reads and queries only; it can't use {tool}")
sys.exit(0)
PY
)
couldnt_run() {
    echo "BLOCKED: the skeptic's tool check couldn't run, so it was blocked to be safe." >&2
    exit 2
}
# Fail closed, as the case-data guard does: only the check's own verdicts pass.
[ -n "$CHECK" ] || couldnt_run
python3 -I -c "$CHECK"
rc=$?
case $rc in 0 | 2) exit $rc ;; esac
couldnt_run
