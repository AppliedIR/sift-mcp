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

ALLOWED = {
    "analyze_filename", "check_autorun", "check_file", "check_hash", "check_hijackable_dll", "check_lolbin",
    "check_pipe", "check_process_tree", "check_registry", "check_scheduled_task", "check_service", "check_tools",
    "check_windows_tools", "get_actions", "get_anti_patterns", "get_case_metadata", "get_checkpoint_requirements",
    "get_collection_checklist", "get_confidence_definitions", "get_corroboration_suggestions", "get_db_stats",
    "get_entity", "get_evidence_standards", "get_evidence_template", "get_false_positive_context", "get_file_info",
    "get_findings", "get_health", "get_investigation_framework", "get_knowledge_stats", "get_playbook",
    "get_recent_indicators", "get_relationships", "get_rules", "get_share_info", "get_timeline", "get_tool_guidance",
    "get_tool_help", "get_windows_tool_help", "idx_aggregate", "idx_case_summary", "idx_count", "idx_field_values",
    "idx_get_event", "idx_ingest_status", "idx_list_detections", "idx_search", "idx_shard_status", "idx_status",
    "idx_timeline", "list_available_tools", "list_files", "list_kape_targets", "list_knowledge_sources",
    "list_missing_windows_tools", "list_playbooks", "list_profiles", "list_reports", "list_todos",
    "list_windows_tools", "lookup_ioc", "run_command", "run_windows_command", "scan_tools", "search_entity",
    "search_knowledge", "search_reports", "search_threat_intel", "suggest_tools", "suggest_windows_tools",
    "validate_finding",
}  # the bare names: Codex names an MCP tool mcp__<server>__<tool>
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
    if tool.rsplit("__", 1)[-1] not in ALLOWED:
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
