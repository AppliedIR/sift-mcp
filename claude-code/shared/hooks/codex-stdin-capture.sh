#!/usr/bin/env bash
#
# Codex Stop hook (and run by the audit hook after each Codex call): records
# the text Codex typed into a running shell with write_stdin, which no hook
# sees. It reads the session's transcript (transcript_path) and appends one
# audit entry per write_stdin call it hasn't recorded yet, to the active
# case's claude-code.jsonl: "client": "codex", "event": "write_stdin", the
# text as "command" (its first 2000 characters, with its length and sha256
# when longer), and its transcript line. The next run starts after the
# highest line recorded for that session in any case: a per-session cursor in
# ~/.vhir/codex-stdin/, so input already recorded in one case is never
# recorded again in the case made active after it. With no active case it
# writes nothing. Never blocks (always exits 0).
#
CAPTURE=$(
    cat <<'PY'
import datetime, hashlib, json, os, sys

MAX = 2000

try:
    payload = json.load(sys.stdin)
    session = str(payload.get("session_id", ""))
    transcript = str(payload.get("transcript_path", ""))
    cwd = str(payload.get("cwd", ""))
    case = os.environ.get("VHIR_CASE_DIR", "")
    if not (case and os.path.isdir(case)):
        with open(os.path.expanduser("~/.vhir/active_case")) as f:
            case = f.read().strip()
    if not (session and transcript and case.startswith("/") and os.path.isdir(case)):
        sys.exit(0)
    audit = os.environ.get("VHIR_AUDIT_DIR", "")
    if not (audit and os.path.isdir(audit)):
        audit = os.path.join(case, "audit")
        os.makedirs(audit, exist_ok=True)
    path = os.path.join(audit, "claude-code.jsonl")
    cursors = os.path.expanduser("~/.vhir/codex-stdin")
    cursor = os.path.join(cursors, hashlib.sha256(session.encode()).hexdigest()[:32])
    stored, hooks = 0, 0
    try:
        with open(cursor) as f:
            stored = int(f.read().strip() or 0)  # recorded already, in whichever case
    except (OSError, ValueError):
        pass
    done = stored
    if os.path.exists(path):
        with open(path) as f:
            for ln in f:
                hooks += '"hook-' in ln
                try:
                    e = json.loads(ln)
                except ValueError:
                    continue
                if e.get("event") == "write_stdin" and e.get("session_id") == session:
                    done = max(done, int(e.get("transcript_line", 0)))
    import pwd

    examiner = os.environ.get("VHIR_EXAMINER") or pwd.getpwuid(os.getuid()).pw_name
    real = os.path.realpath(case)
    outside = not (os.path.realpath(cwd) + "/").startswith(real + "/") if cwd else False
    out = []
    with open(transcript) as f:
        for n, ln in enumerate(f, 1):
            if n <= done or '"write_stdin"' not in ln:
                continue
            try:
                p = json.loads(ln).get("payload") or {}
                if p.get("type") != "function_call" or p.get("name") != "write_stdin":
                    continue
                chars = str(json.loads(p.get("arguments") or "{}").get("chars", ""))
            except (ValueError, AttributeError):
                continue
            hooks += 1
            day = datetime.datetime.now(datetime.timezone.utc)
            entry = {
                "ts": day.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": "claude-code-hook",
                "client": "codex",
                "event": "write_stdin",
                "tool_use_id": str(p.get("call_id", "")),
                "audit_id": f"hook-{examiner}-{day:%Y%m%d}-{hooks:03d}",
                "command": chars[:MAX],
                "cwd": cwd,
                "session_id": session,
                "transcript_line": n,
            }
            if len(chars) > MAX:  # the rest isn't recorded: say so, and what it was
                entry["command_truncated"] = True
                entry["command_length"] = len(chars)
                entry["command_sha256"] = hashlib.sha256(chars.encode()).hexdigest()
            if outside:
                entry["outside_case"] = True
            out.append(json.dumps(entry))
    if out:
        with open(path, "a") as f:
            f.write("\n".join(out) + "\n")
        done = json.loads(out[-1])["transcript_line"]
    if done > stored:  # recorded now, or before the cursor was kept: keep it
        os.makedirs(cursors, mode=0o700, exist_ok=True)
        tmp = f"{cursor}.{os.getpid()}.tmp"
        with open(tmp, "w") as f:
            f.write(str(done))
        os.replace(tmp, cursor)
except Exception:
    pass
PY
)
python3 -I -c "$CAPTURE" 2>/dev/null
exit 0
