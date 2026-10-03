#!/usr/bin/env bash
#
# PreToolUse hook (Bash): refuse commands that would delete or overwrite case
# records. A best-effort check of the commands listed below, not a security
# boundary.
#
# Protected, under ${VHIR_CASES_DIR:-~/cases}: the case records at a case root
# (findings.json, timeline.json, approvals.jsonl, iocs.json, evidence.json,
# todos.json, CASE.yaml, actions.jsonl, pending-reviews.json), everything in
# audit/, every existing file in evidence/ (and evidence/ while non-empty),
# each case root and the cases root. Everything else is allowed: other files,
# reports/, work/, .outputs/, extractions/, filing new files into evidence/,
# and moving unprotected files into DELETE/.
#
# Blocked on a protected path: rm, rmdir, shred, unlink, truncate; mv from or
# onto it; cp, install or ln onto it; > >> >| &> onto it; find rooted at it (or
# at a case or the cases root) with -delete or -exec. Seen through: sudo, env,
# VAR=val, nice, nohup, time, timeout, stdbuf, exec, command, if/then/do/{/!,
# ; && || | & and newlines, cd, quoting, .., absolute command paths, mv -t.
# Not seen: bash -c/sh -c, xargs, scripts, git clean, rsync --delete, tar
# --remove-files, dd of=, brace expansion, variables and $(...).
#
# The command is tokenized only: it is never run, evaluated or expanded by a
# shell. A block exits 2 with the reason on stderr (Claude Code shows it to
# the model); anything else exits 0.
#
GUARD=$(
    cat <<'PY'
import glob, itertools, json, os, shlex, sys

RECORDS = {"findings.json", "timeline.json", "approvals.jsonl", "iocs.json", "evidence.json",
           "todos.json", "CASE.yaml", "actions.jsonl", "pending-reviews.json"}
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "{", "}", "!", "fi", "done"}
SEPS = {";", "&&", "||", "|", "&", "|&", "(", ")"}
REDIRS = {">", ">>", ">|", "&>", "&>>"}
WRAP = {"sudo", "env", "command", "nice", "nohup", "time", "timeout", "stdbuf", "exec"}
CAP = 2000  # glob matches checked per argument (the 5-second bound)


def block(why):
    print(f"BLOCKED: {why}. Case records, audit/ and evidence files are protected; "
          "move other files to the case's DELETE/ directory instead.", file=sys.stderr)
    sys.exit(2)


try:
    payload = json.load(sys.stdin)
except Exception:
    sys.exit(0)
cmd = (payload.get("tool_input") or {}).get("command") or ""
base = payload.get("cwd") or os.getcwd()
cases = os.path.realpath(os.path.expanduser(os.environ.get("VHIR_CASES_DIR", "~/cases")))


def rel(p):
    """Path components under the cases root (None if outside), and the real path."""
    p = os.path.realpath(os.path.join(base, os.path.expanduser(p)))
    if p != cases and not p.startswith(cases + "/"):
        return None, p
    return [x for x in p[len(cases):].split("/") if x], p


def damage(p, new_ok=False):
    """Whether deleting or overwriting p touches protected case data."""
    parts, real = rel(p)
    if parts is None:
        return False
    if len(parts) <= 1:  # the cases root or a case root
        return True
    top = parts[1]
    if top == "audit" or (top in RECORDS and len(parts) == 2):
        return True
    if top == "evidence":
        if len(parts) == 2:  # evidence/ itself, while it holds anything
            return bool(os.listdir(real)) if os.path.isdir(real) else False
        return os.path.lexists(real) or not new_ok
    return False


def could_hold_protected(pattern):
    """Whether a glob's fixed prefix (up to its first wildcard) could reach protected data."""
    fixed = []
    for c in os.path.join(base, os.path.expanduser(pattern)).split("/"):
        if any(ch in c for ch in "*?["):
            break
        fixed.append(c)
    prefix = os.path.realpath("/".join(fixed) or "/")
    if cases == prefix or cases.startswith(prefix.rstrip("/") + "/"):
        return True
    parts, _ = rel(prefix)
    return parts is not None and (len(parts) <= 1 or parts[1] in ("audit", "evidence")
                                  or (len(parts) == 2 and parts[1] in RECORDS))


def expand(a):
    """Glob matches (stdlib only, at most CAP), or the word itself."""
    if not any(c in a for c in "*?["):
        return [a]
    hits = list(itertools.islice(glob.iglob(os.path.join(base, os.path.expanduser(a))), CAP + 1))
    if len(hits) > CAP:
        if could_hold_protected(a):
            block(f"glob {a} has too many matches to check under the cases directory")
        hits = hits[:CAP]
    return hits or [a]


def check(seg):
    global base
    for i, t in enumerate(seg[:-1]):
        if t in REDIRS and damage(seg[i + 1]):
            block(f"redirection onto {seg[i + 1]}")
    seg = [t for i, t in enumerate(seg) if t not in REDIRS and (i == 0 or seg[i - 1] not in REDIRS)]
    while seg and (seg[0] in WRAP or seg[0] in KEYWORDS or ("=" in seg[0] and not seg[0].startswith("-"))):
        w = seg.pop(0)
        while seg and (seg[0].startswith("-") or "=" in seg[0] or (w == "timeout" and seg[0][:1].isdigit())):
            o = seg.pop(0)
            if (w, o) in (("sudo", "-u"), ("sudo", "-g"), ("nice", "-n")) and seg:
                seg.pop(0)
    if not seg:
        return
    name = os.path.basename(seg[0])
    if name == "cd":
        base = os.path.join(base, os.path.expanduser(seg[1] if len(seg) > 1 else "~"))
        return
    args, dd, tdir, it = [], False, None, iter(seg[1:])
    for a in it:
        if a == "--" and not dd:
            dd = True
        elif not dd and a in ("-t", "--target-directory"):
            tdir = next(it, None)
        elif not dd and a.startswith("--target-directory="):
            tdir = a.split("=", 1)[1]
        elif dd or not a.startswith("-"):
            args += expand(a)
    if tdir is not None:
        args.append(tdir)
    if name in ("rm", "rmdir", "shred", "unlink", "truncate"):
        for a in args:
            if damage(a):
                block(f"{name} on {a}")
    elif name in ("mv", "cp", "install", "ln") and len(args) >= 2:
        dst = args[-1]
        for s in args[:-1]:
            if name == "mv" and damage(s):
                block(f"mv away {s}")
            tgt = os.path.join(dst, os.path.basename(s)) if os.path.isdir(os.path.join(base, dst)) else dst
            if damage(tgt, new_ok=True):
                block(f"{name} over {tgt}")
    elif name == "find" and ("-delete" in seg or any(t in ("-exec", "-execdir") for t in seg)):
        for r in [a for a in seg[1:] if not a.startswith("-")][:1] or ["."]:
            parts, _ = rel(r)
            if parts is not None and (len(parts) <= 1 or damage(r)):
                block(f"find -delete/-exec under {r}")


text = cmd.replace("\n", ";")
try:
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    tokens = list(lex)
except ValueError:  # unbalanced quotes: fall back to plain words
    tokens = text.split()
seg = []
for t in tokens + [";"]:
    if t in SEPS:
        check(seg)
        seg = []
    else:
        seg.append(t)
sys.exit(0)
PY
)
exec python3 -c "$GUARD"
