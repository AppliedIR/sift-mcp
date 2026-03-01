---
name: case
description: Manage forensic investigation cases
arguments:
  - name: action
    required: false
    description: "Action: init, open, status, list, or close (omit for quick status)"
  - name: name
    required: false
    description: Case name (for init/open)
---

# Case Management

Run `case-manager.sh` for all case operations. **Do not create directories,
write state files, or edit CASE.yaml directly.** The script handles all
file operations deterministically.

**Script location:** `~/.aiir/bin/case-manager.sh`

**Action:** $action
**Case name:** $name

## Routing

### No action (just `/case`)

1. Run: `bash ~/.aiir/bin/case-manager.sh status`
2. If output says "No active case" → also run `list` and suggest
   `/case init <name>` or `/case open <name>`
3. Otherwise, tell the user the case status from the output

### `init [name]`

1. If no name provided, ask the user for one
2. Ask for a brief description (one line). If user declines, omit it.
3. Run: `bash ~/.aiir/bin/case-manager.sh init <name> --description "<desc>"`
   (omit `--description` if none provided)
4. Tell the user the case was created and show the paths from the output
5. Remind: evidence goes in evidence/, tool output in extractions/,
   documentation in reports/

### `open <name>`

1. Run: `bash ~/.aiir/bin/case-manager.sh open <name>`
2. If the script says the case is closed, tell the user and ask if they
   want to reopen it. If yes, run with `--reopen`:
   `bash ~/.aiir/bin/case-manager.sh open <name> --reopen`
3. Tell the user the case is active and summarize the paths
4. Remind: READ from evidence, WRITE to extractions, UPDATE reports

### `status`

1. Run: `bash ~/.aiir/bin/case-manager.sh status`
2. Present the case information from the output

### `list`

1. Run: `bash ~/.aiir/bin/case-manager.sh list`
2. Present the case list from the output

### `close [name]`

1. If no name, run: `bash ~/.aiir/bin/case-manager.sh close`
2. If name given, run: `bash ~/.aiir/bin/case-manager.sh close <name>`
3. Confirm closure to the user

## Important

- **NEVER write to `~/.aiir/active_case` directly.** The script does this.
- **NEVER create case directories directly.** The script does this.
- **NEVER edit CASE.yaml directly.** The script does this.
- If the script returns an error (exit 1), show the error message to the user.
