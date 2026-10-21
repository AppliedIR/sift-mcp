# Codex on the SIFT workstation

## Opt-out

`vhir setup client --client=codex` installs Codex's managed requirements as
`/etc/codex/requirements.toml`, with root-owned copies of Valhuntir's hooks in
`/etc/codex/vhir-hooks/`. They apply to **every Codex session on this
machine**, whoever starts it and from whatever folder.

With them on, non-forensic use of Codex still works from any folder:

- Codex's own sandbox stays on (`danger-full-access` and the bypass flag are
  refused);
- its shell can't read the signing and approval store (`/var/lib/vhir`), the
  gateway's tokens or the Valhuntir profile;
- each command is recorded in the **active case's** audit file, marked
  `"outside_case": true` with the folder it ran in.

To turn them off (for example on a machine that's also used for other work):

```
sudo mv /etc/codex/requirements.toml /etc/codex/requirements.toml.off
```

This removes every Codex control at once: the sandbox limits above, the
case-data guard and the audit. `vhir setup test`, `vhir setup client` and
`vhir update` then say **CODEX CONTROLS OFF**. Between those checks, nothing
reports it. Codex sessions already running, and the Codex app-server if it
runs, keep the old rules until they're restarted.

To turn them back on, move the file back, or run
`vhir setup client --client=codex` again.

An administrator's own `/etc/codex/requirements.toml` is never changed by
Valhuntir: setup prints the block to merge into it, and reports the Codex
controls as not in effect until it's merged.

## What the managed requirements hold

Tested with Codex 0.158; the managed permission profile needs Codex 0.138 or
later.

- **The sandbox can't be turned off.** Only the `vhir` permissions profile
  (the default) and `:read-only` are allowed, so a request for full access,
  or a profile's `sandbox_mode`, runs under `vhir`: the workspace, with
  `~/.vhir` read-only. The shell can't change the active case, the hooks, the
  configuration or the venv, even started from `~`.
- **The shell can't read** the signing and approval store, the gateway's
  tokens or the Valhuntir profile. If one of those files is missing, Codex
  can't set up its sandbox and every shell command fails (fails closed).
- **Web search is off.** A hosted tool fires no hook, so nothing would audit
  it.
- **The case-data guard runs before a shell command and before an
  apply_patch.** A patch is checked by the paths its headers name (`*** Add
  File`, `Update File`, `Delete File`, `Move to`), never read as shell. A
  refusal is recorded in the case's audit. Codex has no hook for a failed or
  denied call, so an apply_patch that Codex itself rejects leaves no audit
  entry.
- **The finding-skeptic reads and queries only.** Codex applies no tool list
  from an agent file, so a hook checks each call the skeptic makes: an MCP
  tool off Claude Code's skeptic list (`agents/finding-skeptic/claude.md`),
  apply_patch, the shell, or spawning or messaging another agent is refused.
- **Each prompt gets the forensic-rules reminder** Claude Code's hook prints.

## Sandbox

Codex runs its shell commands in a sandbox built with bubblewrap (`bwrap`)
and unprivileged user namespaces. On a kernel that restricts those
namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`, the default
on Ubuntu 24.04 and later), Codex's sandbox needs two things:

- `/usr/bin/bwrap` (the `bubblewrap` package)
- an AppArmor profile that lets `/usr/bin/bwrap` create user namespaces

Codex uses `/usr/bin/bwrap` when it exists. Otherwise it uses its own
bundled copy, which the profile doesn't cover. Without both, **every shell
command fails**: Codex fails closed rather than run unconfined.

SIFT's installer installs `bubblewrap`, and when it finds the restriction
it adds the profile at `/etc/apparmor.d/bwrap` and loads it. Setup prints a
notice when the restriction is on and either is missing.

On another client, an administrator adds the same profile. This is the
profile setup-sift.sh writes, without its comment lines:

```
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
```

Save it as `/etc/apparmor.d/bwrap`, then load it with
`sudo apparmor_parser -r /etc/apparmor.d/bwrap`. Other programs keep the
restriction, but any program that runs `/usr/bin/bwrap` gets user
namespaces through it.
