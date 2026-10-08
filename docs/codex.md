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

## Sandbox

Codex runs its shell commands in a sandbox built on unprivileged user
namespaces. On a kernel that restricts them
(`kernel.apparmor_restrict_unprivileged_userns=1`, the default on Ubuntu
24.04 and later) the sandbox can't start, and **every shell command fails**:
Codex fails closed rather than run unconfined. SIFT's Ubuntu 22.04 isn't
affected. Setup prints a notice when it finds the restriction.

Valhuntir doesn't change it. An administrator can allow Codex's sandbox
helper (`codex-linux-sandbox`) an AppArmor profile, or turn the restriction
off machine-wide (`sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`,
which lowers that protection for every program).
