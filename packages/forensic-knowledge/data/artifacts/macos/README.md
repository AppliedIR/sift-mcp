# macOS Forensic Artifacts

YAML-backed knowledge for macOS forensic artifacts, consumed by `forensic_knowledge.loader` and surfaced to LLM clients during investigations.

## Version Coverage

These artifacts cover **macOS Sequoia (15) through Tahoe (26)**. Earlier versions may share many paths and behaviors but are not guaranteed, and version-specific differences are noted inline in each file's `locations[].os_versions` and `platform_notes` fields.

Earlier versions may be referenced in places where they mark when a feature was **introduced or deprecated**. Those are historical facts an examiner may need in order to interpret evidence and they remain true regardless of which versions the project targets.

## Validation Status

Artifacts were validated formally by Claude Code (Opus 5) against a **live macOS 15.6.1 (Sequoia) host** during August–September 2026. During the same timeframe, most artifacts were validated manually by a practicing DFIR analyst against a **live macOS 26.6.2 (Tahoe) host**. The intention is that through a combination of human-analyst review and AI-automated testing, the best and most accurate results can be achieved. Nevertheless, we make no guarantees that the knowledge files are 100% accurate in all possible cases and scenarios.

## Schema

Each artifact YAML follows the common schema used for Windows and Linux artifacts:

| Field | Type | Purpose |
|---|---|---|
| `name` | string | Human-readable name |
| `description` | string | One-sentence summary |
| `platform` | string | Always `macos` |
| `platform_notes` | string (optional) | macOS-specific context (SIP, SSV, APFS, etc.) |
| `locations` | list | `{path, os_versions, notes}` — one per known path |
| `proves` | list[string] | Claims this artifact can substantiate |
| `does_not_prove` | list[string] | **Required.** Common over-claims to avoid |
| `timestamps` | list (optional) | `{field, meaning, common_misinterpretation}` |
| `common_misinterpretations` | list | `{claim, correction}` |
| `corroborate_with` | dict | `for_execution`, `for_presence`, `for_timeline` — lists of artifact slugs |
| `related_tools` | list[string] | Tool names (matched against tool catalog) |
| `cross_mcp_checks` | list | `{mcp, tool, when}` — when to pivot to other MCPs |
| `references` | list[string] | Primary sources — prefer Apple docs, peer-reviewed DFIR, SANS FOR518 |
| `investigation_patterns` | list (optional) | Named query/pattern guidance |

## Slug Conventions (Cross-Reference Stability)

`corroborate_with` references use **filename slugs** (without `.yaml`). The following slugs are reserved for macOS artifacts — use these names when cross-referencing, even before the referenced file exists:

```
launchd              unified_logging      fsevents
quarantine           tcc                  knowledgec_biome
login_items          system_extensions    cron_at
gatekeeper           safari_artifacts     apfs_snapshots
time_machine         spotlight            quick_look
keychain             xprotect_mrt
```

## Authoring Principles

1. **`does_not_prove` is mandatory.** Every macOS artifact has common over-claims — document them. Example: a LaunchDaemon plist proves persistence was *configured*, not that it ever *executed*.
2. **Version-gate paths.** Apple moves things between releases. Specify which macOS versions a path applies to.
3. **Note SIP/SSV protections.** `/System/Library/*` is on the Sealed System Volume (read-only since Big Sur). Attackers target user-writable locations; explain why a given path is or is not tamperable.
4. **Corroboration is not optional.** Every claim needs at least one corroborating artifact.
5. **Cite primary sources.** Prefer Apple man pages (`man launchd.plist`), Apple Platform Security guide, peer-reviewed DFIR (mac4n6, Objective-See research, SANS FOR518). Avoid undated blog posts.
6. **Validate against real evidence.** Each YAML should be checked against at least one real macOS image or live system before merge.
7. **`related_tools` names tools an examiner should reach for.** Remove a tool only when it cannot parse the artifact *in principle* (e.g. `plutil` cannot parse plain-text crontabs; `qlmanage` has no capability to read the Quick Look cache at all; `libfsapfs`, and therefore Plaso, exposes no APFS snapshot API). **A tool being broken, stale, or unverified at one macOS version is NOT grounds for removal** — that is a version note for the validation record, not a categorical exclusion, and upstream may well fix it. Note also that Plaso's `filestat` timelines any file regardless of parser, so "log2timeline produces output" is trivially true everywhere and useless as a criterion; the bar is whether the tool understands the artifact's *content*.
8. **State whether examiner activity contaminates the artifact.** Several do. For example, previewing files populates the Quick Look cache; requesting keychain secrets raises a console authorization prompt and logs a SecurityAgent event. If an artifact can record the examination, the knowledge file should say so.

## Analysis Caveats to Remember

macOS artifact reliability is complicated by:

- **Extended attributes** (`com.apple.quarantine`, etc.) can be stripped with `xattr -d`. Absence ≠ never present.
- **Timestamp manipulation** via `SetFile -d/-m` or `touch -t` is trivial. Cross-reference Unified Logging for corroboration.
- **FSEvents has no per-event timestamps.** It records *what* changed but not *when*. Use `fsevents` in `corroborate_with.for_presence` only — never in `for_timeline`.
- **Unified Logging retention** is bounded (~days to weeks depending on subsystem). Absence of a log entry for an event outside the retention window proves nothing.
- **Unified Logging fails in two distinct ways**, and they are not equivalent. *Redaction*: the data exists but is emitted as `<private>` — Quick Look redacts every previewed file path, and XProtect Remediator redacts its findings. *Non-emission*: the data was never logged — securityd records keychain unlocks by memory address, naming neither the item nor the requesting process. Only redaction is potentially recoverable via a logging profile. Both defeat object-level attribution.
- **Some artifacts cannot be read in place on a live system.** For example, the Quick Look cache returns `EPERM` to `stat`, `ls` and `find` even for root with Full Disk Access, so a live `find` returns nothing — easily misread as the cache being absent. Collect via an APFS snapshot or dead-box imaging.
- **Binary plists** must be converted (`plutil -convert xml1`) before text tools see them. Always normalize before analysis.
- **SQLite supporting files are not optional.** macOS makes heavy use of SQLite. As such, it's critical to gather all related files. For example, a test Quick Look cache `index.sqlite` file was just 4 KB, accompanied by a 3.7 MB WAL (Write-Ahead Logging) file. Collecting the `.sqlite` alone would yield a virtually empty database. Always gather -wal and -shm files.
- **Never mount a System-volume snapshot of the running boot volume.** Doing so hung a Sequoia 15.6.1 host and required a forced power off. Data-volume snapshot mounts are safe and were performed repeatedly.
