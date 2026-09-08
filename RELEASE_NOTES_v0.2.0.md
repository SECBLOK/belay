# Belay v0.2.0

First release since v0.1.14 (2026-07-22). 123 commits.

The version moves to 0.2.0 rather than 0.1.15 because this window adds a new
command surface (agent-surface sweeps), a new user surface (the enterprise
console), and changes what every audit row contains.

## Highlights

### Agent-surface sweeps

Belay can now enumerate and re-check what an agent can reach, on demand and on
a schedule, and tell you what changed between runs.

- `belay sweep-now` for an on-demand sweep
- `belay sweep-history` and `belay sweep-compare` to see drift over time
- Findings are classified across sweeps, so a new finding is distinguishable
  from one that was already there
- Each sweep records what enumeration **could not** reach, so incomplete
  coverage is visible instead of silently reading as "nothing found"
- Evidence packs carry sweep history

### Standards mappings in the audit log

Every rule in the catalog carries OWASP ASI/LLM Top 10 and MITRE ATLAS
mappings, but the audit log never recorded them - they existed only in the
rule catalog, and anything downstream had to join a row back against
`rules/catalog.yaml` to learn what it mapped to.

Both are now recorded **at write time**, on the hook path and the MCP proxy,
so every row is self-describing and the mapping stays pinned to the ruleset
that actually fired rather than to today's catalog. The approval card shows
them as a compact `Standards` line.

### Detection

- Script-file resolution follows `source` directives, nested script execution,
  and inline bodies inside resolved scripts, so a command that hides its real
  work one file away is still scanned
- Unicode Tags-block folding, so ASCII smuggled through that block is visible
  to every rule rather than only to a dedicated one
- MCP tool-poisoning rules now run over `tools/list` metadata, not just calls
- Runtime-computed writes to the rules source are detected, closing a gap where
  the target path was assembled at runtime rather than written literally

### False positives

A sustained pass over self-tamper, which was the noisiest rule family:

- A redirection only counts as a write when **its own** target is protected
- A duplicated file descriptor is not a file write
- A quoted angle bracket is not a redirect
- Prose that merely mentions a protected file is not a write to it
- Ordinary reads of Belay's own files are no longer denied

Self-disabling subcommands are denied more thoroughly in the same pass, anchored
on every boundary rather than a single prefix.

### Enterprise console and server hardening

- Admin console: sign-in view and console shell, embedded and served by the
  server binary
- Fail-closed CSRF guard for cookie-authenticated writes, covering GET, with
  IPv6 and wildcard host matching fixed
- Host allowlist across the API surface, warning on non-loopback binds with no
  `BELAY_CONSOLE_HOSTS` configured
- Session cookie issued alongside the login token and accepted in `AuthClaims`

### GUI

Twelve fixes, most of one kind: **controls that failed silently**. Egress
allowlist removal, batch approve/deny, host quarantine, skill and ban controls,
mute and tray and findings controls all reported success on a failed daemon
call. The Sidebar claimed "Protected" when it had no idea, the tray popover
guessed at protection state instead of reading it, and the Overview and fleet
views loaded forever instead of saying why they failed.

Also adds a deny-mute button with a mute notice and an Overview revoke panel.

### Reliability

- `install-service` can now upgrade a **running** install. It staged with
  `fs::copy`, which fails with `ETXTBSY` against a live executable - the normal
  case, since it replaces the binary the resident daemon is executing - and the
  error told you to re-run under sudo, which could never help. It now stages to
  a sibling and renames, which is atomic and cannot leave a truncated binary at
  the path your protection depends on.
- The post-install hook self-test no longer fork-bombs under `cargo test`. It
  resolved the binary via `current_exe()`, which under a test run is the libtest
  harness; shelling out to it re-ran the test suite, which self-tested again.
  Observed at ~2000 live processes spawning at ~220/sec before it was caught.
- `belay protect` verifies the installed hook can actually run, catching the
  class of failure where a hook installs perfectly and cannot execute - which
  looks identical to a quiet day.

### AI (optional, BYOK, off by default)

- Daily call budget for the optional BYOK explainer layer

## Upgrading

The one-liner is unchanged:

```
curl -fsSL https://dl.belay.secblok.io/install.sh | bash
```

To upgrade an existing service install in place:

```
sudo belay install-service --enable
```

This is the release where that works against a running daemon.

## Known limitations

- **aarch64-linux is not built.** x86_64 Linux (musl) and both macOS
  architectures are.
- **The Windows installer is unsigned.** Windows SmartScreen will warn on it
  until a code-signing certificate is in place.
- **R2 mirrors `latest` only**, and only for the platforms uploaded to it.
  macOS and aarch64-linux install from GitHub Releases via the automatic
  fallback in `install.sh`.
