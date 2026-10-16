# Belay v0.2.2

Patch release on top of v0.2.1.

## Fixes

- **Claude Code's PowerShell tool is now gated.** On Windows, Claude Code has a
  `PowerShell` tool alongside `Bash`. Every command rule was keyed to `Bash`,
  so a PowerShell-tool call matched nothing and was Allowed: download-and-run
  droppers, `irm ... | iex`, `Remove-Item -Recurse -Force C:\`, and secret
  uploads all went through, and an agent denied on Bash could retry the same
  action through PowerShell. PowerShell-tool calls are now evaluated as shell
  commands, so the existing rules (including the PowerShell-syntax ones) apply.

## Tests

- `daemon/tests/devfest_demo.rs` gains tests 17-19 for PowerShell-tool calls.
