<div align="center">

# Belay

**Detect · Block · Notify — a defense and monitoring layer for AI coding agents.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Discord](https://img.shields.io/badge/Discord-join%20the%20community-5865F2.svg?logo=discord&logoColor=white)](https://discord.gg/pySdeDFy6y)

</div>

Belay is a **local-first security layer** that sits at the **tool-call boundary**
of AI coding agents. It auto-detects the agents you already run, **blocks dangerous
actions outright**, escalates ambiguous-but-risky ones to you for a one-tap
**Allow / Deny**, and notifies you when something happens.

The decision engine is **deterministic, no-LLM, sub-100 ms, and fail-closed** — a
timeout or an internal error becomes a *deny*, never a silent allow. Belay runs
as your user (never root) and **does not phone home by default**.

Works with Claude Code, Codex, Cline, Roo, Cursor, Gemini, Goose, OpenClaw, Hermes,
and more — on a laptop or a headless VPS.

---

## What it stops

- **Secret exfiltration** — `.env` files, API keys, SSH keys
- **Destructive commands** — `rm -rf /`, `curl … | sh`
- **Reverse shells** and command-and-control egress
- **Supply-chain, persistence, privilege-escalation, and recon** patterns

Every rule is tagged with the **OWASP Agentic Security Initiative (ASI) Top 10**,
**OWASP LLM Top 10**, and **MITRE ATLAS**, and the static scanner emits **SARIF 2.1.0**.

## How it works

```
detect  →  protect  →  serve / desktop app
  │           │              │
  │           │              └─ live status, triage, and Allow/Deny in the desktop UI
  │           └─ gate every tool call: Deny > Ask > Allow (fail-closed)
  └─ find the AI agents installed on this machine
```

Belay gates each tool call deterministically. A **Deny** can never be downgraded
by the dev-toolchain allowlist; an **Ask** waits for a human decision and denies on
timeout. Run with `--observe` first to tune in log-only mode before enforcing.

## Features

- **Runtime gating at the tool-call boundary** — native PreToolUse/PostToolUse hooks
  for Claude Code / Codex (`hook` and `gate` integration styles); PostToolUse redacts
  secret-shaped strings from tool output.
- **MCP proxy** (`mcp-proxy`) — wrap any MCP server so every `tools/call` is gated; fail-closed.
- **Deterministic rule catalog** — secrets, egress, destructive, RCE, supply-chain,
  persistence, priv-esc, recon, config-tamper, plus **arm→sink** and **"lethal-trifecta"**
  session correlation.
- **Human-in-the-loop approvals** — Allow / Deny in the terminal or the desktop app; timeout denies.
- **Chat approvals** — when a call is an *Ask*, Belay can send the prompt to a chat channel
  and take your Allow / Deny reply back. Two-way on **Telegram, Discord, WhatsApp, Matrix,
  Mattermost, and Slack**; notify-only on **ntfy, Teams, WeCom, and webhooks**. Enrolment is a
  one-time pairing code, and it is **default-deny** — only enrolled approvers can approve.
- **Explain & Advise** — every verdict carries a plain-English "why is this risky / what to do"
  explanation. An **optional** AI explainer (OFF by default, bring-your-own-key: local Ollama or
  a cloud provider) can add a second opinion. It is advisory only — it never makes or changes a
  decision, and secrets/paths are redacted before anything is sent.
- **Static pre-install scanner** (`scan`) — patterns, AST, taint, YARA, and OSV analyzers
  with provenance-weighted scoring and **SARIF** output for CI. An optional `--llm` cascade
  can filter false positives; with no API keys it runs fully local and heuristic-only.
- **Tamper-evident audit** — a hash-chained audit log plus `evidence build` / `evidence verify`
  (SHA-256 manifest over findings + SARIF).
- **Honeypot canaries** — decoy credential files that trip a Critical verdict on read or egress.
- **Host control** — a native Rust firewall and a bundled per-ecosystem vulnerability DB,
  with **no external tools** and **no NVD key required**. The vuln DB surfaces **CISA KEV**
  (known-exploited) badges and **EPSS** exploit-probability scores, and outbound destinations
  can be annotated with reverse-DNS + ASN / owner / country (display-only — never gates).
- **Desktop app** (Tauri 2) — system-tray status, live audit tailing, and privacy-safe
  notifications (category only — never your paths or commands).

## Install

**Linux & macOS:**

```bash
curl -fsSL https://dl.belay.secblok.io/install.sh | bash
```

**Windows** (PowerShell 5.1+):

```powershell
irm https://dl.belay.secblok.io/install.ps1 | iex
```

The Windows one-liner downloads the verified desktop installer, checks its SHA-256,
and runs it with a progress bar (no clicks) — adding a **Start Menu entry and a
Desktop shortcut**, then launching Belay. To pin it to the taskbar, right-click the
running app and choose *Pin to taskbar*. Add `-WithService` to also register the
boot-start firewall service (prompts for Administrator). The installer is currently
**unsigned** while a code-signing certificate is pending, so SmartScreen may show a
*"More info → Run anyway"* prompt.

Downloads the verified static binary for your OS/arch from the SECBLOK CDN
(`dl.belay.secblok.io`, falling back to GitHub Releases) — checking its SHA-256
against the published `SHA256SUMS` before installing, refusing on a mismatch — installs
it, then launches the interactive `belay setup` wizard (detect agents → protect →
firewall → boot-start service).

Prefer to read it first? Same script, just don't pipe it blind:

```bash
curl -fsSL https://dl.belay.secblok.io/install.sh -o install.sh
less install.sh && bash install.sh
```

Uninstall anytime with `belay uninstall` (add `--purge` to also remove `~/.belay`).

## Quick start

Once installed (see [Install](#install) above), drive Belay with the `belay` binary
already on your `PATH`:

```bash
# 1. See which agents are installed
belay detect

# 2. Protect one in log-only mode first (tune, no enforcement)
belay protect <agent> --observe

# 3. Enforce
belay protect <agent>

# 4. Run the local backend (the desktop app renders the UI)
belay serve
```

Review activity with `belay status` (the last audit rows) and `belay logs` (a longer
tail).

> `belay serve` exposes a **local API + SSE backend on `127.0.0.1`** — it is not a
> web dashboard. The **desktop app** is the user interface. Enable boot-start with
> `belay install-service --enable` (systemd / launchd).

### Build from source

Contributors can build the single static binary from a checkout:

```bash
cargo build --release --bin belay
```

The primary Linux target is a fully-static **musl** build (`--target
x86_64-unknown-linux-musl`), which needs the musl toolchain — install `musl-tools`
(Debian/Ubuntu: `sudo apt install musl-tools`) so `musl-gcc` is available.

## Platform support

| Platform | Status |
|----------|--------|
| **Linux x86_64**              | **Released (v0.1.0)** — primary target with full host control (firewall, eBPF). Fully-static musl build runs on **any** libc (glibc or musl). |
| **macOS x86_64** (Intel)      | **Released (v0.1.0)** |
| **macOS aarch64** (Apple Silicon) | **Released (v0.1.0)** |
| **Linux aarch64**             | Coming soon — not in v0.1.0 yet |
| **Windows**                   | Preview — one-line PowerShell install (`irm …/install.ps1 \| iex`) delivers the desktop app with Start Menu + desktop shortcuts (named-pipe transport, SCM service, desktop app). The installer is currently **unsigned** (SmartScreen may warn) pending a code-signing certificate. |

## Documentation

Full docs live at **https://belay.secblok.io/doc** (landing page:
https://belay.secblok.io) — guides, the complete CLI reference, and configuration.

## Editions & licensing

Belay is **open-core**.

- **Community** — everything above, free and open source under **AGPL-3.0-or-later**.
- **Enterprise** — a commercial license adds centralized capabilities: fleet management,
  organizations / multi-tenancy, device management & enrollment, cross-device correlation,
  SSO (OIDC) + SCIM, a hosted/curated advisory feed (EPSS + CISA-KEV enrichment), audit
  push, and compliance reporting.

For AGPL-incompatible use or the Enterprise edition, see [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md)
or contact **hello@secblok.io**. Contributions require a CLA + DCO sign-off.

Published by **SECBLOK** (Secblok Pty Ltd) · https://www.secblok.io

---

<div align="center">
<sub>Belay is defense-in-depth for AI agents, not a guarantee. Review the docs for its
documented limits (e.g. syscall-level prevention requires elevated privileges and is out of
scope by design).</sub>
</div>
