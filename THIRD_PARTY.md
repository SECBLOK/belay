# Third-Party Attributions

Belay adapts ideas and data from the following MIT-licensed projects. No
source code from these projects is vendored; only detection patterns / data and
engineering approaches were adapted and reimplemented natively in Rust.

## Aegis — https://github.com/antropos17/Aegis (MIT)

Detection content adapted from Aegis's MIT-licensed rule data:

- Credential-access file-path patterns (`.gnupg/`, `.git-credentials`, `.oci/`,
  `.terraform.d/credentials`, `.gcloud/`) added to `rules/catalog.yaml`
  (`secrets.sensitive_path`).
- AI-agent config-directory signatures (`.continue/`, `.windsurf/`, GitHub
  Copilot) and local LLM-runtime discovery (Ollama/LM Studio) added to
  `rules/catalog.yaml` (`recon.agent_config_read`, `recon.agent_runtime_discovery`).

## CrowdStrike falcon-mcp — https://github.com/CrowdStrike/falcon-mcp (MIT)

Design *insight* referenced (no code copied): MCP servers can use a dynamic
"execute_tool"/"tool_name" dispatch pattern that hides the real operation inside
the call's arguments. This informed the `mcp.indirection` rule and the catch-all
argument-inspection projection in `daemon/src/mcp_proxy.rs` (`effective_calls`).

## NVIDIA SkillSpector — https://github.com/NVIDIA/SkillSpector (Apache-2.0)

Design *approach* referenced (no code copied), re-implemented in pure Rust:
file-type / context awareness for false-positive control. SkillSpector
down-weights findings by file class and code-example context so a `pip install`
in a Dockerfile or a `.env` mention in a README does not read as an attack.
Belay's `scanner/src/analyzers/fileclass.rs` applies the same idea — a
per-file `FileClass` plus a contextual-vs-behavioural rule split, applied
centrally across all analyzers (`lib.rs`/`pipeline.rs`) — which fixed the
scanner flagging every well-known MCP server / repo as "do not install".
Further ideas noted for later (per-finding confidence, manifest least-privilege
checks, MCP tool-poisoning detection, baseline suppression).

## CrowdStrike falcon-installer — https://github.com/CrowdStrike/falcon-installer (MIT)

Engineering *patterns* referenced (no code copied): package-manager-lock
wait/retry, package-manager-presence distro detection, up-front privilege
verification. Reimplemented in pure Rust in `daemon/src/distro.rs`
(`detect_os`, `detect_pkg_manager`, `pkg_manager_busy`, `cap_net_admin_status`)
and wired into the firewall apply path (`daemon/src/firewall/mod.rs`
`precheck_privilege`) — all via file reads / path existence, never `exec`.
