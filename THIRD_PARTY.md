# Third-Party Attributions

Belay adapts ideas and data from the following MIT-licensed projects. For the
projects in the first group, no source code is vendored — only detection
patterns / data and engineering approaches were adapted and reimplemented
natively in Rust. The **"Bundled third-party YARA rules"** section at the end is
different: those permissively-licensed rule files ARE bundled verbatim (with
their upstream copyright/license notices retained) and shipped as data the
`yara-x` engine loads.

## Aegis — https://github.com/antropos17/Aegis (MIT)

Detection content adapted from Aegis's MIT-licensed rule data:

- Credential-access file-path patterns (`.gnupg/`, `.git-credentials`, `.oci/`,
  `.terraform.d/credentials`, `.gcloud/`) added to `rules/catalog.yaml`
  (`secrets.sensitive_path`).
- AI-agent config-directory signatures (`.continue/`, `.windsurf/`, GitHub
  Copilot) and local LLM-runtime discovery (Ollama/LM Studio) added to
  `rules/catalog.yaml` (`recon.agent_config_read`, `recon.agent_runtime_discovery`).

What was adapted is a set of well-known, uncopyrightable facts — the on-disk
config-directory/file-path names that specific third-party tools (gnupg, git,
OCI CLI, Terraform, gcloud, Continue, Windsurf, GitHub Copilot, Ollama, LM
Studio) themselves use — not any MIT-licensed source code, comment, or
original expression from the Aegis project. No file, function, or text from
Aegis's `Software` was copied into this repository, so MIT's "The above
copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software" condition is not triggered here.
Aegis's license (verbatim, for reference):

```
MIT License

Copyright (c) 2026 AEGIS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

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

**Native detection port (`skillscan` crate).** Beyond the `fileclass` design
credit above, Belay's `skillscan` leaf crate is a **clean-room Rust
reimplementation of SkillSpector's skill-aware detection *logic*** — manifest
least-privilege (declared-vs-observed capability diff), tool-poisoning
(homoglyph/RTL/hidden-instruction) over `SKILL.md` metadata, rug-pull manifest
diff, prompt-injection/anti-refusal/SSRF/agent-snooping and the excessive-agency
/ output-handling / memory-poisoning / tool-misuse / rogue-agent / supply-chain
regex families, plus SkillSpector's risk-scoring bands (SAFE / CAUTION /
DO_NOT_INSTALL). **No SkillSpector Python source, rule text, or bundled YARA
files were copied** — the patterns/algorithms are functional facts reimplemented
from their documented behaviour. Apache-2.0 permits this; the license text is
included at `LICENSES/Apache-2.0.txt`.

## CrowdStrike falcon-installer — https://github.com/CrowdStrike/falcon-installer (MIT)

Engineering *patterns* referenced (no code copied): package-manager-lock
wait/retry, package-manager-presence distro detection, up-front privilege
verification. Reimplemented in pure Rust in `daemon/src/distro.rs`
(`detect_os`, `detect_pkg_manager`, `pkg_manager_busy`, `cap_net_admin_status`)
and wired into the firewall apply path (`daemon/src/firewall/mod.rs`
`precheck_privilege`) — all via file reads / path existence, never `exec`.

## Bundled third-party YARA rules

Unlike the sections above, these permissively-licensed YARA rule sets are
**bundled verbatim** (the FULL upstream sets, compile-filtered against yara-x —
rules that do not compile on yara-x's module set, or that collide, are dropped)
and compiled at build time into the malware pack (each in its own `yara-x`
namespace; `scanner/build.rs`). Rule bodies are unmodified upstream content; each
file retains its upstream copyright/license header and per-rule `meta`
(author/reference/hash).

### ReversingLabs YARA Rules — https://github.com/reversinglabs/reversinglabs-yara-rules (MIT)

- Copyright (c) 2020 ReversingLabs. Full license text: `LICENSES/MIT.txt`.
- Bundled file: `rules/malware/thirdparty/reversinglabs.yar` — the full rule set
  (~1240 rules across backdoor/ransomware/trojan/infostealer/etc.), compile-filtered,
  unmodified. Pinned to commit `e0a0be54aa1e` (branch `develop`).

### GCTI — Google Cloud Threat Intelligence — https://github.com/chronicle/GCTI (Apache-2.0)

- Copyright Google LLC. Full license text: `LICENSES/Apache-2.0.txt`.
- Bundled file: `rules/malware/thirdparty/gcti.yar` — the full detection set
  (~91 rules, Cobalt Strike + Sliver), compile-filtered, unmodified. Pinned to commit
  `1c5fd42b1895` (branch `main`). (Upstream repo archived
  2025-05; frozen.)
