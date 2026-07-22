# skillscan test corpus

Fixtures under this directory are synthetic (hand-written), license-clean,
fully offline stand-ins for real Agent-Skill packages, used by:

- `../corpus_scan.rs` — the original smoke-test corpus (`benign/`, `malicious/`).
- `../fp_regression.rs` — targeted false-positive / coverage-rule regression
  fixtures (source-only, not on disk).
- `../corpus_regression.rs` — the data-driven, corpus-representative CI
  regression suite (`benign_*`, `malicious_*`, `edge_*` directories below).

## Provenance

The `benign_*` / `malicious_*` / `edge_*` fixtures are modeled on a real
20-repo, 360-skill benchmark of public Claude Code / Agent skills — see
`docs/research/2026-07-18-skillscan-fp-corpus-analysis.md` for the method and
headline false-positive numbers that motivated the FP-reduction and coverage
passes these fixtures guard.

That real corpus is **re-runnable manually** (`gh search` for public skill
repos, then `belay scan <skill-dir>` per skill, exactly what the install-gate
runs) but is **not checked in here**: it is third-party content under mixed
licenses, and a live scan is network-dependent and non-deterministic (repo
contents drift over time). The fixtures in this directory distill the FP and
coverage SHAPES that analysis identified into small, synthetic, deterministic
skills that exercise the same detector code paths, so every PR gets the
regression guard without needing network access or re-running the real
corpus.
