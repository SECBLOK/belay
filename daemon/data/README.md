# Bundled advisory database — seed vs curated

## Seed snapshot vs curated blobs

Two tiers of advisory data live in this directory:

| File | Kind | Ships in | Purpose |
|------|------|----------|---------|
| `advisories.seed.json` | **Open seed** (committed) | both repos | Thin hand-curated snapshot (~15 entries) covering well-known CVEs across all supported ecosystems. Always present. Provides "bundled DB, works offline, no key" for public / open-core builds. |
| `advisories.json` | **Curated paid** (generated) | dev repo only | Full Debian:12 advisory dataset regenerated from the Debian Security Tracker before each release. Absent in the public mirror (task 2.3 export withholds it). |
| `advisories.Ubuntu-24.04.json` | **Curated paid** (generated) | dev repo only | Full Ubuntu 24.04 advisory dataset from the OSV bulk feed. Withheld from the public mirror. |
| `advisories.Debian-sid.json` | **Curated paid** (generated) | dev repo only | Debian unstable/sid best-effort dataset. Withheld from the public mirror. |

### Build-time selection (`build.rs`)

`build.rs::emit_advisory_blob()` calls `resolve_advisory_source(ecosystem, data_dir)`:

1. If the curated file for the selected `BELAY_ECOSYSTEM` exists → use it (production / dev build).
2. If it is absent → fall back to `advisories.seed.json` and emit `cargo:warning` noting the seed is bundled (open / CI build).

Either way the output is an identical zlib-compressed blob (`OUT_DIR/advisories.blob`) `include_bytes!`-d by the runtime.

### Self-serve update for open builds

End users on an open build can refresh advisory data without the curated blob:

```sh
belay advisory refresh
```

This writes `~/.belay/advisories.json`, which `load_advisories()` prefers over the bundled blob on the next scan. The seed remains the bundled fallback if that file is absent or empty.

The per-ecosystem advisory bundle is selected and **zlib-compressed at build
time** by `daemon/build.rs` into `OUT_DIR`, then `include_bytes!`d and inflated
once at load (`daemon/src/vuln/mod.rs::bundled_advisories`). It is the advisory
DB on a fresh install, so **end users never need an NVD API key** — the key is
only a build-time concern. Compression keeps the embedded blob small (the 15 MB
Debian JSON → ~600 KB; the 1.8 MB Ubuntu JSON → ~60 KB).

## Per-ecosystem selection

One bundle is embedded per build, chosen by the `BELAY_ECOSYSTEM` env var:

| `BELAY_ECOSYSTEM` | Source file                         |
| ---------------------- | ----------------------------------- |
| _(unset)_ / `Debian:12`| `advisories.json` (legacy default)  |
| `Ubuntu:24.04`         | `advisories.Ubuntu-24.04.json`      |
| `<Eco>:<ver>`          | `advisories.<Eco>-<ver>.json`       |

```sh
# Debian build (default):
cargo build -p belayd
# Ubuntu build:
BELAY_ECOSYSTEM=Ubuntu:24.04 cargo build -p belayd
```

At runtime the daemon keys advisories by ecosystem (`Debian:12`, `Ubuntu:24.04`)
derived from `/etc/os-release`; an unsupported host (rpm/rolling distro, or a
bundle whose ecosystem differs from the host) gates the posture off rather than
showing a misleading score.

## Format

A JSON array of advisory records (the `Advisory` struct):

```json
[
  {
    "id": "CVE-2024-XXXX",
    "package": "openssl",
    "fixed_version": "3.0.1",
    "severity": "critical",
    "cve": ["CVE-2024-XXXX"],
    "release": "bookworm",
    "ecosystem": "Debian:12",
    "source": "debian-tracker"
  }
]
```

`package` is the dpkg package name; `fixed_version` is the Debian/Ubuntu version
string the fix landed in; `severity` is one of `critical`/`high`/`medium`/`low`.
`release` is the distro codename whose `fixed_version` this record describes —
empty means "any host". `ecosystem` is the OSV key (`Debian:12`, `Ubuntu:24.04`)
the runtime matches against the host; `source` is the provenance
(`debian-tracker` | `osv`). Ecosystem-tagged records are matched by ecosystem;
legacy records with an empty `ecosystem` fall back to the codename rule (see
"Runtime precedence").

## How it is updated (vendor pipeline)

This file is **regenerated before each release** by the `advisory-gen` tool and
the result is committed — that commit is what "bundles the DB with the release":

```sh
# Debian (Security Tracker, per-release):
cargo run -p advisory-gen -- --release bookworm --release trixie --out daemon/data/advisories.json

# Ubuntu (OSV bulk feed, per-ecosystem):
cargo run -p advisory-gen -- --source osv --ecosystem Ubuntu:24.04 --out daemon/data/advisories.Ubuntu-24.04.json

# Kali / Debian rolling (best-effort: Debian unstable, tagged Debian:sid):
cargo run -p advisory-gen -- --release sid --out daemon/data/advisories.Debian-sid.json
```

Kali (and bare Debian testing/sid) hosts map to the `Debian:sid` ecosystem and
are matched against this bundle; the runtime attaches an "approximate" caveat
because sid is not an exact per-release map. Build such a binary with
`BELAY_ECOSYSTEM=Debian:sid`.

`advisory-gen` supports two key-free sources:

* `--source debian-tracker` (default) pulls the **Debian Security Tracker** JSON
  (`https://security-tracker.debian.org/tracker/data/json`), which maps each
  package's CVEs to a per-release fix status + fixed version for dpkg systems.
  `--release` is repeatable (and comma-separated): pass every Debian release the
  product ships on.
* `--source osv --ecosystem <Eco:ver>` streams the **OSV** bulk feed
  (`https://osv-vulnerabilities.storage.googleapis.com/<Eco>/all.zip`); for
  Ubuntu this is Canonical's authoritative Security Notices OSV data. The
  `:LTS` suffix is normalised to the base ecosystem and Ubuntu Pro/FIPS ESM
  variants are excluded (they would over-report on an unsubscribed host).

Neither source needs an NVD API key. Each per-ecosystem file ships empty (`[]`)
until its first generation is committed.

## Runtime precedence

`load_advisories()` prefers a locally-synced cache at
`~/.belay/advisories.json` when present and non-empty (advanced /
self-hosted operators may run their own `BELAY_NVD_API_KEY` sync), and
otherwise falls back to this bundled DB. Either way, records are then filtered to
the host's release codename (from `/etc/os-release` `VERSION_CODENAME`): a record
applies only when its `release` is empty or equals the running release, so a
higher release's `fixed_version` never flags a package already patched here.
