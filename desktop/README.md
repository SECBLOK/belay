# Belay Desktop (Tauri 2)

Native desktop GUI for Belay, built on Tauri 2. The frontend is the shared
React/Vite app in `../web`; the Rust shell lives in `src-tauri/`.

## Prerequisites

- Rust toolchain (stable) and `cargo`
- `cargo-tauri` CLI (`cargo install tauri-cli --version '^2'`, or use the global install)
- System libraries: WebKitGTK 4.1, GTK3, libsoup3, librsvg
- Node.js + npm (for the frontend build)

## Setup

```sh
npm install --prefix desktop   # installs the @tauri-apps CLI/API for the desktop package
```

## Develop

Run the full app (spawns the Vite dev server from `../web`, then the Tauri window).
Requires a display (X11/Wayland):

```sh
npm --prefix desktop run tauri dev
```

## Compile check (no display needed)

Build the Rust shell standalone. `src-tauri` is excluded from the root cargo
workspace, so build it from inside its own directory:

```sh
cd desktop/src-tauri && cargo build
```

The first build pulls the full tauri/wry/webkit stack and can take several
minutes.

> [!WARNING]
> **A bare `cargo build` produces a COMPILE-CHECK binary only — do NOT run it as
> the app.** It skips `beforeBuildCommand`, so the web frontend (`web/dist`) is
> never re-embedded and the window opens **blank white**. This is the #1 cause
> of a "blank desktop" — the binary is fine, it just has no UI inside it. Tell:
> a runnable binary is ~62 MB (frontend embedded in `.rodata`); a bare-`cargo`
> one is ~1.5 MB smaller. Diagnose with
> `readelf -S target/release/belay-desktop | grep -A1 .rodata` — a small
> `.rodata` (~7.8 MB vs ~8.8+ MB) means no embedded frontend.
>
> **To produce a RUNNABLE binary, always go through `tauri build`** (it runs the
> frontend build + sidecar staging first):
>
> ```sh
> cd desktop/src-tauri && cargo tauri build --no-bundle
> ```
>
> `cargo build` and `tauri build` even use different cargo hash slots under
> `target/release/deps/`, so they never clobber each other.

## Tests

The pure-Rust logic (e.g. NDJSON audit parsing) runs without the full Tauri stack:

```sh
cd desktop/src-tauri && cargo test --no-default-features
```

## Icons

App icons live in `src-tauri/icons/`. To regenerate from a 1024x1024 source PNG:

```sh
cd desktop/src-tauri && cargo tauri icon <source.png>
```

## Capabilities

Tauri 2's security model is capability-based. `src-tauri/capabilities/default.json`
grants the `main` window its permissions (`core:default`, `core:event:default`,
`notification:default`, `autostart:default`, `updater:default`).

## Autostart + signed auto-updater

The app registers two native plugins in the Tauri builder
(`src-tauri/src/lib.rs`):

- **`tauri-plugin-autostart`** — launches Belay at login (LaunchAgent on
  macOS; the platform equivalent elsewhere).
- **`tauri-plugin-updater`** — checks `plugins.updater.endpoints` in
  `tauri.conf.json` and applies signed updates. Update artifacts are verified
  against the **minisign public key** embedded in `plugins.updater.pubkey`.

### Updater signing keys

The signing keypair was generated with:

```sh
cargo tauri signer generate -p "" --ci -w desktop/.tauri/updater.key
```

- **Public key** — committed in `src-tauri/tauri.conf.json` (`plugins.updater.pubkey`),
  and saved alongside the private key at `desktop/.tauri/updater.key.pub`.
- **Private key** — `desktop/.tauri/updater.key`. **This is secret and is
  gitignored** (`desktop/.tauri/` is excluded in the repo `.gitignore`). It is
  NEVER committed. Keep a secure backup: losing it means you can no longer sign
  updates. To rotate, regenerate the keypair and replace the `pubkey` in
  `tauri.conf.json`.

## Build signed installers

Signed AppImage/deb bundles (each with a `.sig` for the updater) require the
updater private key in the `TAURI_SIGNING_PRIVATE_KEY` env var:

```sh
TAURI_SIGNING_PRIVATE_KEY=$(cat desktop/.tauri/updater.key) \
  npm --prefix desktop run tauri build
# -> desktop/src-tauri/target/release/bundle/{appimage,deb}/...  (+ .sig per artifact)
```

`tauri build` runs `beforeBuildCommand` (`npm --prefix ../../web run build`), so
the web build must pass too. AppImage/deb packaging needs the system tooling
(`linuxdeploy`/`appimagetool` for AppImage, `dpkg`/`dpkg-deb` for deb). If that
tooling is unavailable, build just the release binary without packaging:

```sh
cd desktop/src-tauri && cargo tauri build --no-bundle
```

`bundle.targets` is set to `["appimage", "deb"]` for this Linux host (dmg/msi are
cross-platform targets, not built here).

## UX guardrail review checklist (must pass before release)

- [ ] No fear-mongering copy anywhere (notifications, cards, empty states).
- [ ] No fake urgency — the only countdown is the real approval timeout; never a FOMO timer.
- [ ] No findings-as-ads / no upsell nags in the protection UI.
- [ ] One meaning per color (green=protected, cyan=monitoring, amber=action, red=blocked); no reuse.
- [ ] Notifications only when not frontmost, copy is category-only (never the secret path).
- [ ] prefers-reduced-motion honored (ring, feed, popover, countdown).
- [ ] Calm by default: tray is monochrome until a real alert; high-risk cards have no default button.
