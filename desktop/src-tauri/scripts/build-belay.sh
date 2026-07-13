#!/bin/sh
# Build the unified `belay` binary and make BOTH places the desktop app
# looks for it point at the fresh build, so the GUI's scan/detect/daemon can
# never silently run a stale copy.
#
# The desktop app shells out to a sibling `belay` binary (see
# `commands.rs::belay_bin`): in `cargo tauri dev` that is
# `target/<profile>/belay` next to `belay-desktop`; in a bundle it is
# the Tauri `externalBin` sidecar `binaries/belay-<target-triple>`.
# `cargo tauri (dev|build)` rebuilds only the desktop crate, NOT this binary —
# this script (wired into beforeDevCommand/beforeBuildCommand) closes that gap.
#
# Usage: build-belay.sh [debug|release]   (default: debug)
set -eu

PROFILE="${1:-debug}"

# Workspace root = three levels up from this script (scripts/ -> src-tauri/ -> desktop/ -> root).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TAURI_DIR="$ROOT/desktop/src-tauri"

cd "$ROOT"

# Host target triple + platform executable suffix. On Windows the built binary
# and the Tauri sidecar both carry a `.exe` suffix; on Unix EXE is empty.
TRIPLE="$(rustc -Vv | sed -n 's/host: //p')"
case "$TRIPLE" in
  *windows*) EXE=".exe" ;;
  *)         EXE="" ;;
esac

# Build WITH `channels` + `ai` + `netenrich` so the desktop-spawned `belay
# daemon` carries the messaging-approval commands (get_channels /
# channel_allow_* / channel_pair_start), the AI-explainer commands
# (get_ai_config / set_ai_config / set_ai_key / explain_action / ai_status),
# AND the destination-enrichment commands (enrich_dest / get_net_enrich /
# set_net_enrich). Without `channels` the Messaging tab shows "off"; without
# `ai` the AI Explanations tab shows "unavailable" and the BYOK
# provider/model/key controls never render; without `netenrich` the
# owner/ASN/country chip never renders (DestOwner always gets `null`). All
# three are additive to the default features (firewall + vulndb); the desktop
# is the full product, so they are always enabled here. (The open `cargo
# build` stays feature-off for byte-identity.)
if [ "$PROFILE" = "release" ]; then
  cargo build --release --bin belay --features channels,ai,netenrich
  SRC="$ROOT/target/release/belay$EXE"
else
  cargo build --bin belay --features channels,ai,netenrich
  SRC="$ROOT/target/debug/belay$EXE"
fi

# (1) Dev path: sibling of the desktop exe. A symlink stays fresh across rebuilds.
DEST_DIR="$TAURI_DIR/target/$PROFILE"
mkdir -p "$DEST_DIR"
ln -sfn "$SRC" "$DEST_DIR/belay$EXE"

# (2) Bundle path: Tauri externalBin expects `binaries/belay-<triple>` (with
# a `.exe` suffix on Windows) as a real file (copied into the app bundle).
mkdir -p "$TAURI_DIR/binaries"
cp -f "$SRC" "$TAURI_DIR/binaries/belay-$TRIPLE$EXE"

echo "build-belay: refreshed belay ($PROFILE) -> $DEST_DIR/belay$EXE and binaries/belay-$TRIPLE$EXE"
