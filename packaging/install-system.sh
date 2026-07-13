#!/usr/bin/env bash
# DEPRECATED: thin wrapper around `belay install-service`.
#
# All install logic (stage binary -> /usr/local/bin, write the systemd unit,
# tear down competing units, enable+start, re-point the Claude Code hook, wait
# for the daemon socket) now lives in the cross-platform `install-service`
# subcommand. Run that directly; this wrapper only keeps the old entry point and
# the "build first" reminder. Run as your normal user (it sudo's itself).
set -euo pipefail
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$SELF_DIR/../target/release/belay"
[ -x "$BIN" ] || { echo "Build first: cargo build --release --bin belay"; exit 1; }
exec sudo "$BIN" install-service --enable "$@"
