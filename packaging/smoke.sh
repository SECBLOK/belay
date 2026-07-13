#!/usr/bin/env bash
# Single-binary smoke test: prove gate / scan / serve all run from the one
# belay binary, against the REAL CLI/server surface.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MUSL_BIN="target/x86_64-unknown-linux-musl/release/belay"
if [[ -x "$MUSL_BIN" ]]; then
  BIN="$MUSL_BIN"
else
  BIN="target/release/belay"
fi
if [[ ! -x "$BIN" ]]; then
  echo "smoke: no belay binary found (looked for $MUSL_BIN and target/release/belay)" >&2
  exit 1
fi

SERVE_PID=""
cleanup() {
  if [[ -n "$SERVE_PID" ]]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# 1) gate: hook request on stdin -> permissionDecision verdict (fail-closed
#    still emits permissionDecision when no daemon is running).
echo '{"session_id":"s","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | "$BIN" gate | grep -q '"permissionDecision"'
echo "smoke: gate OK"

# 2) scan: deterministic JSON scan of a benign fixture -> a recommendation.
"$BIN" scan scanner/tests/corpus_scan/benign/util_lib --format json \
  | grep -q 'recommendation'
echo "smoke: scan OK"

# 3) serve: bring up the HTTP server, hit /api/health, expect {"...ok..."}.
"$BIN" serve &
SERVE_PID=$!
sleep 1
curl -fsS http://127.0.0.1:8787/api/health | grep -q '"ok"'
echo "smoke: serve OK"

# 4) status / logs: run against an isolated empty home (no audit store) - must
#    exit 0 and print nothing (empty store renders empty output).
SMOKE_HOME="$(mktemp -d)"
trap 'cleanup; rm -rf "$SMOKE_HOME"' EXIT
"$BIN" status --home "$SMOKE_HOME" >/dev/null
"$BIN" logs --home "$SMOKE_HOME" >/dev/null
echo "smoke: status/logs OK"

# 5) evidence build -> verify round-trip on a fresh pack (tamper-evident).
"$BIN" evidence build --out "$SMOKE_HOME/pack" --home "$SMOKE_HOME" >/dev/null
"$BIN" evidence verify --dir "$SMOKE_HOME/pack" | grep -qi 'OK'
echo "smoke: evidence build+verify OK"

# 6) mcp-proxy parse: a bad JSON-RPC line must be forwarded as-is by the proxy's
#    stdio bridge to a trivial `cat` child (no gate intercept on non tools/call).
printf 'not-json\n' | "$BIN" mcp-proxy -- cat | grep -q 'not-json'
echo "smoke: mcp-proxy parse OK"

echo "single-binary smoke OK"
