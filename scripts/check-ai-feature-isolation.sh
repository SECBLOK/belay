#!/usr/bin/env sh
# Byte-identity guard for the off-by-default AI explainer (feature `ai`).
#
# The whole point of gating the AI explainer behind a Cargo feature is that a
# default build (no --features ai) never links rig-core (and, transitively,
# never links an HTTP/TLS stack it pulls in for cloud providers) — so a
# default belayd binary is provably unaffected by the AI explainer
# existing in the source tree at all. This script asserts that invariant
# both ways: rig-core must be ABSENT from the default dependency tree, and
# PRESENT once --features ai is passed (proving the feature gate actually
# wires to something, rather than silently doing nothing).
set -eu
cd "$(dirname "$0")/.."

echo "default build must NOT contain rig-core:"
if cargo tree -p belayd -e no-dev 2>/dev/null | grep -qi 'rig-core'; then
  echo "FAIL: rig-core present in the default build" >&2
  exit 1
fi
echo "  ok — absent."

echo "ai build MUST contain rig-core:"
if ! cargo tree -p belayd --features ai -e no-dev 2>/dev/null | grep -qi 'rig-core'; then
  echo "FAIL: rig-core missing from the --features ai build" >&2
  exit 1
fi
echo "  ok — present."

echo "PASS: ai feature isolation holds."
