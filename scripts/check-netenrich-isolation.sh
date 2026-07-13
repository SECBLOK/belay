#!/usr/bin/env sh
# Byte-identity guard for the off-by-default destination enrichment (feature
# `netenrich`).
#
# The whole point of gating destination owner/ASN/country enrichment behind a
# Cargo feature is that a default build (no --features netenrich) never links
# trippy-dns (and, transitively, never links the resolver/network stack it
# pulls in) — so a default belayd binary is provably unaffected by
# enrichment existing in the source tree at all. This script asserts that
# invariant both ways: trippy-dns must be ABSENT from the default dependency
# tree, and PRESENT once --features netenrich is passed (proving the feature
# gate actually wires to something, rather than silently doing nothing).
set -eu
cd "$(dirname "$0")/.."

echo "default build must NOT contain trippy-dns:"
if cargo tree -p belayd -e no-dev 2>/dev/null | grep -qi 'trippy-dns'; then
  echo "FAIL: trippy-dns present in the default build" >&2
  exit 1
fi
echo "  ok — absent."

echo "netenrich build MUST contain trippy-dns:"
if ! cargo tree -p belayd --features netenrich -e no-dev 2>/dev/null | grep -qi 'trippy-dns'; then
  echo "FAIL: trippy-dns missing from the --features netenrich build" >&2
  exit 1
fi
echo "  ok — present."

echo "PASS: netenrich feature isolation holds."
