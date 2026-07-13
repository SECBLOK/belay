#!/usr/bin/env bash
# Sign / checksum a release binary.
#
# The sha256 checksum is ALWAYS produced (works everywhere). Cryptographic
# signing (cosign or minisign) only runs when the tool AND a signing key
# (BELAY_SIGN_KEY) are both present -- i.e. on the release host.
# Otherwise we print a clear notice and exit 0 (never hard-fail).
set -euo pipefail

BIN="${1:-}"
if [[ -z "$BIN" || ! -f "$BIN" ]]; then
  echo "usage: sign.sh <path-to-binary>" >&2
  exit 1
fi

# Always: portable checksum.
sha256sum "$BIN" > "$BIN.sha256"
echo "sign: wrote checksum $BIN.sha256"

KEY="${BELAY_SIGN_KEY:-}"

if command -v cosign >/dev/null 2>&1 && [[ -n "$KEY" ]]; then
  cosign sign-blob --yes --key "$KEY" --output-signature "$BIN.sig" "$BIN"
  echo "sign: cosign signature written to $BIN.sig"
elif command -v minisign >/dev/null 2>&1 && [[ -n "$KEY" ]]; then
  minisign -S -s "$KEY" -m "$BIN" -x "$BIN.minisig"
  echo "sign: minisign signature written to $BIN.minisig"
else
  echo "signing skipped (no cosign/minisign or key); checksum written: $BIN.sha256 -- sign on the release host with cosign + BELAY_SIGN_KEY"
fi

exit 0
