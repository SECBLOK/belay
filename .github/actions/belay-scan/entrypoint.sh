#!/usr/bin/env bash
set -euo pipefail

SCAN_PATH="${INPUT_PATH:-.}"
FAIL_ON="${INPUT_FAIL_ON:-DO_NOT_INSTALL}"

echo "Belay: scanning ${SCAN_PATH} ..."
belay scan "${SCAN_PATH}" --format sarif > belay.sarif

# Check for fail-on pattern in SARIF
if grep -q "\"${FAIL_ON}\"" belay.sarif 2>/dev/null; then
    echo "Belay: found '${FAIL_ON}' rule hit — failing build."
    exit 1
fi

echo "Belay: scan complete. SARIF at belay.sarif"
