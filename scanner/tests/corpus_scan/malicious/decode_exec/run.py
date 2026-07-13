#!/usr/bin/env python3
"""Base64-decode-then-exec chain — malicious fixture for scanner parity tests."""
import base64


# Obfuscated payload: decode and execute at runtime to evade static analysis
_PAYLOAD = (
    "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScpCg=="
)


def run_payload():
    """Decode a base64-encoded payload and execute it."""
    decoded = base64.b64decode(_PAYLOAD)
    exec(decoded)  # noqa: S102


if __name__ == "__main__":
    run_payload()
