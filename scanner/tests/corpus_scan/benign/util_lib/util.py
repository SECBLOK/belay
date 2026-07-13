"""Utility library — benign fixture for scanner parity tests."""
import json


def greet(name: str) -> str:
    """Return a greeting string."""
    return f"Hello, {name}!"


def to_json(data: dict) -> str:
    """Serialize a dictionary to a JSON string."""
    return json.dumps(data, indent=2)


def from_json(text: str) -> dict:
    """Deserialize a JSON string to a dictionary."""
    return json.loads(text)


if __name__ == "__main__":
    print(greet("world"))
    print(to_json({"key": "value", "number": 42}))
