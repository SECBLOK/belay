#!/usr/bin/env python3
"""Round-2 catalog patch: fixes two bypasses an automated security review
found in the round-1 patch (scripts/apply-fp-patch-2026-07-26.py), applied
the same day. Both are real, confirmed empirically against the live engine
before writing this fix — not false alarms.

Agents cannot edit rules/catalog.yaml (tamper.self_protect denies it, by
design), so this ships as a script for the owner to run, same as round 1.

  FINDING 1  secrets.env_dump — the round-1 anchor
             '(?:^|[;&|]\\s*)env\\s*(?:$|[;&|])'
             requires "env" to be followed by NOTHING but end-of-command or
             another chain operator. That drops every real invocation with
             arguments or redirection:
                 env > /tmp/x
                 env -i FOO=bar mycommand
                 env >> /tmp/x 2>&1
             all now silently Allow instead of Ask. Confirmed empirically.
             Fix: replace the trailing group with a plain word boundary, so
             "env" is still required to be the command word (start of
             command, or right after ; & |) but nothing after it is
             restricted. This is what actually closes the original false
             positive too — "env" never appears as a command-position word
             inside `echo "=== unit env ==="`, so that case is unaffected.

  FINDING 2  rce.pipe_to_shell — the round-1 companion pattern
             '...\\b(exec|eval|compile)\\s*\\('
             only catches an inline -c/-e script that calls exec(/eval(/
             compile( directly. It misses the equally-dangerous
                 os.system(sys.stdin.read())
                 subprocess.run(sys.stdin.read(), shell=True)
             shape — confirmed empirically to Allow under round 1. Fix:
             broaden the sink-word alternation to the common
             process-execution sinks (system, popen, check_output,
             check_call), which is still a narrow, function-call-shaped match
             — it does not touch the round-1 FP-1 case (a bare json.load(
             call), which contains none of these words.

Idempotent: re-running after a successful apply is a no-op. Depends on round
1 already being applied (checks for round 1's patterns as the anchor to
replace).
"""
import shutil
import sys
import time
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "rules" / "catalog.yaml"

PATCHES = [
    (
        "Finding 1: env anchor drops trailing args/redirection",
        "        - '(?:^|[;&|]\\s*)env\\s*(?:$|[;&|])'\n",
        "        # Word-boundary anchor, not a trailing-terminator allowlist: \"env\"\n"
        "        # must still be the command word (start of command, or right\n"
        "        # after ; & |), but what follows it — args, a redirect, a pipe,\n"
        "        # or nothing — is unrestricted. Round 1's trailing '(?:$|[;&|])'\n"
        "        # silently dropped `env > file`, `env -i FOO=bar cmd`, and any\n"
        "        # other invocation with real arguments.\n"
        "        - '(?:^|[;&|]\\s*)env\\b'\n",
    ),
    (
        "Finding 2: pipe_to_shell companion misses os.system/subprocess sinks",
        "        - '(curl|wget)\\b[^|]*\\|\\s*(python\\d?|node|ruby|perl)\\b[^|]*\\b(exec|eval|compile)\\s*\\('\n",
        "        - '(curl|wget)\\b[^|]*\\|\\s*(python\\d?|node|ruby|perl)\\b[^|]*\\b(exec|eval|compile|system|popen|check_output|check_call)\\s*\\('\n",
    ),
]


def main() -> int:
    if not CATALOG.is_file():
        print(f"!! catalog not found: {CATALOG}", file=sys.stderr)
        return 2

    text = CATALOG.read_text(encoding="utf-8")
    todo = [(n, o, w) for n, o, w in PATCHES if o in text]
    already = [n for n, o, w in PATCHES if o not in text and w.strip() in text]
    missing = [n for n, o, w in PATCHES if o not in text and w.strip() not in text]

    for name in already:
        print(f"   already applied: {name}")
    for name in missing:
        print(f"!! {name}: neither the round-1 pattern nor the round-2 fix "
              f"is present — has the catalog changed underneath this script?",
              file=sys.stderr)
    if missing:
        return 4
    if not todo:
        print("nothing to do — catalog already patched.")
        return 0

    backup = CATALOG.with_suffix(f".yaml.{int(time.time())}.bak")
    shutil.copy2(CATALOG, backup)
    print(f"   backup: {backup}")

    for name, old, new in todo:
        if text.count(old) != 1:
            print(f"!! {name}: expected exactly 1 match, found {text.count(old)} — aborting",
                  file=sys.stderr)
            return 3
        text = text.replace(old, new, 1)
        print(f"   patched: {name}")

    CATALOG.write_text(text, encoding="utf-8")
    print("\ncatalog updated. The catalog is compiled into the binary, so a")
    print("rebuild + daemon restart is required for this to take effect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
