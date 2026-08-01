#!/usr/bin/env python3
"""Human-applied catalog patch: two false positives found live on 2026-07-26.

Agents cannot edit rules/catalog.yaml (tamper.self_protect denies it, by
design), so this ships as a script for the owner to run.

Both FPs blocked an agent doing authorised read-only work. Neither command
downloads or executes remote code.

  FP-1  rce.pipe_to_shell   `curl … | python3 -c '<inline script>'`
        With -c the program comes from the ARGUMENT, so stdin is data, not
        code. The dangerous shape is a BARE interpreter after the pipe, where
        stdin genuinely is the program. Narrowed to that, plus a companion
        pattern so an inline script that execs what it reads still denies.

  FP-2  secrets.env_dump    `echo "=== unit env ==="; systemctl show …`
        Pattern '(^|\\s)env(\\s|$)' matched the word "env" inside an echo
        string. Data-region masking did not save it because another arg in the
        same command contained a bare '(' inside double quotes, which
        disqualifies masking. Anchored to command position instead, the fix
        already proposed in eval/RULE-FIXES.md Part 5.

Idempotent: re-running after a successful apply is a no-op.
"""
import shutil
import sys
import time
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "rules" / "catalog.yaml"

PATCHES = [
    (
        "FP-1 rce.pipe_to_shell",
        "        - '(curl|wget)\\b[^|]*\\|\\s*(python\\d?|node|ruby|perl)\\b'\n",
        "        # Bare interpreter after the pipe: stdin IS the program.\n"
        "        # `-c`/`-e` supply the program as an argument, so stdin is data\n"
        "        # (`curl … | python3 -c 'json.load(sys.stdin)'` executes nothing\n"
        "        # that was downloaded) — that form is covered by the next pattern\n"
        "        # only when the inline script itself executes what it reads.\n"
        "        - '(curl|wget)\\b[^|]*\\|\\s*(python\\d?|node|ruby|perl)\\b(?!\\s+-)'\n"
        "        - '(curl|wget)\\b[^|]*\\|\\s*(python\\d?|node|ruby|perl)\\b[^|]*\\b(exec|eval|compile)\\s*\\('\n",
    ),
    (
        "FP-2 secrets.env_dump",
        "        - '(^|\\s)env(\\s|$)'\n",
        "        # Command position only. The old '(^|\\s)env(\\s|$)' matched the\n"
        "        # bare word in any prose — an echo string, a heredoc, a comment —\n"
        "        # and data-region masking is disqualified for an arg whose\n"
        "        # sibling contains '(' outside single quotes.\n"
        "        - '(?:^|[;&|]\\s*)env\\s*(?:$|[;&|])'\n",
    ),
]


def main() -> int:
    if not CATALOG.is_file():
        print(f"!! catalog not found: {CATALOG}", file=sys.stderr)
        return 2

    text = CATALOG.read_text(encoding="utf-8")
    todo = [(n, o, w) for n, o, w in PATCHES if o in text]
    already = [n for n, o, w in PATCHES if o not in text and w.strip() in text]

    for name in already:
        print(f"   already applied: {name}")
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
