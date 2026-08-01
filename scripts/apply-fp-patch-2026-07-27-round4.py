#!/usr/bin/env python3
"""Round-4 catalog patch: tamper.agent_config_write denies ordinary READS.

THE BUG
-------
The rule's protected-path patterns are matched against the whole Bash command
string with no read-vs-write discrimination, so merely NAMING a protected file
is a critical Deny. Measured against the live engine on 2026-07-27, all of
these are Deny today and should not be:

    cargo build -p belayd            <-- this repo's own build command
    cat / head / less / wc / grep / stat / md5sum   rules/catalog.yaml
    git diff --stat | git status | git log --       rules/catalog.yaml
    wc -l ~/.belay/audit.ndjson ; tail -5 audit.ndjson ; less audit.ndjson

`cargo build -p belayd` is the worst of them: the pattern is `belayd$`, which
matches the cargo PACKAGE NAME at end-of-string, not a path to the binary.

THE FIX
-------
Three replacements for the three offending patterns:

  1. `belayd$` -> `/belayd$`, so it matches a path to the binary and not a
     bare cargo package argument.
  2. Redirect-into-the-file, which is the dominant write form and is invisible
     to a plain path match: `> catalog.yaml`, `>> catalog.yaml`, quoted or not,
     with or without a leading directory.
  3. An explicit list of file-mutating commands (`cp`, `mv`, `rm`, `tee`,
     `truncate`, `install`, `dd`, in-place `sed`/`perl`, `git checkout`, ...)
     anchored to command position.

WHY POSITIVELY, NOT AS A READ EXCLUSION
---------------------------------------
The obvious shape is "deny unless the command is a read", via a negative
lookahead over an allowlist of read tools. That was measured and works, but it
was rejected on a security ground: a lookahead makes the pattern a
`fancy_regex`, and daemon/src/engine/rules.rs treats a fancy_regex `Err` as
NO MATCH. fancy_regex returns Err when it exceeds its backtrack limit, so a
sufficiently long crafted command would make a *critical Deny rule* silently
fail open. Enumerating writes keeps every pattern a plain `regex` crate
pattern, which has no backtracking and cannot fail that way. The cost is that
an exotic write verb not in the list is not matched HERE - and that is
deliberately backstopped in compiled-in code that the catalog cannot weaken:
self_tamper's `tamper.direct_write` (path + any write-shaped verb -> Ask) and
`tamper.self_protect` (Write/Edit tools -> Deny).

The direction of each residual gap is the safe one: a read is never denied,
and a write that slips this rule still meets the compiled-in backstop.

KNOWN, ACCEPTED RESIDUALS (measured, not guessed)
-------------------------------------------------
  * `sed -n 1,5p rules/catalog.yaml` and `awk '{print $1}' rules/catalog.yaml`
    are reads and are now correctly ALLOWED here. In-place forms (`sed -i`,
    `perl -pi`) are matched.
  * A multi-command line such as `git status X; git diff X` is allowed, since
    each segment is a read. Correct.
  * `python3 - <<'PY' ... open('rules/catalog.yaml','w') ... PY` remains
    ALLOWED by this rule, exactly as before this patch - the path lives in a
    heredoc body, not the command. Unchanged by this patch, still covered by
    self_tamper's opaque/indirect-write handling, and recorded as an open gap
    in docs/research/2026-07-26-self-tamper-bash-gap.md.

Idempotent: re-running after a successful apply is a no-op.

RUN THIS YOURSELF. Do not let an agent run it: agents are blocked from writing
rules/catalog.yaml by design, and an agent applying its own catalog patch
defeats the self-protection this file is part of.

    python3 scripts/apply-fp-patch-2026-07-27-round4.py
    cargo test -p belayd --lib --test eval_corpus
"""
import shutil
import sys
import time
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "rules" / "catalog.yaml"

# The three patterns as they stand today, verbatim including indentation.
OLD = (
    "        - 'belayd$'\n"
    "        - 'rules/catalog\\.yaml$'\n"
    "        - 'audit\\.ndjson$'\n"
)

# Protected-file alternation, reused by each replacement pattern below.
P = "(?:rules/catalog\\.yaml|audit\\.ndjson)"

# \x27 is a literal single quote: written as an escape so the pattern can sit
# inside a single-quoted YAML scalar without needing YAML-level quote doubling.
_Q = "[\"\\x27]"

NEW = (
    # 1. a PATH to the binary, not a bare cargo package name
    "        - '/belayd$'\n"
    # 2. redirection into the file: > or >>, optional quote, optional directory
    f"        - '>{{1,2}}\\s*{_Q}?(?:[^\\s\"\\x27|;&]*/)?{P}'\n"
    # 3. file-mutating commands, anchored to command position
    "        - '(?:^|[;&|]\\s*)(?:sudo\\s+)?"
    "(?:cp|mv|rm|shred|unlink|truncate|touch|chmod|chown|chgrp|ln|install|dd|tee)"
    f"\\b[^|;&]*{P}'\n"
    # 3b. in-place editors: the flag cluster carries an `i`
    "        - '(?:^|[;&|]\\s*)(?:sudo\\s+)?(?:sed|perl|ruby)\\b[^|;&]*"
    f"\\s-[a-zA-Z]*i[a-zA-Z]*\\b[^|;&]*{P}'\n"
    # 3c. yq -i, and git checkout restoring over the file
    f"        - '(?:^|[;&|]\\s*)(?:sudo\\s+)?yq\\b[^|;&]*\\s-i\\b[^|;&]*{P}'\n"
    f"        - '(?:^|[;&|]\\s*)git\\s+checkout\\b[^|;&]*{P}'\n"
)


def main() -> int:
    if not CATALOG.is_file():
        print(f"!! catalog not found: {CATALOG}", file=sys.stderr)
        return 2

    text = CATALOG.read_text()

    if NEW in text:
        print("already applied - nothing to do")
        return 0

    n = text.count(OLD)
    if n != 1:
        print(
            f"!! expected exactly 1 occurrence of the anchor block, found {n}.\n"
            "!! The catalog has drifted from what this patch was written against.\n"
            "!! Re-verify before forcing anything.",
            file=sys.stderr,
        )
        return 3

    backup = CATALOG.with_suffix(f".yaml.{int(time.time())}.bak")
    shutil.copy2(CATALOG, backup)
    CATALOG.write_text(text.replace(OLD, NEW))

    print(f"patched  {CATALOG}")
    print(f"backup   {backup}")
    print()
    print("Now verify, and delete the backup once you are satisfied:")
    print("  cargo test -p belayd --lib --test eval_corpus")
    print(f"  rm {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
