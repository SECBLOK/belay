#!/bin/sh
# Translated text must never reach machine-parsed output.
#
# `src/bin/belay.rs` emits hook-protocol JSON and lines that `manage/src/gates.rs`
# parses (it embeds JS reading `hookSpecificOutput.permissionDecision`). If a
# `t!()` call ever lands in one of those paths, the hook contract breaks for
# every user of a non-English locale, and it breaks silently: the daemon still
# runs, the agent still calls the hook, the decision just stops being understood.
#
# This is a coarse guard on purpose. It flags translation calls that appear near
# protocol markers rather than trying to prove reachability. A false positive
# costs a comment; a false negative costs the contract.
set -eu

cd "$(dirname "$0")/.."

# Any t!() on a line that also mentions a protocol marker.
# (^|[^A-Za-z0-9_]) so this does not match the t!( inside assert!( or format!(
inline=$(grep -rn --include='*.rs' -E '(^|[^A-Za-z0-9_])t!\(' src/ daemon/src/ manage/src/ 2>/dev/null \
  | grep -iE 'hookSpecificOutput|permissionDecision|jsonrpc|to_string_pretty|serde_json::to_string|--json' \
  || true)

# Any t!() inside a function whose name says it emits machine output.
infn=$(awk '
  /^[[:space:]]*(pub )?(async )?fn [a-z_]*(json|emit|protocol|hook_out|wire)[a-z_]*/ { infn=1; name=$0; next }
  infn && /^[[:space:]]*\}/ { infn=0 }
  infn && /(^|[^A-Za-z0-9_])t!\(/ { print FILENAME ": " FNR ": " $0 }
' $(find src daemon/src manage/src -name '*.rs' 2>/dev/null) 2>/dev/null || true)

if [ -n "$inline" ] || [ -n "$infn" ]; then
  echo "i18n: translated text in a machine-parsed path" >&2
  [ -n "$inline" ] && echo "$inline" >&2
  [ -n "$infn" ] && echo "$infn" >&2
  echo "" >&2
  echo "Protocol output stays English. See docs/i18n-multi-language-plan.md Task 0.2." >&2
  exit 1
fi

echo "i18n protocol check: clean"
