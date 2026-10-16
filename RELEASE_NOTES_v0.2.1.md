# Belay v0.2.1

Patch release on top of v0.2.0.

## Fixes

- **`destructive.rm_rf` now denies root and home globs.** `rm -rf /*`,
  `rm -rf ~/*` and `rm -rf $HOME/*` were previously allowed, because the rule
  only matched bare `/`, `~`, `$HOME`, `.` and `*` targets. Deletes of a
  specific folder (`rm -rf ./build`, `rm -rf ~/project/node_modules`) are
  still allowed.

## Tests

- New `daemon/tests/devfest_demo.rs`: a narrated, table-driven suite over the
  real rule catalog and `decide()` gate (blocking, evasions, ask, self-protection,
  false positives, explainability, determinism, latency). Run with:

  ```
  cargo test -p belayd --test devfest_demo -- --nocapture --test-threads=1
  ```
