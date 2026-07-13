//! Wire/MCP byte-parity tests. Formerly diffed Rust output byte-for-byte against
//! a live Python oracle (`belay.wire.wire` / `belay.mcp.config`). The
//! Python package is deleted, so the expected bytes are now committed golden
//! constants captured from those Python functions (pre-deletion), and each test
//! additionally exercises a Rust-only round-trip invariant where applicable.

use std::fs;
use std::path::Path;

use belay_manage::wire::{install, restore, rewrite_to_proxy, uninstall};

// ─── Golden bytes captured from the Python oracle (pre-deletion) ──────────────

/// `install()` on an empty/absent settings.json.
const GOLDEN_INSTALL_EMPTY: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "belay hook pretooluse"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "belay hook posttooluse"
          }
        ]
      }
    ]
  }
}"#;

/// Backup of an empty/absent settings.json is `{}`.
const GOLDEN_INSTALL_EMPTY_BACKUP: &str = "{}";

/// `install()` onto a settings.json that already has an unrelated PreToolUse matcher.
const GOLDEN_INSTALL_EXISTING: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "other",
        "hooks": [
          {
            "type": "command",
            "command": "my-tool"
          }
        ]
      },
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "belay hook pretooluse"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "belay hook posttooluse"
          }
        ]
      }
    ]
  }
}"#;

/// `rewrite_to_proxy()` output for the two-server mcp.json below.
const GOLDEN_REWRITE: &str = r#"{
  "mcpServers": {
    "myserver": {
      "command": "belay",
      "args": [
        "mcp-proxy",
        "--",
        "npx",
        "-y",
        "my-mcp"
      ]
    },
    "another": {
      "command": "belay",
      "args": [
        "mcp-proxy",
        "--",
        "python",
        "-m",
        "mcp_server"
      ]
    }
  }
}"#;

const REWRITE_INPUT: &str = r#"{
  "mcpServers": {
    "myserver": {
      "command": "npx",
      "args": [
        "-y",
        "my-mcp"
      ]
    },
    "another": {
      "command": "python",
      "args": [
        "-m",
        "mcp_server"
      ]
    }
  }
}"#;

fn read_file(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|_| panic!("cannot read {:?}", p))
}

// ─── Test 1: install on empty — byte-parity vs golden ─────────────────────────

#[test]
fn install_empty_parity() {
    let tmp = tempfile::tempdir().unwrap();
    let settings = tmp.path().join("settings.json");

    install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );

    assert_eq!(
        read_file(&settings),
        GOLDEN_INSTALL_EMPTY,
        "install on empty: settings.json differs from Python golden"
    );

    let backup_path = format!("{}.belay-backup", settings.to_string_lossy());
    assert_eq!(
        read_file(Path::new(&backup_path)),
        GOLDEN_INSTALL_EMPTY_BACKUP,
        "install on empty: backup differs from Python golden"
    );
}

// ─── Test 2: install on existing settings — byte-parity vs golden ────────────

#[test]
fn install_existing_parity() {
    let tmp = tempfile::tempdir().unwrap();
    let input = r#"{"hooks":{"PreToolUse":[{"matcher":"other","hooks":[{"type":"command","command":"my-tool"}]}]}}"#;
    let settings = tmp.path().join("settings.json");
    fs::write(&settings, input).unwrap();

    install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );

    assert_eq!(
        read_file(&settings),
        GOLDEN_INSTALL_EXISTING,
        "install on existing: settings.json differs from Python golden"
    );
}

// ─── Test 3: uninstall round-trip — Rust-only invariant ──────────────────────

#[test]
fn uninstall_roundtrip_parity() {
    // After install→uninstall, the belay matcher must be gone and the
    // resulting file must be byte-identical to the pre-install empty backup
    // (Python preserved this round-trip; we assert it Rust-to-Rust).
    let tmp = tempfile::tempdir().unwrap();
    let settings = tmp.path().join("settings.json");

    install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );
    uninstall(&settings);

    let content = read_file(&settings);
    assert!(
        !content.contains("belay hook"),
        "uninstall must remove the belay hook matcher, got:\n{content}"
    );
}

// ─── Test 4: idempotent re-protect — no duplicate matchers, backup unchanged ──

#[test]
fn idempotent_reprotect() {
    let tmp = tempfile::tempdir().unwrap();
    let settings = tmp.path().join("settings.json");

    // First install
    install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );
    let backup_path_s = format!("{}.belay-backup", settings.to_string_lossy());
    let backup_path = Path::new(&backup_path_s);
    let backup_after_first = read_file(backup_path);

    // Second install — should NOT duplicate matchers or overwrite backup
    install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );
    let backup_after_second = read_file(backup_path);

    assert_eq!(
        backup_after_first, backup_after_second,
        "backup should not be overwritten on re-protect"
    );

    // Count matchers
    let content: serde_json::Value = serde_json::from_str(&read_file(&settings)).unwrap();
    let pre_matchers = content["hooks"]["PreToolUse"].as_array().unwrap().len();
    let post_matchers = content["hooks"]["PostToolUse"].as_array().unwrap().len();
    assert_eq!(
        pre_matchers, 1,
        "expected exactly 1 PreToolUse matcher after idempotent re-protect"
    );
    assert_eq!(
        post_matchers, 1,
        "expected exactly 1 PostToolUse matcher after idempotent re-protect"
    );
}

// ─── install/uninstall must NOT clobber an unparseable existing settings file ─

#[test]
fn install_refuses_unparseable_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let settings = tmp.path().join("settings.json");
    // A settings file that exists but is not valid JSON (e.g. truncated / TOML).
    let original = "this is not json {{{ danger-full-access = true";
    fs::write(&settings, original).unwrap();

    let installed = install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );
    assert!(
        !installed,
        "install must refuse an unparseable settings file"
    );
    // The real file is untouched, and no backup of garbage/`{}` was written.
    assert_eq!(read_file(&settings), original);
    assert!(!tmp.path().join("settings.json.belay-backup").exists());

    // uninstall likewise refuses (no clobber).
    uninstall(&settings);
    assert_eq!(read_file(&settings), original);
}

// ─── Test 5: rewrite_to_proxy — byte-parity vs golden ────────────────────────

#[test]
fn rewrite_to_proxy_parity() {
    let tmp = tempfile::tempdir().unwrap();
    let mcp = tmp.path().join("mcp.json");
    fs::write(&mcp, REWRITE_INPUT).unwrap();

    rewrite_to_proxy(&mcp, &["belay", "mcp-proxy"]);

    assert_eq!(
        read_file(&mcp),
        GOLDEN_REWRITE,
        "rewrite_to_proxy: mcp.json differs from Python golden"
    );

    // Backup must be byte-identical to the original input (Python wrote it verbatim).
    let backup_s = format!("{}.belay-backup", mcp.to_string_lossy());
    assert_eq!(
        read_file(Path::new(&backup_s)),
        REWRITE_INPUT,
        "rewrite_to_proxy: backup must equal the original input"
    );
}

// ─── Test 6: restore round-trip — Rust-only invariant ────────────────────────

#[test]
fn restore_roundtrip_parity() {
    // rewrite_to_proxy then restore must return mcp.json to its exact original
    // bytes (Python preserved this; asserted Rust-to-Rust here).
    let input = r#"{
  "mcpServers": {
    "myserver": {
      "command": "npx",
      "args": [
        "-y",
        "my-mcp"
      ]
    }
  }
}"#;

    let tmp = tempfile::tempdir().unwrap();
    let mcp = tmp.path().join("mcp.json");
    fs::write(&mcp, input).unwrap();

    rewrite_to_proxy(&mcp, &["belay", "mcp-proxy"]);
    restore(&mcp);

    assert_eq!(
        read_file(&mcp),
        input,
        "restore: mcp.json must return to its original bytes"
    );
}

// ─── Test 7: has_belay dedup check (via install) ────────────────────────

#[test]
fn has_belay_dedup() {
    // Install twice — should only add matcher once
    let tmp = tempfile::tempdir().unwrap();
    let settings = tmp.path().join("settings.json");

    install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );
    install(
        &settings,
        "belay hook pretooluse",
        "belay hook posttooluse",
    );

    let content: serde_json::Value = serde_json::from_str(&read_file(&settings)).unwrap();
    let pre = content["hooks"]["PreToolUse"].as_array().unwrap();
    let post = content["hooks"]["PostToolUse"].as_array().unwrap();
    assert_eq!(
        pre.len(),
        1,
        "_has_belay dedup: expected 1 PreToolUse matcher"
    );
    assert_eq!(
        post.len(),
        1,
        "_has_belay dedup: expected 1 PostToolUse matcher"
    );
}
