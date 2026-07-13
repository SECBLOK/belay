//! Wire module — port of Python wire.py + mcp/config.py.
//!
//! `install` / `uninstall` mirror the deleted Python predecessor's `wire/wire.py`.
//! `rewrite_to_proxy` / `restore` mirror its `mcp/config.py`.
//!
//! JSON formatting: uses `serde_json::to_string_pretty` which with the
//! `preserve_order` feature preserves object key insertion order, matching
//! Python's `json.dump(..., indent=2)` byte-for-byte.

use serde_json::Value;
use std::fs;
use std::path::Path;

// ─── helpers ────────────────────────────────────────────────────────────────

fn load_json(path: &Path) -> Value {
    if path.exists() {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&text) {
                return val;
            }
        }
    }
    Value::Object(serde_json::Map::new())
}

fn write_json(path: &Path, val: &Value) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(val).unwrap();
    atomic_write(path, text.as_bytes())
}

/// Write `bytes` to `path` atomically: write a sibling temp file then rename over
/// the target (rename is atomic within a directory), so a crash/power-loss mid
/// write can never leave a truncated/corrupt config behind.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("belay-tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

/// Read a JSON file for in-place editing. Returns `Some(object)` when the file
/// is absent/empty (a fresh `{}`) or parses to a JSON object; returns `None`
/// when the file EXISTS with content that is not a JSON object (a parse failure
/// or a non-object JSON value) — callers MUST refuse to clobber it. This closes
/// the same data-loss hole `rewrite_to_proxy` guards against: the old `load_json`
/// silently returned `{}` for an unparseable file and the caller then overwrote
/// the real file with `{}`.
fn load_json_object_guarded(path: &Path) -> Option<Value> {
    match fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => match serde_json::from_str::<Value>(&text) {
            Ok(v @ Value::Object(_)) => Some(v),
            _ => None,
        },
        _ => Some(Value::Object(serde_json::Map::new())),
    }
}

/// Mirror the deleted Python predecessor's `_has_aidefender(matchers)`.
/// Returns true if any matcher has any hook whose `command` contains "belay".
fn has_belay(matchers: &[Value]) -> bool {
    for m in matchers {
        if let Some(hooks) = m.get("hooks").and_then(|v| v.as_array()) {
            for h in hooks {
                if let Some(cmd) = h.get("command").and_then(|v| v.as_str()) {
                    if cmd.contains("belay") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Mirror Python `_servers_obj(d)`: d.get("mcpServers") or d.get("servers") or {}
fn servers_obj_mut(d: &mut Value) -> Option<&mut serde_json::Map<String, Value>> {
    // Check mcpServers first
    if d.get("mcpServers").is_some() {
        return d.get_mut("mcpServers").and_then(|v| v.as_object_mut());
    }
    if d.get("servers").is_some() {
        return d.get_mut("servers").and_then(|v| v.as_object_mut());
    }
    None
}

// ─── wire.py ports ──────────────────────────────────────────────────────────

/// Port of Python `install(settings_path, hook_cmd_pre, hook_cmd_post)`.
///
/// Loads existing settings (or `{}`), writes backup if absent,
/// appends belay hook matchers for PreToolUse and PostToolUse.
///
/// Returns `false` (writing NOTHING) when `settings_path` exists with content
/// that is not a JSON object — refusing to clobber a config we can't understand.
/// Returns `true` once the hook is installed (or was already present).
pub fn install(settings_path: &Path, hook_cmd_pre: &str, hook_cmd_post: &str) -> bool {
    let mut data = match load_json_object_guarded(settings_path) {
        Some(v) => v,
        None => return false, // exists but not a JSON object — refuse to clobber
    };

    // Backup: written only if absent, with ORIGINAL data.
    // Python: backup = settings_path + ".aidefender-backup"
    let backup_path_s = format!("{}.belay-backup", settings_path.to_string_lossy());
    let backup_path = Path::new(&backup_path_s);
    if !backup_path.exists() {
        write_json(backup_path, &data).expect("failed to write backup");
    }

    // Ensure data["hooks"] exists
    if data.get("hooks").is_none() {
        data.as_object_mut()
            .unwrap()
            .insert("hooks".to_string(), Value::Object(serde_json::Map::new()));
    }

    let events = [("PreToolUse", hook_cmd_pre), ("PostToolUse", hook_cmd_post)];
    for (event, cmd) in &events {
        let hooks_obj = data.get_mut("hooks").unwrap().as_object_mut().unwrap();
        if hooks_obj.get(*event).is_none() {
            hooks_obj.insert(event.to_string(), Value::Array(vec![]));
        }
        let matchers = hooks_obj.get_mut(*event).unwrap().as_array_mut().unwrap();
        if !has_belay(matchers) {
            // Build matcher in Python insertion order: "matcher" first, then "hooks"
            // Inner hook: "type" first, then "command"
            let inner_hook = {
                let mut m = serde_json::Map::new();
                m.insert("type".to_string(), Value::String("command".to_string()));
                m.insert("command".to_string(), Value::String(cmd.to_string()));
                Value::Object(m)
            };
            let matcher = {
                let mut m = serde_json::Map::new();
                m.insert("matcher".to_string(), Value::String(".*".to_string()));
                m.insert("hooks".to_string(), Value::Array(vec![inner_hook]));
                Value::Object(m)
            };
            matchers.push(matcher);
        }
    }

    write_json(settings_path, &data).expect("failed to write settings");
    true
}

/// Port of Python `uninstall(settings_path)`.
///
/// Removes matchers whose hooks contain a "belay" command. Refuses to
/// touch a file that exists but is not a JSON object (never clobbers).
pub fn uninstall(settings_path: &Path) {
    let mut data = match load_json_object_guarded(settings_path) {
        Some(v) => v,
        None => return,
    };

    if let Some(hooks_obj) = data.get_mut("hooks").and_then(|v| v.as_object_mut()) {
        for event in &["PreToolUse", "PostToolUse"] {
            if let Some(arr) = hooks_obj.get_mut(*event).and_then(|v| v.as_array_mut()) {
                arr.retain(|m| {
                    if let Some(hooks) = m.get("hooks").and_then(|v| v.as_array()) {
                        !hooks.iter().any(|h| {
                            h.get("command")
                                .and_then(|v| v.as_str())
                                .map(|c| c.contains("belay"))
                                .unwrap_or(false)
                        })
                    } else {
                        true
                    }
                });
            }
        }
    }

    write_json(settings_path, &data).expect("failed to write settings");
}

// ─── mcp/config.py ports ────────────────────────────────────────────────────

/// Port of Python `rewrite_to_proxy(path, proxy_cmd)`.
///
/// For each server with a command that isn't empty and isn't already proxy_cmd[0]:
/// - sets args = proxy_cmd[1:] + ["--", original_cmd, *existing_args]
/// - sets command = proxy_cmd[0]
///
/// With `preserve_order`, IndexMap `insert` updates-in-place if key exists,
/// or appends if new — matching Python dict mutation behavior exactly.
///
/// Returns `true` when, after this call, the config contains at least one server
/// routed through the proxy (whether rewritten now or already proxied) — i.e.
/// protection is in place for this file. Returns `false` when there is nothing
/// to route (no servers) OR the file exists but cannot be parsed as JSON.
///
/// DATA-LOSS GUARD: an existing, non-empty file that does NOT parse as JSON is
/// left completely untouched (no backup, no write). The previous version loaded
/// such a file as `{}` and then unconditionally wrote `{}` back, destroying e.g.
/// a YAML config. We also only write (and back up) when we actually rewrite a
/// server, so a serverless config is never needlessly rewritten.
pub fn rewrite_to_proxy(path: &Path, proxy_cmd: &[&str]) -> bool {
    // Distinguish "absent/empty" (safe to treat as {}) from "present but
    // unparseable" (must not touch).
    let raw = fs::read_to_string(path).ok();
    let present_nonempty = raw.as_ref().map(|t| !t.trim().is_empty()).unwrap_or(false);
    let parsed: Option<Value> = raw.as_deref().and_then(|t| serde_json::from_str(t).ok());
    if present_nonempty && parsed.is_none() {
        // Exists with content we can't parse — refuse rather than clobber.
        return false;
    }
    let original = parsed.unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let mut d = original.clone();

    let mut wrote = false;
    let mut proxied_present = false;
    if let Some(servers) = servers_obj_mut(&mut d) {
        for (_name, server) in servers.iter_mut() {
            let server_obj = match server.as_object_mut() {
                Some(o) => o,
                None => continue,
            };
            let cmd = match server_obj.get("command").and_then(|v| v.as_str()) {
                Some(c) if !c.is_empty() => c.to_string(),
                _ => continue,
            };
            if cmd == proxy_cmd[0] {
                // Already routed through the proxy.
                proxied_present = true;
                continue;
            }
            // Build new args: proxy_cmd[1:] + ["--", original_cmd] + existing_args
            let existing_args: Vec<Value> = server_obj
                .get("args")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut new_args: Vec<Value> = proxy_cmd[1..]
                .iter()
                .map(|s| Value::String(s.to_string()))
                .collect();
            new_args.push(Value::String("--".to_string()));
            new_args.push(Value::String(cmd));
            new_args.extend(existing_args);

            // Python does: s["args"] = ... (update or insert), then s["command"] = ...
            // With IndexMap (preserve_order): insert updates-in-place if key exists,
            // or appends if new. This matches Python dict behavior.
            server_obj.insert("args".to_string(), Value::Array(new_args));
            server_obj.insert(
                "command".to_string(),
                Value::String(proxy_cmd[0].to_string()),
            );
            wrote = true;
            proxied_present = true;
        }
    }

    if wrote {
        // Back up the ORIGINAL (pre-rewrite) bytes, only when we're writing.
        let backup_path_s = format!("{}.belay-backup", path.to_string_lossy());
        let backup_path = Path::new(&backup_path_s);
        if !backup_path.exists() {
            write_json(backup_path, &original).expect("failed to write backup");
        }
        write_json(path, &d).expect("failed to write mcp config");
    }

    proxied_present
}

/// Port of Python `restore(path)`.
///
/// If backup exists, re-parses it and writes it back (with indent=2),
/// mirroring Python's `json.dump(_load(backup), open(path, "w"), indent=2)`.
pub fn restore(path: &Path) {
    let backup_path_s = format!("{}.belay-backup", path.to_string_lossy());
    let backup_path = Path::new(&backup_path_s);
    if backup_path.exists() {
        let data = load_json(backup_path);
        write_json(path, &data).expect("failed to restore from backup");
    }
}
