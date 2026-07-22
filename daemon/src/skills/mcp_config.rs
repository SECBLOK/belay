//! MCP server config parsing: pure data + JSON parsing, no gating.
//!
//! Belay will later scan MCP-server config *writes* (a tool adding a new
//! server entry to `~/.claude.json` etc. is itself a security-relevant
//! event — it can grant a fresh command/URL a standing foothold). This
//! module only knows how to parse the JSON shape into structured entries;
//! deciding what to do about them is a later task.

use std::collections::BTreeMap;

use serde_json::Value;

/// Which known MCP config file a [`crate::skills::enumerate::McpConfig`]
/// path refers to.
///
/// v1 scope: the Claude family only (JSON). Codex (`~/.codex/config.toml`,
/// TOML-shaped) and Cursor are deferred — do not add variants for them here
/// without also adding a parser for their shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpConfigFormat {
    /// `~/.claude.json` — Claude Code's per-user config. Carries both a
    /// top-level `mcpServers` map and per-project `projects.<path>.mcpServers`
    /// maps (verified against a real `~/.claude.json` on disk).
    ClaudeUser,
    /// `.mcp.json` — project-scoped, typically checked in to a repo.
    DotMcpJson,
    /// `claude_desktop_config.json` — Claude Desktop's config.
    ClaudeDesktop,
}

/// One parsed MCP server entry (one key under an `mcpServers` object).
#[derive(Debug, Clone, PartialEq)]
pub struct McpServerEntry {
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub url: Option<String>,
    pub transport: Option<String>,
}

/// Parse the raw JSON text of an MCP config file into its server entries.
///
/// Fail-soft by construction: malformed JSON, or JSON that doesn't have the
/// expected shape at all, yields `vec![]` — this function never panics and
/// never returns an `Err` for the caller to mishandle.
///
/// Collects server entries from the top-level `"mcpServers"` object AND,
/// since Claude Code additionally nests project-scoped servers under
/// `"projects"."<path>"."mcpServers"`, from every project's `mcpServers`
/// object too. All occurrences are merged into one `Vec`; if the same server
/// name appears more than once (e.g. once at top level, once per-project)
/// each occurrence is kept — callers that care about identity dedup by
/// `name` themselves.
pub fn parse_mcp_config(content: &str) -> Vec<McpServerEntry> {
    let root: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(servers) = root.get("mcpServers") {
        collect_servers(servers, &mut out);
    }
    if let Some(Value::Object(projects)) = root.get("projects") {
        for project in projects.values() {
            if let Some(servers) = project.get("mcpServers") {
                collect_servers(servers, &mut out);
            }
        }
    }
    out
}

/// Push one [`McpServerEntry`] per key of `servers` (a `name -> server-object`
/// JSON object) onto `out`. Any other shape (missing, not an object, etc.) is
/// silently a no-op.
fn collect_servers(servers: &Value, out: &mut Vec<McpServerEntry>) {
    let Value::Object(map) = servers else {
        return;
    };
    for (name, def) in map {
        out.push(parse_entry(name, def));
    }
}

/// Extract the fields Belay cares about from one server-object `def`. Any
/// field that's absent or the wrong JSON type is simply left `None`/empty —
/// `Value::get`/`as_*` accessors already fail soft (return `None`) rather
/// than panicking, including when `def` itself isn't a JSON object.
fn parse_entry(name: &str, def: &Value) -> McpServerEntry {
    let command = def.get("command").and_then(Value::as_str).map(String::from);
    let args = def
        .get("args")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();
    let env = def
        .get("env")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let url = def.get("url").and_then(Value::as_str).map(String::from);
    let transport = def.get("transport").and_then(Value::as_str).map(String::from);

    McpServerEntry { name: name.to_string(), command, args, env, url, transport }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_top_level_mcp_servers() {
        let content = r#"{"mcpServers":{"a":{"command":"node","args":["x","y"],"env":{"K":"v"}},"b":{"url":"https://h/","transport":"sse"}}}"#;
        let entries = parse_mcp_config(content);
        assert_eq!(entries.len(), 2);

        let a = entries.iter().find(|e| e.name == "a").expect("entry a");
        assert_eq!(a.command, Some("node".to_string()));
        assert_eq!(a.args, vec!["x".to_string(), "y".to_string()]);
        assert_eq!(a.env.get("K"), Some(&"v".to_string()));
        assert_eq!(a.url, None);
        assert_eq!(a.transport, None);

        let b = entries.iter().find(|e| e.name == "b").expect("entry b");
        assert_eq!(b.url, Some("https://h/".to_string()));
        assert_eq!(b.transport, Some("sse".to_string()));
        assert_eq!(b.command, None);
        assert!(b.args.is_empty());
        assert!(b.env.is_empty());
    }

    #[test]
    fn finds_servers_nested_under_projects() {
        let content = r#"{"projects":{"/p":{"mcpServers":{"c":{"command":"x"}}}}}"#;
        let entries = parse_mcp_config(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "c");
        assert_eq!(entries[0].command, Some("x".to_string()));
    }

    #[test]
    fn merges_top_level_and_project_scoped_servers() {
        let content = r#"{"mcpServers":{"a":{"command":"top"}},"projects":{"/p":{"mcpServers":{"c":{"command":"nested"}}}}}"#;
        let entries = parse_mcp_config(content);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.name == "a"));
        assert!(entries.iter().any(|e| e.name == "c"));
    }

    #[test]
    fn malformed_json_never_panics_and_returns_empty() {
        assert_eq!(parse_mcp_config("{"), Vec::new());
        assert_eq!(parse_mcp_config(""), Vec::new());
        assert_eq!(parse_mcp_config("not json at all"), Vec::new());
    }

    #[test]
    fn absent_mcp_servers_and_projects_returns_empty() {
        assert_eq!(parse_mcp_config(r#"{"other":1}"#), Vec::new());
    }

    #[test]
    fn duplicate_names_across_scopes_are_not_deduped() {
        let content = r#"{"mcpServers":{"a":{"command":"one"}},"projects":{"/p":{"mcpServers":{"a":{"command":"two"}}}}}"#;
        let entries = parse_mcp_config(content);
        assert_eq!(entries.len(), 2, "both occurrences of \"a\" must be kept, not crash or silently dedup");
    }
}
