//! Render helpers for the `status` and `logs` CLI commands — Phase 13 Task 1.
//!
//! Ports the Python `status` / `logs` output exactly:
//!   - `status`: `f"{ts} {verdict} {tool} {rules}"` where `rules` is Python
//!     `str(list)` (single-quoted) and missing scalars are empty strings.
//!   - `logs`: `click.echo(row)` = Python `str(dict)` / `repr(dict)` — single
//!     quoted strings, `True`/`False`/`None`, keys in insertion order, nested
//!     objects recursed.
//!
//! `py_repr` is a faithful recursive Python-`repr` for `serde_json::Value`. It
//! supersedes `detect::py_list_repr` for arrays (an all-string array produces
//! byte-identical output), and is the single source of truth for both commands.
//!
//! serde_json-only — this module adds NO new dependencies.

use serde_json::Value;

/// Faithful recursive Python `repr` of a JSON value.
///
/// Mapping:
///   - Object → `{'key': <py_repr(val)>, ...}` in `Value` (preserve_order)
///     iteration order.
///   - Array  → `[<py_repr(item)>, ...]`.
///   - String → Python `str.__repr__`: single quotes by default; if the string
///     contains `'` but not `"`, use double quotes; escape `\`, `\n`, `\r`,
///     `\t`, the active quote, and other control chars as `\xNN`. Printable
///     non-ASCII (e.g. `é`) is kept literally, matching CPython 3.
///   - Bool   → `True` / `False`.
///   - Null   → `None`.
///   - Number → integers without a trailing `.0`; floats as serde renders them
///     (floats are absent from audit rows in practice).
pub fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_str_repr(s),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(py_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, val)| format!("{}: {}", py_str_repr(k), py_repr(val)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// Python `str.__repr__` for a single string.
///
/// Quote selection mirrors CPython: default single quotes; switch to double
/// quotes only when the string contains a `'` and no `"`.
fn py_str_repr(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };

    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// String value of `row[key]` or `""` if absent or not a string.
fn s(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Render the `status` lines (one per row).
///
/// `f"{ts} {verdict} {tool} {rules}"` where `rules` is `py_repr` of the array
/// if present, else `""`.
pub fn render_status(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            let rules_repr = match row.get("rules") {
                Some(r) => py_repr(r),
                None => String::new(),
            };
            format!(
                "{} {} {} {}",
                s(row, "ts"),
                s(row, "verdict"),
                s(row, "tool"),
                rules_repr
            )
        })
        .collect()
}

/// Render the `logs` lines (Python `str(dict)` repr per row).
pub fn render_logs(rows: &[Value]) -> Vec<String> {
    rows.iter().map(py_repr).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn py_repr_scalars() {
        assert_eq!(py_repr(&json!(true)), "True");
        assert_eq!(py_repr(&json!(false)), "False");
        assert_eq!(py_repr(&Value::Null), "None");
        assert_eq!(py_repr(&json!(42)), "42");
        assert_eq!(py_repr(&json!("hello")), "'hello'");
    }

    #[test]
    fn py_repr_string_quote_selection() {
        // single quote, no double → use double quotes
        assert_eq!(py_repr(&json!("it's bad")), "\"it's bad\"");
        // double quote, no single → single quotes
        assert_eq!(py_repr(&json!("say \"hi\"")), "'say \"hi\"'");
        // both → single quotes, escape the single quote
        assert_eq!(py_repr(&json!("both' and \"")), "'both\\' and \"'");
    }

    #[test]
    fn py_repr_nonascii_literal() {
        assert_eq!(py_repr(&json!("café")), "'café'");
    }

    #[test]
    fn py_repr_control_chars() {
        assert_eq!(py_repr(&json!("a\tb\nc")), "'a\\tb\\nc'");
    }

    #[test]
    fn py_repr_array_matches_py_list_repr() {
        // all-string array must equal the old detect::py_list_repr output
        let arr = json!(["rce.bash_subshell"]);
        assert_eq!(py_repr(&arr), "['rce.bash_subshell']");
        assert_eq!(py_repr(&json!([])), "[]");
        assert_eq!(py_repr(&json!(["a", "b"])), "['a', 'b']");
    }

    #[test]
    fn py_repr_nested_object_insertion_order() {
        let row = json!({"ts": "T", "rules": ["rce.x"], "input": {"command": "echo hi"}});
        assert_eq!(
            py_repr(&row),
            "{'ts': 'T', 'rules': ['rce.x'], 'input': {'command': 'echo hi'}}"
        );
    }

    #[test]
    fn render_status_missing_fields_are_empty() {
        let row = json!({"ts": "2026", "event": "PostToolUse"});
        assert_eq!(render_status(&[row]), vec!["2026   ".to_string()]);
    }

    #[test]
    fn render_status_with_rules() {
        let row = json!({"ts": "T", "verdict": "deny", "tool": "Bash", "rules": ["rce.x"]});
        assert_eq!(
            render_status(&[row]),
            vec!["T deny Bash ['rce.x']".to_string()]
        );
    }

    #[test]
    fn render_logs_is_py_repr() {
        let row = json!({"a": 1, "b": "x"});
        assert_eq!(render_logs(&[row]), vec!["{'a': 1, 'b': 'x'}".to_string()]);
    }
}
