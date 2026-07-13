//! AST analyzer: parse Python files with tree-sitter and detect dangerous call patterns.
//!
//! Mirrors the deleted Python predecessor's `scan/analyzers/ast_scan.py`:
//! - `.py` files only.
//! - Walk all `call` nodes for: exec, eval, os.system, subprocess.{call,run,Popen}.
//! - exec(decode(...)) chain detection upgrades to `ast.exec_decode_chain`.
//! - subprocess with shell=True → `ast.subprocess_shell_true`.
//! - Dedup by (rule_id, rel_path); subprocess-shell check runs first (matches Python order).
//! - reason = "{base_reason} [file: {rel}]", location line = 1-based (start_row + 1).

use std::collections::{BTreeMap, HashSet};

use tree_sitter::Parser;

use crate::types::{Category, Decision, Finding, Location, Severity};

/// Decode function names that, when wrapped in exec(), indicate an obfuscation chain.
const DECODE_SOURCES: &[&str] = &[
    "b64decode",
    "urlsafe_b64decode",
    "b16decode",
    "b32decode",
    "fromhex",
];

/// Scan Python files in `file_cache` for dangerous AST patterns.
pub fn scan_ast(file_cache: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut parser = Parser::new();
    // Fail-soft, consistent with the other analyzers (resolve/yara/osv/patterns
    // all degrade to empty findings): a language-load failure must not crash the
    // whole scan. Log and skip the AST pass rather than panic.
    if let Err(e) = parser.set_language(&tree_sitter_python::language()) {
        eprintln!("belay scan: AST analyzer disabled (tree-sitter-python load failed: {e})");
        return Vec::new();
    }

    let mut findings: Vec<Finding> = Vec::new();

    for (rel, content) in file_cache {
        if !rel.ends_with(".py") {
            continue;
        }

        // tree-sitter is error-tolerant — always yields a tree; proceed regardless.
        let tree = match parser.parse(content.as_bytes(), None) {
            Some(t) => t,
            None => continue,
        };

        let src = content.as_bytes();
        let root = tree.root_node();

        // ONE shared seen set per file (matches Python scope).
        let mut seen: HashSet<(String, String)> = HashSet::new();

        // Run subprocess-shell check FIRST (matches Python execution order).
        check_subprocess_shell(root, src, rel, &mut seen, &mut findings);

        // Walk all nodes for exec/eval/attr calls.
        walk_calls(root, src, rel, &mut seen, &mut findings);
    }

    findings
}

// ---------------------------------------------------------------------------
// subprocess shell=True check (must run first, per Python source order)
// ---------------------------------------------------------------------------

fn check_subprocess_shell(
    root: tree_sitter::Node<'_>,
    src: &[u8],
    rel: &str,
    seen: &mut HashSet<(String, String)>,
    findings: &mut Vec<Finding>,
) {
    // Recursively walk all nodes looking for call nodes that match subprocess.<attr>(shell=True).
    let mut stack: Vec<tree_sitter::Node> = vec![root];

    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            if let Some(func_node) = node.child_by_field_name("function") {
                if func_node.kind() == "attribute" {
                    // Check if it's subprocess.<attr in {call,run,Popen,check_output}>
                    if let (Some(obj_node), Some(attr_node)) = (
                        func_node.child_by_field_name("object"),
                        func_node.child_by_field_name("attribute"),
                    ) {
                        let obj = node_text(obj_node, src);
                        let attr = node_text(attr_node, src);
                        if obj == "subprocess"
                            && matches!(attr.as_str(), "call" | "run" | "Popen" | "check_output")
                        {
                            // Look for shell=True keyword argument
                            if has_shell_true_kw(node, src) {
                                let rule_id = "ast.subprocess_shell_true".to_string();
                                let key = (rule_id.clone(), rel.to_string());
                                if !seen.contains(&key) {
                                    seen.insert(key);
                                    let line = node.start_position().row as u32 + 1;
                                    findings.push(Finding {
                                        rule_id,
                                        severity: Severity::High,
                                        category: Category::Rce,
                                        decision: Decision::Deny,
                                        reason: format!(
                                            "subprocess called with shell=True [file: {}]",
                                            rel
                                        ),
                                        owasp: "ASI05".into(),
                                        atlas: "AML.CodeExecution".into(),
                                        location: Some(Location {
                                            file: rel.to_string(),
                                            line,
                                        }),
                                        fix: String::new(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Push children in reverse order so we visit them left-to-right.
        let child_count = node.child_count();
        for i in (0..child_count).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main walk: exec/eval/os.system/subprocess.*
// ---------------------------------------------------------------------------

fn walk_calls(
    root: tree_sitter::Node<'_>,
    src: &[u8],
    rel: &str,
    seen: &mut HashSet<(String, String)>,
    findings: &mut Vec<Finding>,
) {
    let mut stack: Vec<tree_sitter::Node> = vec![root];

    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            if let Some(func_node) = node.child_by_field_name("function") {
                match func_node.kind() {
                    "identifier" => {
                        // exec(...) or eval(...)
                        let name = node_text(func_node, src);
                        if let Some((rule_id, severity, base_reason)) = match name.as_str() {
                            "exec" => {
                                Some(("ast.exec", Severity::Critical, "exec() call detected"))
                            }
                            "eval" => Some(("ast.eval", Severity::High, "eval() call detected")),
                            _ => None,
                        } {
                            // exec(decode(...)) chain detection
                            let (final_rule, final_sev, final_reason) = if name == "exec" {
                                if let Some(args_node) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = first_positional_arg(args_node) {
                                        if is_decode_call(first_arg, src) {
                                            (
                                                "ast.exec_decode_chain",
                                                Severity::Critical,
                                                "exec(decode(...)) obfuscation chain detected",
                                            )
                                        } else {
                                            (rule_id, severity, base_reason)
                                        }
                                    } else {
                                        (rule_id, severity, base_reason)
                                    }
                                } else {
                                    (rule_id, severity, base_reason)
                                }
                            } else {
                                (rule_id, severity, base_reason)
                            };

                            let key = (final_rule.to_string(), rel.to_string());
                            if !seen.contains(&key) {
                                seen.insert(key);
                                let line = node.start_position().row as u32 + 1;
                                findings.push(Finding {
                                    rule_id: final_rule.to_string(),
                                    severity: final_sev,
                                    category: Category::Rce,
                                    decision: Decision::Deny,
                                    reason: format!("{} [file: {}]", final_reason, rel),
                                    owasp: "ASI05".into(),
                                    atlas: "AML.CodeExecution".into(),
                                    location: Some(Location {
                                        file: rel.to_string(),
                                        line,
                                    }),
                                    fix: String::new(),
                                });
                            }
                        }
                    }
                    "attribute" => {
                        // module.func() — e.g. os.system(), subprocess.run(), etc.
                        if let (Some(obj_node), Some(attr_node)) = (
                            func_node.child_by_field_name("object"),
                            func_node.child_by_field_name("attribute"),
                        ) {
                            let obj = node_text(obj_node, src);
                            let attr = node_text(attr_node, src);
                            if let Some((rule_id, severity, base_reason)) =
                                danger_attr_call(obj.as_str(), attr.as_str())
                            {
                                let key = (rule_id.to_string(), rel.to_string());
                                if !seen.contains(&key) {
                                    seen.insert(key);
                                    let line = node.start_position().row as u32 + 1;
                                    findings.push(Finding {
                                        rule_id: rule_id.to_string(),
                                        severity,
                                        category: Category::Rce,
                                        decision: Decision::Deny,
                                        reason: format!("{} [file: {}]", base_reason, rel),
                                        owasp: "ASI05".into(),
                                        atlas: "AML.CodeExecution".into(),
                                        location: Some(Location {
                                            file: rel.to_string(),
                                            line,
                                        }),
                                        fix: String::new(),
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Push children in reverse order
        let child_count = node.child_count();
        for i in (0..child_count).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract UTF-8 text for a node.
fn node_text(node: tree_sitter::Node<'_>, src: &[u8]) -> String {
    node.utf8_text(src).unwrap_or("").to_string()
}

/// Return the first positional argument from an `argument_list` node.
/// Positional args are those that are NOT `keyword_argument` nodes.
fn first_positional_arg(args_node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut cursor = args_node.walk();
    let mut children = args_node.named_children(&mut cursor);
    children.find(|&child| child.kind() != "keyword_argument")
}

/// Return true if `node` is a call whose function's final name is in DECODE_SOURCES.
///
/// Matches:
///   - `b64decode(...)` — bare identifier
///   - `base64.b64decode(...)` — attribute: attr name is in DECODE_SOURCES
///   - `bytes.fromhex(...)` — attribute: attr name is "fromhex"
fn is_decode_call(node: tree_sitter::Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "call" {
        return false;
    }
    let func = match node.child_by_field_name("function") {
        Some(f) => f,
        None => return false,
    };
    match func.kind() {
        "attribute" => {
            if let Some(attr_node) = func.child_by_field_name("attribute") {
                let attr = node_text(attr_node, src);
                return DECODE_SOURCES.contains(&attr.as_str());
            }
            false
        }
        "identifier" => {
            let name = node_text(func, src);
            DECODE_SOURCES.contains(&name.as_str())
        }
        _ => false,
    }
}

/// Check if a `call` node has a `shell=True` keyword argument.
///
/// A keyword_argument node has field `name` (identifier) and `value`.
/// `True` in Python parses as `true` in tree-sitter-python (node kind "true").
fn has_shell_true_kw(call_node: tree_sitter::Node<'_>, src: &[u8]) -> bool {
    let args_node = match call_node.child_by_field_name("arguments") {
        Some(a) => a,
        None => return false,
    };

    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        if child.kind() == "keyword_argument" {
            // keyword_argument: name = value
            let kw_name = child.child_by_field_name("name");
            let kw_value = child.child_by_field_name("value");
            if let (Some(name_node), Some(val_node)) = (kw_name, kw_value) {
                if node_text(name_node, src) == "shell" && val_node.kind() == "true" {
                    return true;
                }
            }
        }
    }
    false
}

/// Map (module, attr) to (rule_id, severity, base_reason) for attribute calls.
fn danger_attr_call(module: &str, attr: &str) -> Option<(&'static str, Severity, &'static str)> {
    match (module, attr) {
        ("os", "system") => Some(("ast.os_system", Severity::High, "os.system() call detected")),
        ("subprocess", "call") => Some((
            "ast.subprocess_call",
            Severity::High,
            "subprocess.call() detected",
        )),
        ("subprocess", "Popen") => Some((
            "ast.subprocess_popen",
            Severity::High,
            "subprocess.Popen() detected",
        )),
        ("subprocess", "run") => Some((
            "ast.subprocess_run",
            Severity::High,
            "subprocess.run() detected",
        )),
        _ => None,
    }
}
