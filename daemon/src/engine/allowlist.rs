//! Dev-toolchain-aware allowlist — suppress benign build/dev activity.
use crate::engine::rules::RuleSet;
use crate::engine::types::ToolCall;

/// Returns true if the (whitespace-normalized) command contains any shell-chaining
/// metacharacter that could smuggle a dangerous command after a benign prefix.
/// Metacharacters checked: `&&`, `||`, `;`, `|`, backtick, `$(`, newline.
pub fn has_shell_chaining(cmd: &str) -> bool {
    // Check two-character sequences first
    if cmd.contains("&&") || cmd.contains("||") || cmd.contains("$(") {
        return true;
    }
    // Single-character metacharacters and newline
    cmd.contains(';') || cmd.contains('|') || cmd.contains('`') || cmd.contains('\n')
}

/// True only when the command matches a dev-toolchain allowlist pattern
/// AND contains no shell-chaining metacharacter (defense in depth).
pub fn is_dev_benign(rs: &RuleSet, tc: &ToolCall) -> bool {
    let cmd = tc
        .input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if has_shell_chaining(cmd) {
        return false;
    }
    rs.allowlisted(tc)
}
