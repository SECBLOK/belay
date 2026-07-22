//! Interactive setup wizard — Tasks 1+2 of the one-command installer/wizard
//! plan (`docs/superpowers/plans/2026-07-10-one-command-installer-and-setup-wizard.md`).
//!
//! `run_setup` is the wizard's PROMPT LOGIC: it is pure and I/O-injectable —
//! it reads scripted answers from any `BufRead` and writes prompts to any
//! `Write`, and has NO side effects (no file writes, no process spawns, no
//! network). It only builds a `SetupPlan`. Executing that plan (protecting
//! agents, writing daemon config, installing the service) is the caller's
//! job — see `run_setup` in `src/bin/aidefender.rs`.
//!
//! Task 2 adds the Custom path (per-capability prompts, walked by
//! `custom_plan`) plus two pure mappers, `ai_config_args` and
//! `channel_config`, that translate a `SetupPlan`'s choices into the exact
//! JSON shapes the daemon crate's writers accept
//! (`belayd::ai::config::AiConfig::from_args`,
//! `belayd::channels_bridge::config_set_channel`). Those writers live in
//! `belayd`, which this crate does not depend on, so the mappers are the
//! testable contract between this pure module and the binary handler that
//! actually calls them.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use crate::detect::find_agents;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Options controlling how `run_setup` behaves.
#[derive(Debug, Clone, Default)]
pub struct SetupOpts {
    /// Non-interactive: skip all prompts, return the Quick-setup plan without
    /// reading `input` at all.
    pub yes: bool,
    /// Whether stdin/stdout are attached to a real interactive terminal. When
    /// `false` (and `yes` is `false`), `run_setup` prints actionable guidance
    /// and returns immediately WITHOUT reading `input` (never hangs).
    pub interactive: bool,
    /// Override home directory (agent detection + tests).
    pub home: Option<PathBuf>,
    /// Emit ANSI bold around section-level questions so the important choices
    /// stand out on a real terminal. The binary sets this from
    /// `stdout().is_terminal() && $NO_COLOR unset`; tests leave it `false` so
    /// their injectable-`Write` assertions still match plain text.
    pub styled: bool,
}

/// An AI-explainer choice built by the Custom flow's AI prompts.
///
/// `mode` is `"local"` or `"cloud"` (never `"off"` — an Off choice is
/// represented as `SetupPlan.ai == None`). `key` is the plaintext BYOK cloud
/// API key the operator just typed (only present for `mode == "cloud"`); it
/// is never put through `ai_config_args` (which only builds the `ai.json`
/// shape) — the caller writes it separately via the daemon crate's
/// `ai::secret::write_ai_key`, which persists it to its own owner-only file,
/// never inside `ai.json` itself.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct AiChoice {
    pub mode: String,
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    /// Explicit opt-in required before a "cloud" mode is ever saved.
    pub cloud_consent: bool,
    pub key: Option<String>,
    /// LLM skill judge — background watcher path. Off by default.
    pub skill_judge_enabled: bool,
    /// LLM skill judge — synchronous install-gate. Off by default.
    pub skill_judge_gate_enabled: bool,
    /// Per-task judge model override; None = inherit the global `model`.
    pub skill_judge_model: Option<String>,
}

/// A messaging-channel choice built by the Custom flow's channel prompt.
/// `fields` is the platform's adapter-config object, e.g.
/// `{"bot_token":"…","chat_id":"…"}` for Telegram — the exact shape
/// `belayd::channels_bridge::config_set_channel` merges into
/// `channels.json`.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct ChannelChoice {
    pub platform: String,
    pub fields: serde_json::Value,
}

/// The wizard's output: a fully-decided plan of what to set up. Building this
/// plan has NO side effects — a caller executes it separately (protect
/// agents, write configs, install the service).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SetupPlan {
    /// The locale every later surface (GUI, tray, toast, CLI) will use. Asked
    /// FIRST, because every prompt after it should already be in the chosen
    /// language. One of `host_config::SUPPORTED_LOCALES`.
    pub locale: String,
    pub protect_agents: Vec<String>,
    pub firewall: bool,
    pub ssh_guard: bool,
    pub ai: Option<AiChoice>,
    pub channels: Option<ChannelChoice>,
    pub netenrich: bool,
    /// Enable a scheduled (daily) vulnerability scan. Only asked/set by the
    /// Custom flow — the Quick plan leaves it off, matching `netenrich`'s
    /// Quick-plan default.
    pub scan_schedule: bool,
    pub install_service: bool,
}

/// Hand-written rather than derived so `locale` defaults to a REAL locale.
/// `#[derive(Default)]` would hand back `""`, which is not a locale any
/// surface can render in - the non-interactive paths return a default plan,
/// and they must still name a language. Adding a field breaks this impl on
/// purpose: the new field's default deserves a decision, not silence.
impl Default for SetupPlan {
    fn default() -> Self {
        Self {
            locale: DEFAULT_LOCALE.to_string(),
            protect_agents: Vec::new(),
            firewall: false,
            ssh_guard: false,
            ai: None,
            channels: None,
            netenrich: false,
            scan_schedule: false,
            install_service: false,
        }
    }
}

/// Kept in step with `belayd`'s `host_config::SUPPORTED_LOCALES` by
/// `locale_options_match_the_daemons_supported_list`. `manage` does not depend
/// on the daemon crate, so the list is duplicated and the test is what makes
/// the duplication safe.
pub const LOCALE_OPTIONS: &[(&str, &str)] = &[("en", "English"), ("zh-Hans", "中文（简体）")];

pub const DEFAULT_LOCALE: &str = "en";

/// Printed (to `output`) when run non-interactively without `--yes`, instead
/// of hanging on a read from a pipe that will never answer.
pub const NON_INTERACTIVE_GUIDANCE: &str = "Non-interactive shell detected. Re-run `belay setup` in a terminal, or `belay setup --yes` for defaults.";

// ─────────────────────────────────────────────────────────────────────────────
// Prompt helpers — pure, generic over (output: &mut W, input: &mut R)
// ─────────────────────────────────────────────────────────────────────────────

fn read_line<R: BufRead>(input: &mut R) -> io::Result<String> {
    let mut line = String::new();
    input.read_line(&mut line)?;
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}

/// Ask a yes/no question. Prints `question [Y/n]` (or `[y/N]` when `default`
/// is false), reads one line. Empty line -> `default`; `y`/`yes` -> `true`;
/// `n`/`no` -> `false` (case-insensitive); anything else -> `default`.
pub fn prompt_yes_no<W: Write, R: BufRead>(
    out: &mut W,
    inp: &mut R,
    question: &str,
    default: bool,
) -> io::Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    write!(out, "{question} {hint} ")?;
    out.flush()?;
    let line = read_line(inp)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    Ok(match trimmed.to_ascii_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    })
}

/// Ask the user to pick one of `options` (1-based when typed). Prints the
/// numbered list marking the default, reads one line. Empty line ->
/// `default_idx`; a valid in-range number -> that index (0-based); anything
/// else (non-numeric, out of range) -> `default_idx`.
pub fn prompt_choice<W: Write, R: BufRead>(
    out: &mut W,
    inp: &mut R,
    question: &str,
    options: &[&str],
    default_idx: usize,
) -> io::Result<usize> {
    writeln!(out, "{question}")?;
    for (i, opt) in options.iter().enumerate() {
        let marker = if i == default_idx { " (default)" } else { "" };
        writeln!(out, "  {}. {opt}{marker}", i + 1)?;
    }
    write!(out, "> ")?;
    out.flush()?;
    let line = read_line(inp)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(default_idx);
    }
    Ok(match trimmed.parse::<usize>() {
        Ok(n) if n >= 1 && n <= options.len() => n - 1,
        _ => default_idx,
    })
}

/// Ask a free-text question. Prints `question [default]`, reads one line.
/// Empty line -> `default`; otherwise the trimmed line.
pub fn prompt_line<W: Write, R: BufRead>(
    out: &mut W,
    inp: &mut R,
    question: &str,
    default: &str,
) -> io::Result<String> {
    write!(out, "{question} [{default}] ")?;
    out.flush()?;
    let line = read_line(inp)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Ask for a secret (e.g. an API key). Prints `question: `, reads one line,
/// returns it verbatim (no default — an empty line is a valid, if unusual,
/// answer).
///
/// This is pure prompt logic: it does NOT suppress terminal echo, since that
/// is a real-TTY concern (raw-mode toggling) that has nothing to do with the
/// injectable `BufRead`/`Write` this module tests against. A caller wiring
/// this up over a real terminal (the binary's interactive path) is
/// responsible for turning off local echo around the read if it wants the
/// key hidden on-screen.
pub fn prompt_secret<W: Write, R: BufRead>(
    out: &mut W,
    inp: &mut R,
    question: &str,
) -> io::Result<String> {
    write!(out, "{question}: ")?;
    out.flush()?;
    read_line(inp)
}

/// Cloud providers offered by the AI-explainer prompt — mirrors
/// `belayd::ai::config::KNOWN_CLOUD_PROVIDERS` (manage cannot depend on
/// the daemon crate, so this list is kept in sync manually; `ai_config_args`
/// doesn't validate against it — the daemon's `AiConfig::from_args` is the
/// authoritative validator the binary handler calls next).
pub const CLOUD_PROVIDERS: &[&str] = &[
    "openai",
    "anthropic",
    "gemini",
    "xai",
    "deepseek",
    "mistral",
    "groq",
    "cohere",
    "perplexity",
    "together",
    "openrouter",
    "minimax",
];

/// A sensible default chat model per cloud provider, shown as the `Model [..]`
/// default in the wizard so pressing Enter yields a working model id instead of
/// an empty string (which would persist `"model": ""` to ai.json and fail at
/// the first provider call). These lean to each provider's cheap/fast tier
/// (gpt-4o-mini, claude-haiku, etc.): the AI explainer only writes a short,
/// advisory, plain-English risk blurb, so a flagship model is overkill and just
/// adds cost and latency for no real benefit. Ids track the daemon's bundled
/// rig-core provider constants; kept here because `manage` cannot depend on the
/// daemon crate (see CLOUD_PROVIDERS). An unknown provider falls back to "" (no
/// suggestion). The user can always override with a heavier model at the prompt.
fn default_cloud_model(provider: &str) -> &'static str {
    match provider {
        "openai" => "gpt-4o-mini",
        "anthropic" => "claude-haiku-4-5",
        "gemini" => "gemini-2.5-flash",
        "xai" => "grok-3",
        "deepseek" => "deepseek-chat",
        "mistral" => "mistral-small-latest",
        "groq" => "llama-3.3-70b-versatile",
        "cohere" => "command-r",
        "perplexity" => "sonar",
        "together" => "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "openrouter" => "openai/gpt-4o-mini",
        "minimax" => "MiniMax-M2",
        _ => "",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure config mappers — SetupPlan choices -> the JSON shapes the daemon
// crate's writers accept. Kept here (not in the binary) so they're testable
// hermetically; `manage` has no dependency on `belayd`, so the actual
// `AiConfig::from_args`/`config_set_channel` calls happen in the binary.
// ─────────────────────────────────────────────────────────────────────────────

/// Build the exact `{mode,provider,model,base_url,cloud_consent,
/// skill_judge_enabled,skill_judge_gate_enabled,skill_judge_model?}` object
/// that `belayd::ai::config::AiConfig::from_args` accepts. Deliberately omits
/// `choice.key` — the BYOK secret never goes into `ai.json`; the caller
/// writes it separately via `ai::secret::write_ai_key`.
pub fn ai_config_args(choice: &AiChoice) -> serde_json::Value {
    let mut args = serde_json::json!({
        "mode": choice.mode,
        "provider": choice.provider,
        "model": choice.model,
        "cloud_consent": choice.cloud_consent,
        "skill_judge_enabled": choice.skill_judge_enabled,
        "skill_judge_gate_enabled": choice.skill_judge_gate_enabled,
    });
    if let Some(base_url) = &choice.base_url {
        args["base_url"] = serde_json::Value::String(base_url.clone());
    }
    // Omit when None so from_args reads it as "inherit" (same rule as base_url).
    if let Some(judge_model) = &choice.skill_judge_model {
        args["skill_judge_model"] = serde_json::Value::String(judge_model.clone());
    }
    args
}

/// Build the `(platform, fields)` pair that
/// `belayd::channels_bridge::config_set_channel` accepts.
pub fn channel_config(choice: &ChannelChoice) -> (String, serde_json::Value) {
    (choice.platform.clone(), choice.fields.clone())
}

/// Insert `key: value` into a channel `fields` object, but only when `value`
/// is non-blank. `config_set_channel` MERGES the given fields into the
/// existing platform block by key, so a caller must OMIT a field the user
/// left blank (re-running setup and pressing Enter at a secret prompt) —
/// inserting it as `""` would blank the stored secret instead of leaving it
/// untouched. Applies to every channel field (bot_token, chat_id,
/// channel_id, …), not just secrets, for the same reason.
fn insert_channel_field(fields: &mut serde_json::Value, key: &str, value: &str) {
    if !value.trim().is_empty() {
        fields[key] = serde_json::Value::String(value.to_string());
    }
}

/// Wrap `s` in ANSI bold when `styled`, else return it unchanged. Used to make
/// the wizard's section-level questions stand out on a real terminal; gated by
/// `SetupOpts.styled` so the injectable-`Write` tests still see plain text.
pub fn heading(styled: bool, s: &str) -> String {
    if styled {
        format!("\x1b[1m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Wrap `s` in ANSI dim when `styled`, else return it unchanged. Used for the
/// explanatory hint lines under a prompt (setup gotchas, safety framing) so they
/// read as secondary to the question itself. Gated by `styled` like [`heading`].
pub fn note(styled: bool, s: &str) -> String {
    if styled {
        format!("\x1b[2m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Build the local (Ollama, on-device) AI choice: one model prompt, no key, no
/// cloud consent. Shared by the Custom 3-way and the Quick gated AI prompt.
fn build_ai_local<R: BufRead, W: Write>(input: &mut R, output: &mut W) -> io::Result<AiChoice> {
    let model = prompt_line(output, input, "Model", "qwen2.5")?;
    Ok(AiChoice {
        mode: "local".to_string(),
        provider: "ollama".to_string(),
        model,
        base_url: None,
        cloud_consent: false,
        key: None,
        skill_judge_enabled: false,
        skill_judge_gate_enabled: false,
        skill_judge_model: None,
    })
}

/// Build the cloud (BYOK) AI choice: provider, model, API key, then an explicit
/// consent gate. Returns `None` (and says so) without consent - cloud mode
/// sends data off-box, so it is never saved on a silent default. Shared by the
/// Custom 3-way and the Quick gated AI prompt.
fn build_ai_cloud<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
) -> io::Result<Option<AiChoice>> {
    let provider_idx = prompt_choice(output, input, "Cloud provider?", CLOUD_PROVIDERS, 0)?;
    let provider = CLOUD_PROVIDERS[provider_idx].to_string();
    let model = prompt_line(output, input, "Model", default_cloud_model(&provider))?;
    let key = prompt_secret(output, input, "API key")?;
    let consent_question =
        format!("This sends the flagged action (redacted) to {provider}. Consent?");
    let consent = prompt_yes_no(output, input, &consent_question, false)?;
    if consent {
        Ok(Some(AiChoice {
            mode: "cloud".to_string(),
            provider,
            model,
            base_url: None,
            cloud_consent: true,
            key: Some(key),
            skill_judge_enabled: false,
            skill_judge_gate_enabled: false,
            skill_judge_model: None,
        }))
    } else {
        // Hard requirement, not a silent downgrade: cloud mode sends data
        // off-box, so without explicit consent nothing cloud-y is saved.
        writeln!(
            output,
            "Cloud AI needs explicit consent to leave it Off for now - not enabled."
        )?;
        Ok(None)
    }
}

/// Ask whether to connect a messaging channel now and, if so, which platform
/// (+ its tokens). Returns the built `ChannelChoice` or `None` when declined or
/// deferred. Shared by the Custom flow and the Quick flow's optional tail.
fn prompt_channel<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    styled: bool,
) -> io::Result<Option<ChannelChoice>> {
    let want_channel = prompt_yes_no(
        output,
        input,
        &heading(styled, "Connect a messaging channel now? (Telegram/Discord/…)"),
        false,
    )?;
    if !want_channel {
        return Ok(None);
    }
    // Safety framing: the approval channel is additive friction, never a softer
    // path to "allow". Until an approver is enrolled Belay denies all inbound
    // replies by default - say so, so an empty allowlist reads as intended.
    writeln!(
        output,
        "{}",
        note(
            styled,
            "  Approvals are default-deny: only an enrolled approver can allow/deny alerts."
        )
    )?;
    let platform_idx = prompt_choice(
        output,
        input,
        "Which platform?",
        &["Telegram", "Discord", "Other (configure later)"],
        0,
    )?;
    Ok(match platform_idx {
        0 => {
            let bot_token = prompt_secret(output, input, "Telegram bot token")?;
            let chat_id = prompt_line(output, input, "Telegram chat id", "")?;
            writeln!(
                output,
                "{}",
                note(
                    styled,
                    "  This chat id is auto-enrolled as an approver (a Telegram 1:1 DM's sender is its chat id)."
                )
            )?;
            let mut fields = serde_json::json!({});
            insert_channel_field(&mut fields, "bot_token", &bot_token);
            insert_channel_field(&mut fields, "chat_id", &chat_id);
            Some(ChannelChoice {
                platform: "telegram".to_string(),
                fields,
            })
        }
        1 => {
            // The #1 Discord setup trap: without Message Content Intent the bot
            // connects but can't read the Allow/Deny replies, so approvals appear
            // dead. Warn BEFORE the token prompt so it's fixed in the same visit.
            writeln!(
                output,
                "{}",
                heading(
                    styled,
                    "  Discord: enable \"Message Content Intent\" first (Dev Portal -> Bot -> Privileged Gateway Intents)."
                )
            )?;
            writeln!(
                output,
                "{}",
                note(
                    styled,
                    "  Without it the bot connects but can't read your replies, so approvals silently do nothing."
                )
            )?;
            let bot_token = prompt_secret(output, input, "Discord bot token")?;
            let channel_id = prompt_line(output, input, "Discord channel id (a 1:1 DM channel)", "")?;
            writeln!(
                output,
                "{}",
                note(
                    styled,
                    "  Enroll yourself as approver by DMing the bot: pair <code> (get the code from the desktop app's Messaging tab)."
                )
            )?;
            let mut fields = serde_json::json!({});
            insert_channel_field(&mut fields, "bot_token", &bot_token);
            insert_channel_field(&mut fields, "channel_id", &channel_id);
            Some(ChannelChoice {
                platform: "discord".to_string(),
                fields,
            })
        }
        _ => {
            writeln!(
                output,
                "Okay - configure a channel later from the desktop app's Messaging tab."
            )?;
            None
        }
    })
}

/// The Quick flow's optional AI prompt: a yes/no gate (default: skip) that only
/// expands into the local-vs-cloud detail when the user opts in - so pressing
/// Enter keeps Quick fast, but the choice is offered to everyone (not buried in
/// Custom). Custom keeps its own 3-way (Off/Local/Cloud) prompt instead.
fn prompt_ai_gated<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    styled: bool,
) -> io::Result<Option<AiChoice>> {
    let want = prompt_yes_no(
        output,
        input,
        &heading(
            styled,
            "Set up AI explanations now? (local Ollama, or bring your own cloud key)",
        ),
        false,
    )?;
    if !want {
        return Ok(None);
    }
    let idx = prompt_choice(
        output,
        input,
        "AI provider?",
        &["Local (Ollama, on-device)", "Cloud (bring your own key)"],
        0,
    )?;
    Ok(match idx {
        0 => Some(build_ai_local(input, output)?),
        _ => build_ai_cloud(input, output)?,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// The wizard core
// ─────────────────────────────────────────────────────────────────────────────

/// Build the "Quick setup" plan: every currently-detected agent, firewall +
/// ssh-guard on, no AI/channels configured, and install the boot-start
/// service. Pure — `find_agents` only reads the filesystem to enumerate what
/// is already installed; it writes nothing.
fn quick_plan(home: Option<&str>) -> SetupPlan {
    let protect_agents = find_agents(home).into_iter().map(|a| a.name).collect();
    SetupPlan {
        // `--yes` reaches here without asking anything, so English is the only
        // honest answer. The interactive paths overwrite this with the
        // operator's pick.
        locale: DEFAULT_LOCALE.to_string(),
        protect_agents,
        firewall: true,
        ssh_guard: true,
        ai: None,
        channels: None,
        netenrich: false,
        scan_schedule: false,
        install_service: true,
    }
}

/// Walk the Custom flow: a prompt per capability, each pre-filled with a
/// sensible default, building a `SetupPlan` one field at a time. Pure — same
/// no-side-effects contract as `run_setup` itself.
fn custom_plan<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    home: Option<&str>,
    styled: bool,
) -> io::Result<SetupPlan> {
    let mut plan = SetupPlan::default();

    // 1. Protect agents — ask per detected agent (also covers the "decline"
    // branch Task 1's combined yes/no confirmation couldn't exercise alone).
    for agent in find_agents(home) {
        let question = format!("Protect {}?", agent.name);
        if prompt_yes_no(output, input, &heading(styled, &question), true)? {
            plan.protect_agents.push(agent.name);
        }
    }

    // 2. Firewall.
    plan.firewall = prompt_yes_no(
        output,
        input,
        &heading(styled, "Enable the least-privilege firewall (SSH-pinned, auto-revert)?"),
        true,
    )?;

    // 3. SSH brute-force guard.
    plan.ssh_guard = prompt_yes_no(
        output,
        input,
        &heading(styled, "Enable SSH brute-force guard?"),
        true,
    )?;

    // 4. AI explainer: off / local (Ollama) / cloud (BYOK). Custom keeps the
    // 3-way choice; the Local/Cloud detail is shared with the Quick gated
    // prompt via `build_ai_local`/`build_ai_cloud`.
    let ai_mode_idx = prompt_choice(
        output,
        input,
        &heading(styled, "AI explanations?"),
        &[
            "Off",
            "Local (Ollama, on-device)",
            "Cloud (bring your own key)",
        ],
        0,
    )?;
    plan.ai = match ai_mode_idx {
        1 => Some(build_ai_local(input, output)?),
        2 => build_ai_cloud(input, output)?,
        _ => None,
    };

    // 5. Network-destination enrichment (owner/ASN/country; display-only).
    plan.netenrich = prompt_yes_no(
        output,
        input,
        &heading(styled, "Show destination owner/ASN/country (network enrichment)?"),
        true,
    )?;

    // 6. Scheduled vulnerability scan (daily; see
    // `belayd::host_config::default_schedule` for the exact
    // cron/scope the binary handler writes when this is on).
    plan.scan_schedule = prompt_yes_no(
        output,
        input,
        &heading(styled, "Enable a scheduled vulnerability scan (daily)?"),
        true,
    )?;

    // 7. Messaging channel (optional; keep it to a couple of common
    // platforms here — others are configured later via the desktop app).
    plan.channels = prompt_channel(input, output, styled)?;

    // 8. Boot-start service.
    plan.install_service = prompt_yes_no(
        output,
        input,
        &heading(styled, "Install + start Belay as a service now?"),
        true,
    )?;

    Ok(plan)
}

/// Run the setup wizard. Pure prompt logic — reads answers from `input`,
/// writes prompts to `output`, and returns the resulting `SetupPlan`. NO side
/// effects: this function never writes files, spawns processes, or touches
/// the network; it only decides what a caller should later do.
///
/// - `opts.yes` (non-interactive quick defaults): returns the Quick plan
///   WITHOUT reading a single byte from `input`.
/// - `!opts.interactive && !opts.yes` (piped, no `--yes`): prints actionable
///   guidance to `output` and returns a `Default` plan — never reads
///   `input` (never hangs on a pipe that will never answer).
/// - otherwise (interactive): asks Quick vs Custom, then walks the chosen
///   flow - Quick (every detected agent, firewall/ssh-guard on, install the
///   service, plus optional skippable AI/messaging prompts) or Custom
///   (`custom_plan`, a prompt per capability).
pub fn run_setup<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    opts: &SetupOpts,
) -> anyhow::Result<SetupPlan> {
    let home = opts.home.as_deref().and_then(|p| p.to_str());

    if opts.yes {
        return Ok(quick_plan(home));
    }

    if !opts.interactive {
        writeln!(output, "{NON_INTERACTIVE_GUIDANCE}")?;
        return Ok(SetupPlan::default());
    }

    let styled = opts.styled;

    // Question one, before Quick-vs-Custom: everything printed after this
    // point should already be in the chosen language. The question itself is
    // bilingual out of necessity - the operator has not picked a language yet,
    // so it cannot be asked in only one of them.
    let lang = prompt_choice(
        output,
        input,
        &heading(styled, "Choose your language / 选择语言"),
        &LOCALE_OPTIONS.iter().map(|(_, label)| *label).collect::<Vec<_>>(),
        0,
    )?;
    let locale = LOCALE_OPTIONS[lang].0.to_string();

    let mode = prompt_choice(
        output,
        input,
        &heading(styled, "How would you like to set up Belay?"),
        &[
            "Quick setup (recommended) — protect agents, enable firewall, install service",
            "Custom — choose each option",
        ],
        0,
    )?;

    if mode == 1 {
        let mut plan = custom_plan(input, output, home, styled)?;
        plan.locale = locale;
        return Ok(plan);
    }

    let mut plan = quick_plan(home);
    plan.locale = locale;

    let names = plan.protect_agents.join(", ");
    let question = format!(
        "Protect these {} detected agent{}: {names}?",
        plan.protect_agents.len(),
        if plan.protect_agents.len() == 1 {
            ""
        } else {
            "s"
        },
    );
    let confirmed = prompt_yes_no(output, input, &heading(styled, &question), true)?;
    if !confirmed {
        plan.protect_agents.clear();
    }

    // Quick still offers the two "important but optional" capabilities - AI
    // explanations and a messaging channel - as skippable gated prompts
    // (default: skip). Pressing Enter keeps Quick fast; opting in expands into
    // the same detail the Custom flow walks. Everything else stays a Quick
    // default (firewall/ssh/service on, enrichment/scan off).
    plan.ai = prompt_ai_gated(input, output, styled)?;
    plan.channels = prompt_channel(input, output, styled)?;

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn empty_home() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn yes_returns_quick_plan_without_reading_input() {
        let mut input = Cursor::new(&b"this must never be read\nnor this\n"[..]);
        let mut output: Vec<u8> = Vec::new();
        let home = empty_home();
        let opts = SetupOpts {
            yes: true,
            interactive: false,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        assert!(plan.firewall);
        assert!(plan.install_service);
        assert!(plan.ssh_guard);
        assert!(plan.ai.is_none());
        assert!(plan.channels.is_none());
        // The defining behavior: --yes must not read a single byte from input.
        assert_eq!(input.position(), 0, "run_setup read from input under --yes");
    }

    #[test]
    fn interactive_quick_path_selects_quick_and_confirms_agents() {
        let mut input = Cursor::new(&b"1\n1\ny\n"[..]);
        let mut output: Vec<u8> = Vec::new();
        let home = empty_home();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        assert!(plan.install_service);
        assert!(plan.firewall);
    }

    #[test]
    fn interactive_quick_path_with_empty_lines_uses_defaults() {
        let mut input = Cursor::new(&b"\n\n\n"[..]);
        let mut output: Vec<u8> = Vec::new();
        let home = empty_home();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        assert!(plan.install_service);
        assert!(plan.firewall);
    }

    #[test]
    fn interactive_quick_path_offers_optional_ai_and_messaging() {
        // Quick, confirm agents, then opt IN to AI (local) and a Telegram
        // channel - the two optional prompts the Quick flow now surfaces.
        let mut input = Cursor::new(
            &b"1\n1\n\
               y\n\
               y\n1\nllama3\n\
               y\n1\nbot-tok\n42\n"[..],
        );
        // 1=English, 1=Quick, y=confirm agents, y=set-up-AI 1=Local llama3=model,
        // y=connect-channel 1=Telegram bot-tok=token 42=chat id.
        let mut output: Vec<u8> = Vec::new();
        let home = empty_home();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        // Quick defaults still hold.
        assert!(plan.firewall);
        assert!(plan.install_service);
        // AI opted in (local Ollama).
        let ai = plan.ai.expect("ai set");
        assert_eq!(ai.mode, "local");
        assert_eq!(ai.provider, "ollama");
        assert_eq!(ai.model, "llama3");
        // Messaging opted in (Telegram).
        let ch = plan.channels.expect("channel set");
        assert_eq!(ch.platform, "telegram");
        assert_eq!(ch.fields["bot_token"], "bot-tok");
        assert_eq!(ch.fields["chat_id"], "42");
    }

    #[test]
    fn interactive_quick_path_skips_ai_and_messaging_by_default() {
        // Quick, confirm agents, press Enter through both optional prompts ->
        // neither AI nor a channel is configured (the fast default path).
        let mut input = Cursor::new(&b"1\n1\ny\n\n\n"[..]);
        let mut output: Vec<u8> = Vec::new();
        let home = empty_home();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        assert!(plan.install_service);
        assert!(plan.ai.is_none());
        assert!(plan.channels.is_none());
    }

    #[test]
    fn heading_wraps_in_bold_only_when_styled() {
        assert_eq!(heading(false, "Firewall?"), "Firewall?");
        assert_eq!(heading(true, "Firewall?"), "\x1b[1mFirewall?\x1b[0m");
    }

    #[test]
    fn default_cloud_model_covers_every_listed_provider() {
        // Every provider the wizard offers must have a non-empty default so the
        // Model prompt is never blank; an unknown provider falls back to "".
        for p in CLOUD_PROVIDERS {
            assert!(
                !default_cloud_model(p).is_empty(),
                "provider {p} has no default model"
            );
        }
        assert_eq!(default_cloud_model("minimax"), "MiniMax-M2");
        assert_eq!(default_cloud_model("openai"), "gpt-4o-mini");
        assert_eq!(default_cloud_model("does-not-exist"), "");
    }

    #[test]
    fn cloud_empty_model_uses_provider_default() {
        // Select minimax, press Enter at the Model prompt (empty), give a key,
        // consent -> the model must be the provider default, not "".
        let mut input = Cursor::new(&b"12\n\nsk-test\ny\n"[..]);
        let mut output: Vec<u8> = Vec::new();
        let choice = build_ai_cloud(&mut input, &mut output)
            .expect("build_ai_cloud")
            .expect("consented choice");
        assert_eq!(choice.provider, "minimax");
        assert_eq!(choice.model, "MiniMax-M2");
        assert!(!choice.model.is_empty());
    }

    #[test]
    fn cloud_explicit_model_overrides_default() {
        // Typing a model still wins over the provider default.
        let mut input = Cursor::new(&b"1\ngpt-4o-mini\nsk-test\ny\n"[..]);
        let mut output: Vec<u8> = Vec::new();
        let choice = build_ai_cloud(&mut input, &mut output)
            .expect("build_ai_cloud")
            .expect("consented choice");
        assert_eq!(choice.provider, "openai");
        assert_eq!(choice.model, "gpt-4o-mini");
    }

    #[test]
    fn non_interactive_without_yes_prints_guidance_and_does_not_read() {
        let mut input = Cursor::new(&b"this must never be read"[..]);
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: false,
            home: None,
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        assert_eq!(plan, SetupPlan::default());
        assert_eq!(
            input.position(),
            0,
            "non-interactive path must not read input"
        );
        let printed = String::from_utf8(output).expect("utf8 output");
        assert!(
            printed.contains(NON_INTERACTIVE_GUIDANCE),
            "expected guidance in output, got: {printed}"
        );
    }

    #[test]
    fn prompt_yes_no_empty_line_uses_default() {
        let mut input = Cursor::new(&b"\n"[..]);
        let mut output: Vec<u8> = Vec::new();
        assert!(prompt_yes_no(&mut output, &mut input, "q?", true).unwrap());

        let mut input = Cursor::new(&b"\n"[..]);
        assert!(!prompt_yes_no(&mut output, &mut input, "q?", false).unwrap());
    }

    #[test]
    fn prompt_yes_no_parses_y_and_n_case_insensitively() {
        let mut output: Vec<u8> = Vec::new();

        let mut input = Cursor::new(&b"y\n"[..]);
        assert!(prompt_yes_no(&mut output, &mut input, "q?", false).unwrap());

        let mut input = Cursor::new(&b"YES\n"[..]);
        assert!(prompt_yes_no(&mut output, &mut input, "q?", false).unwrap());

        let mut input = Cursor::new(&b"n\n"[..]);
        assert!(!prompt_yes_no(&mut output, &mut input, "q?", true).unwrap());

        let mut input = Cursor::new(&b"NO\n"[..]);
        assert!(!prompt_yes_no(&mut output, &mut input, "q?", true).unwrap());
    }

    #[test]
    fn prompt_yes_no_unrecognized_input_uses_default() {
        let mut output: Vec<u8> = Vec::new();
        let mut input = Cursor::new(&b"maybe\n"[..]);
        assert!(prompt_yes_no(&mut output, &mut input, "q?", true).unwrap());
        let mut input = Cursor::new(&b"maybe\n"[..]);
        assert!(!prompt_yes_no(&mut output, &mut input, "q?", false).unwrap());
    }

    /// `manage` cannot depend on the daemon crate, so `LOCALE_OPTIONS`
    /// duplicates `host_config::SUPPORTED_LOCALES`. If the two drift, the
    /// wizard offers a language the daemon will refuse to persist, and setup
    /// ends with the operator's pick silently discarded. Read the daemon's
    /// list from source so this fails on the drift itself.
    #[test]
    fn locale_options_match_the_daemons_supported_list() {
        let src = include_str!("../../daemon/src/host_config.rs");
        let line = src
            .lines()
            .find(|l| l.contains("SUPPORTED_LOCALES"))
            .expect("daemon lost SUPPORTED_LOCALES");
        for (tag, _) in LOCALE_OPTIONS {
            assert!(
                line.contains(&format!("\"{tag}\"")),
                "wizard offers {tag}, daemon's SUPPORTED_LOCALES does not: {line}"
            );
        }
        assert_eq!(
            line.matches('"').count() / 2,
            LOCALE_OPTIONS.len(),
            "daemon supports a locale the wizard never offers: {line}"
        );
    }

    /// Language is question ONE. Answering `2` selects Chinese, and the plan
    /// carries it through the Quick flow to the caller that persists it.
    #[test]
    fn language_is_the_first_question_and_reaches_the_plan() {
        let home = empty_home();
        let mut output: Vec<u8> = Vec::new();
        // 2 = 中文, 1 = Quick, y = protect, then skip AI + channel prompts.
        let mut input = Cursor::new(&b"2\n1\ny\n\n\n"[..]);
        let plan = run_setup(
            &mut input,
            &mut output,
            &SetupOpts {
                interactive: true,
                home: Some(home.path().to_path_buf()),
                ..Default::default()
            },
        )
        .expect("wizard");
        assert_eq!(plan.locale, "zh-Hans");

        let printed = String::from_utf8(output).expect("utf8");
        let lang_at = printed.find("选择语言").expect("no language prompt");
        let mode_at = printed.find("How would you like").expect("no mode prompt");
        assert!(lang_at < mode_at, "language must be asked first:\n{printed}");
    }

    /// `--yes` answers nothing, so it must not invent a language.
    #[test]
    fn non_interactive_plans_default_to_english() {
        let home = empty_home();
        let mut input = Cursor::new(&b""[..]);
        let mut output: Vec<u8> = Vec::new();
        let plan = run_setup(
            &mut input,
            &mut output,
            &SetupOpts {
                yes: true,
                home: Some(home.path().to_path_buf()),
                ..Default::default()
            },
        )
        .expect("wizard");
        assert_eq!(plan.locale, DEFAULT_LOCALE);
        assert_eq!(SetupPlan::default().locale, DEFAULT_LOCALE);
    }

    #[test]
    fn prompt_choice_empty_line_uses_default_idx() {
        let mut output: Vec<u8> = Vec::new();
        let mut input = Cursor::new(&b"\n"[..]);
        let idx = prompt_choice(&mut output, &mut input, "pick", &["a", "b", "c"], 2).unwrap();
        assert_eq!(idx, 2);
    }

    #[test]
    fn prompt_choice_valid_number_selects_that_index() {
        let mut output: Vec<u8> = Vec::new();
        let mut input = Cursor::new(&b"2\n"[..]);
        let idx = prompt_choice(&mut output, &mut input, "pick", &["a", "b", "c"], 0).unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn prompt_choice_garbage_uses_default_idx() {
        let mut output: Vec<u8> = Vec::new();
        let mut input = Cursor::new(&b"garbage\n"[..]);
        let idx = prompt_choice(&mut output, &mut input, "pick", &["a", "b", "c"], 1).unwrap();
        assert_eq!(idx, 1);

        let mut input = Cursor::new(&b"99\n"[..]);
        let idx = prompt_choice(&mut output, &mut input, "pick", &["a", "b", "c"], 1).unwrap();
        assert_eq!(idx, 1);

        let mut input = Cursor::new(&b"0\n"[..]);
        let idx = prompt_choice(&mut output, &mut input, "pick", &["a", "b", "c"], 1).unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn prompt_line_empty_uses_default_nonempty_keeps_value() {
        let mut output: Vec<u8> = Vec::new();
        let mut input = Cursor::new(&b"\n"[..]);
        assert_eq!(
            prompt_line(&mut output, &mut input, "q?", "default").unwrap(),
            "default"
        );

        let mut input = Cursor::new(&b"x\n"[..]);
        assert_eq!(
            prompt_line(&mut output, &mut input, "q?", "default").unwrap(),
            "x"
        );
    }

    #[test]
    fn prompt_secret_reads_a_line() {
        let mut output: Vec<u8> = Vec::new();
        let mut input = Cursor::new(&b"sk-test-123\n"[..]);
        assert_eq!(
            prompt_secret(&mut output, &mut input, "API key").unwrap(),
            "sk-test-123"
        );
    }

    // ── Task 2: Custom path ──────────────────────────────────────────────────

    #[test]
    fn custom_run_cloud_with_consent_builds_plan() {
        let home = empty_home();
        std::fs::create_dir_all(home.path().join(".claude")).expect("seed .claude dir");

        let script = concat!(
            "1\n",               // Language -> English
            "2\n",               // Quick vs Custom -> Custom
            "y\n",               // Protect claude-code? -> yes
            "y\n",               // Firewall? -> yes
            "y\n",               // SSH guard? -> yes
            "3\n",               // AI explanations? -> Cloud
            "2\n",               // Cloud provider? -> anthropic
            "claude-sonnet-5\n", // Model
            "sk-x\n",            // API key
            "y\n",               // Consent? -> yes
            "n\n",               // Net enrichment? -> no
            "y\n",               // Scheduled vuln scan? -> yes
            "n\n",               // Connect a messaging channel now? -> no
            "n\n",               // Install service now? -> no
        );
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");

        assert_eq!(plan.protect_agents, vec!["claude-code".to_string()]);
        assert!(plan.firewall);
        assert!(plan.ssh_guard);
        assert_eq!(
            plan.ai,
            Some(AiChoice {
                mode: "cloud".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-sonnet-5".to_string(),
                base_url: None,
                cloud_consent: true,
                key: Some("sk-x".to_string()),
                skill_judge_enabled: false,
                skill_judge_gate_enabled: false,
                skill_judge_model: None,
            })
        );
        assert!(!plan.netenrich);
        assert!(plan.scan_schedule);
        assert!(plan.channels.is_none());
        assert!(!plan.install_service);
    }

    #[test]
    fn custom_run_cloud_without_consent_does_not_save_ai() {
        let home = empty_home();
        // No agent dirs are seeded in this tempdir, but `find_agents` may
        // still detect an agent whose CLI happens to be on *this* machine's
        // $PATH (e.g. `claude`) — so answer "protect it" for however many the
        // real detector finds, rather than assuming zero, to stay hermetic
        // across environments.
        let agent_answers = "y\n".repeat(find_agents(home.path().to_str()).len());
        let script =
            format!("1\n2\n{agent_answers}y\ny\n3\n2\nclaude-sonnet-5\nsk-x\nn\nn\nn\nn\nn\n");
        // 1=English, 2=Custom, [per-agent y], y=firewall, y=ssh-guard, 3=AI->Cloud,
        // 2=provider->anthropic, model, key, n=consent, n=netenrich,
        // n=scan-schedule, n=channel, n=install-service.
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");

        assert!(plan.ai.is_none(), "cloud without consent must not be saved");
        let printed = String::from_utf8(output).expect("utf8 output");
        assert!(
            printed.to_lowercase().contains("consent"),
            "expected a consent-required note in output, got: {printed}"
        );
    }

    #[test]
    fn custom_run_declines_agent_protection() {
        let home = empty_home();
        std::fs::create_dir_all(home.path().join(".claude")).expect("seed .claude dir");

        let script = concat!(
            "1\n", // Language -> English
            "2\n", // Custom
            "n\n", // Protect claude-code? -> NO
            "y\n", // Firewall
            "y\n", // SSH guard
            "1\n", // AI -> Off
            "n\n", // Net enrichment
            "n\n", // Scheduled vuln scan
            "n\n", // Channel
            "n\n", // Install service
        );
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");

        assert!(
            plan.protect_agents.is_empty(),
            "declined agent must not be in the plan"
        );
        assert!(plan.ai.is_none());
    }

    #[test]
    fn custom_run_scan_schedule_yes_sets_plan_true() {
        let home = empty_home();
        let agent_answers = "y\n".repeat(find_agents(home.path().to_str()).len());
        // 1=English, 2=Custom, [per-agent y], y=firewall, y=ssh-guard, 1=AI->Off,
        // n=netenrich, y=scheduled vuln scan. Everything after (channel,
        // install-service) hits EOF and falls back to defaults.
        let script = format!("1\n2\n{agent_answers}y\ny\n1\nn\ny\n");
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        assert!(plan.scan_schedule);
    }

    #[test]
    fn custom_run_scan_schedule_no_sets_plan_false() {
        let home = empty_home();
        let agent_answers = "y\n".repeat(find_agents(home.path().to_str()).len());
        // Same as above but declines the scheduled vuln scan.
        let script = format!("1\n2\n{agent_answers}y\ny\n1\nn\nn\n");
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");
        assert!(!plan.scan_schedule);
    }

    #[test]
    fn custom_run_connects_telegram_channel() {
        let home = empty_home();
        // See the comment in `custom_run_cloud_without_consent_does_not_save_ai`:
        // answer "protect it" for however many agents this machine's `$PATH`
        // makes `find_agents` detect, rather than assuming zero.
        let agent_answers = "y\n".repeat(find_agents(home.path().to_str()).len());
        let script = format!("1\n2\n{agent_answers}y\ny\n1\nn\nn\ny\n1\ntg-token\n12345\ny\n");
        // 1=English, 2=Custom, [per-agent y], y=firewall, y=ssh-guard, 1=AI->Off,
        // n=netenrich, n=scan-schedule, y=connect channel, 1=platform->Telegram,
        // bot token, chat id, y=install-service.
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");

        let chan = plan.channels.expect("a channel must have been chosen");
        assert_eq!(chan.platform, "telegram");
        assert_eq!(chan.fields["bot_token"], "tg-token");
        assert_eq!(chan.fields["chat_id"], "12345");

        let (platform, fields) = channel_config(&chan);
        assert_eq!(platform, "telegram");
        assert_eq!(fields["chat_id"], "12345");
    }

    #[test]
    fn custom_run_connects_discord_channel_and_warns_about_intent() {
        let home = empty_home();
        let agent_answers = "y\n".repeat(find_agents(home.path().to_str()).len());
        // ...same as the Telegram case but 2=platform->Discord, then token + channel id.
        let script = format!("1\n2\n{agent_answers}y\ny\n1\nn\nn\ny\n2\ndc-token\nD999\ny\n");
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");

        let chan = plan.channels.expect("a channel must have been chosen");
        assert_eq!(chan.platform, "discord");
        assert_eq!(chan.fields["bot_token"], "dc-token");
        assert_eq!(chan.fields["channel_id"], "D999");

        let out = String::from_utf8(output).expect("utf8");
        assert!(
            out.contains("Message Content Intent"),
            "the Discord path must warn about the #1 setup trap, got: {out}"
        );
        assert!(
            out.contains("default-deny"),
            "channel setup must state the default-deny safety framing"
        );
    }

    #[test]
    fn custom_run_telegram_blank_bot_token_omits_the_key() {
        let home = empty_home();
        // See the comment in `custom_run_cloud_without_consent_does_not_save_ai`:
        // answer "protect it" for however many agents this machine's `$PATH`
        // makes `find_agents` detect, rather than assuming zero.
        let agent_answers = "y\n".repeat(find_agents(home.path().to_str()).len());
        let script = format!("1\n2\n{agent_answers}y\ny\n1\nn\nn\ny\n1\n\n12345\ny\n");
        // 1=English, 2=Custom, [per-agent y], y=firewall, y=ssh-guard, 1=AI->Off,
        // n=netenrich, n=scan-schedule, y=connect channel, 1=platform->Telegram,
        // ""=bot token left BLANK (means "keep the existing secret"),
        // chat id=12345, y=install-service.
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let opts = SetupOpts {
            yes: false,
            interactive: true,
            home: Some(home.path().to_path_buf()),
            styled: false,
        };
        let plan = run_setup(&mut input, &mut output, &opts).expect("run_setup");

        let chan = plan.channels.expect("a channel must have been chosen");
        assert_eq!(chan.platform, "telegram");
        // The blank bot_token must be OMITTED entirely (not written as "") —
        // `config_set_channel` merges by key, so a present-but-empty key
        // would overwrite (blank) a previously-stored token, while an
        // ABSENT key leaves it untouched.
        assert!(
            chan.fields.get("bot_token").is_none(),
            "blank bot_token must be omitted so config_set_channel preserves the stored token, got fields: {:?}",
            chan.fields
        );
        assert_eq!(chan.fields["chat_id"], "12345");
    }

    #[test]
    fn ai_config_args_builds_the_expected_json_shape() {
        let choice = AiChoice {
            mode: "cloud".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-sonnet-5".to_string(),
            base_url: None,
            cloud_consent: true,
            key: Some("sk-x".to_string()),
            skill_judge_enabled: false,
            skill_judge_gate_enabled: false,
            skill_judge_model: None,
        };
        let args = ai_config_args(&choice);
        assert_eq!(args["mode"], "cloud");
        assert_eq!(args["provider"], "anthropic");
        assert_eq!(args["model"], "claude-sonnet-5");
        assert_eq!(args["cloud_consent"], true);
        // The secret key never rides along in the ai.json-shaped args.
        assert!(args.get("key").is_none());
    }

    #[test]
    fn ai_config_args_includes_base_url_when_set() {
        let choice = AiChoice {
            mode: "local".to_string(),
            provider: "ollama".to_string(),
            model: "qwen2.5".to_string(),
            base_url: Some("http://localhost:11434".to_string()),
            cloud_consent: false,
            key: None,
            skill_judge_enabled: false,
            skill_judge_gate_enabled: false,
            skill_judge_model: None,
        };
        let args = ai_config_args(&choice);
        assert_eq!(args["base_url"], "http://localhost:11434");
    }

    #[test]
    fn ai_config_args_emits_judge_fields() {
        let choice = AiChoice {
            mode: "cloud".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-haiku-4-5".to_string(),
            base_url: None,
            cloud_consent: true,
            key: Some("sk-x".to_string()),
            skill_judge_enabled: true,
            skill_judge_gate_enabled: false,
            skill_judge_model: Some("claude-sonnet-5".to_string()),
        };
        let args = ai_config_args(&choice);
        assert_eq!(args["skill_judge_enabled"], true);
        assert_eq!(args["skill_judge_gate_enabled"], false);
        assert_eq!(args["skill_judge_model"], "claude-sonnet-5");
    }

    #[test]
    fn ai_config_args_omits_judge_model_when_none() {
        let choice = AiChoice {
            mode: "local".to_string(),
            provider: "ollama".to_string(),
            model: "qwen2.5".to_string(),
            base_url: None,
            cloud_consent: false,
            key: None,
            skill_judge_enabled: false,
            skill_judge_gate_enabled: false,
            skill_judge_model: None,
        };
        let args = ai_config_args(&choice);
        assert_eq!(args["skill_judge_enabled"], false);
        assert!(args.get("skill_judge_model").is_none());
    }
}
