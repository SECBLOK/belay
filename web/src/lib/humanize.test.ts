import { it, expect } from "vitest";
import { humanizeRule, verdictWord, describeAction } from "./humanize";

it("verdictWord maps deny→Blocked, ask→Waiting, allow→Allowed", () => {
  expect(verdictWord("deny")).toBe("Blocked");
  expect(verdictWord("ask")).toBe("Waiting");
  expect(verdictWord("allow")).toBe("Allowed");
});

it("verdictWord passes through unknown verdicts unchanged", () => {
  expect(verdictWord("unknown")).toBe("unknown");
});

// Every prefix in the shared rule→plain-English map must produce the correct label.
it("maps rce.* prefix to 'Tried to run system code'", () => {
  expect(humanizeRule("rce.shell_exec")).toBe("Tried to run system code");
  expect(humanizeRule("rce")).toBe("Tried to run system code");
});
it("maps destructive.* prefix", () => {
  expect(humanizeRule("destructive.rm_rf")).toBe("Tried a destructive action (delete/wipe)");
});
it("maps secrets.* prefix", () => {
  expect(humanizeRule("secrets.aws_credentials")).toBe("Tried to read your credentials or passwords");
});
it("maps egress.* prefix", () => {
  expect(humanizeRule("egress.new")).toBe("Tried to send data off your computer");
});
it("maps persist and persistence prefixes", () => {
  expect(humanizeRule("persist.cron")).toBe("Tried to install itself permanently");
  expect(humanizeRule("persistence.startup")).toBe("Tried to install itself permanently");
});
it("maps recon.* prefix", () => {
  expect(humanizeRule("recon.host_enum")).toBe("Scanned your system");
});
it("maps tamper.* prefix", () => {
  expect(humanizeRule("tamper.firewall_off")).toBe("Tried to change security settings");
});
it("maps taint.* prefix", () => {
  expect(humanizeRule("taint.sink")).toBe("Moved sensitive data toward the network/execution");
});
it("maps mcp.* prefix", () => {
  expect(humanizeRule("mcp.suspicious")).toBe("Suspicious AI-tool description");
});
it("maps correlate.* prefix", () => {
  expect(humanizeRule("correlate.lethal_trifecta")).toBe("Combined risky steps in one session");
});
it("maps bypass.* prefix", () => {
  expect(humanizeRule("bypass.av")).toBe("Tried to bypass protection");
});
it("maps posture.* prefix", () => {
  expect(humanizeRule("posture.weak_perms")).toBe("A security weakness on your computer");
});
it("falls back for unknown prefixes", () => {
  expect(humanizeRule("supply.install")).toBe("An action that needs your review");
  expect(humanizeRule("")).toBe("An action that needs your review");
  expect(humanizeRule("unknown.thing")).toBe("An action that needs your review");
});
it("is case-insensitive on the prefix", () => {
  expect(humanizeRule("RCE.something")).toBe("Tried to run system code");
  expect(humanizeRule("Secrets.aws")).toBe("Tried to read your credentials or passwords");
});

// ── describeAction (System A) ──────────────────────────────────────────────
it("describeAction reads a file by basename", () => {
  expect(describeAction({ tool: "Read", input: { file_path: "src/lib/api.ts" } }))
    .toBe("Read api.ts");
});
it("describeAction edits a file by basename", () => {
  expect(describeAction({ tool: "Edit", input: { file_path: "rules/catalog.yaml" } }))
    .toBe("Edited catalog.yaml");
});
it("describeAction writes a new file as 'Created'", () => {
  expect(describeAction({ tool: "Write", input: { file_path: "tests/x.py" } }))
    .toBe("Created x.py");
});
it("describeAction maps Bash build commands", () => {
  expect(describeAction({ tool: "Bash", input: { command: "cargo build --release" } }))
    .toBe("Ran a build command");
});
it("describeAction maps Bash test commands before build", () => {
  expect(describeAction({ tool: "Bash", input: { command: "cargo test" } }))
    .toBe("Ran the tests");
});
it("describeAction maps git status to version-history phrasing", () => {
  expect(describeAction({ tool: "Bash", input: { command: "git status" } }))
    .toBe("Checked the project's version history");
});
it("describeAction maps ls to 'Listed files'", () => {
  expect(describeAction({ tool: "Bash", input: { command: "ls -la src/" } }))
    .toBe("Listed files");
});
it("describeAction names a skill, dropping its namespace", () => {
  expect(describeAction({ tool: "Skill", input: { command: "ecc:rust-review" } }))
    .toBe("Used the rust-review skill");
});
it("describeAction shows host-only for WebFetch", () => {
  expect(describeAction({ tool: "WebFetch", input: { url: "https://docs.rs/serde/?search=foo" } }))
    .toBe("Read a web page (docs.rs)");
});
it("describeAction prefers a real reason over the computed phrase", () => {
  expect(describeAction({ tool: "Read", reason: "reads .env", input: { file_path: "/x/.env" } }))
    .toBe("reads .env");
});
it("describeAction falls through 'no findings' to the computed phrase", () => {
  expect(describeAction({ tool: "Bash", reason: "no findings", input: { command: "cargo build" } }))
    .toBe("Ran a build command");
});
it("describeAction uses the first rule when no usable reason", () => {
  expect(describeAction({ tool: "Read", rules: ["secrets.aws_credentials"], input: {} }))
    .toBe("Tried to read your credentials or passwords");
});
it("describeAction falls back to 'Ran <Tool>' for unknown tools", () => {
  expect(describeAction({ tool: "Frobnicate", input: {} })).toBe("Ran Frobnicate");
});
