// Agentic-behavior signatures. Flags common AI-agent / shell-scripting attack
// patterns by TEXTUAL structure (curl/wget piped to a shell interpreter,
// base64 decode piped to execution, reads of well-known sensitive environment
// variable NAMES, credential values flowing into an outbound HTTP call, and
// risky unattended package-install invocations). These are first-party,
// AGPL-3.0-or-later rules: each pattern encodes a generic, publicly documented
// shell/CLI idiom (e.g. `curl ... | sh`, `os.environ["API_KEY"]`, `npx -y`) —
// not real secrets, and not copied from any identifiable third-party rule
// file or commercial signature pack.

rule PipeToShell
{
    meta:
        description = "Detects piping download to shell interpreter"
        severity = "CRITICAL"
        rule_id = "yara.pipe_to_shell"
    strings:
        $curl_pipe = /curl\s+[^\|]+\|\s*(ba|z)?sh/ nocase
        $wget_pipe = /wget\s+[^\|]+\|\s*(ba|z)?sh/ nocase
        $curl_python = /curl\s+[^\|]+\|\s*python/ nocase
    condition:
        any of them
}

rule Base64DecodeExec
{
    meta:
        description = "Detects base64 decode piped to execution"
        severity = "CRITICAL"
        rule_id = "yara.b64_exec"
    strings:
        $b64_sh = /base64\s+-d[^\|]*\|\s*(ba|z)?sh/ nocase
        $b64_exec = "base64.b64decode" nocase
        $eval_b64 = /eval\s+.*base64/ nocase
    condition:
        any of them
}

rule SuspiciousEnvAccess
{
    meta:
        description = "Detects access to sensitive environment variables"
        severity = "HIGH"
        rule_id = "yara.sensitive_env"
    strings:
        $aws_secret = "AWS_SECRET_ACCESS_KEY" nocase
        $aws_key = "AWS_ACCESS_KEY_ID" nocase
        $github_token = "GITHUB_TOKEN" nocase
        $api_key = /os\.environ\[["\'](\w+_)?(API_KEY|SECRET|TOKEN|PASSWORD)["\']/ nocase
    condition:
        any of them
}

rule CredentialExfil
{
    meta:
        description = "Detects potential credential exfiltration patterns"
        severity = "CRITICAL"
        rule_id = "yara.cred_exfil"
    strings:
        $cred_net = /(SECRET|TOKEN|PASSWORD|API_KEY).*requests\.(post|put)/ nocase
        $curl_data = /curl.*(-d|--data).*\$\w*(KEY|TOKEN|SECRET|PASSWORD)/ nocase
    condition:
        any of them
}

rule RiskyInstall
{
    meta:
        description = "Detects risky package installation patterns"
        severity = "HIGH"
        rule_id = "yara.risky_install"
    strings:
        $npx_y = "npx -y" nocase
        $pip_install = "pip install" nocase
        $curl_install = /curl.*install\.sh/ nocase
    condition:
        any of them
}
