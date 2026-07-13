// Credential-content signatures. Flags leaked secrets by key FORMAT /
// private-key headers in file content. The patterns are synthetic matchers for
// well-known, PUBLIC credential formats (e.g. the AWS "AKIA" key prefix, PEM
// "BEGIN ... PRIVATE KEY" headers, provider token shapes) — public facts also
// used by tools such as gitleaks and detect-secrets — not real secrets and not
// copied from any identifiable third-party rule file.

rule LeakedAwsKey
{
    meta:
        description = "Detects an AWS access key id"
        severity = "HIGH"
        rule_id = "secrets.aws_key"
    strings:
        $a = /AKIA[0-9A-Z]{16}/
    condition:
        $a
}

rule LeakedAnthropicKey
{
    meta:
        description = "Detects an Anthropic API key"
        severity = "CRITICAL"
        rule_id = "secrets.anthropic_key"
    strings:
        $a = /sk-ant-[A-Za-z0-9\-]{20,}/
    condition:
        $a
}

rule LeakedGitHubToken
{
    meta:
        description = "Detects a GitHub personal access / app token"
        severity = "HIGH"
        rule_id = "secrets.github_token"
    strings:
        $a = /gh[pousr]_[A-Za-z0-9]{36,}/
    condition:
        $a
}

rule PrivateKeyHeader
{
    meta:
        description = "Detects a private key file header"
        severity = "CRITICAL"
        rule_id = "secrets.private_key"
    strings:
        $a = "BEGIN OPENSSH PRIVATE KEY"
        $b = "BEGIN RSA PRIVATE KEY"
        $c = "BEGIN EC PRIVATE KEY"
        $d = "BEGIN PGP PRIVATE KEY BLOCK"
    condition:
        any of them
}
