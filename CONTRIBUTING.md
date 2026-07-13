# Contributing to Belay

Thank you for your interest in contributing to Belay — a pure-Rust, open-core
AI-agent defense and EDR platform licensed under [AGPL-3.0](LICENSE).

---

## Table of Contents

1. [Licensing and legal requirements](#licensing-and-legal-requirements)
2. [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
3. [Dev setup](#dev-setup)
4. [Pull-request flow](#pull-request-flow)

---

## Licensing and legal requirements

Belay uses a **dual-licensing** model:

| Build surface | License |
|---|---|
| Default (open surface) | [AGPL-3.0](LICENSE) |
| Enterprise surface (`--features enterprise`) | [Commercial License](COMMERCIAL-LICENSE.md) |

Because contributions may be incorporated into both the AGPL and commercial editions,
every contributor **must** sign the [Contributor License Agreement (CLA)](CLA.md)
before their first contribution is merged. A CLA bot will check for a signed CLA on
every pull request. If the check fails, follow the bot's instructions to sign.

You must **also** add a Developer Certificate of Origin sign-off on every commit
(see the next section). Both requirements — CLA and DCO — are mandatory.

---

## Developer Certificate of Origin (DCO)

The [Developer Certificate of Origin (version 1.1)](https://developercertificate.org)
is a lightweight mechanism by which you certify that you wrote the code you are
contributing, or that you have the right to submit it under the project's open-source
license. It takes the form of a single trailer line appended to every commit message:

```
Signed-off-by: Your Name <your@email.com>
```

Add it automatically with `git commit -s` (or `git commit --signoff`). CI enforces
the `Signed-off-by` trailer on every commit in every pull request: any commit that
lacks it will cause the DCO check to fail and block the PR from merging. Use an email
address that matches your Git identity; if you commit on behalf of an employer or
need to attribute work to a legal entity, use the form required by your employer's
contribution policy.

---

## Dev setup

**Prerequisites:** a recent stable Rust toolchain (`rustup` recommended).

```bash
# Clone and build the open surface (default features)
git clone https://github.com/SECBLOK/belay.git
cd belay
cargo build

# Run tests
cargo test

# Build + test the enterprise surface
cargo build --features enterprise
cargo test --features enterprise
```

The default build compiles the open-core surface only. Passing `--features enterprise`
additionally compiles the enterprise-gated code (paid plane). CI runs both surfaces.

---

## Pull-request flow

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Write your code.** Keep changes focused; one logical change per PR.

3. **Make sure tests pass** before opening a PR:
   ```bash
   cargo test
   cargo clippy -- -D warnings
   ```

4. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/) style
   **and** sign off each commit:
   ```bash
   git commit -s -m "feat(scanner): add YARA rule hot-reload"
   ```
   Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`.

5. **Open a pull request** against `main`. Describe *what* changed and *why*.
   - The DCO bot will verify every commit carries a `Signed-off-by` trailer.
   - The CLA bot will verify you have a signed CLA on file. If not, it will guide
     you through the signing process.
   - CI runs `cargo test` and `cargo clippy` on both feature surfaces.

6. Respond to review feedback promptly; squash or rebase as requested by maintainers.

---

## Questions?

Open a [GitHub Discussion](https://github.com/SECBLOK/belay/discussions) or
file an issue. For security-sensitive reports, email **secblok@gmail.com** directly.

*Secblok Pty Ltd — building open, auditable AI-agent defense.*
