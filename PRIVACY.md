<!--
  TEMPLATE — pending review by a qualified lawyer/privacy adviser before publishing.
  This statement must always match what the software ACTUALLY does. If you add any
  network call, telemetry field, or hosted service, update this document in the
  same change. For a security tool, an inaccurate privacy statement is worse than
  none — it destroys the trust the product depends on.
-->

# Belay Privacy & Telemetry Statement

**Effective date:** 30 June 2026
**Published by:** Secblok Pty Ltd ("Secblok", "we", "us")
**Contact:** hello@secblok.io — https://www.secblok.io/

Belay is a security tool that watches what AI coding agents do on your
machine. Because it can see your commands, files, and secrets, we hold ourselves
to a strict standard: **local-first, and no phone-home by default.** This document
explains exactly what the software does and does not do with your data.

## 1. Principles

1. **Local-first.** The free, open-source Belay runs entirely on your own
   machine. Its decisions (allow / ask / deny), its session state, and its audit
   log are computed and stored locally.
2. **No phone-home by default.** Out of the box, Belay does not send your
   activity, code, file contents, commands, prompts, or secrets to Secblok or any
   third party.
3. **Opt-in, not opt-out.** Any feature that transmits data off your machine is
   off until you explicitly turn it on, and this document describes what it sends.
4. **Data minimisation.** Where you do opt in, we collect the least we can to
   provide the feature, and never the contents of your files, commands, or prompts.

## 2. What stays on your machine (and is never transmitted)

The following are processed and stored **locally only**, under your home directory
(for example `~/.belay/`), and are never sent to Secblok:

- The contents of your files, source code, environment variables, or secrets.
- The text of the commands, tool calls, or prompts your AI agent runs.
- Your local audit log (the hash-chained record of allow/ask/deny verdicts).
- Your rules configuration and allowlists.

Belay reads these only to make a local security decision. They do not leave
your device through Belay.

## 3. Optional telemetry (off by default)

To help us understand adoption and prioritise work, Belay MAY offer an
**opt-in** telemetry signal. If — and only if — you enable it, it sends a minimal,
periodic, pseudonymous message containing approximately:

- Belay version and edition;
- operating system and architecture (e.g. "linux x86_64");
- a randomly generated install identifier (not tied to your name);
- coarse counts of activity (e.g. number of verdicts), **never their contents**;
- optionally, if you choose to provide it for organisation/enterprise features,
  your work email domain (e.g. "example.com") — never your full email or files.

Telemetry never includes file contents, command text, prompts, secrets, file
paths, IP-derived location beyond what is inherent to any network request, or any
field not listed above. You can leave it off, and you can turn it off at any time;
when off, no telemetry is sent.

## 4. Update and rule-feed checks

If you enable update checks or subscribe to a managed rule feed, Belay
contacts a Secblok or CDN endpoint to retrieve the latest version or rule pack.
Such a request necessarily includes your IP address and basic request metadata
(as with any download). It does not include your activity data. If these checks
are disabled, no such request is made.

## 5. The paid fleet / management plane

The proprietary fleet, central-management, and compliance components are
**self-hosted by the customer**. Audit and policy data sent from agents to a
fleet server stay within the **customer's own infrastructure**; Secblok does not
receive that data. If Secblok ever offers a Secblok-hosted version of this plane,
it will be governed by a separate, clearly-disclosed agreement and is not covered
by this statement.

## 6. Third parties

We do not sell your data, and we do not share it with advertisers. We use service
providers only as needed to operate (for example, a CDN to distribute releases and
rule packs, and—if you contact us—email). These providers process only what is
necessary for that function.

## 7. Your rights

Depending on where you live, you may have rights to access, correct, or delete
personal information we hold about you, and to withdraw consent to optional
telemetry. Because the free product is local-first, most of "your data" never
reaches us in the first place. To exercise a right or ask a question, contact
hello@secblok.io.

We handle personal information in line with the Australian Privacy Act 1988 (Cth)
and the Australian Privacy Principles, and we aim to honour the equivalent rights
of users in other regions (such as the EU/UK GDPR) where they apply.

## 8. Children

Belay is a developer tool and is not directed at children. We do not
knowingly collect personal information from children.

## 9. Changes to this statement

If we change what the software collects or transmits, we will update this document
in the same release and revise the effective date above. Material changes will be
noted in the project's release notes.

## 10. Contact

Questions, requests, or privacy concerns: **hello@secblok.io**
Secblok Pty Ltd — https://www.secblok.io/
