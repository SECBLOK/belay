# Transport peer-auth: test coverage & manual verification

The Windows named-pipe peer-authentication boundary (`Stream::peer_uid`) is
covered by automated tests in `src/lib.rs` (`#[cfg(all(test, windows))]`):

| Test | Proves |
|---|---|
| `same_user_roundtrip_and_peer_uid_matches` | The full ALLOW plumbing end-to-end over a live pipe: `ImpersonateNamedPipeClient` → `OpenThreadToken` → `GetTokenInformation(TokenUser)` → `EqualSid` → `Ok(0)`. |
| `distinct_sids_denied_equal_sids_allowed` | The DENY branch of the SID-equality decision (`token_user_sids_match`) with a genuinely different, well-formed SID (S-1-5-18 vs S-1-1-0), plus fail-closed on an undersized buffer. |
| `dacl_present_protected_and_no_everyone` | The created pipe's DACL is present, protected, and contains no `Everyone` (S-1-1-0) ACE. |

The Unix path (`SO_PEERCRED` / `getpeereid`) is covered by
`unix_roundtrip_and_peer_uid_is_self` and runs on Linux + macOS in CI.

## LocalSystem peer-auth relaxation (Task A)

When the daemon runs as LocalSystem (the Phase 3 SCM service), `peer_uid`
additionally accepts the SID of the user logged into the active console
session — see the module doc on `mod imp` and the
`windows-localsystem-sid-relaxation-brief.md`. Coverage:

| Test | Proves |
|---|---|
| `client_authorized_six_cases` | All 6 mandatory cases: direct match always wins; the console-user relaxation applies ONLY when `is_system` is true and a console user is known; wrong-user / no-console-user / malformed-buffer all deny. |
| `is_local_system_detects_and_rejects` | LocalSystem SID detection, incl. fail-closed (not-SYSTEM) on a too-short buffer. |
| `sid_to_string_round_trips_well_known_sid` | The raw-SID → SDDL-string conversion (`ConvertSidToStringSidW` + buffer read + `LocalFree`) against a fixed, well-known SID. |
| `build_dacl_sddl_appends_extra_ace_only_when_present` | The DACL SDDL string composition: `None` reproduces the static 3-ACE DACL byte-for-byte; `Some(sid)` appends exactly one more ACE. |
| `dacl_with_extra_user_ace_has_exactly_four_aces_no_everyone` | Applies the extended DACL to a **real** pipe and asserts exactly 4 ACEs (the 3 static ones + the extra user), still no `Everyone` ACE. |

All five run on Windows CI without a live console session or SYSTEM context —
they exercise the SID-membership/DACL-shape *logic* with synthetic well-known
SIDs (the same technique as `distinct_sids_denied_equal_sids_allowed` above).

### Live console-session path — ALLOW side verified ✅

`active_console_user_sid` (`WTSGetActiveConsoleSessionId` / `WTSQueryUserToken`)
and `is_local_system` gating a **real** LocalSystem process cannot be exercised
by the automated suite (CI has no interactive console session, and the daemon
test process does not run as LocalSystem), so this required a manual pass on a
real host:

> **console-path-verified-on: `ALDI-DENNIS`**, commit `5a766fc`
> (`feat/windows-scm-phase3`, rebased onto `feat/daemon-transport-seam` @
> `a4a0a82` — includes both the Phase 3 SCM code and this Task A relaxation).
> Installed the SCM service (`belay install-service --enable`, elevated) —
> confirmed `RUNNING`, `AUTO_START`, `SERVICE_START_NAME: LocalSystem` via
> `sc.exe query`/`sc.exe qc`. From the ordinary, non-admin, interactively
> logged-in console user (a separate, non-elevated process), connected over
> `\\.\pipe\belayd.sock` and sent a `get_posture` command frame: `connect()`
> succeeded (the DACL granted the console-user ACE) and the daemon replied
> `{"protection":"on"}` (`peer_uid()` authorized via the console-user branch of
> `client_authorized`, since this client is neither SYSTEM nor Administrator).
> Both the DACL grant (D3) and the peer_uid accept (D4) are confirmed live.

**Still open:** the cross-account DENY side (a second, non-console user/session
being rejected) was not exercised — that needs provisioning a second local
account, a more invasive change than this pass covered. The deny *logic* itself
is already proven deterministically by `client_authorized_six_cases` (case c:
SYSTEM + a different user denied) and the existing DACL/`EqualSid` DENY tests
below; only the live cross-account path remains a manual gap.

## Documented manual gap: end-to-end cross-*account* DENY

A true second-account client traversing the live impersonation path to hit the
DENY branch is **not automated**, by design:

- The pipe DACL is **protected with no `Everyone` ACE**, so a foreign account is
  refused by the **DACL at `CreateFile`** (`ERROR_ACCESS_DENIED`) **before** the
  connection ever reaches `ImpersonateNamedPipeClient` and the SID comparison.
  An automated cross-account test would therefore pass for the wrong reason
  (proving the ACL, not the `EqualSid` deny branch). Widening the DACL to force
  the connection through would mutate the very security descriptor under test.
- GitHub-hosted Windows runners cannot reliably perform a non-interactive
  second-account logon (interactive-logon-right error 1385); this is only viable
  on a self-hosted runner.

The deny *logic* is therefore proven deterministically in CI
(`distinct_sids_denied_equal_sids_allowed`), and the identical plumbing is proven
by the same-user ALLOW round-trip. To verify the full cross-account path by hand:

> On a Windows host, run `belayd` as user A. From a second standard account
> B, temporarily grant B `FILE_GENERIC_READ | FILE_GENERIC_WRITE` on the pipe's
> DACL and connect. Expect `peer_uid()` to return
> `PermissionDenied: "pipe client SID != daemon SID"`. Revert the DACL change
> afterward.
