//! Cross-platform local IPC transport for Belay.
//!
//! - **Unix** wraps `std::os::unix::net` directly, so behaviour is byte-for-byte
//!   identical to the daemon's existing unix-socket control channel (same
//!   `0700` parent / `0600` socket lockdown, same `SO_PEERCRED`/`getpeereid`
//!   peer check).
//! - **Windows** uses raw Win32 named pipes (`\\.\pipe\<name>`), blocking, to
//!   match the daemon's synchronous thread-per-connection model. The pipe is
//!   created with an explicit *protected* DACL (owner + SYSTEM + Administrators;
//!   NO Everyone) and `PIPE_REJECT_REMOTE_CLIENTS`.
//!
//! [`Stream::peer_uid`] is the trust boundary. On Unix it returns the connected
//! peer's UID (Linux `SO_PEERCRED`, macOS `getpeereid(2)`). On Windows it
//! impersonates the client, reads the client token's user SID, and returns
//! `Ok(0)` only when it equals the daemon's own token-user SID (pairing with
//! [`own_uid`]`() == 0`); ANY Win32 error or SID mismatch returns `Err`, so a
//! caller that authorizes on `peer_uid()` fails closed.
//!
//! **LocalSystem relaxation.** When the daemon runs as LocalSystem (the
//! Windows Service Control Manager path — Phase 3), `client SID == own SID`
//! alone would reject every ordinary user, since `own` is then the LocalSystem
//! SID. In that specific case — and *only* then — the pipe DACL additionally
//! grants, and `peer_uid` additionally accepts, the SID of the user logged into
//! the active console session (never a group, never `Everyone`). A non-SYSTEM
//! daemon's trust is never widened; see [`imp::client_authorized`] (Windows-only).

#[cfg(unix)]
mod imp {
    use std::io::{self, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    /// A bound local listener.
    pub struct Listener(UnixListener);
    /// A single accepted/connected duplex stream.
    pub struct Stream(UnixStream);

    /// Bind a unix-domain socket at `addr`, locked to the owner: the parent dir
    /// is created `0700` if we make it, and the socket itself is `0600`.
    /// Fail-closed — returns an error rather than exposing an unprotected socket.
    pub fn bind(addr: &str) -> io::Result<Listener> {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let _ = std::fs::remove_file(addr);
        if let Some(parent) = std::path::Path::new(addr).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
                std::fs::set_permissions(parent, Permissions::from_mode(0o700))?;
            }
        }
        let listener = UnixListener::bind(addr)?;
        std::fs::set_permissions(addr, Permissions::from_mode(0o600))?;
        Ok(Listener(listener))
    }

    /// Connect to a listener bound at `addr`.
    pub fn connect(addr: &str) -> io::Result<Stream> {
        Ok(Stream(UnixStream::connect(addr)?))
    }

    impl Listener {
        /// Block until a peer connects; returns the accepted [`Stream`].
        pub fn accept(&self) -> io::Result<Stream> {
            let (stream, _addr) = self.0.accept()?;
            Ok(Stream(stream))
        }
    }

    impl Stream {
        /// The connected peer's effective UID (Linux `SO_PEERCRED`).
        #[cfg(target_os = "linux")]
        pub fn peer_uid(&self) -> io::Result<u32> {
            use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
            let creds = getsockopt(&self.0, PeerCredentials).map_err(io::Error::other)?;
            Ok(creds.uid())
        }

        /// The connected peer's effective UID (macOS/BSD `getpeereid(2)`).
        #[cfg(not(target_os = "linux"))]
        pub fn peer_uid(&self) -> io::Result<u32> {
            let (uid, _gid) = nix::unistd::getpeereid(&self.0).map_err(io::Error::other)?;
            Ok(uid.as_raw())
        }
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
}

#[cfg(windows)]
mod imp {
    //! Windows named-pipe transport with a protected DACL + client-SID peer check.
    //!
    //! Two-layer trust boundary. First, the pipe is created with an explicit
    //! *protected* DACL (owner + SYSTEM + Administrators, full access; NO
    //! Everyone / Authenticated Users) and `PIPE_REJECT_REMOTE_CLIENTS`, so only
    //! a same-user (or admin) LOCAL process can even open it. Second, on accept
    //! the server impersonates the client, reads the client token's user SID,
    //! and compares it (`EqualSid`) to the daemon's own token-user SID — anything
    //! but an exact match, or ANY Win32 error, denies.
    //!
    //! Fail-closed: every error path returns `Err`, and `RevertToSelf` runs on
    //! every path after impersonation via a drop guard.
    //!
    //! **LocalSystem relaxation** (only when this process's own token-user SID
    //! is the well-known LocalSystem SID, i.e. running as a Windows service):
    //! the DACL additionally grants, and `peer_uid` additionally accepts, the
    //! SID of the user logged into the *active console session* — resolved via
    //! `WTSGetActiveConsoleSessionId`/`WTSQueryUserToken` fresh on every
    //! bind/accept/peer_uid call (never cached), so a logged-off user's SID is
    //! never honored and a newly logged-in user needs no service restart. Any
    //! failure to resolve SYSTEM-ness or the console user degrades to "grant no
    //! extra user" — never a hard error, and never widens a non-SYSTEM daemon's
    //! trust.
    use std::io::{self, Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetTokenInformation, RevertToSelf, TokenUser,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, WaitNamedPipeW,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT,
    };
    // WTSGetActiveConsoleSessionId/WTSQueryUserToken: resolve the active
    // console-session user's token for the LocalSystem peer-auth relaxation.
    use windows_sys::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

    // GENERIC_READ/GENERIC_WRITE live under different modules across windows-sys
    // point releases; define them locally to avoid an import that drifts.
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    /// Protected DACL: owner + SYSTEM + Administrators, full access; NO Everyone.
    const SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";
    const PIPE_BUF: u32 = 64 * 1024;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Map a logical address (a unix-style path on the daemon side) to a Windows
    /// pipe path: `\\.\pipe\<basename>`.
    fn pipe_path(addr: &str) -> Vec<u16> {
        let base = std::path::Path::new(addr)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| addr.to_string());
        wide(&format!(r"\\.\pipe\{base}"))
    }

    /// A bound named-pipe listener. Each `accept()` creates a fresh secured pipe
    /// instance, so there is no pre-arm race to manage.
    pub struct Listener {
        path: Vec<u16>,
        first: AtomicBool,
    }
    /// A connected duplex pipe stream. Owns the pipe `HANDLE` via `File`
    /// (gives `Read`/`Write` and `Drop` = `CloseHandle`).
    pub struct Stream(std::fs::File);

    /// True iff `s` looks like a well-formed SID string (`S-<revision>-<auth>-
    /// <sub>...`, e.g. `S-1-5-18`): starts with `S-`, followed only by ASCII
    /// digits and hyphens. Defense-in-depth for [`build_dacl_sddl`]: today's
    /// only caller (`resolve_console_user_sid_string`) always supplies
    /// OS-produced output from `ConvertSidToStringSidW`, which is always in
    /// this shape — but this guards against a future caller splicing an
    /// untrusted string into the DACL SDDL (e.g. via a stray `)` breaking out
    /// of the ACE and injecting an extra one).
    pub(crate) fn looks_like_sid_string(s: &str) -> bool {
        match s.strip_prefix("S-") {
            Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-'),
            None => false,
        }
    }

    /// Build the DACL SDDL string: the static owner+SYSTEM+Administrators ACL,
    /// plus one extra full-control ACE for `extra_user_sid` (already in
    /// `S-1-5-...` string form) when present. Pure string logic — split out so
    /// the DACL *shape* is unit-testable without a live SYSTEM context or a real
    /// console session (see `resolve_console_user_sid_string`, which supplies
    /// the real value only when this process is running as LocalSystem).
    /// Fail-safe: a malformed `extra_user_sid` (see [`looks_like_sid_string`])
    /// is silently dropped — the static DACL, not an injected/corrupt one.
    pub(crate) fn build_dacl_sddl(extra_user_sid: Option<&str>) -> String {
        match extra_user_sid {
            Some(sid) if looks_like_sid_string(sid) => format!("{SDDL}(A;;FA;;;{sid})"),
            _ => SDDL.to_string(),
        }
    }

    /// Convert an SDDL DACL string into `SECURITY_ATTRIBUTES`. Caller MUST
    /// `LocalFree` the returned descriptor pointer after the pipe is created.
    /// Fail-closed: any conversion failure returns `Err`.
    pub(crate) unsafe fn security_attributes_for_sddl(
        sddl: &str,
    ) -> io::Result<(SECURITY_ATTRIBUTES, *mut core::ffi::c_void)> {
        let mut psd: *mut core::ffi::c_void = ptr::null_mut();
        let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            ptr::null_mut(),
        );
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        Ok((sa, psd))
    }

    /// True iff `own_buf` (a `TOKEN_USER` buffer as produced by
    /// [`own_token_user_sid`]) is the well-known LocalSystem SID (`S-1-5-18`) —
    /// i.e. this process is running as a Windows service under LocalSystem. Only
    /// when this is true does the console-user relaxation apply (gates both the
    /// extra DACL ACE and `peer_uid`'s extra accept branch); a non-SYSTEM daemon
    /// must never widen its own trust. Fail-closed: any failure to build the
    /// comparison SID returns `false` (not SYSTEM ⇒ no relaxation, the
    /// conservative default).
    pub(crate) unsafe fn is_local_system(own_buf: &[u8]) -> bool {
        if own_buf.len() < core::mem::size_of::<TOKEN_USER>() {
            return false;
        }
        let mut sid_buf = [0u8; 68]; // SECURITY_MAX_SID_SIZE
        let mut len = sid_buf.len() as u32;
        if CreateWellKnownSid(
            WinLocalSystemSid,
            ptr::null_mut(),
            sid_buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut len,
        ) == 0
        {
            return false;
        }
        let own_tu = own_buf.as_ptr() as *const TOKEN_USER;
        EqualSid((*own_tu).User.Sid, sid_buf.as_mut_ptr() as *mut core::ffi::c_void) != 0
    }

    /// This process's own token-user SID plus whether it is LocalSystem,
    /// resolved once and cached for the process's lifetime — unlike the
    /// console-session user (which genuinely can change while the process runs
    /// and is deliberately re-resolved fresh on every call), a process's own
    /// primary token identity cannot change after creation, so caching it here
    /// is a pure efficiency win with zero correctness cost: it removes a
    /// repeated `OpenProcessToken`/`GetTokenInformation` round trip from every
    /// `bind()`/`accept()`/`peer_uid()` call on the common (non-SYSTEM) path.
    /// Only the success case is cached: a transient failure to read our own
    /// token is retried on the next call rather than remembered as permanent.
    static OWN_IDENTITY: std::sync::OnceLock<(Vec<u8>, bool)> = std::sync::OnceLock::new();

    unsafe fn own_identity() -> io::Result<&'static (Vec<u8>, bool)> {
        if let Some(cached) = OWN_IDENTITY.get() {
            return Ok(cached);
        }
        let own = own_token_user_sid()?;
        let is_system = is_local_system(&own);
        Ok(OWN_IDENTITY.get_or_init(|| (own, is_system)))
    }

    /// Resolve the active console session's user, as a `TOKEN_USER` buffer (same
    /// shape [`token_user_sid`] produces elsewhere, so it compares directly with
    /// [`token_user_sids_match`]/[`client_authorized`]). Returns `None` if there
    /// is no active console session, or any step fails — fail-safe: `None`
    /// means "grant/accept no user", never an error to propagate. Re-resolved
    /// fresh on every call (never cached) so a logged-off user's SID is never
    /// honored and a newly logged-in user needs no service restart.
    unsafe fn active_console_user_sid() -> Option<Vec<u8>> {
        let session_id = WTSGetActiveConsoleSessionId();
        if session_id == u32::MAX {
            // 0xFFFFFFFF: no active console session.
            return None;
        }
        let mut token: HANDLE = ptr::null_mut();
        if WTSQueryUserToken(session_id, &mut token) == 0 {
            return None;
        }
        token_user_sid(token).ok()
    }

    /// Convert a raw SID pointer to its SDDL string form (`S-1-5-...`), for
    /// embedding in a dynamically-built DACL SDDL string via
    /// [`build_dacl_sddl`]. Frees the buffer `ConvertSidToStringSidW` allocates
    /// via `LocalFree`. Fail-closed: any conversion failure returns `Err`.
    pub(crate) unsafe fn sid_to_string(sid: *mut core::ffi::c_void) -> io::Result<String> {
        let mut pwstr: windows_sys::core::PWSTR = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut pwstr) == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *pwstr.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(pwstr, len));
        LocalFree(pwstr as *mut core::ffi::c_void);
        Ok(s)
    }

    /// Resolve the extra DACL ACE's SID string: `Some(sid_string)` only when
    /// this process is running as LocalSystem AND an active console-session
    /// user can be resolved. `None` for everything else (not SYSTEM, no console
    /// user, or any resolution failure along the way) — fail-safe: `None` means
    /// "no extra grant", never a hard bind/accept error.
    unsafe fn resolve_console_user_sid_string() -> Option<String> {
        if !own_identity().ok()?.1 {
            return None;
        }
        let console_user = active_console_user_sid()?;
        if console_user.len() < core::mem::size_of::<TOKEN_USER>() {
            return None;
        }
        let tu = console_user.as_ptr() as *const TOKEN_USER;
        sid_to_string((*tu).User.Sid).ok()
    }

    /// Build `SECURITY_ATTRIBUTES` for the current bind/accept, including the
    /// LocalSystem console-user relaxation when applicable (see the module
    /// docs). Caller MUST `LocalFree` the returned descriptor pointer after the
    /// pipe is created. Fail-closed.
    unsafe fn security_attributes() -> io::Result<(SECURITY_ATTRIBUTES, *mut core::ffi::c_void)> {
        let sddl = build_dacl_sddl(resolve_console_user_sid_string().as_deref());
        security_attributes_for_sddl(&sddl)
    }

    pub fn bind(addr: &str) -> io::Result<Listener> {
        // Surface SD-construction errors eagerly (parity with the Unix bind,
        // which fails at bind if it cannot lock the socket down).
        unsafe {
            let (_sa, psd) = security_attributes()?;
            LocalFree(psd);
        }
        Ok(Listener {
            path: pipe_path(addr),
            first: AtomicBool::new(true),
        })
    }

    impl Listener {
        pub fn accept(&self) -> io::Result<Stream> {
            unsafe {
                let (sa, psd) = security_attributes()?;
                let first = self.first.swap(false, Ordering::SeqCst);
                let mut open_mode = PIPE_ACCESS_DUPLEX;
                if first {
                    // First instance pins the name (anti-squat); first-only.
                    open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
                }
                let h = CreateNamedPipeW(
                    self.path.as_ptr(),
                    open_mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    PIPE_BUF,
                    PIPE_BUF,
                    0,
                    &sa,
                );
                LocalFree(psd);
                if h == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                // Block for a client. ERROR_PIPE_CONNECTED means a client already
                // connected before this call — that is success, not an error.
                if ConnectNamedPipe(h, ptr::null_mut()) == 0 {
                    let e = GetLastError();
                    if e != ERROR_PIPE_CONNECTED {
                        CloseHandle(h);
                        return Err(io::Error::from_raw_os_error(e as i32));
                    }
                }
                Ok(Stream(std::fs::File::from_raw_handle(h as RawHandle)))
            }
        }
    }

    impl Stream {
        /// Authorize the connected client: its token-user SID must equal the
        /// daemon's own token-user SID — OR, when the daemon is running as
        /// LocalSystem, the active console-session user's SID (see
        /// [`client_authorized`]). Returns `Ok(0)` on authorization (pairs with
        /// `own_uid() == 0`); `Err` on ANY failure or non-match. Fail-closed.
        pub fn peer_uid(&self) -> io::Result<u32> {
            unsafe {
                // Resolve our OWN identity — and, if we are LocalSystem, the
                // console user — BEFORE impersonating the client. This order is
                // load-bearing, not stylistic: `WTSQueryUserToken` requires
                // `SE_TCB_NAME`, which is checked against the calling THREAD's
                // effective token. Once `ImpersonateNamedPipeClient` below makes
                // that effective token the (typically unprivileged) client's
                // token, `WTSQueryUserToken` would fail with
                // `ERROR_PRIVILEGE_NOT_HELD` on every call — silently and
                // permanently defeating the relaxation for exactly the callers
                // it exists to authorize. `own_token_user_sid` reads the
                // PROCESS's primary token (via `GetCurrentProcess`), which is
                // unaffected by per-thread impersonation either way, but is
                // resolved here too so the whole "our own security context" read
                // happens as one block, before any impersonation begins.
                let identity = own_identity()?;
                let own = &identity.0;
                let is_system = identity.1;
                let console_user = if is_system { active_console_user_sid() } else { None };

                let h = self.0.as_raw_handle() as HANDLE;
                if ImpersonateNamedPipeClient(h) == 0 {
                    return Err(io::Error::last_os_error());
                }
                // RevertToSelf MUST run before returning, on every path.
                struct Revert;
                impl Drop for Revert {
                    fn drop(&mut self) {
                        unsafe {
                            RevertToSelf();
                        }
                    }
                }
                let _revert = Revert;

                let client = thread_token_user_sid()?;
                if client_authorized(&client, own, is_system, console_user.as_deref()) {
                    Ok(0)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pipe client SID != daemon SID",
                    ))
                }
            }
        }

        /// Test-only: the raw server-side pipe handle, for DACL inspection.
        #[cfg(test)]
        pub(crate) fn raw_handle(&self) -> RawHandle {
            self.0.as_raw_handle()
        }
    }

    /// Read `TokenUser` info from `token` into an owned buffer whose bytes begin
    /// with a `TOKEN_USER` (its `.User.Sid` points within the same allocation,
    /// stable for the `Vec`'s lifetime). Closes `token`. Fail-closed.
    unsafe fn token_user_sid(token: HANDLE) -> io::Result<Vec<u8>> {
        let mut len: u32 = 0;
        // First call discovers the required length (returns 0 / sets len).
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
        if len == 0 {
            let e = io::Error::last_os_error();
            CloseHandle(token);
            return Err(e);
        }
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            len,
            &mut len,
        );
        CloseHandle(token);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }

    unsafe fn thread_token_user_sid() -> io::Result<Vec<u8>> {
        let mut token: HANDLE = ptr::null_mut();
        // OpenAsSelf = FALSE: open the impersonation token (the client's).
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        token_user_sid(token)
    }

    unsafe fn own_token_user_sid() -> io::Result<Vec<u8>> {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        token_user_sid(token)
    }

    /// Pure SID-equality decision behind `peer_uid`, factored out so the DENY
    /// branch can be unit-tested without a second user account or a live pipe.
    /// Both args must be `TOKEN_USER` buffers as produced by `token_user_sid`.
    /// Fail-closed: a buffer too small to hold a `TOKEN_USER` yields `false`.
    pub(crate) fn token_user_sids_match(client_buf: &[u8], own_buf: &[u8]) -> bool {
        if client_buf.len() < core::mem::size_of::<TOKEN_USER>()
            || own_buf.len() < core::mem::size_of::<TOKEN_USER>()
        {
            return false; // fail-closed
        }
        unsafe {
            let client_tu = client_buf.as_ptr() as *const TOKEN_USER;
            let own_tu = own_buf.as_ptr() as *const TOKEN_USER;
            EqualSid((*client_tu).User.Sid, (*own_tu).User.Sid) != 0
        }
    }

    /// Pure decision behind `peer_uid`'s authorization — the single source of
    /// truth for "is this client allowed in", factored out so every case is
    /// unit-testable without a live pipe or a second user account. All SID
    /// arguments are `TOKEN_USER` buffers as produced by `token_user_sid`.
    ///
    /// Authorized iff `client == own`, OR (`is_system` AND a console user is
    /// known AND `client == console_user`). Fail-closed: any missing/malformed
    /// input denies. The console-user branch is unreachable unless `is_system`
    /// is true — a non-SYSTEM daemon's trust is never widened by this check.
    pub(crate) fn client_authorized(
        client_buf: &[u8],
        own_buf: &[u8],
        is_system: bool,
        console_user_buf: Option<&[u8]>,
    ) -> bool {
        if token_user_sids_match(client_buf, own_buf) {
            return true;
        }
        is_system
            && console_user_buf.is_some_and(|console| token_user_sids_match(client_buf, console))
    }

    pub fn connect(addr: &str) -> io::Result<Stream> {
        let path = pipe_path(addr);
        unsafe {
            loop {
                let h = CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    // Impersonation-level QoS. The server (daemon) must impersonate
                    // the client to read its token SID for authorization, which
                    // requires at least this level — Identification yields
                    // ERROR_BAD_IMPERSONATION_LEVEL from ImpersonateNamedPipeClient.
                    // Capped at Impersonation (no Delegation), and the pipe DACL +
                    // FIRST_PIPE_INSTANCE keep a rogue local server from ever
                    // receiving this connection.
                    SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                    ptr::null_mut(),
                );
                if h != INVALID_HANDLE_VALUE {
                    return Ok(Stream(std::fs::File::from_raw_handle(h as RawHandle)));
                }
                let e = GetLastError();
                if e == ERROR_PIPE_BUSY {
                    // All instances busy: wait for one to free, then retry.
                    if WaitNamedPipeW(path.as_ptr(), 5_000) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    continue;
                }
                return Err(io::Error::from_raw_os_error(e as i32));
            }
        }
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
}

pub use imp::{bind, connect, Listener, Stream};

/// The daemon's own identity for the peer-equality check.
///
/// Unix: the process UID. Windows: a sentinel `0` — the real boundary is the
/// pipe DACL plus the SID-equality enforced inside [`Stream::peer_uid`], which
/// returns `Ok(0)` only on a match. Pairing `own_uid() == 0` with that `Ok(0)`
/// keeps the daemon's `peer == owner` check correct and platform-agnostic.
#[cfg(unix)]
pub fn own_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

#[cfg(windows)]
pub fn own_uid() -> u32 {
    0
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::io::{self, Read, Write};
    use std::ptr;
    use std::time::Duration;

    fn addr_for(tag: &str) -> String {
        format!("belay-test-{}-{}.sock", std::process::id(), tag)
    }

    fn connect_retry(addr: &str) -> Stream {
        // bind() does not create the pipe; the server's accept() does. Retry
        // until the first instance exists.
        for _ in 0..400 {
            if let Ok(s) = connect(addr) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("client could not connect to {addr}");
    }

    /// Build a well-known SID into a fresh 68-byte (SECURITY_MAX_SID_SIZE)
    /// buffer. Shared by every synthetic-SID test below — none of these need a
    /// second user account or a live console session.
    unsafe fn well_known(kind: i32) -> Vec<u8> {
        use windows_sys::Win32::Security::CreateWellKnownSid;
        let mut sid = vec![0u8; 68];
        let mut len = sid.len() as u32;
        assert_ne!(
            CreateWellKnownSid(
                kind,
                ptr::null_mut(),
                sid.as_mut_ptr() as *mut core::ffi::c_void,
                &mut len,
            ),
            0,
            "CreateWellKnownSid failed"
        );
        sid.truncate(len as usize);
        sid
    }

    /// Wrap a raw SID in a `TOKEN_USER` buffer; `.User.Sid` points past the
    /// header, matching what `token_user_sid()` produces at runtime.
    unsafe fn as_token_user(sid: &[u8]) -> Vec<u8> {
        use windows_sys::Win32::Security::TOKEN_USER;
        let off = core::mem::size_of::<TOKEN_USER>();
        let mut buf = vec![0u8; off + sid.len()];
        buf[off..].copy_from_slice(sid);
        let tu = buf.as_mut_ptr() as *mut TOKEN_USER;
        (*tu).User.Sid = buf[off..].as_ptr() as *mut core::ffi::c_void;
        buf
    }

    #[test]
    fn own_uid_is_zero() {
        assert_eq!(own_uid(), 0);
    }

    /// Same-user round-trip: exercises ImpersonateNamedPipeClient + EqualSid for
    /// real (client and server share this process's identity, so the SID matches).
    #[test]
    fn same_user_roundtrip_and_peer_uid_matches() {
        let addr = addr_for("roundtrip");
        let listener = bind(&addr).expect("bind");
        let caddr = addr.clone();
        let client = std::thread::spawn(move || {
            let mut c = connect_retry(&caddr);
            c.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            c.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"pong");
        });
        let mut s = listener.accept().expect("accept");
        assert_eq!(s.peer_uid().expect("peer_uid"), 0, "same-user peer must authorize");
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        s.write_all(b"pong").unwrap();
        client.join().unwrap();
    }

    /// The regression guard: assert the created pipe's DACL is present, protected,
    /// and contains NO Everyone (S-1-1-0) ACE — i.e. it did not silently fall back
    /// to the fail-open default security descriptor.
    #[test]
    fn dacl_present_protected_and_no_everyone() {
        use std::ptr;
        use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, EqualSid, GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE,
            ACL, DACL_SECURITY_INFORMATION, SE_DACL_PRESENT, SE_DACL_PROTECTED, WinWorldSid,
        };

        let addr = addr_for("dacl");
        let listener = bind(&addr).expect("bind");
        let caddr = addr.clone();
        let client = std::thread::spawn(move || {
            let _c = connect_retry(&caddr);
            std::thread::sleep(Duration::from_millis(200));
        });
        let s = listener.accept().expect("accept");

        unsafe {
            let h = s.raw_handle() as HANDLE;
            let mut pdacl: *mut ACL = ptr::null_mut();
            let mut psd: *mut core::ffi::c_void = ptr::null_mut();
            let rc = GetSecurityInfo(
                h,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut pdacl,
                ptr::null_mut(),
                &mut psd,
            );
            assert_eq!(rc, 0, "GetSecurityInfo failed: {rc}");
            assert!(!pdacl.is_null(), "DACL must be present (null DACL = grant-all)");

            let mut control: u16 = 0;
            let mut revision: u32 = 0;
            assert_ne!(
                GetSecurityDescriptorControl(psd, &mut control, &mut revision),
                0,
                "GetSecurityDescriptorControl failed"
            );
            assert_ne!(control & SE_DACL_PRESENT, 0, "DACL must be present");
            assert_ne!(control & SE_DACL_PROTECTED, 0, "DACL must be protected");

            // Everyone (S-1-1-0); assert no ACE references it.
            let mut everyone = [0u8; 68]; // SECURITY_MAX_SID_SIZE
            let mut elen = everyone.len() as u32;
            assert_ne!(
                CreateWellKnownSid(
                    WinWorldSid,
                    ptr::null_mut(),
                    everyone.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut elen
                ),
                0,
                "CreateWellKnownSid(WinWorldSid) failed"
            );

            for i in 0..(*pdacl).AceCount as u32 {
                let mut pace: *mut core::ffi::c_void = ptr::null_mut();
                assert_ne!(GetAce(pdacl, i, &mut pace), 0, "GetAce failed");
                let ace = pace as *const ACCESS_ALLOWED_ACE;
                let sid = ptr::addr_of!((*ace).SidStart) as *mut core::ffi::c_void;
                assert_eq!(
                    EqualSid(sid, everyone.as_mut_ptr() as *mut core::ffi::c_void),
                    0,
                    "DACL must NOT contain an Everyone (S-1-1-0) ACE"
                );
            }
            LocalFree(psd);
        }
        client.join().unwrap();
    }

    /// GAP-2 closure: the DENY branch of the SID-equality check, exercised with a
    /// genuinely different, well-formed SID and no second account. Deterministic on
    /// every machine (S-1-5-18 can never equal S-1-1-0). A true cross-*account*
    /// runtime test is a documented manual gap — see transport/TESTING.md — because
    /// the protected pipe DACL rejects a foreign SID at CreateFile before the SID
    /// check runs, and hosted CI cannot do a non-interactive second-account logon.
    #[test]
    fn distinct_sids_denied_equal_sids_allowed() {
        use crate::imp::token_user_sids_match;
        use windows_sys::Win32::Security::{WinLocalSystemSid, WinWorldSid};

        unsafe {
            let system = as_token_user(&well_known(WinLocalSystemSid)); // S-1-5-18
            let everyone = as_token_user(&well_known(WinWorldSid)); // S-1-1-0
            let everyone2 = as_token_user(&well_known(WinWorldSid));

            // DENY: a real, different client SID must be rejected.
            assert!(
                !token_user_sids_match(&system, &everyone),
                "distinct SIDs (S-1-5-18 vs S-1-1-0) must be denied"
            );
            // ALLOW: equal SIDs accepted (logic mirror of the same-user round-trip).
            assert!(
                token_user_sids_match(&everyone, &everyone2),
                "identical SIDs must be allowed"
            );
            // Fail-closed: a buffer too small to hold a TOKEN_USER denies.
            assert!(
                !token_user_sids_match(&[0u8; 1], &everyone),
                "buffer smaller than TOKEN_USER must fail closed"
            );
        }
    }

    // ── LocalSystem peer-auth relaxation ─────────────────────────────────────
    //
    // These exercise the SID-membership logic (`client_authorized`,
    // `is_local_system`, `build_dacl_sddl`, `sid_to_string`) with synthetic
    // well-known SIDs — no second user account and no live console session
    // needed, so they run on Windows CI. The *live* console-session resolution
    // (`active_console_user_sid`, real SYSTEM context) is verified on a real
    // Windows host with a logged-in user (see the brief/hand-off doc).

    /// The 6 mandatory `client_authorized` cases (brief section 5): direct
    /// match always wins; the console-user relaxation applies ONLY when
    /// `is_system` is true and a console user is known; every other input
    /// (wrong user, no console user, malformed buffer) denies.
    #[test]
    fn client_authorized_six_cases() {
        use crate::imp::client_authorized;
        use windows_sys::Win32::Security::{
            WinAuthenticatedUserSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, WinWorldSid,
        };

        unsafe {
            let own_system = as_token_user(&well_known(WinLocalSystemSid));
            let own_not_system = as_token_user(&well_known(WinBuiltinAdministratorsSid));
            let console_user = as_token_user(&well_known(WinAuthenticatedUserSid));
            let other_user = as_token_user(&well_known(WinWorldSid));

            // (a) client == own -> authorized, regardless of is_system.
            assert!(
                client_authorized(&own_system, &own_system, false, Some(&console_user)),
                "client==own must authorize (is_system=false)"
            );
            assert!(
                client_authorized(&own_system, &own_system, true, Some(&console_user)),
                "client==own must authorize (is_system=true)"
            );

            // (b) is_system + client == console_user -> authorized.
            assert!(
                client_authorized(&console_user, &own_system, true, Some(&console_user)),
                "SYSTEM + client==console_user must authorize"
            );

            // (c) is_system + client == some other user -> denied.
            assert!(
                !client_authorized(&other_user, &own_system, true, Some(&console_user)),
                "SYSTEM + client==other must deny"
            );

            // (d) NOT is_system + client == console_user -> denied. The
            // relaxation must be unreachable for a non-SYSTEM daemon.
            assert!(
                !client_authorized(&console_user, &own_not_system, false, Some(&console_user)),
                "a non-SYSTEM daemon must never accept the console-user relaxation"
            );

            // (e) console_user == None + client != own -> denied.
            assert!(
                !client_authorized(&other_user, &own_system, true, None),
                "no console user known => only `own` is authorized"
            );

            // (f) short/garbage buffer -> denied (fail-closed).
            assert!(
                !client_authorized(&[0u8; 1], &own_system, true, Some(&console_user)),
                "a too-short client buffer must fail closed"
            );
        }
    }

    /// `is_local_system` detects the well-known LocalSystem SID and rejects
    /// everything else, including a too-short buffer (fail-closed: not-SYSTEM
    /// is the conservative default, so the relaxation stays gated off).
    #[test]
    fn is_local_system_detects_and_rejects() {
        use crate::imp::is_local_system;
        use windows_sys::Win32::Security::{WinLocalSystemSid, WinWorldSid};

        unsafe {
            let system = as_token_user(&well_known(WinLocalSystemSid));
            let not_system = as_token_user(&well_known(WinWorldSid));
            assert!(is_local_system(&system), "LocalSystem SID must be detected as SYSTEM");
            assert!(
                !is_local_system(&not_system),
                "a non-LocalSystem SID must not be detected as SYSTEM"
            );
            assert!(
                !is_local_system(&[0u8; 1]),
                "a too-short buffer must fail closed (treated as not-SYSTEM)"
            );
        }
    }

    /// `sid_to_string` round-trips a well-known SID to its fixed SDDL string
    /// form — exercises the real `ConvertSidToStringSidW` FFI call (including
    /// the buffer read + `LocalFree`) without needing a live console session.
    #[test]
    fn sid_to_string_round_trips_well_known_sid() {
        use crate::imp::sid_to_string;
        use windows_sys::Win32::Security::WinAuthenticatedUserSid;

        unsafe {
            let mut sid = well_known(WinAuthenticatedUserSid);
            let s = sid_to_string(sid.as_mut_ptr() as *mut core::ffi::c_void)
                .expect("sid_to_string");
            assert_eq!(s, "S-1-5-11", "Authenticated Users has a fixed SDDL string form");
        }
    }

    /// `build_dacl_sddl` appends exactly one extra ACE when given a SID string,
    /// and is byte-identical to the static DACL when given `None` — the
    /// non-SYSTEM / no-console-user path must be unchanged.
    #[test]
    fn build_dacl_sddl_appends_extra_ace_only_when_present() {
        use crate::imp::build_dacl_sddl;

        assert_eq!(
            build_dacl_sddl(None),
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            "no extra user => the static DACL, unchanged"
        );
        assert_eq!(
            build_dacl_sddl(Some("S-1-5-11")),
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-11)",
            "an extra user appends exactly one more full-control ACE"
        );
    }

    /// Defense-in-depth: a malformed "SID" string (not produced by
    /// `ConvertSidToStringSidW`, e.g. containing SDDL metacharacters that could
    /// break out of the `(A;;FA;;;{sid})` ACE template) is silently dropped —
    /// `build_dacl_sddl` falls back to the static DACL rather than splicing it
    /// in. `looks_like_sid_string` is the guard.
    #[test]
    fn build_dacl_sddl_rejects_malformed_extra_sid() {
        use crate::imp::{build_dacl_sddl, looks_like_sid_string};

        for bad in [")(A;;FA;;;WD)", "not-a-sid", "", "S-", "S-1-5-1a"] {
            assert!(!looks_like_sid_string(bad), "must reject: {bad:?}");
            assert_eq!(
                build_dacl_sddl(Some(bad)),
                "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
                "a malformed extra SID must fall back to the static DACL: {bad:?}"
            );
        }
        assert!(looks_like_sid_string("S-1-5-18"), "a real SID string must be accepted");
    }

    /// DACL assertion (brief section 5): apply the extended DACL
    /// (`build_dacl_sddl(Some(..))`) to a real pipe and assert it contains
    /// exactly 4 ACEs — the 3 static ones plus the extra user — and still NO
    /// Everyone ACE. Uses Authenticated Users (a fixed, well-known SID string,
    /// `S-1-5-11`) as a convenient stand-in for "the one extra user SID"; real
    /// production code only ever plugs in a resolved individual user SID
    /// (`resolve_console_user_sid_string`), never a group — this test proves
    /// the SDDL-building + DACL-application *mechanics*, not that a group would
    /// ever be granted in practice.
    #[test]
    fn dacl_with_extra_user_ace_has_exactly_four_aces_no_everyone() {
        use crate::imp::{build_dacl_sddl, security_attributes_for_sddl};
        use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
        use windows_sys::Win32::Security::{
            EqualSid, GetAce, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
            WinAuthenticatedUserSid, WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
        };
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        };

        const EXTRA_SID_STRING: &str = "S-1-5-11"; // Authenticated Users, fixed form.
        let sddl = build_dacl_sddl(Some(EXTRA_SID_STRING));
        let name: Vec<u16> = format!(r"\\.\pipe\belay-test-dacl4-{}", std::process::id())
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let (sa, psd) = security_attributes_for_sddl(&sddl).expect("security_attributes_for_sddl");
            let h = CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            );
            LocalFree(psd);
            assert_ne!(h, INVALID_HANDLE_VALUE, "CreateNamedPipeW failed: {}", io::Error::last_os_error());

            let mut pdacl: *mut ACL = ptr::null_mut();
            let mut psd2: *mut core::ffi::c_void = ptr::null_mut();
            let rc = GetSecurityInfo(
                h as HANDLE,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut pdacl,
                ptr::null_mut(),
                &mut psd2,
            );
            assert_eq!(rc, 0, "GetSecurityInfo failed: {rc}");
            assert!(!pdacl.is_null(), "DACL must be present");
            assert_eq!(
                (*pdacl).AceCount, 4,
                "expected exactly 4 ACEs (OW, SY, BA, + the one extra user)"
            );

            let mut everyone = [0u8; 68];
            let mut elen = everyone.len() as u32;
            assert_ne!(
                windows_sys::Win32::Security::CreateWellKnownSid(
                    WinWorldSid,
                    ptr::null_mut(),
                    everyone.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut elen,
                ),
                0
            );
            let mut extra = [0u8; 68];
            let mut xlen = extra.len() as u32;
            assert_ne!(
                windows_sys::Win32::Security::CreateWellKnownSid(
                    WinAuthenticatedUserSid,
                    ptr::null_mut(),
                    extra.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut xlen,
                ),
                0
            );

            let mut saw_extra = false;
            for i in 0..(*pdacl).AceCount as u32 {
                let mut pace: *mut core::ffi::c_void = ptr::null_mut();
                assert_ne!(GetAce(pdacl, i, &mut pace), 0, "GetAce failed");
                let ace = pace as *const ACCESS_ALLOWED_ACE;
                let sid = ptr::addr_of!((*ace).SidStart) as *mut core::ffi::c_void;
                assert_eq!(
                    EqualSid(sid, everyone.as_mut_ptr() as *mut core::ffi::c_void),
                    0,
                    "DACL must NOT contain an Everyone (S-1-1-0) ACE"
                );
                if EqualSid(sid, extra.as_mut_ptr() as *mut core::ffi::c_void) != 0 {
                    saw_extra = true;
                }
            }
            assert!(saw_extra, "expected an ACE granting the extra user SID");

            LocalFree(psd2);
            CloseHandle(h as HANDLE);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn unix_roundtrip_and_peer_uid_is_self() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.sock");
        let addr = path.to_str().unwrap().to_string();

        let listener = bind(&addr).expect("bind");

        // Socket is locked to the owner (0600).
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be 0600");

        let client_addr = addr.clone();
        let client = std::thread::spawn(move || {
            let mut c = connect(&client_addr).expect("connect");
            c.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            c.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"pong");
        });

        let mut s = listener.accept().expect("accept");
        // The peer is this same process, so the same UID.
        assert_eq!(s.peer_uid().expect("peer_uid"), nix::unistd::getuid().as_raw());
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        s.write_all(b"pong").unwrap();

        client.join().unwrap();
    }
}
