//! Boot-start service generation + self-tamper protection.

/// Generate a systemd unit that runs the daemon as `user`, never root.
///
/// The daemon derives its socket and audit-log paths from `$HOME`
/// (`~/.belay/...`), and the per-user agent hook (running as that same
/// user) connects to and must own that socket. A root-run unit would bind
/// `/root/.belay`, which the hook can neither reach nor own.
pub fn systemd_unit(exe_path: &str, user: &str) -> String {
    format!(
        "[Unit]\n\
         Description=Belay resident core (belayd)\n\
         After=network.target\n\n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         Environment=HOME=/home/{user}\n\
         ExecStart={exe_path} daemon\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         NoNewPrivileges=true\n\
         ReadOnlyPaths={exe_path}\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Generate a launchd plist that runs the daemon as `user`, not in the root
/// LaunchDaemon context, so the socket/audit paths under the user's $HOME
/// (`~/.belay/...`, i.e. /Users/<user> on macOS) match where the per-user
/// agent hook connects. A root context would bind /var/root/.belay.
pub fn launchd_plist(exe_path: &str, user: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>com.secblok.belay</string>\n\
         <key>ProgramArguments</key><array><string>{exe_path}</string><string>daemon</string></array>\n\
         <key>UserName</key><string>{user}</string>\n\
         <key>EnvironmentVariables</key><dict><key>HOME</key><string>/Users/{user}</string></dict>\n\
         <key>KeepAlive</key><true/>\n\
         <key>RunAtLoad</key><true/>\n\
         </dict></plist>\n"
    )
}

/// Windows boot-start registration spec. Returns the service name and the
/// `sc.exe` argv that registers `<exe> daemon --scm` as an auto-start service —
/// the structural analogue of [`systemd_unit`] / [`launchd_plist`].
///
/// This is the human-readable `--print` view of what the SCM API path
/// (`register_service`, Phase 3) actually does: same service name, same
/// `daemon --scm` launch arguments, same auto-start. The live registration goes
/// through `windows-service`'s `ServiceManager::create_service`, not `sc.exe`;
/// this argv is for display/parity only. `sc.exe` requires the space after
/// `binPath=`/`start=` to be part of a single token, so the binary path is
/// embedded in the `binPath=` argument here.
pub fn windows_service_spec(exe: &str, _user: &str) -> (String, Vec<String>) {
    let name = "Belay".to_string();
    let argv = vec![
        "sc".to_string(),
        "create".to_string(),
        name.clone(),
        // `--scm` selects the SCM dispatcher path; matches register_service's
        // launch_arguments so --print is faithful to the real registration.
        format!("binPath= \"{exe}\" daemon --scm"),
        "start= auto".to_string(),
        "DisplayName= Belay resident core".to_string(),
    ];
    (name, argv)
}

/// True if the path is a daemon-protected artifact agents must not write.
///
/// Normalises `\` → `/` so Windows paths (`C:\…\belay.exe`) are
/// matched identically to POSIX paths.
pub fn is_self_tamper(path: &str) -> bool {
    let p = path.replace('\\', "/");
    let f = p.rsplit('/').next().unwrap_or(&p);
    matches!(f, "belayd" | "belay" | "belayd.exe" | "belay.exe")
        || p.ends_with("rules/catalog.yaml")
        || p.ends_with("audit.ndjson")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_has_restart_and_exec() {
        let u = systemd_unit("/usr/local/bin/belayd", "alice");
        assert!(u.contains("Restart=on-failure"));
        // ExecStart launches the daemon subcommand, not the bare binary.
        assert!(u.contains("ExecStart=/usr/local/bin/belayd daemon"));
        assert!(u.contains("[Install]"));
        // Standard system-service target.
        assert!(u.contains("WantedBy=multi-user.target"));
        // Runs as the given user, never root.
        assert!(u.contains("User=alice"));
        assert!(u.contains("Environment=HOME=/home/alice"));
        assert!(!u.contains("User=root"));
        // Self-tamper guard: the binary path is read-only to the service.
        assert!(u.contains("ReadOnlyPaths=/usr/local/bin/belayd"));
    }

    #[test]
    fn launchd_plist_keepalive() {
        let p = launchd_plist("/usr/local/bin/belayd", "alice");
        assert!(p.contains("<key>KeepAlive</key>"));
        assert!(p.contains("/usr/local/bin/belayd"));
        // ProgramArguments launches the daemon subcommand.
        assert!(p.contains("<string>daemon</string>"));
        // Runs as the given user, never the root daemon context.
        assert!(p.contains("<key>UserName</key><string>alice</string>"));
        assert!(p.contains("/Users/alice"));
    }

    #[test]
    fn windows_service_spec_registers_daemon_autostart() {
        let (name, argv) = windows_service_spec("C:\\Program Files\\Belay\\belay.exe", "alice");
        assert_eq!(name, "Belay");
        assert_eq!(argv[0], "sc");
        assert!(argv.contains(&"create".to_string()));
        // Launches the daemon subcommand from the quoted exe path, in SCM mode
        // (`--scm`) — parity with register_service's launch_arguments.
        assert!(argv.iter().any(|a| a.contains("belay.exe")
            && a.contains("daemon")
            && a.contains("--scm")));
        // Auto-start at boot (the systemd WantedBy / launchd RunAtLoad analogue).
        assert!(argv.iter().any(|a| a.starts_with("start=") && a.contains("auto")));
    }

    #[test]
    fn self_tamper_paths_detected() {
        assert!(is_self_tamper("/usr/local/bin/belayd"));
        assert!(is_self_tamper("/usr/local/bin/belay"));
        assert!(is_self_tamper("/home/u/project/rules/catalog.yaml"));
        assert!(is_self_tamper("/home/u/.belay/audit.ndjson"));
        assert!(!is_self_tamper("/home/u/project/src/main.py"));
    }

    #[test]
    fn self_tamper_windows_paths_detected() {
        // Windows exe basename — backslash separator must be normalised.
        assert!(is_self_tamper(r"C:\Program Files\Belay\belay.exe"));
        // Windows backslash path to the audit log.
        assert!(is_self_tamper(r"C:\Users\user\.belay\audit.ndjson"));
        // A benign Windows path must not fire.
        assert!(!is_self_tamper(r"C:\Users\user\Documents\report.pdf"));
    }
}
