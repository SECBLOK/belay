//! Honeypot canary tokens. Plant fake credential files; any read or egress of
//! their sentinel bytes is CRITICAL (cheap, very high-signal).
use crate::engine::types::{Decision, Severity, Verdict};
use crate::observe::{EventKind, ObservedEvent};
use std::path::{Path, PathBuf};

/// Phase-1 Windows honeytoken canary: a no-admin last-access poller that turns
/// "a canary file's LastAccessTime moved" into an [`ObservedEvent`] the existing
/// [`Honeypot::classify_access`] escalates. `#[cfg(windows)]` — the only new
/// *producer*; everything downstream (classify, audit) is reused.
#[cfg(windows)]
pub mod watch_win;

pub struct Honeypot {
    pub dir: PathBuf,
    pub sentinels: Vec<String>,
    pub canary_paths: Vec<String>,
}

impl Honeypot {
    /// Plant the canary files under `<data_dir>/honeypot/`.
    ///
    /// On production paths `data_dir` is `paths::data_dir()` (`~/.belay`
    /// on Unix, `%PROGRAMDATA%\Belay` on Windows).  Tests may pass a
    /// temp-dir path to keep each test isolated from the real data directory.
    pub fn plant(data_dir: &Path) -> std::io::Result<Honeypot> {
        let dir = data_dir.join("honeypot");
        std::fs::create_dir_all(&dir)?;

        let aws_sentinel = "AKIAHONEYPOTDECOY0000".to_string();
        let env_sentinel = "BELAY_CANARY_TOKEN=c4n4ry-d0-n0t-use".to_string();

        let aws = dir.join("aws_credentials");
        std::fs::write(
            &aws,
            format!("[default]\naws_access_key_id = {aws_sentinel}\naws_secret_access_key = decoydecoydecoydecoydecoydecoydecoydecoy\n"),
        )?;
        let env = dir.join(".env");
        std::fs::write(&env, format!("{env_sentinel}\nDB_PASSWORD=decoy\n"))?;

        Ok(Honeypot {
            dir,
            sentinels: vec![aws_sentinel, env_sentinel],
            canary_paths: vec![
                aws.to_string_lossy().into_owned(),
                env.to_string_lossy().into_owned(),
            ],
        })
    }

    /// Plant an ADDITIONAL decoy `.env` at an arbitrary path and register it as a
    /// canary. The baseline [`plant`] drops decoys under `%PROGRAMDATA%\Belay`,
    /// which the closed desktop apps never scan — so placement is coverage. Use
    /// this to put a decoy where an agent actually roams (a project dir, the user
    /// profile). Idempotent-ish: re-registers cleanly; the file is (re)written
    /// with the same sentinel content the egress tripwire already recognizes.
    pub fn plant_decoy_at(&mut self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Reuse the env sentinel so `classify_access`'s egress leg also recognizes
        // these bytes if they ever leave the host on a Belay-visible surface.
        let env_sentinel = &self.sentinels[1];
        std::fs::write(path, format!("{env_sentinel}\nDB_PASSWORD=decoy\n"))?;
        let s = path.to_string_lossy().into_owned();
        if !self.canary_paths.contains(&s) {
            self.canary_paths.push(s);
        }
        Ok(())
    }

    /// CRITICAL if the event reads a canary path or carries a sentinel byte run.
    pub fn classify_access(&self, ev: &ObservedEvent) -> Option<Verdict> {
        match ev.kind {
            EventKind::Open => {
                if self.canary_paths.iter().any(|p| p == &ev.detail) {
                    return Some(self.verdict(
                        "honeypot.canary_read",
                        format!("canary file read: {}", ev.detail),
                    ));
                }
                None
            }
            EventKind::TlsWrite | EventKind::Connect => {
                if self.sentinels.iter().any(|s| ev.detail.contains(s)) {
                    return Some(self.verdict(
                        "honeypot.canary_egress",
                        "canary sentinel bytes leaving the host".into(),
                    ));
                }
                None
            }
            EventKind::Exec | EventKind::OpenWrite => None,
        }
    }

    fn verdict(&self, rule: &str, reason: String) -> Verdict {
        Verdict {
            decision: Decision::Deny,
            reason,
            rules: vec![rule.to_string()],
            severity: Severity::Critical,
            primary_rule: None,
            category: None,
            owasp: None,
            atlas: None,
            explain: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::{Decision, Severity};
    use crate::observe::{EventKind, ObservedEvent};

    #[test]
    fn read_of_canary_is_critical() {
        let tmp = tempfile::tempdir().unwrap();
        let hp = Honeypot::plant(tmp.path()).unwrap();
        let canary = hp.canary_paths[0].clone();
        let ev = ObservedEvent {
            pid: 1,
            kind: EventKind::Open,
            detail: canary,
        };
        let v = hp
            .classify_access(&ev)
            .expect("canary read must be flagged");
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.rules.iter().any(|r| r == "honeypot.canary_read"));
    }

    #[test]
    fn read_of_normal_file_is_not_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        let hp = Honeypot::plant(tmp.path()).unwrap();
        // Use a platform-canonical "normal" file that is never a canary path.
        #[cfg(not(windows))]
        let normal_path = "/etc/hostname";
        #[cfg(windows)]
        let normal_path = r"C:\Windows\System32\drivers\etc\hosts";
        let ev = ObservedEvent {
            pid: 1,
            kind: EventKind::Open,
            detail: normal_path.into(),
        };
        assert!(hp.classify_access(&ev).is_none());
    }

    #[test]
    fn egress_of_sentinel_bytes_is_critical() {
        let tmp = tempfile::tempdir().unwrap();
        let hp = Honeypot::plant(tmp.path()).unwrap();
        let sentinel = hp.sentinels[0].clone();
        let ev = ObservedEvent {
            pid: 1,
            kind: EventKind::TlsWrite,
            detail: format!("POST /collect body={sentinel}"),
        };
        let v = hp
            .classify_access(&ev)
            .expect("sentinel egress must be flagged");
        assert!(v.rules.iter().any(|r| r == "honeypot.canary_egress"));
    }

    #[test]
    fn planted_files_exist_with_sentinels() {
        let tmp = tempfile::tempdir().unwrap();
        let hp = Honeypot::plant(tmp.path()).unwrap();
        for p in &hp.canary_paths {
            let contents = std::fs::read_to_string(p).unwrap();
            assert!(hp.sentinels.iter().any(|s| contents.contains(s)));
        }
    }

    #[test]
    fn plant_decoy_at_registers_and_writes_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hp = Honeypot::plant(tmp.path()).unwrap();
        let before = hp.canary_paths.len();
        let extra = tmp.path().join("proj").join(".env");
        hp.plant_decoy_at(&extra).unwrap();

        // Registered as a canary, exactly once.
        let s = extra.to_string_lossy().into_owned();
        assert!(hp.canary_paths.contains(&s));
        assert_eq!(hp.canary_paths.len(), before + 1);
        // Re-planting the same path does not duplicate the registration.
        hp.plant_decoy_at(&extra).unwrap();
        assert_eq!(hp.canary_paths.len(), before + 1);

        // File written with a recognized sentinel, and a read of it classifies.
        let contents = std::fs::read_to_string(&extra).unwrap();
        assert!(hp.sentinels.iter().any(|sen| contents.contains(sen)));
        let ev = ObservedEvent {
            pid: 0,
            kind: EventKind::Open,
            detail: s,
        };
        assert!(hp.classify_access(&ev).is_some());
    }
}
