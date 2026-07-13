//! End-to-end eBPF test. Requires the `ebpf` feature, a Linux kernel, and root.
//! Self-skips cleanly anywhere those are missing so the suite stays green.
#![cfg(feature = "ebpf")]

use belayd::ebpf;
use belayd::engine::{
    evaluate_event,
    types::{Decision, SessionState, Severity},
};
use belayd::honeypot::Honeypot;
use belayd::observe::EventKind;
use belayd::reflex::{Killer, Reflex, Sink};

#[derive(Default)]
struct RecKiller {
    killed: Vec<u32>,
}
impl Killer for RecKiller {
    // Do NOT actually SIGKILL in CI; just record the intent.
    fn kill(&mut self, pid: u32) -> std::io::Result<()> {
        self.killed.push(pid);
        Ok(())
    }
}
#[derive(Default)]
struct RecSink {
    audits: Vec<serde_json::Value>,
}
impl Sink for RecSink {
    fn escalate(&mut self, _row: serde_json::Value) {}
    fn audit(&mut self, row: serde_json::Value) {
        self.audits.push(row);
    }
}

fn is_root() -> bool {
    // EUID 0 check without extra deps.
    std::fs::metadata("/proc/1/environ").is_ok() && unsafe { libc_geteuid() } == 0
}
extern "C" {
    fn geteuid() -> u32;
}
unsafe fn libc_geteuid() -> u32 {
    geteuid()
}

#[test]
fn proc_environ_and_honeypot_read_trip_reflex() {
    // 1) Skip cleanly where eBPF cannot run.
    let sensor = match ebpf::start() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SKIP ebpf_integration: {e}");
            return;
        }
    };
    if !is_root() {
        eprintln!("SKIP ebpf_integration: not root");
        return;
    }
    let mut bpf = sensor.into_bpf();

    // 2) Plant a honeypot and trigger reads in this very process.
    let home = tempfile::tempdir().unwrap();
    let hp = Honeypot::plant(home.path()).unwrap();
    // Trigger an observable open() of /proc/self/environ ...
    let _ = std::fs::read(format!("/proc/{}/environ", std::process::id()));
    // ... and a read of the canary file.
    let _ = std::fs::read(&hp.canary_paths[0]);

    // 3) Give the ring buffer a moment, then drain.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let events = ebpf::ringbuf::drain(&mut bpf);
    assert!(!events.is_empty(), "expected at least one observed event");

    // 4) Run them through honeypot + engine; assert a critical deny appears.
    let mut st = SessionState::new("itest");
    let mut reflex = Reflex::new(RecKiller::default(), RecSink::default());
    let mut saw_critical = false;
    for ev in &events {
        let verdict = hp
            .classify_access(ev)
            .unwrap_or_else(|| evaluate_event(ev, &mut st));
        if verdict.decision == Decision::Deny && verdict.severity == Severity::Critical {
            saw_critical = true;
            let act = reflex.react(ev, &verdict, "itest");
            assert!(act.killed && act.escalated && act.audited);
        }
    }
    assert!(
        saw_critical,
        "expected a critical bypass verdict from kernel events"
    );
    // 5) An audit row with a hash chain was written.
    assert!(reflex
        .sink
        .audits
        .iter()
        .any(|r| r["verdict"] == "deny" && r.get("hash").is_some()));
    let _ = EventKind::Open; // keep import used regardless of kernel filtering
}
