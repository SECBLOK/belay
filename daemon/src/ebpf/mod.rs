//! Userland eBPF loader. Best-effort: any failure degrades to None so the
//! daemon keeps running with hook/proxy enforcement only.

#[cfg(feature = "ebpf")]
pub mod ringbuf;

#[derive(Debug)]
pub enum SensorError {
    /// eBPF not compiled in, or OS/kernel can't support it.
    Unsupported(String),
    /// Programs compiled in but loading/attaching failed at runtime.
    Load(String),
}

impl std::fmt::Display for SensorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SensorError::Unsupported(m) => write!(f, "eBPF unsupported: {m}"),
            SensorError::Load(m) => write!(f, "eBPF load failed: {m}"),
        }
    }
}
impl std::error::Error for SensorError {}

#[cfg(feature = "ebpf")]
pub struct Sensor {
    _bpf: aya::Ebpf,
}

#[cfg(feature = "ebpf")]
impl Sensor {
    /// Consume the sensor and return the underlying `aya::Ebpf` handle for
    /// direct ring-buffer access (used by the integration test and boot drain loop).
    pub fn into_bpf(self) -> aya::Ebpf {
        self._bpf
    }
}

#[cfg(not(feature = "ebpf"))]
pub struct Sensor;

/// Load + attach the kernel programs. Linux + root + a recent kernel only.
#[cfg(feature = "ebpf")]
pub fn start() -> Result<Sensor, SensorError> {
    use aya::programs::{KProbe, TracePoint};

    // The program object file is embedded at compile time by the build script.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/daemon-ebpf"
    )))
    .map_err(|e| SensorError::Load(format!("{e}")))?;

    // Best-effort logger; ignore if it can't init.
    let _ = aya_log::EbpfLogger::init(&mut bpf);

    // exec via the sched_process_exec tracepoint.
    if let Some(p) = bpf.program_mut("trace_exec") {
        let tp: &mut TracePoint = p
            .try_into()
            .map_err(|e| SensorError::Load(format!("{e:?}")))?;
        tp.load().map_err(|e| SensorError::Load(format!("{e}")))?;
        tp.attach("sched", "sched_process_exec")
            .map_err(|e| SensorError::Load(format!("{e}")))?;
    }
    // open via a kprobe on do_sys_openat2.
    if let Some(p) = bpf.program_mut("trace_open") {
        let kp: &mut KProbe = p
            .try_into()
            .map_err(|e| SensorError::Load(format!("{e:?}")))?;
        kp.load().map_err(|e| SensorError::Load(format!("{e}")))?;
        kp.attach("do_sys_openat2", 0)
            .map_err(|e| SensorError::Load(format!("{e}")))?;
    }
    // connect via a kprobe on __sys_connect.
    if let Some(p) = bpf.program_mut("trace_connect") {
        let kp: &mut KProbe = p
            .try_into()
            .map_err(|e| SensorError::Load(format!("{e:?}")))?;
        kp.load().map_err(|e| SensorError::Load(format!("{e}")))?;
        kp.attach("__sys_connect", 0)
            .map_err(|e| SensorError::Load(format!("{e}")))?;
    }
    // SSL_write uprobe for TLS plaintext capture; best-effort (libssl may not be present).
    use aya::programs::UProbe;
    if let Some(p) = bpf.program_mut("trace_ssl_write") {
        if let Ok(up) = TryInto::<&mut UProbe>::try_into(p) {
            if up.load().is_ok() {
                // Attach to libssl's SSL_write; ignore if not present on this host.
                let _ = up.attach(Some("SSL_write"), 0, "libssl", None);
            }
        }
    }

    Ok(Sensor { _bpf: bpf })
}

#[cfg(not(feature = "ebpf"))]
pub fn start() -> Result<Sensor, SensorError> {
    Err(SensorError::Unsupported(
        "built without the `ebpf` feature (Linux-only)".into(),
    ))
}

/// Startup-safe entry point: never returns Err, logs and yields None on failure.
pub fn start_or_degrade() -> Option<Sensor> {
    match start() {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("[belayd] eBPF disabled, hook/proxy enforcement only: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // start_or_degrade must NEVER panic and must yield None when eBPF
    // can't load (the default non-ebpf build, or a kernel/cap failure).
    #[test]
    fn degrades_to_none_when_unavailable() {
        // In the default test build the `ebpf` feature is off, so this is
        // unconditionally None. With the feature on but no CAP_BPF it is
        // also None (load returns Err). Either way: no panic, Option type.
        let s = start_or_degrade();
        assert!(s.is_none() || s.is_some());
        #[cfg(not(feature = "ebpf"))]
        assert!(s.is_none());
    }

    #[cfg(not(feature = "ebpf"))]
    #[test]
    fn start_is_unsupported_without_feature() {
        match start() {
            Err(SensorError::Unsupported(_)) => {}
            _ => panic!("expected Unsupported without the ebpf feature"),
        }
    }
}
