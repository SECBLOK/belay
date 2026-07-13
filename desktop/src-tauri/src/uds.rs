/// The daemon control address, resolved through the daemon's OWN path helper so
/// the desktop and daemon can never disagree. On Windows the transport maps this
/// path's basename to `\\.\pipe\<basename>`, so sharing one source keeps the pipe
/// name identical on both ends; it also honors `BELAY_SOCK` and follows
/// Phase 4's `%PROGRAMDATA%` layout for free. (The desktop already links
/// `belayd`.)
pub fn socket_path() -> String {
    belayd::paths::socket_path()
}

/// Map a UDS connect failure (socket missing / refused) to a clear, user-facing
/// message instead of a raw "No such file or directory (os error 2)". Read calls
/// discard this (fail-soft); mutations surface it, so the GUI now explains that
/// the daemon is down rather than leaking an io error code.
#[cfg(feature = "tokio")]
fn daemon_down(e: std::io::Error) -> std::io::Error {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    match e.kind() {
        NotFound | ConnectionRefused => std::io::Error::new(
            e.kind(),
            "Belay daemon is not running — start it with `belay daemon`",
        ),
        _ => e,
    }
}

/// Connect, write one length-prefixed JSON frame, read one length-prefixed reply.
///
/// Routes through the blocking [`belay_transport`] crate — the SAME client
/// path the daemon's own clients use — inside `spawn_blocking`, rather than a
/// hand-rolled tokio pipe. This is load-bearing on Windows: the daemon authorizes
/// a peer by `ImpersonateNamedPipeClient`, which requires the client to open the
/// pipe at `SECURITY_IMPERSONATION` QoS. `belay_transport::connect` already
/// sets that QoS + busy-retry + `\\.\pipe\<basename>` mapping; a hand-rolled
/// tokio client would silently connect at the wrong QoS and fail auth in a
/// Windows-only way that is untestable on Linux.
#[cfg(feature = "tokio")]
pub async fn request(frame: &serde_json::Value) -> std::io::Result<serde_json::Value> {
    let addr = socket_path();
    let body = serde_json::to_vec(frame)?;
    let reply = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
        use std::io::{Read, Write};
        let mut s = belay_transport::connect(&addr).map_err(daemon_down)?;
        s.write_all(&(body.len() as u32).to_be_bytes())?;
        s.write_all(&body)?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len)?;
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut buf)?;
        Ok(buf)
    })
    .await
    .map_err(|e| std::io::Error::other(format!("ipc task panicked: {e}")))??;
    Ok(serde_json::from_slice(&reply)?)
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;

    /// End-to-end round trip through the real transport + spawn_blocking path:
    /// bind an in-process listener, echo one length-prefixed frame straight back,
    /// and assert `request()` returns the decoded JSON unchanged. Proves the
    /// framing survived the transport rewrite and that `request()` targets the
    /// shared `socket_path()` address (pointed here via `BELAY_SOCK`, which
    /// `belayd::paths::socket_path()` honors). Runs on Linux/CI (the desktop
    /// crate does not yet compile on msvc — see the server Windows-gating gap).
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn request_round_trips_through_transport() {
        let dir = tempfile::tempdir().unwrap();
        let addr = dir.path().join("desk.sock").to_string_lossy().into_owned();
        std::env::set_var("BELAY_SOCK", &addr);

        // Bind BEFORE spawning request so the address exists when it connects.
        let listener = belay_transport::bind(&addr).unwrap();
        let echo = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut s = listener.accept().unwrap();
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&len).unwrap();
            s.write_all(&buf).unwrap();
        });

        let frame = serde_json::json!({"type": "command", "name": "get_posture"});
        let reply = request(&frame).await.expect("request round-trip");
        assert_eq!(reply, frame, "framing must round-trip unchanged");

        echo.join().unwrap();
        std::env::remove_var("BELAY_SOCK");
    }
}
