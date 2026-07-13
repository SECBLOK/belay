//! OS-observation event model shared by the eBPF userland and the engine.

pub mod secrets;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    Exec = 0,
    Open = 1,
    Connect = 2,
    TlsWrite = 3,
    OpenWrite = 4,
}

impl EventKind {
    pub fn from_u8(v: u8) -> Option<EventKind> {
        match v {
            0 => Some(EventKind::Exec),
            1 => Some(EventKind::Open),
            2 => Some(EventKind::Connect),
            3 => Some(EventKind::TlsWrite),
            4 => Some(EventKind::OpenWrite),
            _ => None,
        }
    }
}

/// A decoded observation handed to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEvent {
    pub pid: u32,
    pub kind: EventKind,
    pub detail: String,
}

/// Fixed wire layout written by the kernel programs into the ring buffer.
/// Plain-old-data so it is identical on the kernel and userland sides.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub pid: u32,
    pub kind: u8,
    pub len: u16,
    pub data: [u8; 256],
}

/// Decode the first `size_of::<RawEvent>()` bytes of a ring-buffer record.
pub fn decode_raw(bytes: &[u8]) -> Option<ObservedEvent> {
    if bytes.len() < core::mem::size_of::<RawEvent>() {
        return None;
    }
    // SAFETY: length checked above; read_unaligned avoids any alignment requirement on the input slice.
    let raw: RawEvent = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const RawEvent) };
    let kind = EventKind::from_u8(raw.kind)?;
    let len = (raw.len as usize).min(raw.data.len());
    let detail = String::from_utf8_lossy(&raw.data[..len]).into_owned();
    Some(ObservedEvent {
        pid: raw.pid,
        kind,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(pid: u32, kind: u8, s: &str) -> Vec<u8> {
        let mut r = RawEvent {
            pid,
            kind,
            len: s.len() as u16,
            data: [0u8; 256],
        };
        r.data[..s.len()].copy_from_slice(s.as_bytes());
        // SAFETY: RawEvent is #[repr(C)] POD; reinterpret as bytes for the test.
        unsafe {
            core::slice::from_raw_parts(
                (&r as *const RawEvent) as *const u8,
                core::mem::size_of::<RawEvent>(),
            )
        }
        .to_vec()
    }

    #[test]
    fn decode_open_event() {
        let ev = decode_raw(&raw(4321, 1, "/proc/99/environ")).unwrap();
        assert_eq!(ev.pid, 4321);
        assert!(matches!(ev.kind, EventKind::Open));
        assert_eq!(ev.detail, "/proc/99/environ");
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert!(decode_raw(&[0u8; 4]).is_none());
    }

    #[test]
    fn decode_unknown_kind_is_none() {
        assert!(decode_raw(&raw(1, 9, "x")).is_none());
    }

    #[test]
    fn kind_from_u8_roundtrip() {
        assert!(matches!(EventKind::from_u8(3), Some(EventKind::TlsWrite)));
        assert!(EventKind::from_u8(255).is_none());
    }

    #[test]
    fn decodes_open_write_kind() {
        assert!(matches!(EventKind::from_u8(4), Some(EventKind::OpenWrite)));
        let bytes = raw(7, 4, "/p/rules/catalog.yaml");
        let ev = decode_raw(&bytes).unwrap();
        assert!(matches!(ev.kind, EventKind::OpenWrite));
        assert_eq!(ev.detail, "/p/rules/catalog.yaml");
    }
}
