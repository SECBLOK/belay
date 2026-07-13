//! Reads RawEvent records out of the aya RingBuf and decodes them.
use crate::observe::{decode_raw, ObservedEvent};

/// Drain all currently-available events from the ring buffer named EVENTS.
pub fn drain(bpf: &mut aya::Ebpf) -> Vec<ObservedEvent> {
    let mut out = Vec::new();
    let Some(map) = bpf.map_mut("EVENTS") else {
        return out;
    };
    let Ok(mut rb) = aya::maps::RingBuf::try_from(map) else {
        return out;
    };
    while let Some(item) = rb.next() {
        if let Some(ev) = decode_raw(&item) {
            out.push(ev);
        }
    }
    out
}
