#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_probe_read_user, gen::bpf_probe_read_user_str_bytes},
    macros::{kprobe, map, tracepoint, uprobe},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub pid: u32,
    pub kind: u8,
    pub len: u16,
    pub data: [u8; 256],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn emit(kind: u8, ptr: *const u8) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(mut slot) = EVENTS.reserve::<RawEvent>(0) {
        let ev = unsafe { &mut *slot.as_mut_ptr() };
        ev.pid = pid;
        ev.kind = kind;
        ev.data = [0u8; 256];
        let n = unsafe {
            bpf_probe_read_user_str_bytes(ptr, &mut ev.data)
                .map(|s| s.len())
                .unwrap_or(0)
        };
        ev.len = n as u16;
        slot.submit(0);
    }
}

#[tracepoint]
pub fn trace_exec(ctx: TracePointContext) -> u32 {
    // filename pointer lives at a fixed offset in the tracepoint record.
    let ptr = unsafe { ctx.read_at::<*const u8>(8).unwrap_or(core::ptr::null()) };
    if !ptr.is_null() {
        emit(0, ptr);
    }
    0
}

// Linux fcntl constants (x86_64/generic): write intent if not purely O_RDONLY,
// or if the open creates/truncates.
const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;

#[kprobe]
pub fn trace_open(ctx: ProbeContext) -> u32 {
    let Some(name) = ctx.arg::<*const u8>(1) else { return 0 };
    // Read open_how.flags (first u64 at arg2) from user memory.
    let how = ctx.arg::<*const u64>(2);
    let mut write_intent = false;
    if let Some(how_ptr) = how {
        if let Ok(flags) = unsafe { bpf_probe_read_user::<u64>(how_ptr) } {
            let acc = flags & O_ACCMODE;
            write_intent =
                acc == O_WRONLY || acc == O_RDWR || (flags & (O_CREAT | O_TRUNC)) != 0;
        }
    }
    emit(if write_intent { 4 } else { 1 }, name);
    0
}

#[kprobe]
pub fn trace_connect(_ctx: ProbeContext) -> u32 {
    // sockaddr decoding is added in Task 4; emit a marker for now.
    emit(2, b"connect\0".as_ptr());
    0
}

// int SSL_write(SSL *ssl, const void *buf, int num)
#[uprobe]
pub fn trace_ssl_write(ctx: ProbeContext) -> u32 {
    let buf = ctx.arg::<*const u8>(1).unwrap_or(core::ptr::null());
    let num = ctx.arg::<i32>(2).unwrap_or(0);
    if buf.is_null() || num <= 0 {
        return 0;
    }
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(mut slot) = EVENTS.reserve::<RawEvent>(0) {
        let ev = unsafe { &mut *slot.as_mut_ptr() };
        ev.pid = pid;
        ev.kind = 3; // TlsWrite
        ev.data = [0u8; 256];
        let n = (num as usize).min(ev.data.len());
        let _ = unsafe {
            aya_ebpf::helpers::gen::bpf_probe_read_user(
                ev.data.as_mut_ptr() as *mut core::ffi::c_void,
                n as u32,
                buf as *const core::ffi::c_void,
            )
        };
        ev.len = n as u16;
        slot.submit(0);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
