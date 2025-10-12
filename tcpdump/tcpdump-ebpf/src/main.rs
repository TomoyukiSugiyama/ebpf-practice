#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use core::str;

#[kprobe]
pub fn tcpdump(ctx: ProbeContext) -> u32 {
    match try_tcpdump(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcpdump(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let mut comm_buf = [0u8; 16];
    let mut comm_valid = false;
    if let Ok(buf) = bpf_get_current_comm() {
        comm_buf = buf;
        comm_valid = true;
    }

    let mut len = 0usize;
    while len < comm_buf.len() {
        if comm_buf[len] == 0 {
            break;
        }
        len += 1;
    }

    let comm_str = if !comm_valid {
        "<unknown>"
    } else if len == 0 {
        "<empty>"
    } else {
        unsafe { str::from_utf8_unchecked(&comm_buf[..len]) }
    };

    info!(
        &ctx,
        "tcp_connect pid={} tgid={} comm={}",
        pid,
        tgid,
        comm_str
    );
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
