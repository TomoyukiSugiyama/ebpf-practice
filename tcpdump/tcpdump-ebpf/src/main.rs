#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use tcpdump_common::{TcpEvent, ebpf};

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

    let mut event = TcpEvent {
        pid,
        tgid,
        comm: [0; 16],
        src_ip: 0,
        dst_ip: 0,
    };

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    let sock_ptr = ctx.arg::<usize>(0).ok_or(1u32)? as *const u8;
    if !sock_ptr.is_null() {
        const SKC_RCV_SADDR_OFFSET: usize = 0x1C;
        const SKC_DADDR_OFFSET: usize = 0x20;
        unsafe {
            event.src_ip = bpf_probe_read_kernel(sock_ptr.add(SKC_RCV_SADDR_OFFSET) as *const u32)
                .map_err(|_| 1u32)?;
            event.dst_ip = bpf_probe_read_kernel(sock_ptr.add(SKC_DADDR_OFFSET) as *const u32)
                .map_err(|_| 1u32)?;
        }
    }

    unsafe {
        (*ebpf::events_map()).output(&ctx, &event, 0);
    }
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
