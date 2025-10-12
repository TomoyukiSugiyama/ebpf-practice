#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::kprobe,
    programs::ProbeContext,
};
use tcpdump_common::{
    TCP_DIRECTION_INCOMING, TCP_DIRECTION_OUTGOING, TCP_DIRECTION_UNKNOWN, TcpEvent, ebpf,
};

mod bindings;
use bindings::sock;

const AF_INET: u16 = 2;
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;
const TCP_SYN_RECV: i32 = 3;

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

    let mut event = TcpEvent::default();
    event.pid = pid;
    event.tgid = tgid;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    let sock_ptr = ctx.arg::<usize>(0).ok_or(1u32)? as *const sock;
    let state = ctx.arg::<i32>(1).ok_or(1u32)?;
    event.state = state as u32;

    if sock_ptr.is_null() {
        return Ok(0);
    }

    if state != TCP_ESTABLISHED && state != TCP_SYN_SENT && state != TCP_SYN_RECV {
        return Ok(0);
    }

    unsafe {
        let common = bpf_probe_read_kernel(core::ptr::addr_of!((*sock_ptr).__sk_common))
            .map_err(|_| 1u32)?;
        if common.skc_family as u16 != AF_INET {
            return Ok(0);
        }
        let v4 = common.__bindgen_anon_1.__bindgen_anon_1;
        event.src_ip = u32::from_be(v4.skc_rcv_saddr as u32);
        event.dst_ip = u32::from_be(v4.skc_daddr as u32);
        let ports = common.__bindgen_anon_3.__bindgen_anon_1;
        event.src_port = ports.skc_num;
        event.dst_port = u16::from_be(ports.skc_dport as u16);
    }

    event.direction = match state {
        TCP_SYN_SENT => TCP_DIRECTION_OUTGOING,
        TCP_SYN_RECV => TCP_DIRECTION_INCOMING,
        _ => TCP_DIRECTION_UNKNOWN,
    };

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
