#![no_std]
#![no_main]

#[cfg(target_arch = "bpf")]
use aya_ebpf::{
    EbpfContext,
    bindings::xdp_action,
    helpers,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
#[cfg(target_arch = "bpf")]
use tcpdump_common::ebpf::{MAX_PAYLOAD_LEN, PacketEvent};

#[cfg(target_arch = "bpf")]
const RING_BUF_CAPACITY: u32 = 1 << 12;

#[cfg(target_arch = "bpf")]
const PACKET_EVENT_HEADER_SIZE: usize = core::mem::size_of::<PacketEvent>();

#[cfg(target_arch = "bpf")]
const PACKET_EVENT_CAPACITY: usize = PACKET_EVENT_HEADER_SIZE + MAX_PAYLOAD_LEN;

#[cfg(target_arch = "bpf")]
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_CAPACITY, 0);

#[cfg(target_arch = "bpf")]
fn load_packet(
    ctx: &XdpContext,
    len: u32,
    entry: &mut aya_ebpf::maps::ring_buf::RingBufBytes<'_>,
) -> Result<(), i64> {
    if len == 0 {
        return Ok(());
    }

    let buf: &mut [u8] = &mut *entry;
    let (header_buf, payload_buf) = buf.split_at_mut(PACKET_EVENT_HEADER_SIZE);
    let payload_buf = &mut payload_buf[..MAX_PAYLOAD_LEN];
    let header = unsafe { &mut *(header_buf.as_mut_ptr() as *mut PacketEvent) };
    header.len = len;

    let ret = unsafe {
        helpers::bpf_xdp_load_bytes(ctx.as_ptr().cast(), 0, payload_buf.as_mut_ptr().cast(), len)
    };

    if ret != 0 {
        return Err(ret);
    }

    Ok(())
}

#[cfg(target_arch = "bpf")]
#[xdp]
pub fn tcpdump(ctx: XdpContext) -> u32 {
    match try_tcpdump(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[cfg(target_arch = "bpf")]
fn try_tcpdump(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let total_len = data_end - data;

    let mut len = total_len as u32;
    if len > MAX_PAYLOAD_LEN as u32 {
        len = MAX_PAYLOAD_LEN as u32;
    }

    len &= MAX_PAYLOAD_LEN as u32;

    if len == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let len_usize = len as usize;

    if data + len_usize > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    unsafe {
        #[allow(static_mut_refs)]
        let events = &mut *core::ptr::addr_of_mut!(EVENTS);

        if let Some(mut entry) = events.reserve_bytes(PACKET_EVENT_CAPACITY, 0) {
            match load_packet(&ctx, len, &mut entry) {
                Ok(()) => entry.submit(0),
                Err(_) => {
                    entry.discard(0);
                    return Err(xdp_action::XDP_ABORTED);
                }
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(target_arch = "bpf")]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
