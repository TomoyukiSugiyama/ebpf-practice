#![no_std]

#[cfg(target_arch = "bpf")]
mod maps {
    use aya_ebpf::{macros::map, maps::RingBuf};

    const RING_BUF_CAPACITY: u32 = 1 << 12;

    #[map]
    pub static mut EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_CAPACITY, 0);
}

#[cfg(target_arch = "bpf")]
pub use maps::EVENTS;
