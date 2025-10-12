#![cfg_attr(not(feature = "user"), no_std)]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpEvent {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub src_ip: u32,
    pub dst_ip: u32,
}

#[cfg(all(feature = "ebpf", target_arch = "bpf"))]
pub mod ebpf {
    use super::TcpEvent;
    use aya_ebpf::{macros::map, maps::PerfEventArray};

    #[map(name = "EVENTS")]
    pub static mut EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

    pub unsafe fn events_map() -> *mut PerfEventArray<TcpEvent> {
        &raw mut EVENTS
    }
}

#[cfg(feature = "user")]
pub mod user {
    use aya::Pod;
    use std::net::Ipv4Addr;
    use super::TcpEvent;
    unsafe impl Pod for TcpEvent {}

    impl TcpEvent {
        pub fn command(&self) -> String {
            let end = self
                .comm
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(self.comm.len());
            String::from_utf8_lossy(&self.comm[..end]).to_string()
        }

        pub fn src_addr(&self) -> Ipv4Addr {
            Ipv4Addr::from(self.src_ip)
        }

        pub fn dst_addr(&self) -> Ipv4Addr {
            Ipv4Addr::from(self.dst_ip)
        }
    }
}
