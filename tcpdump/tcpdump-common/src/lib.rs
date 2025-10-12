#![cfg_attr(not(feature = "user"), no_std)]

pub const TCP_DIRECTION_UNKNOWN: u8 = 0;
pub const TCP_DIRECTION_OUTGOING: u8 = 1;
pub const TCP_DIRECTION_INCOMING: u8 = 2;

pub const TCP_STATE_ESTABLISHED: u32 = 1;
pub const TCP_STATE_SYN_SENT: u32 = 2;
pub const TCP_STATE_SYN_RECV: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpEvent {
    pub pid: u32,
    pub tgid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub state: u32,
    pub direction: u8,
    pub _reserved: u8,
}

impl Default for TcpEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            tgid: 0,
            timestamp_ns: 0,
            comm: [0; 16],
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            state: 0,
            direction: TCP_DIRECTION_UNKNOWN,
            _reserved: 0,
        }
    }
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
    use super::{
        TCP_DIRECTION_INCOMING, TCP_DIRECTION_OUTGOING, TCP_DIRECTION_UNKNOWN,
        TCP_STATE_ESTABLISHED, TCP_STATE_SYN_RECV, TCP_STATE_SYN_SENT, TcpEvent,
    };
    use aya::Pod;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };
    unsafe impl Pod for TcpEvent {}

    impl TcpEvent {
        pub fn direction(&self) -> u8 {
            self.direction
        }

        pub fn direction_label(&self) -> &'static str {
            match self.direction {
                TCP_DIRECTION_OUTGOING => "out",
                TCP_DIRECTION_INCOMING => "in",
                TCP_DIRECTION_UNKNOWN => "?",
                _ => "?",
            }
        }

        pub fn state(&self) -> u32 {
            self.state
        }

        pub fn state_label(&self) -> &'static str {
            match self.state {
                TCP_STATE_ESTABLISHED => "ESTABLISHED",
                TCP_STATE_SYN_SENT => "SYN_SENT",
                TCP_STATE_SYN_RECV => "SYN_RECV",
                _ => "STATE",
            }
        }

        pub fn timestamp_ns(&self) -> u64 {
            self.timestamp_ns
        }

        pub fn timestamp_duration(&self) -> Duration {
            Duration::from_nanos(self.timestamp_ns)
        }

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

        pub fn src_port(&self) -> u16 {
            self.src_port
        }

        pub fn dst_port(&self) -> u16 {
            self.dst_port
        }

        pub fn src_socket(&self) -> SocketAddrV4 {
            SocketAddrV4::new(self.src_addr(), self.src_port)
        }

        pub fn dst_socket(&self) -> SocketAddrV4 {
            SocketAddrV4::new(self.dst_addr(), self.dst_port)
        }
    }
}
