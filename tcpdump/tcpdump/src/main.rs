use anyhow::Context as _;
use aya::maps::ring_buf::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use std::{fmt, net::Ipv4Addr};
use tcpdump_common::user::PacketEventExt as _;
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s1")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tcpdump"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let ring_buf_map = ebpf.take_map("EVENTS").context("EVENTS map not found")?;
    let ring_buf = RingBuf::try_from(ring_buf_map)?;

    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("tcpdump").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    println!("Waiting for Ctrl-C...");

    let ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let reader = task::spawn(async move {
        let mut ring_buf = ring_buf;
        loop {
            let mut guard = ring_buf.readable_mut().await?;
            {
                let ring_buf = guard.get_inner_mut();
                while let Some(event) = ring_buf.next() {
                    if let Some(packet) = event.packet_event() {
                        let payload = packet.payload();
                        debug!("raw packet: {:02x?}", payload);
                        match describe_packet(payload) {
                            Ok(summary) => info!("{summary}"),
                            Err(err) => {
                                warn!("failed to analyze packet (len={}): {err}", payload.len())
                            }
                        }
                    }
                }
            }
            guard.clear_ready();
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    signal::ctrl_c().await?;
    println!("Exiting...");
    reader.abort();

    Ok(())
}

fn describe_packet(bytes: &[u8]) -> Result<String, &'static str> {
    const ETH_HEADER_LEN: usize = 14;

    if bytes.len() < ETH_HEADER_LEN {
        return Err("frame too short for Ethernet header");
    }

    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&bytes[..6]);
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&bytes[6..12]);
    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    let frame_len = bytes.len();

    if ethertype != 0x0800 {
        return Ok(format!(
            "eth {} -> {} type=0x{:04x} captured_len={}",
            MacAddr(src_mac),
            MacAddr(dst_mac),
            ethertype,
            frame_len
        ));
    }

    let ip_bytes = &bytes[ETH_HEADER_LEN..];
    if ip_bytes.len() < 20 {
        return Err("frame too short for IPv4 header");
    }

    let version = ip_bytes[0] >> 4;
    if version != 4 {
        return Err("unexpected IPv4 version");
    }

    let ihl = (ip_bytes[0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return Err("invalid IPv4 header length");
    }
    if ip_bytes.len() < ihl {
        return Err("truncated IPv4 header");
    }

    let total_length = u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]) as usize;
    let ttl = ip_bytes[8];
    let protocol = ip_bytes[9];
    let src_ip = Ipv4Addr::new(ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
    let dst_ip = Ipv4Addr::new(ip_bytes[16], ip_bytes[17], ip_bytes[18], ip_bytes[19]);

    if protocol != 6 {
        return Ok(format!(
            "eth {} -> {} type=0x{:04x}; ipv4 {} -> {} ttl={} total_len={} captured_len={} proto={}",
            MacAddr(src_mac),
            MacAddr(dst_mac),
            ethertype,
            src_ip,
            dst_ip,
            ttl,
            total_length,
            frame_len,
            protocol
        ));
    }

    let tcp_bytes = &ip_bytes[ihl..];
    if tcp_bytes.len() < 20 {
        return Err("frame too short for TCP header");
    }

    let src_port = u16::from_be_bytes([tcp_bytes[0], tcp_bytes[1]]);
    let dst_port = u16::from_be_bytes([tcp_bytes[2], tcp_bytes[3]]);
    let seq = u32::from_be_bytes([tcp_bytes[4], tcp_bytes[5], tcp_bytes[6], tcp_bytes[7]]);
    let ack = u32::from_be_bytes([tcp_bytes[8], tcp_bytes[9], tcp_bytes[10], tcp_bytes[11]]);
    let offset_reserved_flags = u16::from_be_bytes([tcp_bytes[12], tcp_bytes[13]]);
    let data_offset = ((offset_reserved_flags >> 12) & 0x0f) as usize * 4;
    if data_offset < 20 {
        return Err("invalid TCP header length");
    }
    if tcp_bytes.len() < data_offset {
        return Err("truncated TCP header");
    }

    let flags = offset_reserved_flags & 0x01ff;
    let window = u16::from_be_bytes([tcp_bytes[14], tcp_bytes[15]]);
    let payload_len = tcp_bytes.len().saturating_sub(data_offset);

    Ok(format!(
        "eth {} -> {} type=0x{:04x}; ipv4 {} -> {} ttl={} total_len={} captured_len={}; tcp {} -> {} seq={} ack={} flags=[{}] win={} tcp_header_len={} payload={}B",
        MacAddr(src_mac),
        MacAddr(dst_mac),
        ethertype,
        src_ip,
        dst_ip,
        ttl,
        total_length,
        frame_len,
        src_port,
        dst_port,
        seq,
        ack,
        TcpFlags(flags),
        window,
        data_offset,
        payload_len
    ))
}

#[derive(Clone, Copy)]
struct MacAddr([u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

struct TcpFlags(u16);

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: &[(u16, &str)] = &[
            (0x100, "NS"),
            (0x080, "CWR"),
            (0x040, "ECE"),
            (0x020, "URG"),
            (0x010, "ACK"),
            (0x008, "PSH"),
            (0x004, "RST"),
            (0x002, "SYN"),
            (0x001, "FIN"),
        ];

        let mut wrote = false;
        for (mask, name) in NAMES {
            if self.0 & mask != 0 {
                if wrote {
                    f.write_str(",")?;
                }
                f.write_str(name)?;
                wrote = true;
            }
        }

        if !wrote {
            f.write_str("none")?;
        }

        Ok(())
    }
}
