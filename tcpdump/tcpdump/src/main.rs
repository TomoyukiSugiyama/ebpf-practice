use std::{
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    thread,
    time::Duration,
};

use aya::maps::perf::{PerfBufferError, PerfEventArrayBuffer};
use aya::maps::PerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{debug, info, warn};
use tcpdump_common::TcpEvent;
use tokio::{signal, task};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("aya-log disabled: {e}");
    }

    let mut events = PerfEventArray::try_from(ebpf.take_map("EVENTS").ok_or_else(|| anyhow::anyhow!("EVENTS map missing"))?)?;
    let mut perf_buffers: Vec<(u32, PerfEventArrayBuffer<_>)> = online_cpus()
        .map_err(|(_, error)| error)?
        .into_iter()
        .map(|cpu_id| events.open(cpu_id, None).map(|buf| (cpu_id, buf)))
        .collect::<Result<_, _>>()?;

    let running = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();
    for (cpu_id, mut buf) in perf_buffers.drain(..) {
        let running = running.clone();
        handles.push(task::spawn_blocking(move || {
            let mut buffers = [BytesMut::with_capacity(core::mem::size_of::<TcpEvent>())];
            loop {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                match buf.read_events(&mut buffers) {
                    Ok(events) => {
                        if events.read > 0 {
                            for bytes in buffers.iter().filter(|b| !b.is_empty()) {
                                if bytes.len() >= core::mem::size_of::<TcpEvent>() {
                                    let evt = unsafe { *(bytes.as_ptr() as *const TcpEvent) };
                                    info!(
                                        "cpu={} tcp_connect pid={} tgid={} comm={} src_ip={} dst_ip={}",
                                        cpu_id,
                                        evt.pid,
                                        evt.tgid,
                                        evt.command(),
                                        evt.src_addr(),
                                        evt.dst_addr()
                                    );
                                }
                            }
                        }
                        for buf in &mut buffers {
                            buf.clear();
                        }
                        if events.read == 0 {
                            thread::sleep(Duration::from_millis(10));
                        }
                    }
                    Err(PerfBufferError::NoBuffers) => {
                        warn!("perf buffer returned no buffers");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => warn!("failed to read perf event on cpu {cpu_id}: {e}"),
                }
            }
        }));
    }

    let program: &mut KProbe = ebpf.program_mut("tcpdump").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    running.store(false, Ordering::Relaxed);
    for handle in handles {
        if let Err(e) = handle.await {
            warn!("failed to join reader task: {e}");
        }
    }

    Ok(())
}
