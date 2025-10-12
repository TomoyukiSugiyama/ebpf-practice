use std::{
    ptr,
    sync::{
        Arc, Once, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use aya::Ebpf;
use aya::maps::perf::{PerfBufferError, PerfEventArrayBuffer};
use aya::maps::{MapData, PerfEventArray};
use aya::programs::KProbe;
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{debug, info, warn};
use tcpdump_common::TcpEvent;
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{signal, task};

const EVENT_SIZE: usize = core::mem::size_of::<TcpEvent>();
const BUFFER_COUNT: usize = 4;

static PRINT_HEADER: Once = Once::new();
static BASE_MONO_TS: OnceLock<u64> = OnceLock::new();
static BASE_WALL_TIME: OnceLock<OffsetDateTime> = OnceLock::new();

fn print_header() {
    PRINT_HEADER.call_once(|| {
        info!(
            "{:<3} {:<7} {:<7} {:<16} {:<35} {:<4} {:<11} {:>2} {:<22} {:<22}",
            "CPU", "PID", "TGID", "COMM", "TIME", "DIR", "STATE", "ID", "SRC", "DST"
        );
    });
}

#[inline]
fn parse_event(bytes: &BytesMut) -> Option<TcpEvent> {
    if bytes.len() < EVENT_SIZE {
        return None;
    }

    let mut event = TcpEvent::default();

    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut event as *mut TcpEvent as *mut u8,
            EVENT_SIZE,
        );
    }

    Some(event)
}

fn log_event(cpu_id: u32, bytes: &BytesMut) {
    match parse_event(bytes) {
        Some(event) => {
            let base_ts = *BASE_MONO_TS.get_or_init(|| event.timestamp_ns());
            let base_wall = *BASE_WALL_TIME.get_or_init(|| {
                OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
            });
            let delta_ns = event.timestamp_ns().saturating_sub(base_ts);
            let seconds = (delta_ns / 1_000_000_000) as i64;
            let nanos = (delta_ns % 1_000_000_000) as i32;
            let event_time = base_wall + TimeDuration::new(seconds, nanos);
            let formatted_ts = event_time
                .format(&Rfc3339)
                .unwrap_or_else(|_| format!("{event_time:?}"));
            info!(
                "{:<3} {:<7} {:<7} {:<16} {:<35} {:<4} {:<11} {:>2} {:<22} {:<22}",
                cpu_id,
                event.pid,
                event.tgid,
                event.command(),
                formatted_ts,
                event.direction_label(),
                event.state_label(),
                event.state(),
                event.src_socket(),
                event.dst_socket()
            );
        }
        None => warn!(
            "malformed perf event; expected {EVENT_SIZE} bytes, got {}",
            bytes.len()
        ),
    }
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn load_ebpf() -> anyhow::Result<Ebpf> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tcpdump"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("aya-log disabled: {e}");
    }
    Ok(ebpf)
}

fn create_event_array(ebpf: &mut Ebpf) -> anyhow::Result<PerfEventArray<MapData>> {
    let map = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("EVENTS map missing"))?;
    PerfEventArray::try_from(map).map_err(Into::into)
}

fn spawn_reader_tasks(
    events: &mut PerfEventArray<MapData>,
    running: Arc<AtomicBool>,
) -> anyhow::Result<Vec<task::JoinHandle<()>>> {
    let perf_buffers = online_cpus()
        .map_err(|(_, error)| error)?
        .into_iter()
        .map(|cpu_id| events.open(cpu_id, None).map(|buf| (cpu_id, buf)))
        .collect::<Result<Vec<_>, _>>()?;

    let mut handles = Vec::with_capacity(perf_buffers.len());
    for (cpu_id, buf) in perf_buffers.into_iter() {
        let running = running.clone();
        handles.push(task::spawn_blocking(move || {
            let mut buf = buf;
            reader_loop(cpu_id, running, &mut buf);
        }));
    }

    Ok(handles)
}

fn reader_loop(cpu_id: u32, running: Arc<AtomicBool>, buf: &mut PerfEventArrayBuffer<MapData>) {
    let mut buffers: [BytesMut; BUFFER_COUNT] =
        core::array::from_fn(|_| BytesMut::with_capacity(EVENT_SIZE));

    while running.load(Ordering::Relaxed) {
        match buf.read_events(&mut buffers) {
            Ok(events) => {
                if events.read > 0 {
                    buffers
                        .iter()
                        .filter(|buf| !buf.is_empty())
                        .for_each(|buf| log_event(cpu_id, buf));
                }
                buffers.iter_mut().for_each(|buf| buf.clear());
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
}

fn load_program(ebpf: &mut Ebpf) -> anyhow::Result<&mut KProbe> {
    let program = ebpf
        .program_mut("tcpdump")
        .ok_or_else(|| anyhow::anyhow!("tcpdump program not found"))?;
    let program: &mut KProbe = program.try_into()?;
    program.load()?;
    Ok(program)
}

async fn run_program(
    program: &mut KProbe,
    running: Arc<AtomicBool>,
    handles: Vec<task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    print_header();
    program.attach("tcp_set_state", 0)?;
    ctrl_c.await?;
    info!("Exiting...");

    running.store(false, Ordering::Relaxed);
    for handle in handles {
        if let Err(e) = handle.await {
            warn!("failed to join reader task: {e}");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    bump_memlock_rlimit();

    let mut ebpf = load_ebpf()?;
    let mut events = create_event_array(&mut ebpf)?;
    let running = Arc::new(AtomicBool::new(true));
    let handles = spawn_reader_tasks(&mut events, running.clone())?;
    let program = load_program(&mut ebpf)?;

    run_program(program, running, handles).await
}
