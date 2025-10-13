use anyhow::{Context as _, Result};
use aya::maps::ring_buf::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use chrono::{DateTime, Local};
use clap::Parser;
use crossterm::{
    event::{self, Event as CEvent, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use log::{debug, warn};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell as TuiCell, Paragraph, Row, Table, TableState, Wrap},
};
use std::{
    fmt::{self, Write as FmtWrite},
    io::{self, Stdout},
    net::Ipv4Addr,
    time::{Duration, SystemTime},
};
use tcpdump_common::user::PacketEventExt as _;
use tokio::{signal, sync::mpsc, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s1")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tcpdump"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = match logger.readable_mut().await {
                        Ok(g) => g,
                        Err(_) => break,
                    };
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
    program.attach(&iface, XdpFlags::default()).context(
        "failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE",
    )?;

    let ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let (packet_tx, packet_rx) = mpsc::channel::<CapturedPacket>(1024);

    let reader_handle: task::JoinHandle<Result<(), anyhow::Error>> = {
        let tx = packet_tx.clone();
        task::spawn(async move {
            let mut ring_buf = ring_buf;

            loop {
                let mut guard = match ring_buf.readable_mut().await {
                    Ok(g) => g,
                    Err(err) => return Err(err.into()),
                };
                {
                    let ring_buf = guard.get_inner_mut();
                    while let Some(event) = ring_buf.next() {
                        if let Some(packet) = event.packet_event() {
                            let payload = packet.payload();
                            debug!("raw packet: {:02x?}", payload);
                            match describe_packet(payload) {
                                Ok(parsed) => {
                                    if tx.send(parsed).await.is_err() {
                                        return Ok(());
                                    }
                                }
                                Err(err) => {
                                    warn!("failed to analyze packet (len={}): {err}", payload.len())
                                }
                            }
                        }
                    }
                }
                guard.clear_ready();
            }
        })
    };
    drop(packet_tx);

    let mut terminal = setup_terminal()?;
    let input_rx = spawn_input_listener();
    let app_result = run_app(&mut terminal, packet_rx, input_rx).await;
    restore_terminal(&mut terminal)?;

    reader_handle.abort();
    if let Err(err) = reader_handle.await
        && !err.is_cancelled()
    {
        warn!("packet reader task failed: {err}");
    }

    app_result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;
    terminal.clear()?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    terminal.show_cursor()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    mut packet_rx: mpsc::Receiver<CapturedPacket>,
    mut input_rx: mpsc::UnboundedReceiver<InputEvent>,
) -> Result<()> {
    let mut app = App::new();
    let mut ctrl_c = Box::pin(signal::ctrl_c());
    let mut packets_closed = false;
    let mut input_closed = false;

    loop {
        terminal.draw(|frame| draw(frame, &app))?;

        if packets_closed && input_closed {
            break;
        }

        tokio::select! {
            _ = &mut ctrl_c => break,
            maybe_packet = packet_rx.recv(), if !packets_closed => match maybe_packet {
                Some(packet) => app.on_packet(packet),
                None => packets_closed = true,
            },
            maybe_event = input_rx.recv(), if !input_closed => match maybe_event {
                Some(event) => {
                    if app.handle_input(event) {
                        break;
                    }
                }
                None => input_closed = true,
            },
        }
    }

    Ok(())
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ])
        .split(frame.size());

    draw_summary(frame, chunks[0], app);
    draw_details(frame, chunks[1], app);
    draw_payload(frame, chunks[2], app);
}

fn draw_summary(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let view_capacity = area.height.saturating_sub(3).max(1) as usize;
    let start = app.summary_start(view_capacity);
    let rows: Vec<Row> = app
        .packets
        .iter()
        .enumerate()
        .skip(start)
        .map(|(idx, packet)| {
            let summary = &packet.summary;
            Row::new(vec![
                TuiCell::from(summary.cached_time.clone()),
                TuiCell::from(summary.source.clone()),
                TuiCell::from(summary.destination.clone()),
                TuiCell::from(summary.protocol.clone()),
                TuiCell::from(summary.length.to_string()),
                TuiCell::from(summary.info.clone()),
            ])
            .style(if Some(idx) == app.selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            })
        })
        .collect();

    let header = Row::new(vec![
        TuiCell::from("Time"),
        TuiCell::from("Source"),
        TuiCell::from("Destination"),
        TuiCell::from("Protocol"),
        TuiCell::from("Length"),
        TuiCell::from("Info"),
    ]);

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Packets"))
    .highlight_style(
        Style::default()
            .bg(Color::Cyan)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    let mut table_state = TableState::default();
    if let Some(selected) = app.selected
        && selected >= start
    {
        table_state.select(Some(selected - start));
    }

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn draw_details(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let lines: Vec<Line> = match app.current_packet() {
        Some(packet) => packet
            .details
            .iter()
            .map(|entry| {
                Line::from(vec![
                    Span::styled(
                        format!("{:<12}", entry.label),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(entry.value.clone()),
                ])
            })
            .collect(),
        None => vec![Line::from("Waiting for packets...")],
    };

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Details"))
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

fn draw_payload(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let dump = match app.current_packet() {
        Some(packet) => format_hexdump(&packet.raw),
        None => String::from(""),
    };

    let paragraph = Paragraph::new(dump)
        .block(Block::default().borders(Borders::ALL).title("Raw Bytes"))
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

fn format_hexdump(data: &[u8]) -> String {
    if data.is_empty() {
        return String::from("<empty>");
    }
    let mut output = String::new();
    for (index, chunk) in data.chunks(16).enumerate() {
        let offset = index * 16;
        let _ = write!(output, "{offset:04x}  ");
        for i in 0..16 {
            if let Some(byte) = chunk.get(i) {
                let _ = write!(output, "{:02x} ", byte);
            } else {
                output.push_str("   ");
            }
            if i == 7 {
                output.push(' ');
            }
        }
        output.push(' ');
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            output.push(ch);
        }
        output.push('\n');
    }
    output
}

fn spawn_input_listener() -> mpsc::UnboundedReceiver<InputEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        loop {
            if tx.is_closed() {
                break;
            }
            if event::poll(Duration::from_millis(200)).unwrap_or(false) {
                match event::read() {
                    Ok(CEvent::Key(key)) => {
                        if tx.send(InputEvent::Key(key)).is_err() {
                            break;
                        }
                    }
                    Ok(CEvent::Resize(_, _)) => {
                        let _ = tx.send(InputEvent::Resize);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    });
    rx
}

struct App {
    packets: Vec<CapturedPacket>,
    selected: Option<usize>,
}

impl App {
    fn new() -> Self {
        Self {
            packets: Vec::new(),
            selected: None,
        }
    }

    fn on_packet(&mut self, packet: CapturedPacket) {
        const MAX_PACKETS: usize = 512;
        let follow_tail = self
            .selected
            .map(|idx| idx + 1 == self.packets.len())
            .unwrap_or(true);

        self.packets.push(packet);

        if self.packets.len() > MAX_PACKETS {
            self.packets.remove(0);
            if let Some(idx) = self.selected {
                self.selected = Some(idx.saturating_sub(1));
            }
        }

        if self.packets.is_empty() {
            self.selected = None;
        } else if follow_tail || self.selected.is_none() {
            self.selected = Some(self.packets.len() - 1);
        } else if let Some(idx) = self.selected
            && idx >= self.packets.len()
        {
            self.selected = Some(self.packets.len() - 1);
        }
    }

    fn handle_input(&mut self, event: InputEvent) -> bool {
        match event {
            InputEvent::Key(KeyEvent {
                code, modifiers, ..
            }) => {
                if modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(code, KeyCode::Char('c') | KeyCode::Char('C'))
                {
                    return true;
                }

                match code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return true,
                    KeyCode::Up => self.select_prev(1),
                    KeyCode::Down => self.select_next(1),
                    KeyCode::PageUp => self.select_prev(10),
                    KeyCode::PageDown => self.select_next(10),
                    KeyCode::Home => self.select_first(),
                    KeyCode::End => self.select_last(),
                    _ => {}
                }
            }
            InputEvent::Resize => {}
        }
        false
    }

    fn select_prev(&mut self, count: usize) {
        if self.packets.is_empty() {
            return;
        }
        let current = self.selected.unwrap_or(0);
        let new = current.saturating_sub(count);
        self.selected = Some(new);
    }

    fn select_next(&mut self, count: usize) {
        if self.packets.is_empty() {
            return;
        }
        let current = self
            .selected
            .unwrap_or_else(|| self.packets.len().saturating_sub(1));
        let new = (current + count).min(self.packets.len().saturating_sub(1));
        self.selected = Some(new);
    }

    fn select_first(&mut self) {
        if self.packets.is_empty() {
            return;
        }
        self.selected = Some(0);
    }

    fn select_last(&mut self) {
        if self.packets.is_empty() {
            return;
        }
        self.selected = Some(self.packets.len() - 1);
    }

    fn current_packet(&self) -> Option<&CapturedPacket> {
        self.selected.and_then(|idx| self.packets.get(idx))
    }

    fn summary_start(&self, capacity: usize) -> usize {
        if self.packets.len() <= capacity {
            return 0;
        }
        let selected = self
            .selected
            .unwrap_or_else(|| self.packets.len().saturating_sub(1));
        if selected < capacity {
            0
        } else {
            selected + 1 - capacity
        }
    }
}

enum InputEvent {
    Key(KeyEvent),
    Resize,
}

struct CapturedPacket {
    summary: SummaryRow,
    details: Vec<DetailEntry>,
    raw: Vec<u8>,
}

struct SummaryRow {
    source: String,
    destination: String,
    protocol: String,
    length: usize,
    info: String,
    cached_time: String,
}

struct DetailEntry {
    label: &'static str,
    value: String,
}

impl DetailEntry {
    fn new(label: &'static str, value: String) -> Self {
        Self { label, value }
    }
}

fn describe_packet(bytes: &[u8]) -> Result<CapturedPacket, &'static str> {
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

    let timestamp = SystemTime::now();
    let cached_time = format_cached_time(timestamp);
    let mut details = vec![
        DetailEntry::new("Timestamp", cached_time.clone()),
        DetailEntry::new("Frame", format!("{frame_len} bytes")),
        DetailEntry::new(
            "Ethernet",
            format!(
                "{} -> {} type=0x{:04x}",
                MacAddr(src_mac),
                MacAddr(dst_mac),
                ethertype
            ),
        ),
    ];

    let mut summary = SummaryRow {
        source: MacAddr(src_mac).to_string(),
        destination: MacAddr(dst_mac).to_string(),
        protocol: format!("0x{:04x}", ethertype),
        length: frame_len,
        info: format!("ethertype=0x{:04x}", ethertype),
        cached_time,
    };

    if ethertype != 0x0800 {
        return Ok(CapturedPacket {
            summary,
            details,
            raw: bytes.to_vec(),
        });
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

    summary.source = src_ip.to_string();
    summary.destination = dst_ip.to_string();
    summary.protocol = if protocol == 6 {
        "TCP".to_string()
    } else {
        format!("IPv4/{protocol}")
    };

    details.push(DetailEntry::new(
        "IPv4",
        format!(
            "{} -> {} TTL={} TotalLen={}",
            src_ip, dst_ip, ttl, total_length
        ),
    ));

    if protocol != 6 {
        summary.info = format!("proto={} ttl={} total_len={}", protocol, ttl, total_length);
        return Ok(CapturedPacket {
            summary,
            details,
            raw: bytes.to_vec(),
        });
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

    summary.info = format!(
        "{} -> {} seq={} ack={} flags=[{}] len={}",
        src_port,
        dst_port,
        seq,
        ack,
        TcpFlags(flags),
        payload_len
    );

    details.push(DetailEntry::new(
        "TCP",
        format!(
            "{} -> {} Seq={} Ack={} Window={} Header={} Payload={}",
            src_port, dst_port, seq, ack, window, data_offset, payload_len
        ),
    ));
    details.push(DetailEntry::new("Flags", TcpFlags(flags).to_string()));

    Ok(CapturedPacket {
        summary,
        details,
        raw: bytes.to_vec(),
    })
}

fn format_cached_time(ts: SystemTime) -> String {
    let datetime: DateTime<Local> = ts.into();
    datetime.format("%H:%M:%S%.3f").to_string()
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
