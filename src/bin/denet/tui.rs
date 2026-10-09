//! `--tui`: a live full-screen view of the monitored process tree.
//!
//! The screen belongs to the TUI, so while it runs our stderr (warnings) and
//! the command's stdout/stderr go to a log file, named on exit.

use super::format_bytes;
use denet::core::constants::sampling::LIVENESS_POLL;
use denet::monitor::AggregatedMetrics;
use denet::ProcessMonitor;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Block, Chart, Dataset, GraphType};
use ratatui::DefaultTerminal;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Samples kept per graph: a 512-column graph's worth in braille.
const HISTORY: usize = 1024;
/// Per-sample decay of a graph's scale once its peak has passed: the scale
/// jumps up at once but eases down (halves in ~70 samples) instead of
/// snapping when a spike scrolls off.
const SCALE_DECAY: f64 = 0.99;
/// Graph styles `m` cycles through: (marker, name, dot columns per cell).
const MARKERS: [(Marker, &str, usize); 5] = [
    (Marker::Braille, "braille", 2),
    (Marker::Octant, "octant", 2),
    (Marker::Sextant, "sextant", 2),
    (Marker::Quadrant, "quadrant", 2),
    (Marker::HalfBlock, "half-block", 1),
];

/// Lines of the log shown when the command fails.
const LOG_TAIL_LINES: usize = 20;

/// The log file, once [`stderr_to_log`] has made one.
static LOG_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

#[cfg(target_os = "linux")]
static SAVED_STDERR: std::sync::Mutex<Option<(std::os::fd::OwnedFd, std::path::PathBuf)>> =
    std::sync::Mutex::new(None);

/// Point fd 2 at a fresh log file. Call before spawning, so the command
/// inherits it too.
#[cfg(target_os = "linux")]
pub fn stderr_to_log() -> io::Result<()> {
    use std::os::fd::{AsFd, AsRawFd};
    let path = std::env::temp_dir().join(format!("denet-tui-{}.log", std::process::id()));
    let log = std::fs::File::create(&path)?;
    let saved = io::stderr().as_fd().try_clone_to_owned()?;
    if unsafe { libc::dup2(log.as_raw_fd(), 2) } < 0 {
        return Err(io::Error::last_os_error());
    }
    *SAVED_STDERR.lock().unwrap() = Some((saved, path.clone()));
    let _ = LOG_PATH.set(path);
    Ok(())
}

/// Undo [`stderr_to_log`] and say where the output went. No-op otherwise.
#[cfg(target_os = "linux")]
pub fn restore_stderr() {
    use std::os::fd::AsRawFd;
    if let Some((saved, path)) = SAVED_STDERR.lock().unwrap().take() {
        unsafe { libc::dup2(saved.as_raw_fd(), 2) };
        eprintln!("Command output and warnings: {}", path.display());
    }
}

/// Print the last lines of the log to stderr, after the command exited with
/// `code`. Reads only the end of the file, however large it grew.
pub fn print_log_tail(code: i32) {
    use std::io::{Read, Seek, SeekFrom};
    let Some(path) = LOG_PATH.get() else { return };
    let Ok(mut log) = std::fs::File::open(path) else {
        return;
    };
    let len = log.metadata().map(|m| m.len()).unwrap_or(0);
    let mut tail = Vec::new();
    if log
        .seek(SeekFrom::Start(len.saturating_sub(64 * 1024)))
        .is_err()
        || log.read_to_end(&mut tail).is_err()
    {
        return;
    }
    let tail = String::from_utf8_lossy(&tail);
    let lines: Vec<&str> = tail.lines().collect();
    if lines.is_empty() {
        return;
    }
    eprintln!("\nCommand exited with status {code}; last lines of its output:");
    for line in &lines[lines.len().saturating_sub(LOG_TAIL_LINES)..] {
        eprintln!("  {line}");
    }
}

// No fd juggling off Linux: output there may draw over the TUI.
#[cfg(not(target_os = "linux"))]
pub fn stderr_to_log() -> io::Result<()> {
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub fn restore_stderr() {}

#[derive(Clone, Copy)]
struct Counters {
    ts_ms: u64,
    disk: (u64, u64),
    tcp: Option<(u64, u64)>,
}

/// One graph. Mirrored ones (disk, TCP) plot `down` (write/tx) below a
/// center line, btop style; the others only plot `up`.
#[derive(Default)]
struct Panel {
    title: Line<'static>,
    colors: (Color, Color),
    mirrored: bool,
    data: VecDeque<(u64, u64)>,
    /// Decaying (up, down) scale, see [`SCALE_DECAY`].
    scale: (f64, f64),
    /// Round the up scale up to a multiple of this (CPU: whole cores).
    scale_step: Option<f64>,
}

impl Panel {
    fn up_scale(&self) -> f64 {
        match self.scale_step {
            // A tenth of a step of slack: a noisy 203% stays on a 2-core
            // scale (clipped at the top) instead of flipping to 3.
            Some(step) => ((self.scale.0 - step / 10.0) / step).ceil().max(1.0) * step,
            None => self.scale.0,
        }
    }
}

/// A panel's latest sample: title, colors, value, mirrored value.
type Sample = (Line<'static>, (Color, Color), u64, Option<u64>);

/// `" Disk  ▲ read 1MB/s  ▼ write 2MB/s "`, each half in its graph's color.
fn mirrored_title(name: &str, colors: (Color, Color), up: String, down: String) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!(" {name}  ")),
        Span::styled(format!("▲ {up}"), colors.0),
        Span::raw("  "),
        Span::styled(format!("▼ {down}"), colors.1),
        Span::raw(" "),
    ])
}

pub struct Tui {
    term: DefaultTerminal,
    label: String,
    started: Instant,
    procs: usize,
    /// Index into [`MARKERS`].
    marker: usize,
    /// Bytes; the memory graph's fixed scale.
    total_ram: u64,
    prev: Option<Counters>,
    /// CPU, memory, disk, TCP, then GPU once a sample has it.
    panels: Vec<Panel>,
}

impl Tui {
    pub fn new(label: String) -> Self {
        let term = ratatui::init();
        // ratatui's hook restores the terminal; ours first puts stderr back
        // so the panic message reaches it rather than the log.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_stderr();
            hook(info)
        }));
        Tui {
            term,
            label,
            started: Instant::now(),
            procs: 0,
            marker: 0,
            total_ram: {
                let mut sys = sysinfo::System::new();
                sys.refresh_memory();
                sys.total_memory()
            },
            prev: None,
            panels: (0..4)
                .map(|i| Panel {
                    // CPU: full height means N cores busy, N the fewest that
                    // fit the recent peak, rather than "the peak, whatever it was".
                    scale_step: (i == 0).then_some(100.0),
                    ..Default::default()
                })
                .collect(),
        }
    }

    pub fn update(&mut self, m: &AggregatedMetrics) -> io::Result<()> {
        let now = Counters {
            ts_ms: m.ts_ms,
            disk: (m.disk_read_bytes, m.disk_write_bytes),
            tcp: m.tcp_rx_bytes.zip(m.tcp_tx_bytes),
        };
        let prev = self.prev.replace(now).unwrap_or(now);
        let secs = now.ts_ms.saturating_sub(prev.ts_ms) as f64 / 1000.0;
        // Counters are cumulative since monitoring started; show per-second rates.
        let rate = |cur: u64, old: u64| {
            if secs > 0.0 {
                (cur.saturating_sub(old) as f64 / secs) as u64
            } else {
                0
            }
        };
        let (dr, dw) = (rate(now.disk.0, prev.disk.0), rate(now.disk.1, prev.disk.1));
        let (rx, tx) = match now.tcp {
            Some((rx, tx)) => {
                let (prx, ptx) = prev.tcp.unwrap_or((rx, tx));
                (rate(rx, prx), rate(tx, ptx))
            }
            None => (0, 0),
        };
        let (disk, tcp) = (
            (Color::Yellow, Color::LightBlue),
            (Color::Green, Color::LightMagenta),
        );
        let tcp_title = if now.tcp.is_some() {
            mirrored_title(
                "TCP",
                tcp,
                format!("rx {}/s", format_bytes(rx)),
                format!("tx {}/s", format_bytes(tx)),
            )
        } else {
            Line::from(" TCP  n/a (tree in another network namespace?) ")
        };

        self.procs = m.process_count;
        let rss = m.mem_rss_kb * 1024;
        let mut samples: Vec<Sample> = vec![
            (
                Line::from(format!(" CPU  {:.0}% ", m.cpu_usage)),
                (Color::Cyan, Color::Cyan),
                m.cpu_usage as u64,
                None,
            ),
            (
                Line::from(format!(
                    " Memory  {} RSS ({:.1}% of {}) ",
                    format_bytes(rss),
                    rss as f64 * 100.0 / self.total_ram.max(1) as f64,
                    format_bytes(self.total_ram)
                )),
                (Color::Magenta, Color::Magenta),
                rss,
                None,
            ),
            (
                mirrored_title(
                    "Disk",
                    disk,
                    format!("read {}/s", format_bytes(dr)),
                    format!("write {}/s", format_bytes(dw)),
                ),
                disk,
                dr,
                Some(dw),
            ),
            (tcp_title, tcp, rx, Some(tx)),
        ];
        if let Some((title, util)) = gpu_series(m) {
            samples.push((
                Line::from(title),
                (Color::LightRed, Color::LightRed),
                util,
                None,
            ));
            if self.panels.len() < samples.len() {
                // Zero-pad so its samples line up with the other graphs'.
                let len = self.panels[0].data.len().saturating_sub(1);
                self.panels.push(Panel {
                    data: VecDeque::from(vec![(0, 0); len]),
                    ..Default::default()
                });
            }
        }
        for (panel, (title, colors, up, down)) in self.panels.iter_mut().zip(samples) {
            panel.title = title;
            panel.colors = colors;
            panel.mirrored = down.is_some();
            if panel.data.len() == HISTORY {
                panel.data.pop_front();
            }
            let down = down.unwrap_or(0);
            panel.data.push_back((up, down));
            let decay = |scale: f64, v: u64| (v as f64).max(scale * SCALE_DECAY).max(1.0);
            panel.scale = (decay(panel.scale.0, up), decay(panel.scale.1, down));
        }
        // RSS hardly moves, so against its own peak it would always fill the
        // graph: scale it to the machine's RAM instead, as btop does.
        self.panels[1].scale.0 = self.total_ram.max(1) as f64;
        let cores = self.panels[0].up_scale() / 100.0;
        self.panels[0].title = Line::from(format!(
            " CPU  {:.0}%  (scale {cores} core{}) ",
            m.cpu_usage,
            if cores > 1.0 { "s" } else { "" }
        ));
        self.draw()
    }

    fn draw(&mut self) -> io::Result<()> {
        let (marker, marker_name, dots) = MARKERS[self.marker];
        let header = format!(
            " denet  {}s  {} procs  (q: stop, m: {marker_name})  {} ",
            self.started.elapsed().as_secs(),
            self.procs,
            self.label
        );
        let panels = &self.panels;
        self.term.draw(|f| {
            let outer = Block::bordered().title(header);
            let rows = Layout::vertical(vec![Constraint::Fill(1); panels.len()])
                .split(outer.inner(f.area()));
            f.render_widget(outer, f.area());
            for (panel, area) in panels.iter().zip(rows.iter()) {
                let block = Block::bordered().title(panel.title.clone());
                // One sample per dot column (two per cell for braille), newest
                // at the right edge, each filled to zero (btop style).
                let slots = block.inner(*area).width as usize * dots;
                let skip = panel.data.len().saturating_sub(slots);
                let offset = slots.saturating_sub(panel.data.len()) as f64;
                // Each half has its own scale (as btop does), so a trickle of
                // tx still shows next to a large rx.
                let points =
                    |sign: f64, scale: f64, pick: fn(&(u64, u64)) -> u64| -> Vec<(f64, f64)> {
                        panel
                            .data
                            .iter()
                            .skip(skip)
                            .map(pick)
                            .enumerate()
                            .filter(|&(_, v)| v > 0) // a zero would still draw its dot
                            .map(|(i, v)| (offset + i as f64, sign * v as f64 / scale))
                            .collect()
                    };
                let up = points(1.0, panel.up_scale(), |d| d.0);
                let down = points(-1.0, panel.scale.1, |d| d.1);
                let floor = if panel.mirrored { -1.0 } else { 0.0 };
                let dataset = |points, color| {
                    Dataset::default()
                        .marker(marker)
                        .graph_type(GraphType::Bar)
                        .style(Style::default().fg(color))
                        .data(points)
                };
                f.render_widget(
                    Chart::new(vec![
                        dataset(&up, panel.colors.0),
                        dataset(&down, panel.colors.1),
                    ])
                    .block(block)
                    .x_axis(Axis::default().bounds([0.0, slots.saturating_sub(1) as f64]))
                    .y_axis(Axis::default().bounds([floor, 1.0])),
                    *area,
                );
            }
        })?;
        Ok(())
    }

    /// [`ProcessMonitor::wait_next_sample`] plus key handling. Raw mode turns
    /// Ctrl-C into a key, so q/Esc/Ctrl-C re-raise SIGINT on our process
    /// group, stopping the command exactly as a terminal Ctrl-C would.
    pub fn wait(
        &mut self,
        monitor: &mut ProcessMonitor,
        interval: Duration,
        running: &AtomicBool,
    ) -> io::Result<()> {
        let deadline = Instant::now() + interval;
        while monitor.is_running() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(());
            }
            if !event::poll(left.min(LIVENESS_POLL))? {
                continue;
            }
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    let ctrl_c =
                        k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
                    if ctrl_c || matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                        running.store(false, Ordering::SeqCst);
                        #[cfg(target_os = "linux")]
                        unsafe {
                            libc::kill(0, libc::SIGINT)
                        };
                        return Ok(());
                    }
                    if k.code == KeyCode::Char('m') {
                        self.marker = (self.marker + 1) % MARKERS.len();
                        self.draw()?;
                    }
                }
                Event::Resize(..) => self.draw()?,
                _ => {}
            }
        }
        Ok(())
    }
}

/// GPU graph: the tree's own utilization when NVML reports it per process,
/// else the busiest device's (many GPUs only give per-process memory).
/// Needs `--gpu` (and the `gpu` feature).
#[cfg(feature = "gpu")]
fn gpu_series(m: &AggregatedMetrics) -> Option<(String, u64)> {
    let gpu = m.gpu.as_ref()?;
    let (util, scope) = match gpu.max_process_utilization() {
        Some(util) => (util, ""),
        None => (gpu.max_system_utilization()?, " (system-wide)"),
    };
    let mem = if gpu.has_process_data {
        format!("  {} VRAM", format_bytes(gpu.total_process_memory_usage()))
    } else {
        String::new()
    };
    Some((format!(" GPU  {util}%{scope}{mem} "), util as u64))
}

#[cfg(not(feature = "gpu"))]
fn gpu_series(_: &AggregatedMetrics) -> Option<(String, u64)> {
    None
}

impl Drop for Tui {
    fn drop(&mut self) {
        ratatui::restore();
        restore_stderr();
    }
}
