use clap::{Parser, Subcommand};
use colored::*;
use crossterm;
use pmet::process_monitor::{ProcessMonitor, Metrics};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

/// Process Monitoring and Execution Tool (PMET)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Output in JSON format
    #[clap(short, long)]
    json: bool,

    /// Write output to file
    #[clap(short, long, value_name = "FILE")]
    out: Option<PathBuf>,

    /// Base sampling interval in milliseconds (default: 100)
    #[clap(short, long, default_value = "100")]
    interval: u64,

    /// Maximum sampling interval in milliseconds (default: 1000)
    #[clap(short, long, default_value = "1000")]
    max_interval: u64,
    
    /// Update output in place instead of printing new lines
    #[clap(short, long)]
    update_in_place: bool,
    
    /// Maximum duration to monitor in seconds (0 = unlimited)
    #[clap(short, long, default_value = "0")]
    duration: u64,
    
    /// Show I/O since process start instead of since monitoring start
    #[clap(long)]
    since_process_start: bool,
    
    /// Exclude child processes from monitoring (monitor only the main process)
    #[clap(long)]
    exclude_children: bool,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run and monitor a new process
    Run {
        /// Command to run and monitor
        #[clap(required = true)]
        command: Vec<String>,
    },
    
    /// Monitor an existing process by PID
    Attach {
        /// Process ID (PID) to monitor
        #[clap(required = true)]
        pid: usize,
    }
}

fn main() -> io::Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Create output file if specified
    let out_path = args.out.clone(); // Clone to keep the original
    let mut out_file = args.out.as_ref().map(|path| {
        File::create(path).unwrap_or_else(|err| {
            eprintln!("Error creating output file: {}", err);
            exit(1);
        })
    });
    
    // Create process monitor based on the subcommand
    let mut monitor = match &args.command {
        Commands::Run { command } => {
            if command.is_empty() {
                eprintln!("Error: Empty command");
                exit(1);
            }
            
            match ProcessMonitor::new_with_options(
                command.clone(),
                Duration::from_millis(args.interval),
                Duration::from_millis(args.max_interval),
                args.since_process_start,
            ) {
                Ok(m) => {
                    println!("Monitoring process: {}", command.join(" ").cyan());
                    m
                },
                Err(err) => {
                    eprintln!("Error starting command: {}", err);
                    exit(1);
                }
            }
        },
        Commands::Attach { pid } => {
            match ProcessMonitor::from_pid_with_options(
                *pid,
                Duration::from_millis(args.interval),
                Duration::from_millis(args.max_interval),
                args.since_process_start,
            ) {
                Ok(m) => {
                    println!("Monitoring existing process with PID: {}", pid.to_string().cyan());
                    m
                },
                Err(err) => {
                    eprintln!("Error attaching to process: {}", err);
                    exit(1);
                }
            }
        }
    };
    
    // Setup signal handling for clean shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\nReceived Ctrl-C, finishing...");
    }).expect("Error setting Ctrl-C handler");
    
    println!("Press Ctrl+C to stop monitoring");
    println!();
    
    // For in-place updates - use a more sophisticated approach
    let mut terminal_width = 80; // Default fallback
    if let Ok((w, _)) = crossterm::terminal::size() {
        terminal_width = w as usize;
    }
    let mut needs_newline_on_exit = false;
    
    // Progress indicator for in-place updates
    let progress_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut progress_index = 0;
    
    // Variables for collecting results
    let start_time = Instant::now();
    let mut metrics_count = 0;
    let mut results = Vec::new();
    
    // Calculate timeout if duration is specified
    let timeout = if args.duration > 0 {
        Some(Duration::from_secs(args.duration))
    } else {
        None
    };
    
    // Monitoring loop
    while monitor.is_running() && running.load(Ordering::SeqCst) {
        // Check timeout
        if let Some(timeout_duration) = timeout {
            if start_time.elapsed() >= timeout_duration {
                println!("\nTimeout reached after {} seconds", args.duration);
                break;
            }
        }
            
        if args.exclude_children {
            // Monitor only the main process
            if let Some(metrics) = monitor.sample_metrics() {
                metrics_count += 1;
                    
                // Store metrics for final summary if we're writing to a file
                if args.out.is_some() {
                    results.push(metrics.clone());
                }
                    
                // Format and display metrics
                if args.json {
                    let json = serde_json::to_string(&metrics).unwrap();
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", json)?;
                    } else if args.update_in_place {
                        // Clear line and print new content with spinner and elapsed time
                        let spinner = progress_chars[progress_index % progress_chars.len()];
                        let elapsed = start_time.elapsed().as_secs();
                        print!("\r{}\r{} [{}s] {}", " ".repeat(terminal_width.saturating_sub(1)), spinner.to_string().cyan(), elapsed.to_string().bright_black(), json);
                        io::stdout().flush()?;
                        needs_newline_on_exit = true;
                        progress_index += 1;
                    } else {
                        println!("{}", json);
                    }
                } else {
                    let formatted = format_metrics(&metrics);
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", formatted)?;
                    } else if args.update_in_place {
                        // Clear line and print new content with spinner and elapsed time
                        let spinner = progress_chars[progress_index % progress_chars.len()];
                        let elapsed = start_time.elapsed().as_secs();
                        print!("\r{}\r{} [{}s] {}", " ".repeat(terminal_width.saturating_sub(1)), spinner.to_string().cyan(), elapsed.to_string().bright_black(), formatted);
                        io::stdout().flush()?;
                        needs_newline_on_exit = true;
                        progress_index += 1;
                    } else {
                        println!("{}", formatted);
                    }
                }
            }
        } else {
            // Monitor process tree (default behavior)
            let tree_metrics = monitor.sample_tree_metrics();
            if let Some(agg_metrics) = tree_metrics.aggregated.as_ref() {
                metrics_count += 1;
                    
                // Store aggregated metrics for final summary if we're writing to a file
                if args.out.is_some() {
                    // Convert aggregated metrics to regular metrics for storage compatibility
                    let storage_metrics = convert_aggregated_to_metrics(agg_metrics);
                    results.push(storage_metrics);
                }
                    
                // Format and display metrics
                if args.json {
                    let json = serde_json::to_string(&tree_metrics).unwrap();
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", json)?;
                    } else if args.update_in_place {
                        // For in-place updates, show just aggregated metrics
                        let agg_json = serde_json::to_string(&agg_metrics).unwrap();
                        let spinner = progress_chars[progress_index % progress_chars.len()];
                        let elapsed = start_time.elapsed().as_secs();
                        print!("\r{}\r{} [{}s] {}", " ".repeat(terminal_width.saturating_sub(1)), spinner.to_string().cyan(), elapsed.to_string().bright_black(), agg_json);
                        io::stdout().flush()?;
                        needs_newline_on_exit = true;
                        progress_index += 1;
                    } else {
                        println!("{}", json);
                    }
                } else {
                    let formatted = format_aggregated_metrics(agg_metrics);
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", formatted)?;
                    } else if args.update_in_place {
                        // Clear line and print new content with spinner and elapsed time
                        let spinner = progress_chars[progress_index % progress_chars.len()];
                        let elapsed = start_time.elapsed().as_secs();
                        print!("\r{}\r{} [{}s] {}", " ".repeat(terminal_width.saturating_sub(1)), spinner.to_string().cyan(), elapsed.to_string().bright_black(), formatted);
                        io::stdout().flush()?;
                        needs_newline_on_exit = true;
                        progress_index += 1;
                    } else {
                        println!("{}", formatted);
                    }
                }
            }
        }
            
        // Sleep for the adaptive interval
        std::thread::sleep(monitor.adaptive_interval());
    }
    
    // Clean up and ensure we have a newline if we were updating in place
    if needs_newline_on_exit {
        println!();
    }
    
    // Print summary
    let runtime = start_time.elapsed();
    println!("\nMonitoring complete after {:.1} seconds", runtime.as_secs_f64());
    println!("Collected {} metric samples", metrics_count);
    
    // If we wrote to a file, print the path
    if let Some(path) = &out_path {
        println!("Results written to {}", path.display().to_string().green());
        println!("Sample count: {}", results.len());
    }
    
    Ok(())
}

fn format_metrics(metrics: &Metrics) -> String {
    let cpu_color = match metrics.cpu_usage {
        c if c < 10.0 => "green",
        c if c < 50.0 => "yellow",
        _ => "red",
    };
    
    let mem_mb = metrics.mem_rss_kb as f64 / 1024.0;
    let mem_color = match mem_mb {
        m if m < 100.0 => "green",
        m if m < 500.0 => "yellow",
        _ => "red",
    };
    
    format!(
        "CPU: {} | Memory: {} | Threads: {} | Disk: {} read, {} written | Net: {} rx, {} tx | Uptime: {}s",
        format!("{:.1}%", metrics.cpu_usage).color(cpu_color),
        format!("{:.1} MB", mem_mb).color(mem_color),
        metrics.thread_count,
        format_bytes(metrics.disk_read_bytes).cyan(),
        format_bytes(metrics.disk_write_bytes).cyan(),
        format_bytes(metrics.net_rx_bytes).green(),
        format_bytes(metrics.net_tx_bytes).green(),
        metrics.uptime_secs,
    )
}

fn format_aggregated_metrics(metrics: &pmet::process_monitor::AggregatedMetrics) -> String {
    let cpu_color = match metrics.cpu_usage {
        c if c < 10.0 => "green",
        c if c < 50.0 => "yellow", 
        _ => "red",
    };
    
    let mem_mb = metrics.mem_rss_kb as f64 / 1024.0;
    let mem_color = match mem_mb {
        m if m < 100.0 => "green",
        m if m < 500.0 => "yellow",
        _ => "red",
    };
    
    format!(
        "Tree ({} procs): CPU: {} | Memory: {} | Threads: {} | Disk: {} read, {} written | Net: {} rx, {} tx | Uptime: {}s",
        metrics.process_count,
        format!("{:.1}%", metrics.cpu_usage).color(cpu_color),
        format!("{:.1} MB", mem_mb).color(mem_color),
        metrics.thread_count,
        format_bytes(metrics.disk_read_bytes).cyan(),
        format_bytes(metrics.disk_write_bytes).cyan(),
        format_bytes(metrics.net_rx_bytes).green(),
        format_bytes(metrics.net_tx_bytes).green(),
        metrics.uptime_secs,
    )
}

fn convert_aggregated_to_metrics(agg: &pmet::process_monitor::AggregatedMetrics) -> pmet::process_monitor::Metrics {
    pmet::process_monitor::Metrics {
        cpu_usage: agg.cpu_usage,
        mem_rss_kb: agg.mem_rss_kb,
        disk_read_bytes: agg.disk_read_bytes,
        disk_write_bytes: agg.disk_write_bytes,
        net_rx_bytes: agg.net_rx_bytes,
        net_tx_bytes: agg.net_tx_bytes,
        thread_count: agg.thread_count,
        uptime_secs: agg.uptime_secs,
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}