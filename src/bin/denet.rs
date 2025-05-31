use clap::{Parser, Subcommand};
use colored::Colorize;
use crossterm;
use denet::process_monitor::{AggregatedMetrics, Metrics, ProcessMonitor};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

/// Dynamic Explorer of Nested Executions Tool (DENET)
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

    /// Print new lines instead of updating in place
    #[clap(short, long)]
    no_update: bool,

    /// Maximum duration to monitor in seconds (0 = unlimited)
    #[clap(short, long, default_value = "0")]
    duration: u64,

    /// Show I/O since process start instead of since monitoring start
    #[clap(long)]
    since_process_start: bool,

    /// Exclude child processes from monitoring (monitor only the main process)
    #[clap(long)]
    exclude_children: bool,

    /// Quiet mode: no output to stdout (except with --json)
    #[clap(short, long)]
    quiet: bool,

    /// Disable automatic JSON dump to out.json
    #[clap(long)]
    nodump: bool,

    /// Write statistics to file on completion
    #[clap(long, value_name = "FILE")]
    stats: Option<PathBuf>,

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
    },

    /// Generate statistics from a previously saved metrics file
    Stats {
        /// Path to the metrics file
        #[clap(required = true)]
        file: PathBuf,
    },

    /// Alias for stats command
    Summary {
        /// Path to the metrics file
        #[clap(required = true)]
        file: PathBuf,
    },
}

fn main() -> io::Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Handle stats/summary subcommand separately as they don't require a monitor
    match &args.command {
        Commands::Stats { file } | Commands::Summary { file } => {
            if let Some(old_cmd) = std::env::args().nth(1) {
                if old_cmd == "summary" && !args.quiet {
                    eprintln!("Note: Using 'stats' is recommended over 'summary'");
                }
            }
            return generate_summary_from_file(file, args.json, args.out.as_ref());
        }
        Commands::Run { .. } | Commands::Attach { .. } => {}
    }

    // Create output files
    let out_path = args.out.clone(); // Clone to keep the original
    let default_out_path = if !args.nodump && args.out.is_none() {
        Some(PathBuf::from("out.json"))
    } else {
        None
    };

    let mut out_file = out_path.as_ref().or(default_out_path.as_ref()).map(|path| {
        File::create(path).unwrap_or_else(|err| {
            eprintln!("Error creating output file: {}", err);
            exit(1);
        })
    });

    // Create stats output file if specified
    let _stats_file = args.stats.as_ref().map(|path| {
        File::create(path).unwrap_or_else(|err| {
            eprintln!("Error creating stats output file: {}", err);
            exit(1);
        })
    });

    // Create process monitor based on the subcommand
    let mut monitor = match &args.command {
        // Stats and Summary commands are handled above, not here
        Commands::Stats { .. } | Commands::Summary { .. } => unreachable!(),
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
                    if !args.quiet {
                        println!("Monitoring process: {}", command.join(" ").cyan());
                    }
                    m
                }
                Err(err) => {
                    eprintln!("Error starting command: {}", err);
                    exit(1);
                }
            }
        }
        Commands::Attach { pid } => {
            match ProcessMonitor::from_pid_with_options(
                *pid,
                Duration::from_millis(args.interval),
                Duration::from_millis(args.max_interval),
                args.since_process_start,
            ) {
                Ok(m) => {
                    if !args.quiet {
                        println!(
                            "Monitoring existing process with PID: {}",
                            pid.to_string().cyan()
                        );
                    }
                    m
                }
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
        if !args.quiet {
            println!("\nReceived Ctrl-C, finishing...");
        }
    })
    .expect("Error setting Ctrl-C handler");

    if !args.quiet {
        println!("Press Ctrl+C to stop monitoring");
        println!();
    }

    // For in-place updates - use a sophisticated approach
    let mut terminal_width = 80; // Default fallback
    if let Ok((w, _)) = crossterm::terminal::size() {
        terminal_width = w as usize;
    }
    let update_in_place = !args.no_update && !args.json;
    let mut needs_newline_on_exit = false;

    // Progress indicator for in-place updates
    let progress_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut progress_index = 0;

    // Variables for collecting results
    let start_time = Instant::now();
    let mut metrics_count = 0;
    let mut results = Vec::new();
    let mut aggregated_metrics: Vec<AggregatedMetrics> = Vec::new();

    // Calculate timeout if duration is specified
    let timeout = if args.duration > 0 {
        Some(Duration::from_secs(args.duration))
    } else {
        None
    };

    // Get metadata
    let metadata = monitor.get_metadata();

    // Emit metadata first (always for files, only output to console if JSON mode)
    if let Some(metadata_ref) = &metadata {
        let metadata_json = serde_json::to_string(&metadata_ref).unwrap();
        if let Some(file) = &mut out_file {
            writeln!(file, "{}", metadata_json)?;
        }
        if args.json && !args.quiet {
            println!("{}", metadata_json);
        }
    }

    // Monitoring loop
    while monitor.is_running() && running.load(Ordering::SeqCst) {
        // Check timeout
        if let Some(timeout_duration) = timeout {
            if start_time.elapsed() >= timeout_duration {
                if !args.quiet {
                    println!("\nTimeout reached after {} seconds", args.duration);
                }
                break;
            }
        }

        if args.exclude_children {
            // Monitor only the main process
            if let Some(metrics) = monitor.sample_metrics() {
                metrics_count += 1;

                // Store metrics for final summary
                results.push(metrics.clone());

                // Format and display metrics
                if args.json {
                    let json = serde_json::to_string(&metrics).unwrap();
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", json)?;
                    }
                    if !args.quiet {
                        if update_in_place {
                            // Clear line and print new content with spinner and elapsed time
                            let spinner = progress_chars[progress_index % progress_chars.len()];
                            let elapsed = start_time.elapsed().as_secs();
                            print!(
                                "\r{}\r{} [{}s] {}",
                                " ".repeat(terminal_width.saturating_sub(1)),
                                spinner.to_string().cyan(),
                                elapsed.to_string().bright_black(),
                                json
                            );
                            io::stdout().flush()?;
                            needs_newline_on_exit = true;
                            progress_index += 1;
                        } else {
                            println!("{}", json);
                        }
                    }
                } else {
                    let formatted = format_metrics(&metrics);
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", serde_json::to_string(&metrics).unwrap())?;
                    }
                    if !args.quiet {
                        if update_in_place {
                            // Use compact format for in-place updates
                            let formatted_compact = format_metrics_compact(&metrics);
                            let spinner = progress_chars[progress_index % progress_chars.len()];
                            let elapsed = start_time.elapsed().as_secs();
                            print!(
                                "\r{}\r{} [{}s] {}",
                                " ".repeat(terminal_width.saturating_sub(1)),
                                spinner.to_string().cyan(),
                                elapsed.to_string().bright_black(),
                                formatted_compact
                            );
                            io::stdout().flush()?;
                            needs_newline_on_exit = true;
                            progress_index += 1;
                        } else {
                            println!("{}", formatted);
                        }
                    }
                }
            }
        } else {
            // Monitor process tree (default behavior)
            let tree_metrics = monitor.sample_tree_metrics();
            if let Some(agg_metrics) = tree_metrics.aggregated.as_ref() {
                metrics_count += 1;

                // Store aggregated metrics for final summary
                // Convert aggregated metrics to regular metrics for storage compatibility
                let storage_metrics = convert_aggregated_to_metrics(agg_metrics);
                results.push(storage_metrics);

                // Also store for specialized aggregated stats
                aggregated_metrics.push(agg_metrics.clone());

                // Format and display tree metrics
                if args.json {
                    let json = serde_json::to_string(&tree_metrics).unwrap();
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", json)?;
                    }
                    if !args.quiet {
                        if update_in_place {
                            // For in-place updates, show just aggregated metrics
                            let agg_json = serde_json::to_string(&agg_metrics).unwrap();
                            let spinner = progress_chars[progress_index % progress_chars.len()];
                            let elapsed = start_time.elapsed().as_secs();
                            print!(
                                "\r{}\r{} [{}s] {}",
                                " ".repeat(terminal_width.saturating_sub(1)),
                                spinner.to_string().cyan(),
                                elapsed.to_string().bright_black(),
                                agg_json
                            );
                            io::stdout().flush()?;
                            needs_newline_on_exit = true;
                            progress_index += 1;
                        } else {
                            println!("{}", json);
                        }
                    }
                } else {
                    // Format and display tree metrics with parent and children
                    let formatted = format_aggregated_metrics(agg_metrics);
                    if let Some(file) = &mut out_file {
                        writeln!(file, "{}", serde_json::to_string(&tree_metrics).unwrap())?;
                    }
                    if !args.quiet {
                        if update_in_place {
                            // Use compact format for in-place updates
                            let formatted_compact = format_aggregated_metrics_compact(agg_metrics);
                            let spinner = progress_chars[progress_index % progress_chars.len()];
                            let elapsed = start_time.elapsed().as_secs();
                            print!(
                                "\r{}\r{} [{}s] {}",
                                " ".repeat(terminal_width.saturating_sub(1)),
                                spinner.to_string().cyan(),
                                elapsed.to_string().bright_black(),
                                formatted_compact
                            );
                            io::stdout().flush()?;
                            needs_newline_on_exit = true;
                            progress_index += 1;
                        } else {
                            println!("{}", formatted);
                        }
                    }
                }
            }
        }

        // Sleep for the adaptive interval
        std::thread::sleep(monitor.adaptive_interval());
    }

    // Calculate summary
    let runtime = start_time.elapsed();

    // Only print if not in quiet mode
    if !args.quiet {
        // Clean up and ensure we have a newline if we were updating in place
        if needs_newline_on_exit {
            println!();
        }

        println!(
            "\nMonitoring complete after {:.1} seconds",
            runtime.as_secs_f64()
        );
        println!("Collected {} metric samples", metrics_count);

        // If we wrote to a file, print the path
        if let Some(path) = &out_path {
            println!("Results written to {}", path.display().to_string().green());
        }

        // Generate and print summary
        if !results.is_empty() {
            print_summary(&results, runtime.as_secs_f64());
        }
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
        "CPU: {} | Memory: {} | Threads: {} | Disk: {} rd, {} wr | Net: {} rx, {} tx | Uptime: {}s",
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

fn format_metrics_compact(metrics: &Metrics) -> String {
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
        "CPU {} | Mem {} | Threads {} | Disk {} rd, {} wr | Net {} rx, {} tx",
        format!("{:.1}%", metrics.cpu_usage).color(cpu_color),
        format!("{:.0}M", mem_mb).color(mem_color),
        metrics.thread_count,
        format_bytes(metrics.disk_read_bytes).cyan(),
        format_bytes(metrics.disk_write_bytes).cyan(),
        format_bytes(metrics.net_rx_bytes).green(),
        format_bytes(metrics.net_tx_bytes).green(),
    )
}

fn format_aggregated_metrics(metrics: &AggregatedMetrics) -> String {
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
        "Tree ({} procs): CPU: {} | Memory: {} | Threads: {} | Disk: {} rd, {} wr | Net: {} rx, {} tx | Uptime: {}s",
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

fn format_aggregated_metrics_compact(metrics: &AggregatedMetrics) -> String {
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
        "Tree({}): CPU {} | Mem {} | Threads {} | Disk {} rd, {} wr | Net {} rx, {} tx",
        metrics.process_count,
        format!("{:.1}%", metrics.cpu_usage).color(cpu_color),
        format!("{:.0}M", mem_mb).color(mem_color),
        metrics.thread_count,
        format_bytes(metrics.disk_read_bytes).cyan(),
        format_bytes(metrics.disk_write_bytes).cyan(),
        format_bytes(metrics.net_rx_bytes).green(),
        format_bytes(metrics.net_tx_bytes).green(),
    )
}

fn convert_aggregated_to_metrics(agg: &AggregatedMetrics) -> Metrics {
    Metrics {
        ts_ms: agg.ts_ms,
        cpu_usage: agg.cpu_usage,
        mem_rss_kb: agg.mem_rss_kb,
        mem_vms_kb: agg.mem_vms_kb,
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

/// Generate and print a summary from metrics
/// Print a summary of collected metrics
fn print_summary(metrics: &[Metrics], duration: f64) {
    let summary = denet::process_monitor::Summary::from_metrics(metrics, duration);

    println!("\n{}", "EXECUTION SUMMARY".bold());
    println!("{}", "=================".bold());
    println!("Duration: {:.2} seconds", summary.total_time_secs);
    println!("Samples: {}", summary.sample_count);
    println!("Max processes: {}", summary.max_processes);
    println!("Max threads: {}", summary.max_threads);
    println!(
        "Peak memory usage: {} MB",
        (summary.peak_mem_rss_kb as f64 / 1024.0).round()
    );
    println!("Average CPU usage: {:.1}%", summary.avg_cpu_usage);
    println!(
        "Total disk read: {}",
        format_bytes(summary.total_disk_read_bytes)
    );
    println!(
        "Total disk write: {}",
        format_bytes(summary.total_disk_write_bytes)
    );
    println!(
        "Total network received: {}",
        format_bytes(summary.total_net_rx_bytes)
    );
    println!(
        "Total network sent: {}",
        format_bytes(summary.total_net_tx_bytes)
    );
}

/// Generate a summary from a JSON file with metrics
fn generate_summary_from_file(
    file_path: &PathBuf,
    json_output: bool,
    out_file: Option<&PathBuf>,
) -> io::Result<()> {
    if !json_output {
        println!("Generating statistics from file: {}", file_path.display());
    }

    match denet::process_monitor::Summary::from_json_file(file_path) {
        Ok(summary) => {
            if json_output {
                let json = serde_json::to_string_pretty(&summary).unwrap();

                // If out file is specified, write JSON to the file
                if let Some(out_path) = out_file {
                    let mut file = File::create(out_path)?;
                    writeln!(file, "{}", json)?;
                } else {
                    // Otherwise print to stdout
                    println!("{}", json);
                }
            } else {
                // If out file is specified, write human-readable output to the file
                if let Some(out_path) = out_file {
                    let mut file = File::create(out_path)?;
                    writeln!(file, "\n{}", "FILE STATISTICS".bold())?;
                    writeln!(file, "{}", "===============".bold())?;
                    writeln!(file, "Duration: {:.2} seconds", summary.total_time_secs)?;
                    writeln!(file, "Samples: {}", summary.sample_count)?;
                    writeln!(file, "Max processes: {}", summary.max_processes)?;
                    writeln!(file, "Max threads: {}", summary.max_threads)?;
                    writeln!(
                        file,
                        "Peak memory usage: {} MB",
                        (summary.peak_mem_rss_kb as f64 / 1024.0).round()
                    )?;
                    writeln!(file, "Average CPU usage: {:.1}%", summary.avg_cpu_usage)?;
                    writeln!(
                        file,
                        "Total disk read: {}",
                        format_bytes(summary.total_disk_read_bytes)
                    )?;
                    writeln!(
                        file,
                        "Total disk write: {}",
                        format_bytes(summary.total_disk_write_bytes)
                    )?;
                    writeln!(
                        file,
                        "Total network received: {}",
                        format_bytes(summary.total_net_rx_bytes)
                    )?;
                    writeln!(
                        file,
                        "Total network sent: {}",
                        format_bytes(summary.total_net_tx_bytes)
                    )?;
                } else {
                    // Otherwise print to stdout
                    println!("\n{}", "FILE STATISTICS".bold());
                    println!("{}", "===============".bold());
                    println!("Duration: {:.2} seconds", summary.total_time_secs);
                    println!("Samples: {}", summary.sample_count);
                    println!("Max processes: {}", summary.max_processes);
                    println!("Max threads: {}", summary.max_threads);
                    println!(
                        "Peak memory usage: {} MB",
                        (summary.peak_mem_rss_kb as f64 / 1024.0).round()
                    );
                    println!("Average CPU usage: {:.1}%", summary.avg_cpu_usage);
                    println!(
                        "Total disk read: {}",
                        format_bytes(summary.total_disk_read_bytes)
                    );
                    println!(
                        "Total disk write: {}",
                        format_bytes(summary.total_disk_write_bytes)
                    );
                    println!(
                        "Total network received: {}",
                        format_bytes(summary.total_net_rx_bytes)
                    );
                    println!(
                        "Total network sent: {}",
                        format_bytes(summary.total_net_tx_bytes)
                    );
                }
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Error processing metrics file: {}", e);
            Err(e)
        }
    }
}
