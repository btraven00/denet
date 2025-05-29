use clap::Parser;
use colored::*;
use pmet::process_monitor::{ProcessMonitor, Metrics};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

/// Process Monitoring and Execution Tool (PMET)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Command to run and monitor
    #[clap(value_name = "COMMAND")]
    command: Vec<String>,

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
}

fn main() -> io::Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Ensure we have a command to run
    if args.command.is_empty() {
        eprintln!("Error: No command specified");
        eprintln!("Usage: pmet [OPTIONS] COMMAND");
        exit(1);
    }
    
    // Create output file if specified
    let mut out_file = args.out.map(|path| {
        File::create(&path).unwrap_or_else(|err| {
            eprintln!("Error creating output file: {}", err);
            exit(1);
        })
    });
    
    // Create a process monitor
    let mut monitor = match ProcessMonitor::new(
        args.command.clone(),
        Duration::from_millis(args.interval),
        Duration::from_millis(args.max_interval),
    ) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("Error starting command: {}", err);
            exit(1);
        }
    };
    
    println!("Monitoring process: {}", args.command.join(" ").cyan());
    println!("Press Ctrl+C to stop monitoring");
    println!();
    
    // Monitoring loop
    while monitor.is_running() {
        if let Some(metrics) = monitor.sample_metrics() {
            // Format and display metrics
            if args.json {
                let json = serde_json::to_string(&metrics).unwrap();
                if let Some(file) = &mut out_file {
                    writeln!(file, "{}", json)?;
                } else {
                    println!("{}", json);
                }
            } else {
                let formatted = format_metrics(&metrics);
                if let Some(file) = &mut out_file {
                    writeln!(file, "{}", formatted)?;
                } else {
                    println!("{}", formatted);
                }
            }
        }
        
        // Sleep for the adaptive interval
        std::thread::sleep(monitor.adaptive_interval());
    }
    
    println!("\nProcess has completed.");
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
        "CPU: {:.1}% | Memory: {:.1} MB | Threads: {} | I/O: {} read, {} written | Uptime: {}s",
        metrics.cpu_usage.to_string().color(cpu_color),
        mem_mb.to_string().color(mem_color),
        metrics.thread_count,
        format_bytes(metrics.read_bytes).cyan(),
        format_bytes(metrics.write_bytes).cyan(),
        metrics.uptime_secs,
    )
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