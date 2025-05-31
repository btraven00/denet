# Denet JSON Data Format

Denet outputs JSON in a streaming format optimized for efficiency and time-series analysis.

## Format Structure

**First line**: Process metadata (emitted once)
```json
{"pid": 1234, "cmd": ["sleep", "5"], "exe": "/usr/bin/sleep", "t0_ms": 1748542000000}
```

**Subsequent lines**: Process tree metrics (streamed continuously)
```json
{"ts_ms": 1748542001000, "parent": {...}, "children": [...], "aggregated": {...}}
```

## Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Process ID |
| `cmd` | string[] | Command line arguments |
| `exe` | string | Executable path |
| `t0_ms` | number | Process start time (Unix milliseconds) |

## Metrics Fields

### Tree Structure
| Field | Type | Description |
|-------|------|-------------|
| `ts_ms` | number | Sample timestamp (Unix milliseconds) |
| `parent` | Metrics? | Parent process metrics (null if terminated) |
| `children` | ChildMetrics[] | Child process metrics |
| `aggregated` | AggregatedMetrics? | Combined parent + children metrics |

### Individual Process Metrics
| Field | Type | Description |
|-------|------|-------------|
| `ts_ms` | number | Sample timestamp |
| `cpu_usage` | number | CPU usage percentage |
| `mem_rss_kb` | number | Resident memory (KB) |
| `mem_vms_kb` | number | Virtual memory (KB) |
| `disk_read_bytes` | number | Disk bytes read |
| `disk_write_bytes` | number | Disk bytes written |
| `net_rx_bytes` | number | Network bytes received |
| `net_tx_bytes` | number | Network bytes transmitted |
| `thread_count` | number | Number of threads |
| `uptime_secs` | number | Process uptime (seconds) |

### Child Process Metrics
| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Child process ID |
| `command` | string | Child process name |
| `metrics` | Metrics | Child process metrics |

### Aggregated Metrics
Includes all fields from Individual Process Metrics plus:
| Field | Type | Description |
|-------|------|-------------|
| `process_count` | number | Total processes (parent + children) |

## I/O Accounting

- **Default**: Shows delta I/O since monitoring started
- **`--since-process-start`**: Shows cumulative I/O since process start
- **Network I/O**: System-wide approximation (not per-process)

## Output Options

- **Default**: Update metrics in-place in the terminal and write JSON to `out.json`
- **`--json`**: Output JSON format to stdout
- **`--no-update`**: Print new lines instead of updating in-place
- **`--quiet`**: Suppress stdout output (except when used with `--json`)
- **`--nodump`**: Disable automatic JSON dump to `out.json`
- **`--out FILE`**: Write JSON output to specified file
- **`--stats FILE`**: Write summary statistics to specified file

## Example Complete Record

```json
{"pid":1234,"cmd":["python","script.py"],"exe":"/usr/bin/python3","t0_ms":1748542000000}
{"ts_ms":1748542001000,"parent":{"ts_ms":1748542001050,"cpu_usage":15.2,"mem_rss_kb":8192,"mem_vms_kb":32768,"disk_read_bytes":1024,"disk_write_bytes":2048,"net_rx_bytes":512,"net_tx_bytes":256,"thread_count":3,"uptime_secs":1},"children":[{"pid":1235,"command":"worker","metrics":{"ts_ms":1748542001060,"cpu_usage":5.1,"mem_rss_kb":4096,"mem_vms_kb":16384,"disk_read_bytes":512,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":1,"uptime_secs":1}}],"aggregated":{"ts_ms":1748542001000,"cpu_usage":20.3,"mem_rss_kb":12288,"mem_vms_kb":49152,"disk_read_bytes":1536,"disk_write_bytes":2048,"net_rx_bytes":512,"net_tx_bytes":256,"thread_count":4,"process_count":2,"uptime_secs":1}}
```

## Statistics Output

When a monitoring session completes, statistics are calculated and can be shown or saved:

```json
{
  "total_time_secs": 10.5,
  "sample_count": 42,
  "max_processes": 3,
  "max_threads": 8,
  "total_disk_read_bytes": 1536,
  "total_disk_write_bytes": 2048, 
  "total_net_rx_bytes": 512,
  "total_net_tx_bytes": 256,
  "peak_mem_rss_kb": 12288,
  "avg_cpu_usage": 18.7
}
```

The `stats` command can be used to generate these statistics from a saved JSON file.