✅ Goals

You want a ProcessMonitor that:

    ✅ Tracks wall time, CPU, RSS memory (including children)

    ✅ Records disk I/O, number of threads, and possibly per-thread CPU

    ✅ Exports JSON logs, optionally per-interval and/or summary

    ✅ Can run any command (Popen) or attach to an existing PID

    ✅ Is configurable, with extensible metrics (via plugins/hooks later)

    ✅ Can be packaged as a PyPI module or CLI tool

🧱 Dev Plan (Phases)

Phase 1 — MVP: Core Monitoring

Track process and children

Poll at fixed interval (e.g. 100ms)

Collect:

    RSS memory (sum across children)

    CPU percent (total)

    Thread count

    I/O (read/write bytes)

    Export JSON log (per-sample and final summary)

Phase 2 — CLI tool + Python API

CLI interface like:

monitor-proc --interval 100ms --output result.json -- python myscript.py

Allow attaching to existing PID

    Handle shell commands and env passthrough

Phase 3 — Advanced features

Custom metric hooks (user-provided)

Export Prometheus-style summary / CSV

Profile child processes individually

Async/streaming mode

Thread-level metrics via /proc/[pid]/task/[tid]


🧪 Example usage

if __name__ == "__main__":
    mon = ProcessMonitor(["python", "example.py"], interval=0.1)
    mon.run()

Or attach to a running PID:

mon = ProcessMonitor(None, interval=0.2, attach_pid=12345)
mon.run()

🧰 Packaging Plan

project/
├── monitor/
│   ├── __init__.py
│   ├── monitor.py
│   └── cli.py
├── setup.py
├── pyproject.toml
└── README.md

    CLI: monitor-proc -- python my_script.py

    PyPI: pip install monitor-proc

    Later: add rich for TUI, click for CLI, prometheus_client exporter, etc.


nsuring your ProcessMonitor is testable and maintainable:
1. Isolate side effects

    Wrap all system calls (psutil, subprocess) in interfaces or adapters.

    This allows you to mock or stub these calls in tests.

Example:

class ProcessInterface:
    def __init__(self, pid):
        self.proc = psutil.Process(pid)
    def memory_info(self):
        return self.proc.memory_info()
    def cpu_percent(self, interval=None):
        return self.proc.cpu_percent(interval=interval)
    def io_counters(self):
        return self.proc.io_counters()
    def children(self, recursive=True):
        return [ProcessInterface(p.pid) for p in self.proc.children(recursive)]
    def num_threads(self):
        return self.proc.num_threads()

In tests, mock ProcessInterface to return fake data.
2. Dependency Injection

    Pass interfaces or hooks into ProcessMonitor rather than calling psutil directly.

    Example:

def __init__(self, cmd, interval=0.1, output='metrics.json', proc_interface_cls=ProcessInterface):
    ...
    self.proc_interface_cls = proc_interface_cls

This lets you inject a mock process interface in tests.
3. Test small units

    Test _gather_metrics() separately by feeding it mock processes.

    Test JSON export independently (test that output matches expected schema).

    Test CLI parsing logic in isolation.

4. Use fixtures and mocks

    Use pytest + unittest.mock.

    Mock subprocess to simulate command start/stop without actually running code.

    Mock psutil.Process and children, making them return canned values for CPU, memory, etc.

Example:

from unittest.mock import MagicMock

mock_proc = MagicMock()
mock_proc.memory_info.return_value.rss = 1000
mock_proc.cpu_percent.return_value = 10.0
mock_proc.io_counters.return_value.read_bytes = 100
mock_proc.io_counters.return_value.write_bytes = 50
mock_proc.num_threads.return_value = 5
mock_proc.children.return_value = []

metrics = ProcessMonitor._gather_metrics(ProcessInterface(mock_proc))
assert metrics['memory_rss'] == 1000

5. Integration / End-to-end tests

    Run lightweight commands (sleep 1 or yes > /dev/null) monitored by the ProcessMonitor.

    Assert output contains expected keys, reasonable values.

    Check that monitor terminates on process exit.

6. Handling timing

    For timing-dependent parts (polling intervals), mock time.sleep and time.time to speed up tests and get predictable results.

7. Continuous integration

    Add these tests to CI (GitHub Actions, GitLab CI).

    Check coverage and ensure no flaky tests due to real-time waits or system load.

